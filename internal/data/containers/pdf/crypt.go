// The PDF Standard security handler, revisions 2 to 6.
//
// An encrypted PDF still writes its object graph, cross-reference table and
// trailer as plain text; only strings and stream bodies are ciphertext. This
// file derives the file key from a user password, checks it against the /U
// verifier, and — for revisions 2 to 4 — turns an object number and generation
// into the per-object key that RC4 or AESV2 needs. Revision 5 hashes the
// password with SHA-256, revision 6 with Algorithm 2.B, and both protect the
// file key itself in /UE; AESV3 uses that file key for every object directly.
//
// The ciphers are the ones the handler names: RC4 (V1, V2 and a V4 `V2` crypt
// filter), AES-128-CBC (a V4 `AESV2` crypt filter) and AES-256-CBC (V5
// `AESV3`). Key material stays in this file: callers receive plaintext or an
// error, never a key.

package pdf

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"strconv"
)

// passwordPadding is the 32-byte padding string of Algorithm 2. A password
// shorter than 32 bytes is completed with it; a longer one is truncated.
var passwordPadding = [32]byte{
	0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
	0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
}

// cipherKind is the symmetric cipher a crypt filter selects.
type cipherKind uint8

const (
	cipherRC4 cipherKind = iota
	cipherAESV2
	cipherAESV3
)

func (c cipherKind) name() string {
	switch c {
	case cipherRC4:
		return "RC4"
	case cipherAESV2:
		return "AESV2"
	case cipherAESV3:
		return "AESV3"
	}
	return "unknown cipher"
}

// decisionKind is what a /StmF or /StrF name means for this reader.
type decisionKind uint8

const (
	decisionIdentity decisionKind = iota
	decisionCipher
	decisionUnsupported
)

type cryptDecision struct {
	kind   decisionKind
	cipher cipherKind
	reason string
}

func (d cryptDecision) cipherValue() (cipherKind, bool) {
	if d.kind == decisionCipher {
		return d.cipher, true
	}
	return 0, false
}

// cryptFilter is one /CF subdictionary.
type cryptFilter struct {
	method      string
	hasMethod   bool
	lengthBytes int64
	hasLength   bool
}

// encryptParams is everything /Encrypt records that key derivation and
// decryption need.
type encryptParams struct {
	filter          string
	hasFilter       bool
	version         int64
	hasVersion      bool
	revision        int64
	hasRevision     bool
	lengthBits      int64
	hasLengthBits   bool
	permissions     int64
	hasPermissions  bool
	owner           []byte
	user            []byte
	ownerEncrypted  []byte
	userEncrypted   []byte
	perms           []byte
	hasPerms        bool
	encryptMetadata bool
	hasEncryptMeta  bool
	streamFilter    string
	hasStreamFilter bool
	stringFilter    string
	hasStringFilter bool
	cryptFilters    map[string]cryptFilter
	hasCryptFilters bool
	id0             []byte
	hasID0          bool
}

func encryptParamsFromDict(dict *Dict, id0 []byte) *encryptParams {
	params := &encryptParams{cryptFilters: make(map[string]cryptFilter), id0: id0, hasID0: id0 != nil}
	if name, ok := dict.GetName([]byte("Filter")); ok {
		params.filter, params.hasFilter = lossyUTF8(name), true
	}
	if v, ok := dict.GetInt([]byte("V")); ok {
		params.version, params.hasVersion = v, true
	}
	if v, ok := dict.GetInt([]byte("R")); ok {
		params.revision, params.hasRevision = v, true
	}
	if v, ok := dict.GetInt([]byte("Length")); ok {
		params.lengthBits, params.hasLengthBits = v, true
	}
	if v, ok := dict.GetInt([]byte("P")); ok {
		params.permissions, params.hasPermissions = v, true
	}
	if v, ok := dict.Get([]byte("O")); ok {
		params.owner, _ = v.AsString()
	}
	if v, ok := dict.Get([]byte("U")); ok {
		params.user, _ = v.AsString()
	}
	if v, ok := dict.Get([]byte("OE")); ok {
		params.ownerEncrypted, _ = v.AsString()
	}
	if v, ok := dict.Get([]byte("UE")); ok {
		params.userEncrypted, _ = v.AsString()
	}
	if v, ok := dict.Get([]byte("Perms")); ok {
		params.perms, params.hasPerms = v.AsString()
	}
	if v, ok := dict.GetBool([]byte("EncryptMetadata")); ok {
		params.encryptMetadata, params.hasEncryptMeta = v, true
	}
	if name, ok := dict.GetName([]byte("StmF")); ok {
		params.streamFilter, params.hasStreamFilter = lossyUTF8(name), true
	}
	if name, ok := dict.GetName([]byte("StrF")); ok {
		params.stringFilter, params.hasStringFilter = lossyUTF8(name), true
	}
	if filters, ok := dict.GetDict([]byte("CF")); ok {
		params.hasCryptFilters = true
		for _, item := range filters.Items() {
			filterDict, ok := item.Value.AsDict()
			if !ok {
				continue
			}
			var filter cryptFilter
			if name, ok := filterDict.GetName([]byte("CFM")); ok {
				filter.method, filter.hasMethod = lossyUTF8(name), true
			}
			if v, ok := filterDict.GetInt([]byte("Length")); ok {
				filter.lengthBytes, filter.hasLength = v, true
			}
			params.cryptFilters[string(item.Key)] = filter
		}
	}
	return params
}

// cryptState is a verified handler: the file key plus what each category
// should do.
type cryptState struct {
	fileKey          []byte
	stream           cryptDecision
	stringValue      cryptDecision
	encryptMetadata  bool
	decryptedStreams int
	decryptedStrings int
	failedStreams    int
	failedStrings    int
}

func (s *cryptState) streamCipher() (cipherKind, bool) { return s.stream.cipherValue() }
func (s *cryptState) stringCipher() (cipherKind, bool) { return s.stringValue.cipherValue() }

func (s *cryptState) streamUnsupported() (string, bool) {
	if s.stream.kind == decisionUnsupported {
		return s.stream.reason, true
	}
	return "", false
}

func (s *cryptState) stringUnsupported() (string, bool) {
	if s.stringValue.kind == decisionUnsupported {
		return s.stringValue.reason, true
	}
	return "", false
}

// decryptStrings decrypts every string in an indirect object's value,
// replacing a string whose ciphertext does not decrypt with Null so no
// ciphertext reaches a text field.
func (s *cryptState) decryptStrings(value *Value, number uint32, generation uint16) {
	cipherKindValue, ok := s.stringCipher()
	if !ok {
		return
	}
	key := objectKey(s.fileKey, number, generation, cipherKindValue)
	decryptValue(value, key, cipherKindValue, s)
}

func decryptValue(value *Value, key []byte, kind cipherKind, state *cryptState) {
	switch value.kind {
	case KindString:
		plain, err := decryptBytes(key, kind, value.bytes)
		if err != nil {
			*value = NullValue()
			state.failedStrings++
			return
		}
		value.bytes = plain
		state.decryptedStrings++
	case KindArray:
		for i := range value.array {
			decryptValue(&value.array[i], key, kind, state)
		}
	case KindDictionary:
		if value.dict == nil {
			return
		}
		for entryKey, entryValue := range value.dict.entries {
			decryptValue(&entryValue, key, kind, state)
			value.dict.entries[entryKey] = entryValue
		}
	}
}

// decryptStream decrypts one stream body. number and generation identify the
// indirect object that owns the stream.
func (s *cryptState) decryptStream(number uint32, generation uint16, kind cipherKind, data []byte) ([]byte, error) {
	key := objectKey(s.fileKey, number, generation, kind)
	plain, err := decryptBytes(key, kind, data)
	if err != nil {
		s.failedStreams++
		return nil, err
	}
	s.decryptedStreams++
	return plain, nil
}

// unlocked is the outcome of a successful password check.
type unlocked struct {
	state *cryptState
	notes []string
}

// unlock checks a handler and, when a password is supplied, verifies it.
//
// (nil, nil) means the handler is understood but no password was offered. An
// error names why the document must stay opaque; the caller turns it into a
// note rather than failing the whole parse.
func unlock(params *encryptParams, password []byte, provided bool) (*unlocked, error) {
	version := int64(0)
	if params.hasVersion {
		version = params.version
	}
	revision := int64(0)
	if params.hasRevision {
		revision = params.revision
	}

	if params.hasFilter && params.filter != "Standard" {
		return nil, errorf("PDF encryption filter %s is not the Standard security handler", params.filter)
	}
	if version == 5 || revision >= 5 {
		return unlockV5(params, password, provided)
	}
	if version != 1 && version != 2 && version != 4 {
		return nil, errorf("PDF encryption V%d is not implemented; only V1, V2, V4 and V5 are decoded", version)
	}
	if revision < 2 || revision > 4 {
		return nil, errorf("PDF encryption R%d is not implemented; only R2 to R6 are decoded", revision)
	}

	var notes []string
	var stream, stringValue cryptDecision
	switch version {
	case 1, 2:
		// V1 and V2 have no crypt filters: every string and stream is RC4.
		stream = cryptDecision{kind: decisionCipher, cipher: cipherRC4}
		stringValue = cryptDecision{kind: decisionCipher, cipher: cipherRC4}
	case 4:
		stream = resolveFilter(params, params.streamFilter, params.hasStreamFilter, &notes)
		stringValue = resolveFilter(params, params.stringFilter, params.hasStringFilter, &notes)
	}
	_, streamHas := stream.cipherValue()
	_, stringHas := stringValue.cipherValue()
	requiresCipher := streamHas || stringHas
	keyLen, err := keyLength(params, revision, stream, stringValue)
	if err != nil {
		return nil, err
	}

	if !requiresCipher {
		return &unlocked{
			state: &cryptState{
				stream:          stream,
				stringValue:     stringValue,
				encryptMetadata: !params.hasEncryptMeta || params.encryptMetadata,
			},
			notes: notes,
		}, nil
	}

	if len(params.owner) != 32 {
		return nil, errorf("the /O verifier is %d bytes; revisions 2 to 4 write 32", len(params.owner))
	}
	userBytes := 16
	if revision == 2 {
		userBytes = 32
	}
	if len(params.user) < userBytes {
		return nil, errorf("the /U verifier is %d bytes; revision %d needs at least %d", len(params.user), revision, userBytes)
	}
	if !params.hasPermissions {
		return nil, errorf("the encryption dictionary has no /P permissions entry")
	}
	if !provided {
		return nil, nil
	}
	if !params.hasID0 {
		return nil, errorf("the trailer has no /ID entry, so the encryption key cannot be derived")
	}

	fileKey, err := deriveFileKey(params, password, keyLen)
	if err != nil {
		return nil, err
	}
	if !userPasswordMatches(revision, fileKey, params.user, params.id0) {
		return nil, errorf("the supplied passphrase is not the user password (owner-password recovery is not implemented)")
	}
	return &unlocked{
		state: &cryptState{
			fileKey:         fileKey,
			stream:          stream,
			stringValue:     stringValue,
			encryptMetadata: !params.hasEncryptMeta || params.encryptMetadata,
		},
		notes: notes,
	}, nil
}

// unlockV5 handles revision 5 and 6: AES-256, a 48-byte /U and /O, and the file
// key protected in /UE and /OE. Only the user password is checked; the owner
// entry is described, not used.
func unlockV5(params *encryptParams, password []byte, provided bool) (*unlocked, error) {
	version := int64(0)
	if params.hasVersion {
		version = params.version
	}
	revision := int64(0)
	if params.hasRevision {
		revision = params.revision
	}
	if version != 5 {
		return nil, errorf("PDF encryption V%d R%d is inconsistent; revisions 5 and 6 need V5", version, revision)
	}
	if revision != 5 && revision != 6 {
		return nil, errorf("PDF encryption V5 R%d is not implemented; only revisions 5 and 6 use AESV3", revision)
	}
	if !params.hasPermissions {
		return nil, errorf("the encryption dictionary has no /P permissions entry")
	}
	if len(params.owner) != 48 {
		return nil, errorf("the /O verifier is %d bytes; revision %d writes 48", len(params.owner), revision)
	}
	if len(params.user) != 48 {
		return nil, errorf("the /U verifier is %d bytes; revision %d writes 48", len(params.user), revision)
	}
	if len(params.ownerEncrypted) != 32 {
		return nil, errorf("the /OE entry is %d bytes; revision %d writes 32", len(params.ownerEncrypted), revision)
	}
	if len(params.userEncrypted) != 32 {
		return nil, errorf("the /UE entry is %d bytes; revision %d writes 32", len(params.userEncrypted), revision)
	}
	if params.hasPerms && len(params.perms) != 16 {
		return nil, errorf("the /Perms entry is %d bytes; revision %d writes 16", len(params.perms), revision)
	}
	if params.hasLengthBits && params.lengthBits != 256 {
		return nil, errorf("revision %d uses a 256-bit key, but /Length says %d bits", revision, params.lengthBits)
	}

	var notes []string
	stream := resolveV5Filter(params, params.streamFilter, params.hasStreamFilter, &notes)
	stringValue := resolveV5Filter(params, params.stringFilter, params.hasStringFilter, &notes)
	_, streamHas := stream.cipherValue()
	_, stringHas := stringValue.cipherValue()
	requiresCipher := streamHas || stringHas
	if !requiresCipher {
		return &unlocked{
			state: &cryptState{
				stream:          stream,
				stringValue:     stringValue,
				encryptMetadata: !params.hasEncryptMeta || params.encryptMetadata,
			},
			notes: notes,
		}, nil
	}
	if !provided {
		return nil, nil
	}
	if len(password) > 127 {
		password = password[:127]
	}

	if !userPasswordMatchesV5(revision, password, params.user) {
		return nil, errorf("the supplied passphrase is not the user password (owner-password recovery is not implemented)")
	}
	fileKey, err := deriveFileKeyV5(revision, password, params.user, params.userEncrypted)
	if err != nil {
		return nil, err
	}
	if params.hasPerms {
		if err := verifyPerms(fileKey, params.perms, params); err != nil {
			return nil, err
		}
	}
	return &unlocked{
		state: &cryptState{
			fileKey:         fileKey,
			stream:          stream,
			stringValue:     stringValue,
			encryptMetadata: !params.hasEncryptMeta || params.encryptMetadata,
		},
		notes: notes,
	}, nil
}

func resolveV5Filter(params *encryptParams, name string, hasName bool, notes *[]string) cryptDecision {
	if !hasName {
		name = "Identity"
	}
	if name == "Identity" {
		return cryptDecision{kind: decisionIdentity}
	}
	filter, ok := params.cryptFilters[name]
	if !ok {
		reason := "crypt filter /" + name + " is not defined in /CF; its strings and streams were not decoded"
		*notes = append(*notes, reason)
		return cryptDecision{kind: decisionUnsupported, reason: reason}
	}
	switch {
	case filter.hasMethod && filter.method == "None":
		return cryptDecision{kind: decisionIdentity}
	case filter.hasMethod && filter.method == "AESV3":
		if filter.hasLength && filter.lengthBytes != 32 {
			reason := "crypt filter /" + name + " declares a " + itoa(filter.lengthBytes) + "-byte key; AESV3 needs 32"
			*notes = append(*notes, reason)
			return cryptDecision{kind: decisionUnsupported, reason: reason}
		}
		return cryptDecision{kind: decisionCipher, cipher: cipherAESV3}
	case filter.hasMethod:
		reason := "crypt filter /" + name + " uses CFM /" + filter.method + "; revision 5 and 6 need AESV3"
		*notes = append(*notes, reason)
		return cryptDecision{kind: decisionUnsupported, reason: reason}
	default:
		reason := "crypt filter /" + name + " names no CFM"
		*notes = append(*notes, reason)
		return cryptDecision{kind: decisionUnsupported, reason: reason}
	}
}

func resolveFilter(params *encryptParams, name string, hasName bool, notes *[]string) cryptDecision {
	if !hasName {
		name = "Identity"
	}
	if name == "Identity" {
		return cryptDecision{kind: decisionIdentity}
	}
	filter, ok := params.cryptFilters[name]
	if !ok {
		reason := "crypt filter /" + name + " is not defined in /CF; its strings and streams were not decoded"
		*notes = append(*notes, reason)
		return cryptDecision{kind: decisionUnsupported, reason: reason}
	}
	switch {
	case filter.hasMethod && filter.method == "None":
		return cryptDecision{kind: decisionIdentity}
	case filter.hasMethod && filter.method == "V2":
		return cryptDecision{kind: decisionCipher, cipher: cipherRC4}
	case filter.hasMethod && filter.method == "AESV2":
		return cryptDecision{kind: decisionCipher, cipher: cipherAESV2}
	case filter.hasMethod && filter.method == "AESV3":
		reason := "crypt filter /" + name + " uses CFM /AESV3 with V" +
			itoa(int64Value(params.version, params.hasVersion)) + " R" +
			itoa(int64Value(params.revision, params.hasRevision)) +
			"; AESV3 is decoded only for V5 at revision 5 or 6"
		*notes = append(*notes, reason)
		return cryptDecision{kind: decisionUnsupported, reason: reason}
	case filter.hasMethod:
		reason := "crypt filter /" + name + " uses unknown CFM /" + filter.method
		*notes = append(*notes, reason)
		return cryptDecision{kind: decisionUnsupported, reason: reason}
	default:
		reason := "crypt filter /" + name + " names no CFM"
		*notes = append(*notes, reason)
		return cryptDecision{kind: decisionUnsupported, reason: reason}
	}
}

// keyLength returns the file encryption key length in bytes (Algorithm 2 step
// f).
func keyLength(params *encryptParams, revision int64, stream, stringValue cryptDecision) (int, error) {
	streamCipher, streamHas := stream.cipherValue()
	stringCipher, stringHas := stringValue.cipherValue()
	aes := (streamHas && streamCipher == cipherAESV2) || (stringHas && stringCipher == cipherAESV2)
	if revision == 2 {
		if aes {
			return 0, errorf("AESV2 needs revision 4, not revision 2")
		}
		if params.hasLengthBits && params.lengthBits != 40 {
			return 0, errorf("revision 2 uses a 40-bit key, but /Length says %d bits", params.lengthBits)
		}
		return 5, nil
	}

	bits := int64(40)
	if aes {
		bits = 128
	}
	if params.hasLengthBits {
		bits = params.lengthBits
	}
	if bits%8 != 0 || bits < 40 || bits > 128 {
		return 0, errorf("unsupported PDF key length %d bits; revisions 3 and 4 accept 40 to 128 bits in multiples of 8", bits)
	}
	keyLen := int(bits / 8)
	if aes && keyLen != 16 {
		return 0, errorf("AESV2 requires a 128-bit key, but the document declares %d bits", bits)
	}
	for _, name := range []struct {
		value string
		has   bool
	}{{params.streamFilter, params.hasStreamFilter}, {params.stringFilter, params.hasStringFilter}} {
		if !name.has {
			continue
		}
		filter, ok := params.cryptFilters[name.value]
		if !ok {
			continue
		}
		var expected int
		hasExpected := false
		switch {
		case filter.hasMethod && filter.method == "AESV2":
			expected, hasExpected = 16, true
		case filter.hasMethod && filter.method == "V2":
			expected, hasExpected = keyLen, true
		}
		if hasExpected && filter.hasLength && (filter.lengthBytes < 0 || int(filter.lengthBytes) != expected) {
			return 0, errorf("crypt filter /%s declares a %d-byte key, but the file key is %d bytes",
				name.value, filter.lengthBytes, expected)
		}
	}
	return keyLen, nil
}

// deriveFileKey implements Algorithm 2: the file encryption key from the user
// password.
func deriveFileKey(params *encryptParams, password []byte, keyLen int) ([]byte, error) {
	revision := int64(0)
	if params.hasRevision {
		revision = params.revision
	}
	if !params.hasPermissions {
		return nil, errorf("the encryption dictionary has no /P permissions entry")
	}
	if params.permissions < -2147483648 || params.permissions > 2147483647 {
		return nil, errorf("/P value %d does not fit a 32-bit integer", params.permissions)
	}
	if !params.hasID0 {
		return nil, errorf("the trailer has no /ID entry")
	}

	input := make([]byte, 0, 64+len(params.id0))
	padded := paddedPassword(password)
	input = append(input, padded[:]...)
	input = append(input, params.owner...)
	permissions := int32(params.permissions)
	input = append(input, byte(permissions), byte(permissions>>8), byte(permissions>>16), byte(permissions>>24))
	input = append(input, params.id0...)
	// Algorithm 2 step c: revisions 4 and later mix in four FF bytes when the
	// metadata stream is not encrypted.
	if revision >= 4 && params.hasEncryptMeta && !params.encryptMetadata {
		input = append(input, 0xFF, 0xFF, 0xFF, 0xFF)
	}

	digest := md5.Sum(input)
	key := digest[:]
	if revision >= 3 {
		for i := 0; i < 50; i++ {
			next := md5.Sum(key[:keyLen])
			key = next[:]
		}
	}
	return append([]byte(nil), key[:keyLen]...), nil
}

// paddedPassword returns the 32-byte padded password of Algorithm 2 step a.
func paddedPassword(password []byte) [32]byte {
	var out [32]byte
	copied := len(password)
	if copied > 32 {
		copied = 32
	}
	copy(out[:], password[:copied])
	copy(out[copied:], passwordPadding[:32-copied])
	return out
}

// userPasswordMatches implements Algorithm 4 (R2) and Algorithm 5 (R3/R4).
func userPasswordMatches(revision int64, key, user, id0 []byte) bool {
	if revision == 2 {
		expected := rc4(key, passwordPadding[:])
		return len(user) >= 32 && string(expected) == string(user[:32])
	}
	input := make([]byte, 0, 32+len(id0))
	input = append(input, passwordPadding[:]...)
	input = append(input, id0...)
	digestSum := md5.Sum(input)
	digest := rc4(key, digestSum[:])
	for index := byte(1); index <= 19; index++ {
		round := make([]byte, len(key))
		for i, b := range key {
			round[i] = b ^ index
		}
		digest = rc4(round, digest)
	}
	return len(user) >= 16 && string(digest) == string(user[:16])
}

// passwordHash implements the revision 5 SHA-256 hash and the revision 6
// Algorithm 2.B hash. salt is the validation salt when checking /U, or the key
// salt when deriving the file key; udata is empty for the user entry.
func passwordHash(revision int64, password, salt, udata []byte) []byte {
	if revision == 5 {
		input := make([]byte, 0, len(password)+len(salt)+len(udata))
		input = append(input, password...)
		input = append(input, salt...)
		input = append(input, udata...)
		sum := sha256.Sum256(input)
		return sum[:]
	}
	return algorithm2B(password, salt, udata)
}

// algorithm2B implements the revision 6 password hash. It is deliberately
// expensive and terminates once the last ciphertext byte falls below
// round-32, which is certain by round 288.
func algorithm2B(password, salt, udata []byte) []byte {
	input := make([]byte, 0, len(password)+len(salt)+len(udata))
	input = append(input, password...)
	input = append(input, salt...)
	input = append(input, udata...)
	sum := sha256.Sum256(input)
	k := append([]byte(nil), sum[:]...)
	round := 0
	for {
		input := make([]byte, 0, 64*(len(password)+len(k)+len(udata)))
		for i := 0; i < 64; i++ {
			input = append(input, password...)
			input = append(input, k...)
			input = append(input, udata...)
		}
		encrypted, err := cbcEncryptRaw(k[:16], k[16:32], input)
		if err != nil {
			// The input length is always a multiple of 16; this cannot happen
			// for a well-formed password. Return a wrong key rather than panic.
			return make([]byte, 32)
		}
		selector := 0
		for _, b := range encrypted[:16] {
			selector = (selector + int(b)) % 3
		}
		switch selector {
		case 0:
			s := sha256.Sum256(encrypted)
			k = s[:]
		case 1:
			s := sha512.Sum384(encrypted)
			k = s[:]
		default:
			s := sha512.Sum512(encrypted)
			k = s[:]
		}
		round++
		if round >= 64 && int(encrypted[len(encrypted)-1]) <= round-32 {
			break
		}
	}
	return append([]byte(nil), k[:32]...)
}

// userPasswordMatchesV5 checks the user entry of /U: its first 32 bytes are
// the password hash of the 8-byte validation salt that follows them.
func userPasswordMatchesV5(revision int64, password, user []byte) bool {
	hash := passwordHash(revision, password, user[32:40], nil)
	return string(hash) == string(user[:32])
}

// deriveFileKeyV5 decrypts /UE with the key-salt hash to recover the 32-byte
// file key.
func deriveFileKeyV5(revision int64, password, user, userEncrypted []byte) ([]byte, error) {
	intermediate := passwordHash(revision, password, user[40:48], nil)
	plain, err := cbcDecryptRaw(intermediate[:32], make([]byte, 16), userEncrypted)
	if err != nil {
		return nil, errorf("the /UE entry could not be decrypted: %v", err)
	}
	if len(plain) != 32 {
		return nil, errorf("the /UE entry decrypted to %d bytes; the file key is 32", len(plain))
	}
	return plain, nil
}

// verifyPerms checks /Perms: the file key's own check on /P.
func verifyPerms(fileKey, perms []byte, params *encryptParams) error {
	blockCipher, err := aes.NewCipher(fileKey)
	if err != nil {
		return errorf("an AES-256 file key of %d bytes is invalid", len(fileKey))
	}
	var block [16]byte
	copy(block[:], perms)
	blockCipher.Decrypt(block[:], block[:])
	if !params.hasPermissions {
		return errorf("the encryption dictionary has no /P permissions entry")
	}
	if params.permissions < -2147483648 || params.permissions > 2147483647 {
		return errorf("the /P value does not fit a 32-bit integer")
	}
	permissions := int32(params.permissions)
	expected := []byte{byte(permissions), byte(permissions >> 8), byte(permissions >> 16), byte(permissions >> 24)}
	if string(block[:4]) != string(expected) {
		return errorf("the /Perms entry does not match /P; the password is wrong or the file is damaged")
	}
	if block[4] != 0xFF || block[5] != 0xFF || block[6] != 0xFF || block[7] != 0xFF ||
		block[9] != 'a' || block[10] != 'd' || block[11] != 'b' {
		return errorf("the /Perms entry carries the wrong marker; the password is wrong or the file is damaged")
	}
	if block[8] != 'T' && block[8] != 'F' {
		return errorf("the /Perms entry carries no metadata flag")
	}
	if params.hasEncryptMeta {
		expectedFlag := byte('F')
		if params.encryptMetadata {
			expectedFlag = 'T'
		}
		if block[8] != expectedFlag {
			return errorf("the /Perms metadata flag does not match /EncryptMetadata")
		}
	}
	return nil
}

// objectKey implements Algorithm 1: the per-object key. The low three bytes of
// the object number and the two bytes of its generation are mixed in, plus
// `sAlT` for AESV2. AESV3 uses the file key itself.
func objectKey(fileKey []byte, number uint32, generation uint16, kind cipherKind) []byte {
	if kind == cipherAESV3 {
		return append([]byte(nil), fileKey...)
	}
	input := make([]byte, 0, len(fileKey)+9)
	input = append(input, fileKey...)
	input = append(input, byte(number), byte(number>>8), byte(number>>16))
	input = append(input, byte(generation), byte(generation>>8))
	if kind == cipherAESV2 {
		input = append(input, 's', 'A', 'l', 'T')
	}
	sum := md5.Sum(input)
	length := len(fileKey) + 5
	if length > 16 {
		length = 16
	}
	return append([]byte(nil), sum[:length]...)
}

func decryptBytes(key []byte, kind cipherKind, data []byte) ([]byte, error) {
	switch kind {
	case cipherRC4:
		return rc4(key, data), nil
	case cipherAESV2, cipherAESV3:
		if len(data) < 32 || (len(data)-16)%16 != 0 {
			return nil, errorf("an %s ciphertext of %d bytes is not a 16-byte IV plus whole blocks", kind.name(), len(data))
		}
		plain, err := cbcDecryptRaw(key, data[:16], data[16:])
		if err != nil {
			return nil, errorf("%s decryption failed: %v", kind.name(), err)
		}
		plain, err = unpadPKCS7(plain)
		if err != nil {
			return nil, errorf("the %s plaintext has invalid PKCS #7 padding", kind.name())
		}
		return plain, nil
	}
	return nil, errorf("unknown cipher")
}

// cbcDecryptRaw decrypts whole AES-CBC blocks without removing padding.
func cbcDecryptRaw(key, iv, data []byte) ([]byte, error) {
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != aes.BlockSize || len(data)%aes.BlockSize != 0 {
		return nil, errorf("AES-CBC input is not a 16-byte IV plus whole blocks")
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(blockCipher, iv).CryptBlocks(out, data)
	return out, nil
}

// cbcEncryptRaw encrypts whole AES-CBC blocks without adding padding.
func cbcEncryptRaw(key, iv, data []byte) ([]byte, error) {
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != aes.BlockSize || len(data)%aes.BlockSize != 0 {
		return nil, errorf("AES-CBC input is not a 16-byte IV plus whole blocks")
	}
	out := make([]byte, len(data))
	cipher.NewCBCEncrypter(blockCipher, iv).CryptBlocks(out, data)
	return out, nil
}

func unpadPKCS7(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errorf("empty padded plaintext")
	}
	pad := int(data[len(data)-1])
	if pad < 1 || pad > aes.BlockSize || pad > len(data) {
		return nil, errorf("invalid PKCS #7 padding")
	}
	for _, b := range data[len(data)-pad:] {
		if int(b) != pad {
			return nil, errorf("invalid PKCS #7 padding")
		}
	}
	return data[:len(data)-pad], nil
}

// rc4 implements RC4 as published in RFC 6229.
func rc4(key, data []byte) []byte {
	if len(key) == 0 {
		return append([]byte(nil), data...)
	}
	var state [256]byte
	for i := 0; i < 256; i++ {
		state[i] = byte(i)
	}
	var j byte
	for i := 0; i < 256; i++ {
		j += state[i] + key[i%len(key)]
		state[i], state[j] = state[j], state[i]
	}
	var i, jj byte
	out := make([]byte, len(data))
	for index, b := range data {
		i++
		jj += state[i]
		state[i], state[jj] = state[jj], state[i]
		position := state[i] + state[jj]
		out[index] = b ^ state[position]
	}
	return out
}

// encryptedError marks a stream or string that could not be decoded because
// the document is encrypted and no usable key was available. Callers turn it
// into a note and never use the ciphertext as content.
type encryptedError struct{ message string }

func (e encryptedError) Error() string { return e.message }

// errorf builds a plain error carrying a refusal reason.
func errorf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

func int64Value(v int64, has bool) int64 {
	if has {
		return v
	}
	return 0
}
