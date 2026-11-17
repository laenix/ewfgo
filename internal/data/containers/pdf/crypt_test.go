package pdf

import (
	"crypto/aes"
	"encoding/hex"
	"testing"
)

func hexText(bytesValue []byte) string { return hex.EncodeToString(bytesValue) }

func cryptParams(t *testing.T, text string, id0 []byte) *encryptParams {
	t.Helper()
	value, err := ParseFirstValue([]byte(text))
	if err != nil {
		t.Fatalf("ParseFirstValue error = %v", err)
	}
	dict, ok := value.AsDict()
	if !ok {
		t.Fatal("value is not a dictionary")
	}
	return encryptParamsFromDict(dict, id0)
}

// RFC 6229 section 2: key "Key", plaintext "Plaintext".
func TestRC4MatchesRFC6229(t *testing.T) {
	ciphertext := rc4([]byte("Key"), []byte("Plaintext"))
	if got := hexText(ciphertext); got != "bbf316e8d940af0ad3" {
		t.Fatalf("rc4 = %s", got)
	}
	if got := string(rc4([]byte("Key"), ciphertext)); got != "Plaintext" {
		t.Fatalf("rc4 inverse = %q", got)
	}
}

func TestObjectKeysMixNumberGenerationAndAESSalt(t *testing.T) {
	fileKey := make([]byte, 16)
	for i := range fileKey {
		fileKey[i] = 0x11
	}
	first := objectKey(fileKey, 7, 0, cipherAESV2)
	if len(first) != 16 {
		t.Fatalf("key length = %d", len(first))
	}
	if string(first) == string(objectKey(fileKey, 8, 0, cipherAESV2)) {
		t.Fatal("different object numbers produced the same key")
	}
	if string(first) == string(objectKey(fileKey, 7, 1, cipherAESV2)) {
		t.Fatal("different generations produced the same key")
	}
	if string(first) == string(objectKey(fileKey, 7, 0, cipherRC4)) {
		t.Fatal("AESV2 and RC4 keys are equal; sAlT was not mixed in")
	}
	longKey := make([]byte, 32)
	for i := range longKey {
		longKey[i] = 0x22
	}
	if string(objectKey(longKey, 7, 0, cipherAESV3)) != string(longKey) {
		t.Fatal("AESV3 did not use the file key unchanged")
	}
}

// A fixed Algorithm 2 input whose output pins the padding, the little-endian
// /P word, /ID, the 50 MD5 rounds and the key truncation.
func TestAlgorithmTwoDerivesExpectedFileKey(t *testing.T) {
	params := cryptParams(t, "<< /Filter /Standard /V 2 /R 3 /Length 128 /P -4 "+
		"/O <28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A> "+
		"/U <0000000000000000000000000000000000000000000000000000000000000000> >>",
		[]byte("0123456789abcdef"))
	key, err := deriveFileKey(params, []byte(""), 16)
	if err != nil {
		t.Fatalf("deriveFileKey error = %v", err)
	}
	if got := hexText(key); got != "103ce8b966fb6efeb62aee8870316248" {
		t.Fatalf("file key = %s", got)
	}
}

func TestRevisionTwoUsesFiveBytesAndWrongPasswordDoesNotMatch(t *testing.T) {
	params := cryptParams(t, "<< /Filter /Standard /V 1 /R 2 /P -4 "+
		"/O <28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A> "+
		"/U <0000000000000000000000000000000000000000000000000000000000000000> >>",
		[]byte("0123456789abcdef"))
	key, err := deriveFileKey(params, []byte("user"), 5)
	if err != nil {
		t.Fatalf("deriveFileKey error = %v", err)
	}
	if len(key) != 5 {
		t.Fatalf("key length = %d", len(key))
	}
	if userPasswordMatches(2, key, params.user, params.id0) {
		t.Fatal("a wrong password verified")
	}
}

// Revision 5 is SHA-256 over password, salt and (for the owner entry) the user
// verifier. The expected bytes come from an implementation independent of this
// package.
func TestRevisionFiveHashesWithSHA256(t *testing.T) {
	salt := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	hash := passwordHash(5, []byte("forensic-aes256-r6"), salt, nil)
	if got := hexText(hash); got != "93e43065020f2d22a4e9ef975ebe77d2ee1ba793c8faecbac029fdcaac3feefb" {
		t.Fatalf("R5 hash = %s", got)
	}
}

// Algorithm 2.B is pinned against an independent implementation: 70 rounds for
// the first input, 64 for the second.
func TestAlgorithm2BMatchesIndependentImplementation(t *testing.T) {
	salt := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	if got := hexText(algorithm2B([]byte("forensic-aes256-r6"), salt, nil)); got !=
		"63c3f0688ffe9d56f739b0586d85484a18219a47c1e4069fd31d292325c36bd0" {
		t.Fatalf("algorithm 2.B (first) = %s", got)
	}
	other := []byte{0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}
	if got := hexText(algorithm2B([]byte("forensic-pdf"), other, nil)); got !=
		"bbc95be6f720ae2e11a60eeed8df3ec1dd7e0f868deb2b2b9d74b31dd3abd5af" {
		t.Fatalf("algorithm 2.B (second) = %s", got)
	}
}

func TestRevisionFiveNeedsFortyEightByteVerifiersAndAESV3(t *testing.T) {
	incomplete := cryptParams(t, "<< /Filter /Standard /V 5 /R 6 /Length 256 /P -4 "+
		"/O <00> /U <00> /OE <00> /UE <00> >>", []byte("id"))
	if _, err := unlockV5(incomplete, nil, false); err == nil {
		t.Fatal("short verifiers were accepted")
	} else if !contains(err.Error(), "/O verifier") {
		t.Fatalf("error = %v", err)
	}
	wrongVersion := cryptParams(t, "<< /Filter /Standard /V 4 /R 6 /Length 256 /P -4 "+
		"/O <00> /U <00> /OE <00> /UE <00> >>", []byte("id"))
	if _, err := unlockV5(wrongVersion, nil, false); err == nil || !contains(err.Error(), "inconsistent") {
		t.Fatalf("error = %v", err)
	}
}

func TestRevisionFourStillNamesAESV3InsteadOfGuessing(t *testing.T) {
	params := cryptParams(t, "<< /Filter /Standard /V 4 /R 4 /Length 128 /P -4 /O <00> /U <00> "+
		"/StmF /StdCF /StrF /StdCF /CF << /StdCF << /CFM /AESV3 /Length 32 >> >> >>", []byte("id"))
	unlocked, err := unlock(params, nil, false)
	if err != nil {
		t.Fatalf("unlock error = %v", err)
	}
	if unlocked == nil {
		t.Fatal("unlock returned no handler")
	}
	if !contains(joinNotes(unlocked.notes), "AESV3") {
		t.Fatalf("notes = %v", unlocked.notes)
	}
	if _, refused := unlocked.state.streamUnsupported(); !refused {
		t.Fatal("stream filter was not refused")
	}
}

func TestKeyLengthsFollowHandlerRules(t *testing.T) {
	full := cryptParams(t, "<< /Filter /Standard /V 4 /R 4 /Length 128 /P -4 /StmF /StdCF /StrF /StdCF "+
		"/CF << /StdCF << /CFM /AESV2 /Length 16 >> >> >>", []byte("id"))
	length, err := keyLength(full, 4,
		cryptDecision{kind: decisionCipher, cipher: cipherAESV2},
		cryptDecision{kind: decisionCipher, cipher: cipherAESV2})
	if err != nil || length != 16 {
		t.Fatalf("keyLength = %d, %v", length, err)
	}
	short := cryptParams(t, "<< /Filter /Standard /V 4 /R 4 /Length 40 /P -4 /StmF /StdCF /StrF /StdCF "+
		"/CF << /StdCF << /CFM /AESV2 /Length 5 >> >> >>", []byte("id"))
	if _, err := keyLength(short, 4,
		cryptDecision{kind: decisionCipher, cipher: cipherAESV2},
		cryptDecision{kind: decisionCipher, cipher: cipherAESV2}); err == nil {
		t.Fatal("short AESV2 key was accepted")
	}
}

func TestUnlockWithoutPasswordLeavesCipherHandlerOpaque(t *testing.T) {
	params := cryptParams(t, "<< /Filter /Standard /V 4 /R 4 /Length 128 /P -4 "+
		"/O <000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F> "+
		"/U <202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F> "+
		"/StmF /StdCF /StrF /StdCF /CF << /StdCF << /CFM /AESV2 /Length 16 >> >> >>",
		[]byte("id"))
	unlocked, err := unlock(params, nil, false)
	if err != nil {
		t.Fatalf("unlock error = %v", err)
	}
	if unlocked != nil {
		t.Fatalf("unlock returned a state without a password: %+v", unlocked)
	}
}

func TestAESStreamDecryptionUsesPerObjectKeys(t *testing.T) {
	fileKey := make([]byte, 16)
	for i := range fileKey {
		fileKey[i] = byte(i + 1)
	}
	plain := []byte("AES stream content")
	padded := append([]byte(nil), plain...)
	padding := aes.BlockSize - len(plain)%aes.BlockSize
	for i := 0; i < padding; i++ {
		padded = append(padded, byte(padding))
	}
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(0xA0 + i)
	}
	perObject := objectKey(fileKey, 7, 0, cipherAESV2)
	ciphertext, err := cbcEncryptRaw(perObject, iv, padded)
	if err != nil {
		t.Fatalf("cbcEncryptRaw error = %v", err)
	}
	state := &cryptState{
		fileKey:         fileKey,
		stream:          cryptDecision{kind: decisionCipher, cipher: cipherAESV2},
		stringValue:     cryptDecision{kind: decisionCipher, cipher: cipherAESV2},
		encryptMetadata: true,
	}
	decrypted, err := state.decryptStream(7, 0, cipherAESV2, append(iv, ciphertext...))
	if err != nil || string(decrypted) != string(plain) {
		t.Fatalf("decryptStream = %q/%v", decrypted, err)
	}
	if state.decryptedStreams != 1 {
		t.Fatalf("decryptedStreams = %d", state.decryptedStreams)
	}
	if _, err := state.decryptStream(7, 0, cipherAESV2, []byte{1, 2, 3}); err == nil {
		t.Fatal("short AES ciphertext was accepted")
	}
	if state.failedStreams != 1 {
		t.Fatalf("failedStreams = %d", state.failedStreams)
	}

	longKey := make([]byte, 32)
	for i := range longKey {
		longKey[i] = byte(0x40 + i)
	}
	aesv3State := &cryptState{
		fileKey:         longKey,
		stream:          cryptDecision{kind: decisionCipher, cipher: cipherAESV3},
		stringValue:     cryptDecision{kind: decisionCipher, cipher: cipherAESV3},
		encryptMetadata: true,
	}
	aesv3Cipher, err := cbcEncryptRaw(longKey, iv, padded)
	if err != nil {
		t.Fatalf("AESV3 cbcEncryptRaw error = %v", err)
	}
	decrypted, err = aesv3State.decryptStream(9, 0, cipherAESV3, append(iv, aesv3Cipher...))
	if err != nil || string(decrypted) != string(plain) {
		t.Fatalf("AESV3 decryptStream = %q/%v", decrypted, err)
	}
}

func TestRevisionFiveUnlocksAndVerifiesPerms(t *testing.T) {
	password := []byte("password")
	validationSalt := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	keySalt := []byte{9, 10, 11, 12, 13, 14, 15, 16}
	user := make([]byte, 48)
	copy(user[:32], passwordHash(5, password, validationSalt, nil))
	copy(user[32:40], validationSalt)
	copy(user[40:48], keySalt)
	fileKey := make([]byte, 32)
	for i := range fileKey {
		fileKey[i] = byte(0x20 + i)
	}
	intermediate := passwordHash(5, password, keySalt, nil)
	userEncrypted, err := cbcEncryptRaw(intermediate[:32], make([]byte, 16), fileKey)
	if err != nil {
		t.Fatalf("UE encryption error = %v", err)
	}
	var block [16]byte
	permissions := int32(-4)
	block[0] = byte(permissions)
	block[1] = byte(permissions >> 8)
	block[2] = byte(permissions >> 16)
	block[3] = byte(permissions >> 24)
	block[4], block[5], block[6], block[7] = 0xFF, 0xFF, 0xFF, 0xFF
	block[8] = 'T'
	copy(block[9:12], []byte("adb"))
	blockCipher, err := aes.NewCipher(fileKey)
	if err != nil {
		t.Fatalf("aes.NewCipher error = %v", err)
	}
	blockCipher.Encrypt(block[:], block[:])

	params := &encryptParams{
		hasFilter: true, filter: "Standard",
		hasVersion: true, version: 5,
		hasRevision: true, revision: 5,
		hasLengthBits: true, lengthBits: 256,
		hasPermissions: true, permissions: -4,
		owner: make([]byte, 48), user: user,
		ownerEncrypted: make([]byte, 32), userEncrypted: userEncrypted,
		perms: block[:], hasPerms: true,
		hasEncryptMeta: true, encryptMetadata: true,
		hasStreamFilter: true, streamFilter: "StdCF",
		hasStringFilter: true, stringFilter: "StdCF",
		hasCryptFilters: true,
		cryptFilters: map[string]cryptFilter{
			"StdCF": {method: "AESV3", hasMethod: true, lengthBytes: 32, hasLength: true},
		},
	}
	unlocked, err := unlock(params, password, true)
	if err != nil {
		t.Fatalf("unlock error = %v", err)
	}
	if unlocked == nil || string(unlocked.state.fileKey) != string(fileKey) {
		t.Fatalf("unlocked = %+v", unlocked)
	}
	if kind, ok := unlocked.state.streamCipher(); !ok || kind != cipherAESV3 {
		t.Fatalf("stream cipher = %v/%v", kind, ok)
	}
	if _, err := unlock(params, []byte("wrong"), true); err == nil || !contains(err.Error(), "not the user password") {
		t.Fatalf("wrong password error = %v", err)
	}

	wrongPerms := block
	wrongPerms[0] ^= 0xFF
	params.perms = wrongPerms[:]
	if err := verifyPerms(fileKey, params.perms, params); err == nil {
		t.Fatal("a corrupted /Perms block verified")
	}
	if err := verifyPerms(make([]byte, 32), block[:], params); err == nil {
		t.Fatal("a different file key verified /Perms")
	}
}

func TestResolveV5FilterNamesUnsupportedMethods(t *testing.T) {
	params := &encryptParams{
		hasCryptFilters: true,
		cryptFilters: map[string]cryptFilter{
			"AES":  {method: "AESV3", hasMethod: true, lengthBytes: 32, hasLength: true},
			"BAD":  {method: "AESV2", hasMethod: true},
			"NONE": {method: "None", hasMethod: true},
		},
	}
	var notes []string
	if decision := resolveV5Filter(params, "AES", true, &notes); decision.kind != decisionCipher || decision.cipher != cipherAESV3 {
		t.Fatalf("AES decision = %+v", decision)
	}
	if decision := resolveV5Filter(params, "NONE", true, &notes); decision.kind != decisionIdentity {
		t.Fatalf("None decision = %+v", decision)
	}
	if decision := resolveV5Filter(params, "BAD", true, &notes); decision.kind != decisionUnsupported {
		t.Fatalf("BAD decision = %+v", decision)
	}
	if decision := resolveV5Filter(params, "MISSING", true, &notes); decision.kind != decisionUnsupported {
		t.Fatalf("missing decision = %+v", decision)
	}
	if len(notes) < 2 {
		t.Fatalf("notes = %v", notes)
	}
}

func TestAESPKCS7RoundTrip(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	iv := make([]byte, 16)
	plain := []byte("0123456789abc") // 13 bytes
	padded := append([]byte(nil), plain...)
	padded = append(padded, byte(3), byte(3), byte(3))
	encrypted, err := cbcEncryptRaw(key, iv, padded)
	if err != nil {
		t.Fatalf("cbcEncryptRaw error = %v", err)
	}
	decrypted, err := cbcDecryptRaw(key, iv, encrypted)
	if err != nil {
		t.Fatalf("cbcDecryptRaw error = %v", err)
	}
	decrypted, err = unpadPKCS7(decrypted)
	if err != nil {
		t.Fatalf("unpadPKCS7 error = %v", err)
	}
	if string(decrypted) != string(plain) {
		t.Fatalf("round trip = %q, want %q", decrypted, plain)
	}
}

func contains(text, want string) bool {
	for i := 0; i+len(want) <= len(text); i++ {
		if text[i:i+len(want)] == want {
			return true
		}
	}
	return false
}
