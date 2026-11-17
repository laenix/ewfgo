package sqlcipher

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

var fixtureSalt = [SaltBytes]byte{
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
}

func fastParams(params Params) Params {
	params.KDFIterations = 1000
	params.HMACKDFIterations = 2
	return params
}

func plaintextDatabase(pages int, params Params) []byte {
	pageSize := int(params.PageSize)
	usable := pageSize - params.ReserveBytes()
	db := make([]byte, pages*pageSize)
	for index := 0; index < pages; index++ {
		page := db[index*pageSize : (index+1)*pageSize]
		header := 100
		page[header] = 13
		page[header+5] = byte(usable >> 8)
		page[header+6] = byte(usable)
	}
	first := db[:pageSize]
	copy(first[:SaltBytes], SQLiteMagic)
	if params.PageSize == MaxPageSize {
		putBE16(first, 16, 1)
	} else {
		putBE16(first, 16, uint16(params.PageSize))
	}
	first[18] = 2
	first[19] = 2
	first[20] = byte(params.ReserveBytes())
	first[21] = 64
	first[22] = 32
	first[23] = 32
	putBE32(first, 24, 1)
	putBE32(first, 28, uint32(pages))
	putBE32(first, 40, 1)
	putBE32(first, 44, 4)
	putBE32(first, 56, 1)
	putBE32(first, 92, 1)
	putBE32(first, 96, 3_049_001)
	return db
}

func putBE16(buf []byte, at int, value uint16) {
	buf[at] = byte(value >> 8)
	buf[at+1] = byte(value)
}

func putBE32(buf []byte, at int, value uint32) {
	buf[at] = byte(value >> 24)
	buf[at+1] = byte(value >> 16)
	buf[at+2] = byte(value >> 8)
	buf[at+3] = byte(value)
}

func putLE32(buf []byte, at int, value uint32) {
	buf[at] = byte(value)
	buf[at+1] = byte(value >> 8)
	buf[at+2] = byte(value >> 16)
	buf[at+3] = byte(value >> 24)
}

func memorySource(data []byte) source.ByteSource {
	return source.NewMemorySourceWithImage(1, 9, data)
}

func mustUnlock(t *testing.T, ciphertext, passphrase []byte, params Params) *Source {
	t.Helper()
	unlocked, err := Unlock(2, memorySource(ciphertext), passphrase, params)
	if err != nil {
		t.Fatalf("Unlock error = %v", err)
	}
	return unlocked
}

func readAll(t *testing.T, src source.ByteSource) []byte {
	t.Helper()
	out := make([]byte, src.Len())
	if _, err := src.ReadAt(0, out); err != nil {
		t.Fatalf("ReadAt error = %v", err)
	}
	return out
}

func hexOf(data []byte) string { return hex.EncodeToString(data) }

func TestDetect(t *testing.T) {
	params := fastParams(ParamsV4())
	plaintext := plaintextDatabase(2, params)
	ciphertext, err := EncryptDatabase(plaintext, fixtureSalt, []byte("correct horse"), params)
	if err != nil {
		t.Fatalf("EncryptDatabase error = %v", err)
	}
	header, err := Detect(memorySource(ciphertext))
	if err != nil {
		t.Fatalf("Detect error = %v", err)
	}
	if header == nil {
		t.Fatal("Detect returned nil for an encrypted database")
	}
	if header.Salt != fixtureSalt {
		t.Fatalf("salt = %x, want %x", header.Salt, fixtureSalt)
	}
	if header.Version != Version4 || header.HasPageSize || header.HasReservedBytes {
		t.Fatalf("header = %+v", header)
	}
	if header.FileSize != uint64(len(ciphertext)) {
		t.Fatalf("file size = %d, want %d", header.FileSize, len(ciphertext))
	}

	short, err := Detect(memorySource(ciphertext[:SaltBytes-1]))
	if err != nil || short != nil {
		t.Fatalf("Detect(short) = %+v, %v; want nil, nil", short, err)
	}
	plainHeader, err := Detect(memorySource(plaintext))
	if err != nil || plainHeader != nil {
		t.Fatalf("Detect(plaintext) = %+v, %v; want nil, nil", plainHeader, err)
	}
}

func TestUnlockAllProfiles(t *testing.T) {
	cases := []struct {
		name            string
		params          Params
		expectedPage    uint32
		expectedReserve int
	}{
		{"v4", ParamsV4(), 4096, SQLCipher4ReserveBytes},
		{"v3", ParamsV3(), 1024, SQLCipher3ReserveBytes},
		{"v2", ParamsV2(), 1024, SQLCipher3ReserveBytes},
		{"v1", ParamsV1(), 1024, SQLCipher1ReserveBytes},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			params := fastParams(test.params)
			plaintext := plaintextDatabase(3, params)
			ciphertext, err := EncryptDatabase(plaintext, fixtureSalt, []byte("legacy horse"), params)
			if err != nil {
				t.Fatalf("EncryptDatabase error = %v", err)
			}
			if bytes.Equal(ciphertext[:SaltBytes], []byte(SQLiteMagic)) {
				t.Fatal("ciphertext starts with the SQLite magic")
			}
			unlocked := mustUnlock(t, ciphertext, []byte("legacy horse"), params)
			if unlocked.Len() != uint64(len(ciphertext)) {
				t.Fatalf("Len = %d, want %d", unlocked.Len(), len(ciphertext))
			}
			if unlocked.PageSize() != test.expectedPage || unlocked.PageCount() != 3 {
				t.Fatalf("geometry = %d/%d", unlocked.PageSize(), unlocked.PageCount())
			}
			header := unlocked.Header()
			if !header.HasPageSize || header.PageSize != test.expectedPage {
				t.Fatalf("header page size = %+v", header)
			}
			if !header.HasReservedBytes || int(header.ReservedBytes) != test.expectedReserve {
				t.Fatalf("header reserve = %+v", header)
			}
			if got := readAll(t, unlocked); !bytes.Equal(got, plaintext) {
				t.Fatal("decrypted bytes do not round-trip")
			}
		})
	}
}

func TestDefaultIterationProfilesUnlock(t *testing.T) {
	for _, params := range []Params{ParamsV4(), ParamsV3()} {
		t.Run(params.Version.Label(), func(t *testing.T) {
			plaintext := plaintextDatabase(1, params)
			ciphertext := mustEncryptDatabase(t, plaintext, params, []byte("default horse"))
			unlocked := mustUnlock(t, ciphertext, []byte("default horse"), params)
			if got := readAll(t, unlocked); !bytes.Equal(got, plaintext) {
				t.Fatal("default-iteration profile did not round-trip")
			}
		})
	}
}

func TestDefaultProfileParameters(t *testing.T) {
	if ParamsV4().KDFIterations != DefaultKDFIterations ||
		ParamsV4().HMACKDFIterations != DefaultHMACKDFIterations {
		t.Fatal("SQLCipher 4 KDF defaults changed")
	}
	profiles := DefaultProfiles()
	if len(profiles) != 4 {
		t.Fatalf("DefaultProfiles length = %d", len(profiles))
	}
	reserves := []int{80, 48, 48, 16}
	labels := []string{"SQLCipher 4", "SQLCipher 3", "SQLCipher 2", "SQLCipher 1"}
	for index, profile := range profiles {
		if profile.ReserveBytes() != reserves[index] {
			t.Fatalf("profile %d reserve = %d, want %d", index, profile.ReserveBytes(), reserves[index])
		}
		if profile.Version.Label() != labels[index] {
			t.Fatalf("profile %d label = %q", index, profile.Version.Label())
		}
	}
}

func TestDerivedKeyVector(t *testing.T) {
	params := fastParams(ParamsV4())
	key, err := DeriveKey([]byte("forensic"), fixtureSalt, params)
	if err != nil {
		t.Fatalf("DeriveKey error = %v", err)
	}
	if got := hexOf(key.EncryptionKey[:]); got != "596d395e126d95d69ab54585c43bc82d6a6bde2ae49a3d318c14fbb7283e4936" {
		t.Fatalf("encryption key = %s", got)
	}
	if got := hexOf(key.HMACKey[:]); got != "fd10fd9ce1bfdeb2e5fe747cc0b67296714d9e7dde11c09810c4e159e98e14dc" {
		t.Fatalf("HMAC key = %s", got)
	}
}

func TestRawKeyHMACVector(t *testing.T) {
	var encryptionKey [EncryptionKeyBytes]byte
	var salt [SaltBytes]byte
	for index := range encryptionKey {
		encryptionKey[index] = byte(index)
	}
	for index := range salt {
		salt[index] = byte(index)
	}
	key, err := KeyFromRaw(encryptionKey, salt, ParamsV4())
	if err != nil {
		t.Fatalf("KeyFromRaw error = %v", err)
	}
	if key.EncryptionKey != encryptionKey {
		t.Fatal("raw encryption key was not used unchanged")
	}
	if got := hexOf(key.HMACKey[:]); got != "601364baed0dde5a2d291ede302ae7e0540a85b57a281a0d19c344b7d4f382ce" {
		t.Fatalf("HMAC key = %s", got)
	}
	legacy, err := KeyFromRaw(encryptionKey, salt, ParamsV1())
	if err != nil {
		t.Fatalf("KeyFromRaw(v1) error = %v", err)
	}
	if legacy.HMACKey != [EncryptionKeyBytes]byte{} {
		t.Fatal("SQLCipher 1 derived a non-zero HMAC key")
	}
}

func TestWrongPassphraseIsExplicit(t *testing.T) {
	params := fastParams(ParamsV4())
	_, ciphertext := encryptedFixture(t, 2, params, []byte("correct horse"))
	_, err := Unlock(2, memorySource(ciphertext), []byte("wrong horse"), params)
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("error = %v, want ErrWrongPassphrase", err)
	}
	if !errors.Is(err, source.ErrDecrypt) {
		t.Fatalf("error = %v, want source.ErrDecrypt", err)
	}
	var structured *Error
	if !errors.As(err, &structured) || structured.Check != "HMAC-SHA512" {
		t.Fatalf("structured error = %+v", structured)
	}
	if !strings.Contains(err.Error(), "page-1 HMAC-SHA512") {
		t.Fatalf("error text = %q", err)
	}
}

func encryptedFixture(t *testing.T, pages int, params Params, passphrase []byte) ([]byte, []byte) {
	t.Helper()
	plaintext := plaintextDatabase(pages, params)
	ciphertext, err := EncryptDatabase(plaintext, fixtureSalt, passphrase, params)
	if err != nil {
		t.Fatalf("EncryptDatabase error = %v", err)
	}
	return plaintext, ciphertext
}

func TestDamagedPageHMACIsCorrupt(t *testing.T) {
	params := fastParams(ParamsV4())
	_, ciphertext := encryptedFixture(t, 2, params, []byte("correct horse"))
	ciphertext[len(ciphertext)-1] ^= 0x01
	unlocked := mustUnlock(t, ciphertext, []byte("correct horse"), params)

	buf := bytes.Repeat([]byte{0xaa}, 32)
	n, err := unlocked.ReadAt(uint64(params.PageSize), buf)
	if n != 0 {
		t.Fatalf("ReadAt returned %d bytes with an error", n)
	}
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("ReadAt error = %v, want source.ErrCorrupt", err)
	}
	if !bytes.Equal(buf, bytes.Repeat([]byte{0xaa}, 32)) {
		t.Fatal("a failed page was zero-filled or otherwise written")
	}
	if got := unlocked.Stats().CorruptBytes; got != uint64(params.PageSize) {
		t.Fatalf("corrupt bytes = %d, want %d", got, params.PageSize)
	}
}

func TestLossyReadDoesNotHideCorruption(t *testing.T) {
	params := fastParams(ParamsV3())
	_, ciphertext := encryptedFixture(t, 2, params, []byte("lossy horse"))
	// SQLCipher 3's 20-byte HMAC sits at the start of the 48-byte reserve;
	// mutating the padding after it would not be an authentication failure.
	macAt := int(params.PageSize) - params.ReserveBytes() + IVBytes
	ciphertext[int(params.PageSize)+macAt] ^= 0x01
	unlocked := mustUnlock(t, ciphertext, []byte("lossy horse"), params)

	buf := bytes.Repeat([]byte{0x5a}, 64)
	n, err := unlocked.ReadAtLossy(uint64(params.PageSize), buf)
	if n != 0 || !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("ReadAtLossy = %d, %v", n, err)
	}
	if !bytes.Equal(buf, bytes.Repeat([]byte{0x5a}, 64)) {
		t.Fatal("lossy read filled a corrupt page with bytes")
	}
}

func TestHMACUnderTheWrongKeyIsNotSkipped(t *testing.T) {
	params := fastParams(ParamsV4())
	_, ciphertext := encryptedFixture(t, 2, params, []byte("correct horse"))
	key, err := DeriveKey([]byte("correct horse"), fixtureSalt, params)
	if err != nil {
		t.Fatalf("DeriveKey error = %v", err)
	}
	page := int(params.PageSize)
	raw := ciphertext[page : 2*page]
	macAt := page - params.ReserveBytes() + IVBytes
	message := append([]byte(nil), raw[:macAt]...)
	message = append(message, byte(2), 0, 0, 0)
	wrong := params.HMAC.Compute(key.EncryptionKey[:], message)
	if len(wrong) == 0 {
		t.Fatal("HMAC profile produced no tag")
	}
	copy(ciphertext[page+macAt:page+macAt+len(wrong)], wrong)

	unlocked := mustUnlock(t, ciphertext, []byte("correct horse"), params)
	buf := make([]byte, 16)
	if _, err := unlocked.ReadAt(uint64(page), buf); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("ReadAt error = %v, want source.ErrCorrupt", err)
	}
}

func TestMovedPageIsCorrupt(t *testing.T) {
	params := fastParams(ParamsV4())
	_, ciphertext := encryptedFixture(t, 3, params, []byte("move horse"))
	page := int(params.PageSize)
	for offset := 0; offset < page; offset++ {
		ciphertext[page+offset], ciphertext[2*page+offset] = ciphertext[2*page+offset], ciphertext[page+offset]
	}
	unlocked := mustUnlock(t, ciphertext, []byte("move horse"), params)
	if _, err := unlocked.ReadAt(uint64(page), make([]byte, 16)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("ReadAt error = %v, want source.ErrCorrupt", err)
	}
}

func TestTruncatedDatabase(t *testing.T) {
	params := fastParams(ParamsV4())
	_, ciphertext := encryptedFixture(t, 2, params, []byte("truncated horse"))
	ciphertext = ciphertext[:len(ciphertext)-100]
	_, err := Unlock(2, memorySource(ciphertext), []byte("truncated horse"), params)
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("error = %v, want ErrTruncated", err)
	}
	if !errors.Is(err, source.ErrUnexpectedEOF) {
		t.Fatalf("error = %v, want source.ErrUnexpectedEOF", err)
	}
}

func TestPlaintextDatabaseIsNotSQLCipher(t *testing.T) {
	params := fastParams(ParamsV4())
	plaintext := plaintextDatabase(2, params)
	_, err := Unlock(2, memorySource(plaintext), []byte("correct horse"), params)
	if !errors.Is(err, ErrNotSQLCipher) {
		t.Fatalf("error = %v, want ErrNotSQLCipher", err)
	}
	if !strings.Contains(err.Error(), "plaintext SQLite header") {
		t.Fatalf("error text = %q", err)
	}
}

func TestInvalidPageSize(t *testing.T) {
	params := fastParams(ParamsV4())
	params.PageSize = 3000
	err := params.Validate()
	if !errors.Is(err, ErrInvalidPageSize) {
		t.Fatalf("Validate error = %v, want ErrInvalidPageSize", err)
	}
	if !strings.Contains(err.Error(), "powers of two") {
		t.Fatalf("error text = %q", err)
	}

	tooSmall := fastParams(ParamsV4())
	tooSmall.PageSize = 512
	err = tooSmall.Validate()
	if !errors.Is(err, ErrInvalidPageSize) {
		t.Fatalf("Validate(512) error = %v", err)
	}
	if !strings.Contains(err.Error(), "below SQLite's 480") {
		t.Fatalf("error text = %q", err)
	}
}

func TestUnsupportedProfilesAreNamed(t *testing.T) {
	cases := []struct {
		name    string
		params  Params
		needles []string
	}{
		{
			name: "plaintext header",
			params: func() Params {
				p := fastParams(ParamsV4())
				p.PlaintextHeaderSize = 32
				return p
			}(),
			needles: []string{"plaintext header", "cipher_plaintext_header_size"},
		},
		{
			name: "cipher",
			params: func() Params {
				p := fastParams(ParamsV4())
				p.Cipher = CipherFromName("aes-128-cbc")
				return p
			}(),
			needles: []string{"aes-128-cbc"},
		},
		{
			name: "kdf",
			params: func() Params {
				p := fastParams(ParamsV4())
				p.KDF = KDFFromName("PBKDF2_HMAC_SHA1")
				return p
			}(),
			needles: []string{"SQLCipher 4", "PBKDF2-HMAC-SHA1"},
		},
		{
			name: "hmac",
			params: func() Params {
				p := fastParams(ParamsV3())
				p.HMAC = HMACSHA512
				return p
			}(),
			needles: []string{"SQLCipher 3", "HMAC-SHA512"},
		},
		{
			name: "zero iterations",
			params: func() Params {
				p := fastParams(ParamsV4())
				p.KDFIterations = 0
				return p
			}(),
			needles: []string{"zero PBKDF2 iterations"},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			err := test.params.Validate()
			if !errors.Is(err, ErrUnsupported) {
				t.Fatalf("Validate error = %v, want ErrUnsupported", err)
			}
			for _, needle := range test.needles {
				if !strings.Contains(err.Error(), needle) {
					t.Fatalf("error %q does not contain %q", err, needle)
				}
			}
		})
	}
}

func TestSQLCipher1HasNoPageHMAC(t *testing.T) {
	params := fastParams(ParamsV1())
	plaintext := plaintextDatabase(2, params)
	ciphertext, err := EncryptDatabase(plaintext, fixtureSalt, []byte("v1 horse"), params)
	if err != nil {
		t.Fatalf("EncryptDatabase error = %v", err)
	}
	page := int(params.PageSize)
	ciphertext[page+100] ^= 0x01
	unlocked := mustUnlock(t, ciphertext, []byte("v1 horse"), params)
	got := make([]byte, 200)
	if _, err := unlocked.ReadAt(uint64(page), got); err != nil {
		t.Fatalf("ReadAt error = %v", err)
	}
	if bytes.Equal(got, plaintext[page:page+200]) {
		t.Fatal("unauthenticated ciphertext change was not visible")
	}
}

func TestProfileTrialOrder(t *testing.T) {
	params := fastParams(ParamsV3())
	plaintext := plaintextDatabase(2, params)
	ciphertext, err := EncryptDatabase(plaintext, fixtureSalt, []byte("order horse"), params)
	if err != nil {
		t.Fatalf("EncryptDatabase error = %v", err)
	}
	candidates := []Params{
		fastParams(ParamsV4()),
		params,
		fastParams(ParamsV2()),
	}
	unlocked, err := UnlockTryingProfiles(2, memorySource(ciphertext), []byte("order horse"), candidates)
	if err != nil {
		t.Fatalf("UnlockTryingProfiles error = %v", err)
	}
	if unlocked.Params().Version != Version3 || unlocked.Header().Version != Version3 {
		t.Fatalf("winner = %v / %v, want SQLCipher 3", unlocked.Params().Version, unlocked.Header().Version)
	}

	_, err = UnlockTryingProfiles(2, memorySource(ciphertext), []byte("wrong horse"), []Params{params})
	if !errors.Is(err, ErrNoProfile) {
		t.Fatalf("error = %v, want ErrNoProfile", err)
	}
	var structured *Error
	if !errors.As(err, &structured) || len(structured.Attempts) != 1 {
		t.Fatalf("attempts = %+v", structured)
	}
	if !strings.Contains(structured.Attempts[0], "SQLCipher 3") {
		t.Fatalf("attempt = %q", structured.Attempts[0])
	}
}

func TestRAWKeyUnlock(t *testing.T) {
	params := fastParams(ParamsV4())
	var encryptionKey [EncryptionKeyBytes]byte
	for index := range encryptionKey {
		encryptionKey[index] = 0x42
	}
	key, err := KeyFromRaw(encryptionKey, fixtureSalt, params)
	if err != nil {
		t.Fatalf("KeyFromRaw error = %v", err)
	}
	plaintext := plaintextDatabase(3, params)
	ciphertext, err := EncryptDatabaseWithKey(plaintext, fixtureSalt, key, params)
	if err != nil {
		t.Fatalf("EncryptDatabaseWithKey error = %v", err)
	}

	unlocked, err := UnlockRaw(2, memorySource(ciphertext), encryptionKey, nil, params)
	if err != nil {
		t.Fatalf("UnlockRaw(file salt) error = %v", err)
	}
	if unlocked.Header().Salt != fixtureSalt {
		t.Fatal("raw-key unlock lost the file salt")
	}
	if got := readAll(t, unlocked); !bytes.Equal(got, plaintext) {
		t.Fatal("raw-key unlock did not round-trip")
	}

	supplied := fixtureSalt
	if _, err := UnlockRaw(2, memorySource(ciphertext), encryptionKey, &supplied, params); err != nil {
		t.Fatalf("UnlockRaw(matching salt) error = %v", err)
	}
	wrongSalt := fixtureSalt
	wrongSalt[0] ^= 0xff
	_, err = UnlockRaw(2, memorySource(ciphertext), encryptionKey, &wrongSalt, params)
	if !errors.Is(err, ErrSaltMismatch) {
		t.Fatalf("UnlockRaw(wrong salt) error = %v, want ErrSaltMismatch", err)
	}

	wrongKey := encryptionKey
	wrongKey[0] ^= 0xff
	_, err = UnlockRaw(2, memorySource(ciphertext), wrongKey, nil, params)
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("UnlockRaw(wrong key) error = %v, want ErrWrongPassphrase", err)
	}
}

func TestParseRawKeyText(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, EncryptionKeyBytes)
	salt := bytes.Repeat([]byte{0x22}, SaltBytes)
	keyHex := hexOf(key)
	bothHex := keyHex + hexOf(salt)

	parsed, parsedSalt, err := ParseRawKeyText(keyHex)
	if err != nil || !bytes.Equal(parsed[:], key) || parsedSalt != nil {
		t.Fatalf("ParseRawKeyText(key) = %x, %v, %v", parsed, parsedSalt, err)
	}
	parsed, parsedSalt, err = ParseRawKeyText(bothHex)
	if err != nil || !bytes.Equal(parsed[:], key) || parsedSalt == nil || !bytes.Equal(parsedSalt[:], salt) {
		t.Fatalf("ParseRawKeyText(key+salt) = %x, %v, %v", parsed, parsedSalt, err)
	}
	for _, quoted := range []string{"x'" + keyHex + "'", "X'" + keyHex + "'"} {
		parsed, parsedSalt, err = ParseRawKeyText(quoted)
		if err != nil || !bytes.Equal(parsed[:], key) || parsedSalt != nil {
			t.Fatalf("ParseRawKeyText(%q) = %x, %v, %v", quoted, parsed, parsedSalt, err)
		}
	}

	invalid := []struct {
		text   string
		needle string
	}{
		{keyHex + "\n", "non-hex"},
		{"0x" + keyHex, "non-hex"},
		{keyHex + ":" + hexOf(salt), "non-hex"},
		{keyHex[:62], "62 hex digits"},
		{bothHex + "0", "97 hex digits"},
		{"x'" + keyHex, "single quote"},
		{keyHex + "'", "stray single quote"},
	}
	for _, test := range invalid {
		_, _, err := ParseRawKeyText(test.text)
		if !errors.Is(err, ErrRawKey) {
			t.Fatalf("ParseRawKeyText(%q) error = %v, want ErrRawKey", test.text, err)
		}
		if !strings.Contains(err.Error(), test.needle) {
			t.Fatalf("ParseRawKeyText(%q) error = %q, want %q", test.text, err, test.needle)
		}
	}
}

func TestExtentsAndMapToImage(t *testing.T) {
	params := fastParams(ParamsV4())
	_, ciphertext := encryptedFixture(t, 3, params, []byte("extent horse"))
	unlocked := mustUnlock(t, ciphertext, []byte("extent horse"), params)

	extents, err := unlocked.Extents(4090, 20)
	if err != nil {
		t.Fatalf("Extents error = %v", err)
	}
	if len(extents) != 2 {
		t.Fatalf("extents = %+v", extents)
	}
	if extents[0].Parent != 1 || extents[0].ParentOffset != 4090 || extents[0].Len != 6 ||
		extents[0].Kind != source.RangeData {
		t.Fatalf("extent 0 = %+v", extents[0])
	}
	if extents[1].ParentOffset != 4096 || extents[1].Len != 14 {
		t.Fatalf("extent 1 = %+v", extents[1])
	}

	image, err := unlocked.MapToImage(0, 16)
	if err != nil {
		t.Fatalf("MapToImage error = %v", err)
	}
	if len(image) != 1 || image[0].ImageID != 9 || image[0].ImageOffset != 0 || image[0].Len != 16 {
		t.Fatalf("image ranges = %+v", image)
	}

	if _, err := unlocked.Extents(unlocked.Len(), 1); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("Extents(out of range) error = %v", err)
	}
}

func TestReadRangesAndCacheStats(t *testing.T) {
	params := fastParams(ParamsV4())
	_, ciphertext := encryptedFixture(t, 3, params, []byte("range horse"))
	unlocked := mustUnlock(t, ciphertext, []byte("range horse"), params)

	if n, err := unlocked.ReadAt(0, nil); n != 0 || err != nil {
		t.Fatalf("empty ReadAt = %d, %v", n, err)
	}
	if _, err := unlocked.ReadAt(unlocked.Len(), make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("ReadAt(end) error = %v", err)
	}
	tail := make([]byte, 8)
	if n, err := unlocked.ReadAt(unlocked.Len()-4, tail); n != 4 || err != nil {
		t.Fatalf("short ReadAt = %d, %v", n, err)
	}

	pageTwo := uint64(params.PageSize)
	buf := make([]byte, params.PageSize)
	if _, err := unlocked.ReadAt(pageTwo, buf); err != nil {
		t.Fatalf("first page-2 read error = %v", err)
	}
	if _, err := unlocked.ReadAt(pageTwo, buf); err != nil {
		t.Fatalf("second page-2 read error = %v", err)
	}
	stats := unlocked.Stats()
	if stats.CacheMisses != 2 || stats.CacheHits != 1 {
		t.Fatalf("cache stats = %+v", stats)
	}
	if stats.BytesRead != 2*uint64(params.PageSize)+4 {
		t.Fatalf("bytes read = %d", stats.BytesRead)
	}
}

func TestWALPageRoundTrip(t *testing.T) {
	params := fastParams(ParamsV4())
	plaintext := plaintextDatabase(2, params)
	page1 := plaintext[:params.PageSize]
	page2 := plaintext[params.PageSize:]

	raw1, err := EncryptWALPage(page1, 1, fixtureSalt, []byte("wal horse"), params)
	if err != nil {
		t.Fatalf("EncryptWALPage(page 1) error = %v", err)
	}
	raw2, err := EncryptWALPage(page2, 2, fixtureSalt, []byte("wal horse"), params)
	if err != nil {
		t.Fatalf("EncryptWALPage(page 2) error = %v", err)
	}
	unlocked := mustUnlock(t, mustEncryptDatabase(t, plaintext, params, []byte("wal horse")), []byte("wal horse"), params)
	got1, err := unlocked.DecryptWALPage(1, raw1)
	if err != nil {
		t.Fatalf("DecryptWALPage(page 1) error = %v", err)
	}
	if !bytes.Equal(got1, page1) {
		t.Fatal("WAL page 1 does not round-trip")
	}
	got2, err := unlocked.DecryptWALPage(2, raw2)
	if err != nil {
		t.Fatalf("DecryptWALPage(page 2) error = %v", err)
	}
	if !bytes.Equal(got2, page2) {
		t.Fatal("WAL page 2 does not round-trip")
	}

	if _, err := unlocked.DecryptWALPage(0, raw2); !errors.Is(err, ErrWALFrame) {
		t.Fatalf("page 0 error = %v", err)
	}
	if _, err := unlocked.DecryptWALPage(2, raw2[:len(raw2)-1]); !errors.Is(err, ErrWALFrame) {
		t.Fatalf("short frame error = %v", err)
	}
	badPage1 := append([]byte(nil), raw1...)
	badPage1[0] ^= 0xff
	if _, err := unlocked.DecryptWALPage(1, badPage1); !errors.Is(err, ErrWALFrame) {
		t.Fatalf("page-1 salt mismatch error = %v", err)
	}
	badMAC := append([]byte(nil), raw2...)
	badMAC[len(badMAC)-1] ^= 0x01
	if _, err := unlocked.DecryptWALPage(2, badMAC); !errors.Is(err, ErrWALFrame) {
		t.Fatalf("bad WAL HMAC error = %v", err)
	}
}

func mustEncryptDatabase(t *testing.T, plaintext []byte, params Params, passphrase []byte) []byte {
	t.Helper()
	ciphertext, err := EncryptDatabase(plaintext, fixtureSalt, passphrase, params)
	if err != nil {
		t.Fatalf("EncryptDatabase error = %v", err)
	}
	return ciphertext
}

func TestEncryptionHelpersRejectBadGeometry(t *testing.T) {
	params := fastParams(ParamsV4())
	if _, err := EncryptDatabase(make([]byte, 100), fixtureSalt, []byte("x"), params); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("short plaintext error = %v", err)
	}
	if _, err := EncryptDatabase(make([]byte, params.PageSize), fixtureSalt, []byte("x"), params); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("missing SQLite magic error = %v", err)
	}
	page := plaintextDatabase(1, params)[:params.PageSize]
	if _, err := EncryptWALPage(page, 0, fixtureSalt, []byte("x"), params); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("WAL page 0 error = %v", err)
	}
	if _, err := EncryptWALPage(page[:len(page)-1], 1, fixtureSalt, []byte("x"), params); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("WAL short page error = %v", err)
	}
	bad := append([]byte(nil), page...)
	bad[0] = 0
	if _, err := EncryptWALPage(bad, 1, fixtureSalt, []byte("x"), params); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("WAL page 1 without magic error = %v", err)
	}
}

func TestCustomPageSizes(t *testing.T) {
	for _, pageSize := range []uint32{1024, 2048, 8192, MaxPageSize} {
		t.Run(fmt.Sprintf("%d", pageSize), func(t *testing.T) {
			params := fastParams(ParamsV4())
			params.PageSize = pageSize
			plaintext := plaintextDatabase(2, params)
			ciphertext := mustEncryptDatabase(t, plaintext, params, []byte("page horse"))
			unlocked := mustUnlock(t, ciphertext, []byte("page horse"), params)
			if unlocked.PageSize() != pageSize {
				t.Fatalf("page size = %d, want %d", unlocked.PageSize(), pageSize)
			}
			if got := readAll(t, unlocked); !bytes.Equal(got, plaintext) {
				t.Fatalf("page size %d did not round-trip", pageSize)
			}
		})
	}
}

func TestUnlockRawTryingProfiles(t *testing.T) {
	params := fastParams(ParamsV3())
	var encryptionKey [EncryptionKeyBytes]byte
	for index := range encryptionKey {
		encryptionKey[index] = byte(index + 1)
	}
	key, err := KeyFromRaw(encryptionKey, fixtureSalt, params)
	if err != nil {
		t.Fatalf("KeyFromRaw error = %v", err)
	}
	plaintext := plaintextDatabase(2, params)
	ciphertext, err := EncryptDatabaseWithKey(plaintext, fixtureSalt, key, params)
	if err != nil {
		t.Fatalf("EncryptDatabaseWithKey error = %v", err)
	}
	unlocked, err := UnlockRawTryingProfiles(
		2, memorySource(ciphertext), encryptionKey, nil,
		[]Params{fastParams(ParamsV4()), params},
	)
	if err != nil {
		t.Fatalf("UnlockRawTryingProfiles error = %v", err)
	}
	if unlocked.Params().Version != Version3 {
		t.Fatalf("winner = %v", unlocked.Params().Version)
	}

	wrongSalt := fixtureSalt
	wrongSalt[15] ^= 1
	_, err = UnlockRawTryingProfiles(
		2, memorySource(ciphertext), encryptionKey, &wrongSalt,
		[]Params{params, fastParams(ParamsV1())},
	)
	if !errors.Is(err, ErrSaltMismatch) {
		t.Fatalf("salt mismatch error = %v, want ErrSaltMismatch", err)
	}
}

func TestReadAtLossyAndErrorsPreserveBuffer(t *testing.T) {
	params := fastParams(ParamsV4())
	_, ciphertext := encryptedFixture(t, 2, params, []byte("buffer horse"))
	ciphertext[len(ciphertext)-1] ^= 1
	unlocked := mustUnlock(t, ciphertext, []byte("buffer horse"), params)
	buf := bytes.Repeat([]byte{0xcc}, int(params.PageSize)+16)
	if n, err := unlocked.ReadAt(uint64(params.PageSize), buf); n != 0 || !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("ReadAt = %d, %v", n, err)
	}
}

func TestSourceInterfaceAndIdentity(t *testing.T) {
	params := fastParams(ParamsV4())
	_, ciphertext := encryptedFixture(t, 1, params, []byte("identity horse"))
	unlocked := mustUnlock(t, ciphertext, []byte("identity horse"), params)
	if unlocked.SourceID() != 2 || unlocked.ImageID() != 9 || unlocked.SectorSize() != 512 {
		t.Fatalf("identity = %d/%d/%d", unlocked.SourceID(), unlocked.ImageID(), unlocked.SectorSize())
	}
	if unlocked.Parent().SourceID() != 1 {
		t.Fatalf("parent id = %d", unlocked.Parent().SourceID())
	}
	if unlocked.IsEmpty() {
		t.Fatal("IsEmpty = true")
	}
	if unlocked.Salt() != fixtureSalt {
		t.Fatal("Salt() mismatch")
	}
	var _ source.ByteSource = unlocked
}

func TestAutoUnlockTriesShippedProfiles(t *testing.T) {
	params := ParamsV3()
	plaintext := plaintextDatabase(1, params)
	ciphertext := mustEncryptDatabase(t, plaintext, params, []byte("auto horse"))
	unlocked, err := UnlockAuto(2, memorySource(ciphertext), []byte("auto horse"))
	if err != nil {
		t.Fatalf("UnlockAuto error = %v", err)
	}
	if unlocked.Params().Version != Version3 {
		t.Fatalf("winner = %v", unlocked.Params().Version)
	}
	if got := readAll(t, unlocked); !bytes.Equal(got, plaintext) {
		t.Fatal("auto unlock did not round-trip")
	}

	_, err = UnlockAuto(2, memorySource(ciphertext), []byte("wrong horse"))
	if !errors.Is(err, ErrNoProfile) {
		t.Fatalf("wrong passphrase error = %v, want ErrNoProfile", err)
	}
	var structured *Error
	if !errors.As(err, &structured) || len(structured.Attempts) != len(DefaultProfiles()) {
		t.Fatalf("attempts = %+v", structured)
	}
}

func TestNameMappingsAndDescriptions(t *testing.T) {
	if CipherFromName("aes-256-cbc") != CipherAES256CBC || !CipherAES256CBC.Supported() {
		t.Fatal("AES-256-CBC name mapping failed")
	}
	if CipherFromName("aes-128-cbc").Supported() {
		t.Fatal("unsupported cipher reported supported")
	}
	if KDFFromName("PBKDF2-HMAC-SHA512") != KDFPBKDF2HMACSHA512 ||
		KDFFromName("pbkdf2_hmac_sha1") != KDFPBKDF2HMACSHA1 {
		t.Fatal("KDF alias mapping failed")
	}
	if KDFPBKDF2HMACSHA512.DigestBytes() != HMACSHA512Bytes ||
		KDFPBKDF2HMACSHA1.DigestBytes() != HMACSHA1Bytes ||
		KDF("other").DigestBytes() != 0 {
		t.Fatal("KDF digest sizes are wrong")
	}
	if HMACFromName("HMAC_SHA512") != HMACSHA512 ||
		HMACFromName("hmac-sha1") != HMACSHA1 ||
		HMACFromName("none") != HMACNone {
		t.Fatal("HMAC alias mapping failed")
	}
	if HMACNone.DigestBytes() != 0 || HMAC("next").DigestBytes() != 0 {
		t.Fatal("HMACNone/unsupported digest size is non-zero")
	}
	if HMACNone.Name() != "no HMAC" || HMACNone.CheckName() != "SQLite magic and header (SQLCipher 1 has no HMAC)" {
		t.Fatal("HMACNone descriptions are wrong")
	}
	if KDF("other").Name() != "other" || HMAC("next").Name() != "next" ||
		Cipher("other").Name() != "other" {
		t.Fatal("unsupported names were not preserved")
	}
	if Version(99).Label() == "" || Version(99).Defaults() == "" {
		t.Fatal("unknown version descriptions are empty")
	}
	if DefaultParams() != ParamsV4() {
		t.Fatal("DefaultParams is not SQLCipher 4")
	}
	key, err := DeriveKey([]byte("forensic"), fixtureSalt, fastParams(ParamsV4()))
	if err != nil {
		t.Fatalf("DeriveKey error = %v", err)
	}
	if strings.Contains(key.String(), hexOf(key.EncryptionKey[:])) {
		t.Fatal("Key.String exposed the encryption key")
	}
}

func TestIntoSourceErrorMapping(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want error
	}{
		{"corrupt page", corruptPageError(2, 7, "bad page"), source.ErrCorrupt},
		{"wrong passphrase", wrongPassphraseError("HMAC-SHA512"), source.ErrDecrypt},
		{"no profile", &Error{Kind: ErrNoProfile}, source.ErrDecrypt},
		{"unsupported", unsupportedError("cipher"), source.ErrUnsupported},
		{"page size", pageSizeError(3000, "bad"), source.ErrUnsupported},
		{"raw key", rawKeyError("bad"), source.ErrUnsupported},
		{"salt mismatch", saltMismatchError(fixtureSalt, fixtureSalt), source.ErrUnsupported},
		{"truncated", truncatedError(7, 4096), source.ErrUnexpectedEOF},
		{"not SQLCipher", notSQLCipherError("plaintext"), source.ErrCorrupt},
		{"WAL", walFrameError(2, "bad"), source.ErrCorrupt},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			mapped := intoSourceError(test.err, 123)
			if !errors.Is(mapped, test.want) {
				t.Fatalf("intoSourceError = %v, want %v", mapped, test.want)
			}
		})
	}
	original := source.NewCorrupt(9, "passthrough")
	if got := intoSourceError(original, 1); got != original {
		t.Fatalf("source error was wrapped: %#v", got)
	}
}

func TestHMACVectors(t *testing.T) {
	key := bytes.Repeat([]byte{0x0b}, 20)
	if got := hexOf(HMACSHA512.Compute(key, []byte("Hi There"))); got !=
		"87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854" {
		t.Fatalf("HMAC-SHA512 = %s", got)
	}
	if got := hexOf(HMACSHA1.Compute(key, []byte("Hi There"))); got != "b617318655057264e28bc0b6fb378c8ef146be00" {
		t.Fatalf("HMAC-SHA1 = %s", got)
	}
	if got := HMACNone.Compute(key, []byte("unused")); got != nil {
		t.Fatalf("HMACNone.Compute = %x", got)
	}
}
