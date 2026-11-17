package unlock

import (
	"bytes"
	"errors"
	"testing"
)

// The XTS vector is a 512-byte data unit under a 64-byte key at sector 7,
// produced by OpenSSL and recorded by the Rust reference tests. It pins the
// key split, the little-endian tweak, AES-256 data encryption and the GF(2^128)
// tweak multiplication together.
func TestXTSPLAIN64MatchesExternalVector(t *testing.T) {
	key := make([]byte, 64)
	for index := range key {
		key[index] = byte(index)
	}
	plain := make([]byte, 512)
	for index := range plain {
		plain[index] = byte(index)
	}
	ciphertext := decodeHexTest(t,
		"b2d9289b998ebd6bcc8a6d434711b8af6f974e732a6253c9ed6c74de21b56629"+
			"bc87fef9fde088fd9009a8357801561c03be40ad3367f539c9846dd3b5bb4185"+
			"dbfe28e52d291ec5addf5f68bb96cb89b8c79b40aeeba7b577b3598ea58a0261"+
			"06c16745a8e8c266672aff02e1982afad09cea4ff803f815deb3ae08fa6016c0"+
			"4c423f9553263cc3ef78c5b58349665e3f4d8dace07be3f6c43d8df238007767"+
			"b38f026af8374b1da3e07529f3fdf7a2409068889a5fe2be650f8b90d739b717"+
			"5cd179ecd90c23a4a19e8139a5278488d3e45f4380cd197266065454af2a83f8"+
			"c00d74e9a0046b88e452318a435f1cf658f4e9abc77dd5ddb7451411f09aa50c"+
			"c3436eeb31a881b451fd109a9f1548b73504accc319160754ac51fd6da9fae30"+
			"c5e73d5b71f25eec5a8c60dc4c298077bbb90c521fadca1c00a2becfc3697eba"+
			"37d1933e095d52fe0ee81735fa370371df785cecbacea98fe4052f06420f50c5"+
			"7fc26c0594d310393113f622e0ebdd949267f57f5ff0618e6be70c801337f48c"+
			"1b495a4c239861baa4b4f9f28b8738815f53776423b5712bd15b21472c37a201"+
			"c3e6e8e9237560f24ebb42b57a5a491067c6367ad2b0141065ba84528874ad50"+
			"f47594110f4bc8d4e2b9b345c1bc718f08e89a452379b36ef39316225b0e2be7"+
			"5a51cc15e284f031985913ccfacef041ce14269e6a5074a0a0cea22385af5a35")
	spec, err := parseEncryption("aes-xts-plain64")
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := newSectorCipher(spec, key)
	if err != nil {
		t.Fatal(err)
	}
	unit := append([]byte(nil), plain...)
	if err := cipher.encryptSector(7, unit); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unit, ciphertext) {
		t.Fatalf("encrypt mismatch:\n got %s\nwant %s", hexString(unit), hexString(ciphertext))
	}
	if err := cipher.decryptSector(7, unit); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unit, plain) {
		t.Fatal("XTS round trip did not restore the plaintext")
	}
}

// OpenSSL-produced CBC-ESSIV-SHA256 vector: key 00..1f, sector 1, plaintext
// 00..0f.
func TestCBCEssivMatchesExternalVector(t *testing.T) {
	key := decodeHexTest(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	ciphertext := decodeHexTest(t, "604e9628aef2fcc39d3b4e1c6a27defc")
	plaintext := decodeHexTest(t, "000102030405060708090a0b0c0d0e0f")
	spec, _ := parseEncryption("aes-cbc-essiv:sha256")
	cipher, err := newSectorCipher(spec, key)
	if err != nil {
		t.Fatal(err)
	}
	block := append([]byte(nil), ciphertext...)
	if err := cipher.decryptSector(1, block); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(block, plaintext) {
		t.Fatalf("decrypt = %s, want %s", hexString(block), hexString(plaintext))
	}
	// The sector number is part of the IV.
	wrong := append([]byte(nil), ciphertext...)
	if err := cipher.decryptSector(0, wrong); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(wrong, plaintext) {
		t.Fatal("sector 0 decrypted like sector 1")
	}
}

func TestCBCPlain64MatchesExternalVectors(t *testing.T) {
	key := decodeHexTest(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	plaintext := decodeHexTest(t, "000102030405060708090a0b0c0d0e0f")
	spec, _ := parseEncryption("aes-cbc-plain64")
	cipher, err := newSectorCipher(spec, key)
	if err != nil {
		t.Fatal(err)
	}
	block := decodeHexTest(t, "0acfabf55076ef56f511995390a5f210")
	if err := cipher.decryptSector(1, block); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(block, plaintext) {
		t.Fatalf("decrypt = %s, want %s", hexString(block), hexString(plaintext))
	}

	// AES-192, sector 0x0102030405060708: the whole 64-bit number is the IV.
	key192 := decodeHexTest(t, "000102030405060708090a0b0c0d0e0f1011121314151617")
	cipher, err = newSectorCipher(spec, key192)
	if err != nil {
		t.Fatal(err)
	}
	block = decodeHexTest(t, "f6e7e4ddb224396eb82e49ae68d5f399")
	if err := cipher.decryptSector(0x0102030405060708, block); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(block, plaintext) {
		t.Fatalf("AES-192 decrypt = %s, want %s", hexString(block), hexString(plaintext))
	}
}

func TestCBCPlainMatchesExternalVector(t *testing.T) {
	key := decodeHexTest(t, "000102030405060708090a0b0c0d0e0f")
	plaintext := decodeHexTest(t, "000102030405060708090a0b0c0d0e0f")
	spec, _ := parseEncryption("aes-cbc-plain")
	cipher, err := newSectorCipher(spec, key)
	if err != nil {
		t.Fatal(err)
	}
	block := decodeHexTest(t, "337eb7949ccf71bc48170e20a6a4fde3")
	if err := cipher.decryptSector(0x11223344, block); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(block, plaintext) {
		t.Fatalf("decrypt = %s, want %s", hexString(block), hexString(plaintext))
	}
	// The IV is only 32 bits wide; a larger sector is refused, not truncated.
	if err := cipher.decryptSector(1<<32, block); !errors.Is(err, ErrIVSector) {
		t.Fatalf("32-bit IV overflow error = %v", err)
	}
}

func TestXTSPlain64BigEndianTweak(t *testing.T) {
	key := bytesOf(0x5a, 64)
	spec, _ := parseEncryption("AES-XTS-PLAIN64BE")
	cipher, err := newSectorCipher(spec, key)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, 64)
	for index := range plain {
		plain[index] = byte(index)
	}
	want := append([]byte(nil), plain...)
	if err := cipher.encryptSector(0x0102030405060708, want); err != nil {
		t.Fatal(err)
	}
	if err := cipher.decryptSector(0x0102030405060708, want); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, plain) {
		t.Fatal("plain64be round trip failed")
	}
	// A different byte order must produce different ciphertext.
	tweak, err := cipher.xtsTweak(0x0102030405060708)
	if err != nil {
		t.Fatal(err)
	}
	if tweak[0] != 0x01 || tweak[7] != 0x08 {
		t.Fatalf("plain64be tweak bytes = %x", tweak)
	}
}

func TestCipherKeySizes(t *testing.T) {
	for _, name := range []string{"aes-xts-plain64", "aes-xts-plain64be", "aes-xts-plain"} {
		spec, _ := parseEncryption(name)
		for _, size := range []int{32, 64} {
			if _, err := newSectorCipher(spec, bytesOf(1, size)); err != nil {
				t.Fatalf("%s with %d bytes: %v", name, size, err)
			}
		}
		for _, size := range []int{16, 24, 20} {
			if _, err := newSectorCipher(spec, bytesOf(1, size)); !errors.Is(err, ErrKeyBytes) {
				t.Fatalf("%s accepted %d bytes: %v", name, size, err)
			}
		}
	}
	for _, name := range []string{"aes-cbc-essiv:sha256", "aes-cbc-plain64", "aes-cbc-plain"} {
		spec, _ := parseEncryption(name)
		for _, size := range []int{16, 24, 32} {
			if _, err := newSectorCipher(spec, bytesOf(1, size)); err != nil {
				t.Fatalf("%s with %d bytes: %v", name, size, err)
			}
		}
		if _, err := newSectorCipher(spec, bytesOf(1, 20)); !errors.Is(err, ErrKeyBytes) {
			t.Fatalf("%s accepted a 20-byte key", name)
		}
	}
}

func TestCipherRefusesUnknownNames(t *testing.T) {
	for _, name := range []string{
		"serpent-xts-plain64",
		"twofish-cbc-essiv:sha256",
		"aes-cbc-essiv:sha1",
		"aes-cbc-essiv:sha512",
		"aes",
		"aes-xts-benbi",
		"",
	} {
		if _, err := parseEncryption(name); !errors.Is(err, ErrUnsupportedCipher) {
			t.Fatalf("%q was not refused: %v", name, err)
		}
	}
}

func TestCipherLeavesShortTailsUntouched(t *testing.T) {
	spec, _ := parseEncryption("aes-cbc-plain64")
	cipher, _ := newSectorCipher(spec, bytesOf(3, 32))
	unit := make([]byte, 17)
	for index := range unit {
		unit[index] = byte(index)
	}
	before := append([]byte(nil), unit...)
	if err := cipher.decryptSector(0, unit); err != nil {
		t.Fatal(err)
	}
	if unit[16] != before[16] {
		t.Fatal("a partial trailing block was consumed")
	}
	xts, _ := parseEncryption("aes-xts-plain64")
	xtsCipher, _ := newSectorCipher(xts, bytesOf(4, 32))
	if err := xtsCipher.decryptSector(0, unit); !errors.Is(err, ErrCipherBlockSize) {
		t.Fatalf("XTS accepted a partial block: %v", err)
	}
}
