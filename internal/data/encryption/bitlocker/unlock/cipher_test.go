package unlock

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/encryption/bitlocker"
)

func sequence(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

// XTS-AES-256, a 512-byte data unit at sector 7 with the key 00..3f. The
// ciphertext was produced by OpenSSL, not by this package.
func TestXTSMatchesOpenSSLCiphertext(t *testing.T) {
	const expectedHex = "" +
		"b2d9289b998ebd6bcc8a6d434711b8af6f974e732a6253c9ed6c74de21b56629" +
		"bc87fef9fde088fd9009a8357801561c03be40ad3367f539c9846dd3b5bb4185" +
		"dbfe28e52d291ec5addf5f68bb96cb89b8c79b40aeeba7b577b3598ea58a0261" +
		"06c16745a8e8c266672aff02e1982afad09cea4ff803f815deb3ae08fa6016c0" +
		"4c423f9553263cc3ef78c5b58349665e3f4d8dace07be3f6c43d8df238007767" +
		"b38f026af8374b1da3e07529f3fdf7a2409068889a5fe2be650f8b90d739b717" +
		"5cd179ecd90c23a4a19e8139a5278488d3e45f4380cd197266065454af2a83f8" +
		"c00d74e9a0046b88e452318a435f1cf658f4e9abc77dd5ddb7451411f09aa50c" +
		"c3436eeb31a881b451fd109a9f1548b73504accc319160754ac51fd6da9fae30" +
		"c5e73d5b71f25eec5a8c60dc4c298077bbb90c521fadca1c00a2becfc3697eba" +
		"37d1933e095d52fe0ee81735fa370371df785cecbacea98fe4052f06420f50c5" +
		"7fc26c0594d310393113f622e0ebdd949267f57f5ff0618e6be70c801337f48c" +
		"1b495a4c239861baa4b4f9f28b8738815f53776423b5712bd15b21472c37a201" +
		"c3e6e8e9237560f24ebb42b57a5a491067c6367ad2b0141065ba84528874ad50" +
		"f47594110f4bc8d4e2b9b345c1bc718f08e89a452379b36ef39316225b0e2be7" +
		"5a51cc15e284f031985913ccfacef041ce14269e6a5074a0a0cea22385af5a35"
	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		t.Fatal(err)
	}
	key := sequence(64)
	plain := sequence(512)
	xts, err := newXTSCipher(key)
	if err != nil {
		t.Fatalf("newXTSCipher: %v", err)
	}
	unit := append([]byte(nil), plain...)
	if err := xts.encrypt(7*512, unit); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !bytes.Equal(unit, expected) {
		t.Fatalf("ciphertext = %x, want %x", unit, expected)
	}
	if err := xts.decrypt(7*512, unit); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(unit, plain) {
		t.Fatal("XTS round trip did not restore the plaintext")
	}
}

// Vectors emitted by dislocker 0.7.4's own diffuser.c over 00 01 .. ff.
func TestElephantDiffuserMatchesDislockerVectors(t *testing.T) {
	sector := sequence(512)
	if err := diffuserADecrypt(sector); err != nil {
		t.Fatalf("diffuser A: %v", err)
	}
	if got, want := hex.EncodeToString(sector[:32]), "3801315a34bcf9a780c829991d6ddf64ade750ef774c1e85805afc65aa5e058b"; got != want {
		t.Fatalf("diffuser A = %s, want %s", got, want)
	}

	sector = sequence(512)
	if err := diffuserBDecrypt(sector); err != nil {
		t.Fatalf("diffuser B: %v", err)
	}
	if got, want := hex.EncodeToString(sector[:32]), "ac2e62c68646646e6f535147e13735f3edf0e0086066ec0e4e76726641171d93"; got != want {
		t.Fatalf("diffuser B = %s, want %s", got, want)
	}

	// The pair a CBC+Elephant sector applies after AES-CBC, in order.
	sector = sequence(512)
	if err := diffuserBDecrypt(sector); err != nil {
		t.Fatal(err)
	}
	if err := diffuserADecrypt(sector); err != nil {
		t.Fatal(err)
	}
	wantPair := "3d48f8b6e89826fff9aa7fb86d8c7ebe" +
		"b9ace567ab82bc1f8b60aaa8d85dd56d" +
		"00d7e63c8b481efaeebce366bb5d8fd8" +
		"66a71cf22bb651447d590415426fecfd"
	if got := hex.EncodeToString(sector[:64]); got != wantPair {
		t.Fatalf("diffuser B then A = %s, want %s", got, wantPair)
	}
}

func TestSectorCipherRoundTripsEveryMethod(t *testing.T) {
	elephant128 := make([]byte, 64)
	copy(elephant128[:16], fixtureCBCKey128)
	copy(elephant128[32:48], fixtureElephant128)
	elephant256 := make([]byte, 64)
	copy(elephant256[:32], fixtureCBCKey256)
	copy(elephant256[32:], fixtureElephant256)

	cases := []struct {
		name   string
		method uint16
		key    []byte
	}{
		{"aes-128-xts", bitlocker.MethodAES128XTS, fixtureFVEK128},
		{"aes-256-xts", bitlocker.MethodAES256XTS, fixtureFVEK},
		{"aes-128-cbc", bitlocker.MethodAES128CBC, fixtureCBCKey128},
		{"aes-256-cbc", bitlocker.MethodAES256CBC, fixtureCBCKey256},
		{"aes-128-cbc-elephant", bitlocker.MethodAES128CBCElephant, elephant128},
		{"aes-256-cbc-elephant", bitlocker.MethodAES256CBCElephant, elephant256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plain := sequence(512)
			encrypted := encryptFixtureSector(tc.method, tc.key, fixtureDataOffset, plain)
			if bytes.Equal(encrypted, plain) {
				t.Fatal("fixture encryption left the sector unchanged")
			}
			cipher, err := newSectorCipher(tc.method, tc.key)
			if err != nil {
				t.Fatalf("newSectorCipher: %v", err)
			}
			unit := append([]byte(nil), encrypted...)
			if err := cipher.decrypt(fixtureDataOffset, unit); err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(unit, plain) {
				t.Fatal("sector cipher did not restore the plaintext")
			}
		})
	}
}

func TestSectorCipherRefusesBadShapes(t *testing.T) {
	if _, err := newSectorCipher(bitlocker.MethodAES256XTS, make([]byte, 32)); !errors.Is(err, ErrKeySize) {
		t.Fatalf("short XTS key error = %v, want ErrKeySize", err)
	}
	if _, err := newSectorCipher(bitlocker.MethodAES128CBC, make([]byte, 17)); !errors.Is(err, ErrKeySize) {
		t.Fatalf("bad CBC key error = %v, want ErrKeySize", err)
	}
	if _, err := newSectorCipher(0x8006, make([]byte, 64)); !errors.Is(err, ErrUnsupportedMethod) {
		t.Fatalf("unknown method error = %v, want ErrUnsupportedMethod", err)
	}
	if err := diffuserADecrypt(make([]byte, 16)); err == nil {
		t.Fatal("a four-word diffuser sector must be refused")
	}
	xts, err := newXTSCipher(sequence(32))
	if err != nil {
		t.Fatal(err)
	}
	if err := xts.decrypt(0, make([]byte, 17)); err == nil {
		t.Fatal("a partial XTS block must be refused")
	}
}
