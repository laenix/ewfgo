package unlock

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func mustHex(t *testing.T, text string) []byte {
	t.Helper()
	out, err := hex.DecodeString(text)
	if err != nil {
		t.Fatalf("hex %q: %v", text, err)
	}
	return out
}

// RFC 3610 §8 Packet Vector #1, an answer this package did not compute: a
// 13-byte nonce, an 8-byte tag and 8 bytes of associated data.
func TestCCMRFC3610PacketVector1(t *testing.T) {
	key := mustHex(t, "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF")
	nonce := mustHex(t, "00000003020100A0A1A2A3A4A5")
	aad := mustHex(t, "0001020304050607")
	plaintext := mustHex(t, "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E")

	ciphertext, tag, err := ccmSeal(key, nonce, aad, plaintext, 8)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if want := mustHex(t, "588C979A61C663D2F066D0C2C0F989806D5F6B61DAC384"); !bytes.Equal(ciphertext, want) {
		t.Fatalf("ciphertext = %X, want %X", ciphertext, want)
	}
	if want := mustHex(t, "17E8D12CFDF926E0"); !bytes.Equal(tag, want) {
		t.Fatalf("tag = %X, want %X", tag, want)
	}
	opened, err := ccmOpen(key, nonce, aad, ciphertext, tag)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened = %X, want %X", opened, plaintext)
	}
}

// The BitLocker profile: a 12-byte nonce, a 16-byte tag, no associated data.
func TestCCMBitlockerProfileRoundTripAndTagCheck(t *testing.T) {
	key := []byte("0123456789ABCDEF")
	nonce := []byte{0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24}
	plaintext := []byte("a 12-byte sized key container")

	ciphertext, tag, err := ccmSeal(key, nonce, nil, plaintext, 16)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	opened, err := ccmOpen(key, nonce, nil, ciphertext, tag)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened = %q, want %q", opened, plaintext)
	}

	// A wrong key must fail the tag and return no plaintext.
	if opened, err := ccmOpen([]byte("FEDCBA9876543210"), nonce, nil, ciphertext, tag); !errors.Is(err, ErrTagMismatch) {
		t.Fatalf("wrong key error = %v, want ErrTagMismatch", err)
	} else if opened != nil {
		t.Fatalf("wrong key returned %d bytes of plaintext", len(opened))
	}

	tampered := append([]byte(nil), ciphertext...)
	tampered[0] ^= 0x80
	if opened, err := ccmOpen(key, nonce, nil, tampered, tag); !errors.Is(err, ErrTagMismatch) {
		t.Fatalf("tampered ciphertext error = %v, want ErrTagMismatch", err)
	} else if opened != nil {
		t.Fatalf("tampered ciphertext returned %d bytes of plaintext", len(opened))
	}

	badTag := append([]byte(nil), tag...)
	badTag[15] ^= 0x01
	if opened, err := ccmOpen(key, nonce, nil, ciphertext, badTag); !errors.Is(err, ErrTagMismatch) {
		t.Fatalf("tampered tag error = %v, want ErrTagMismatch", err)
	} else if opened != nil {
		t.Fatalf("tampered tag returned %d bytes of plaintext", len(opened))
	}
}

func TestCCMParameterRefusals(t *testing.T) {
	nonce12 := make([]byte, 12)
	if _, err := ccmOpen(make([]byte, 15), nonce12, nil, nil, make([]byte, 16)); !errors.Is(err, ErrCCMKeySize) {
		t.Fatalf("bad key error = %v, want ErrCCMKeySize", err)
	}
	if _, err := ccmOpen(make([]byte, 16), make([]byte, 6), nil, nil, make([]byte, 16)); !errors.Is(err, ErrCCMNonceSize) {
		t.Fatalf("bad nonce error = %v, want ErrCCMNonceSize", err)
	}
	if _, err := ccmOpen(make([]byte, 16), nonce12, nil, nil, make([]byte, 3)); !errors.Is(err, ErrCCMTagSize) {
		t.Fatalf("bad tag error = %v, want ErrCCMTagSize", err)
	}
	if _, _, err := ccmSeal(make([]byte, 16), nonce12, nil, make([]byte, MaxCCMMessageBytes+1), 16); !errors.Is(err, ErrCCMMessageTooLong) {
		t.Fatalf("oversized message error = %v, want ErrCCMMessageTooLong", err)
	}
}
