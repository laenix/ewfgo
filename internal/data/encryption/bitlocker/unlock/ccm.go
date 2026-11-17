package unlock

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"fmt"
)

// AES-CCM (RFC 3610). BitLocker uses one profile — a 12-byte nonce (so the
// length field is 3 bytes), a 16-byte tag, and no associated data — but the
// parameters are general so the implementation can be checked against the
// RFC's own vectors. The RFC stores the tag after the ciphertext; BitLocker
// stores it before, which is the caller's layout decision.

const (
	// MaxCCMMessageBytes bounds one CCM operation so a malformed length cannot
	// force a large allocation.
	MaxCCMMessageBytes = 1 << 20
	ccmBlockBytes      = aes.BlockSize
)

// CCM parameter refusals.
var (
	// ErrCCMKeySize means the AES-CCM key is neither 16 nor 32 bytes.
	ErrCCMKeySize = errors.New("bitlocker unlock: AES-CCM key is not 16 or 32 bytes")
	// ErrCCMNonceSize means the nonce is outside 7..=13 bytes.
	ErrCCMNonceSize = errors.New("bitlocker unlock: AES-CCM nonce is outside 7..13 bytes")
	// ErrCCMTagSize means the tag is not even and in 4..=16 bytes.
	ErrCCMTagSize = errors.New("bitlocker unlock: AES-CCM tag is not even and in 4..16 bytes")
	// ErrCCMMessageTooLong means the message does not fit the length field or
	// the package's allocation bound.
	ErrCCMMessageTooLong = errors.New("bitlocker unlock: AES-CCM message is too long")
)

// ccmOpen decrypts ciphertext and verifies its tag.
//
// The tag is verified over the recovered plaintext. On failure the plaintext
// is discarded and ErrTagMismatch is returned; a caller never sees bytes that
// failed the check.
func ccmOpen(key, nonce, aad, ciphertext, tag []byte) ([]byte, error) {
	setup, err := newCCM(key, nonce, len(tag), len(ciphertext))
	if err != nil {
		return nil, err
	}
	plaintext := append([]byte(nil), ciphertext...)
	ccmXORKeystream(setup.block, nonce, plaintext)
	expected := setup.mac(nonce, aad, plaintext)
	ccmMaskTag(setup.block, nonce, &expected)
	if subtle.ConstantTimeCompare(expected[:len(tag)], tag) != 1 {
		return nil, ErrTagMismatch
	}
	return plaintext, nil
}

// ccmSeal encrypts and authenticates plaintext, returning ciphertext and tag.
// Unlocking only needs open; seal exists so tests and fixtures can build
// valid wrapped keys without external tooling.
func ccmSeal(key, nonce, aad, plaintext []byte, tagBytes int) ([]byte, []byte, error) {
	setup, err := newCCM(key, nonce, tagBytes, len(plaintext))
	if err != nil {
		return nil, nil, err
	}
	ciphertext := append([]byte(nil), plaintext...)
	ccmXORKeystream(setup.block, nonce, ciphertext)
	tag := setup.mac(nonce, aad, plaintext)
	ccmMaskTag(setup.block, nonce, &tag)
	return ciphertext, append([]byte(nil), tag[:tagBytes]...), nil
}

type ccmSetup struct {
	block       cipher.Block
	lengthBytes int
	tagBytes    int
}

func newCCM(key, nonce []byte, tagBytes, messageLen int) (*ccmSetup, error) {
	if len(key) != 16 && len(key) != 32 {
		return nil, fmt.Errorf("%w: %d bytes", ErrCCMKeySize, len(key))
	}
	if len(nonce) < 7 || len(nonce) > 13 {
		return nil, fmt.Errorf("%w: %d bytes", ErrCCMNonceSize, len(nonce))
	}
	if tagBytes < 4 || tagBytes > 16 || tagBytes%2 != 0 {
		return nil, fmt.Errorf("%w: %d bytes", ErrCCMTagSize, tagBytes)
	}
	lengthBytes := 15 - len(nonce)
	max := uint64(^uint64(0))
	if lengthBytes < 8 {
		max = (uint64(1) << (8 * lengthBytes)) - 1
	}
	if uint64(messageLen) > max || messageLen > MaxCCMMessageBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrCCMMessageTooLong, messageLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCCMKeySize, err)
	}
	return &ccmSetup{block: block, lengthBytes: lengthBytes, tagBytes: tagBytes}, nil
}

func (s *ccmSetup) mac(nonce, aad, plaintext []byte) [ccmBlockBytes]byte {
	var flags byte
	flags |= byte((s.tagBytes-2)/2) << 3
	flags |= byte(s.lengthBytes - 1)
	if len(aad) > 0 {
		flags |= 0x40
	}
	var block [ccmBlockBytes]byte
	block[0] = flags
	copy(block[1:], nonce)
	putBigEndian(block[ccmBlockBytes-s.lengthBytes:], uint64(len(plaintext)))
	s.block.Encrypt(block[:], block[:])
	state := block

	if len(aad) > 0 {
		var encoded []byte
		if len(aad) < 0xff00 {
			encoded = make([]byte, 2+len(aad))
			encoded[0] = byte(len(aad) >> 8)
			encoded[1] = byte(len(aad))
			copy(encoded[2:], aad)
		} else {
			encoded = make([]byte, 6+len(aad))
			encoded[0], encoded[1] = 0xff, 0xfe
			putBigEndian(encoded[2:6], uint64(len(aad)))
			copy(encoded[6:], aad)
		}
		state = ccmMacBlocks(s.block, state, encoded)
	}
	state = ccmMacBlocks(s.block, state, plaintext)
	return state
}

func ccmMacBlocks(block cipher.Block, state [ccmBlockBytes]byte, data []byte) [ccmBlockBytes]byte {
	for at := 0; at < len(data); at += ccmBlockBytes {
		var chunk [ccmBlockBytes]byte
		end := at + ccmBlockBytes
		if end > len(data) {
			end = len(data)
		}
		copy(chunk[:], data[at:end])
		for i := 0; i < ccmBlockBytes; i++ {
			chunk[i] ^= state[i]
		}
		block.Encrypt(chunk[:], chunk[:])
		state = chunk
	}
	return state
}

func ccmXORKeystream(block cipher.Block, nonce []byte, buffer []byte) {
	lengthBytes := 15 - len(nonce)
	counter := uint64(0)
	for at := 0; at < len(buffer); at += ccmBlockBytes {
		counter++
		var stream [ccmBlockBytes]byte
		stream[0] = byte(lengthBytes - 1)
		copy(stream[1:], nonce)
		putBigEndian(stream[ccmBlockBytes-lengthBytes:], counter)
		block.Encrypt(stream[:], stream[:])
		end := at + ccmBlockBytes
		if end > len(buffer) {
			end = len(buffer)
		}
		for i := at; i < end; i++ {
			buffer[i] ^= stream[i-at]
		}
	}
}

func ccmMaskTag(block cipher.Block, nonce []byte, tag *[ccmBlockBytes]byte) {
	lengthBytes := 15 - len(nonce)
	var stream [ccmBlockBytes]byte
	stream[0] = byte(lengthBytes - 1)
	copy(stream[1:], nonce)
	// Counter zero: the length field stays zero, so no putBigEndian needed.
	block.Encrypt(stream[:], stream[:])
	for i := 0; i < ccmBlockBytes; i++ {
		tag[i] ^= stream[i]
	}
}

func putBigEndian(dst []byte, value uint64) {
	for i := len(dst) - 1; i >= 0; i-- {
		dst[i] = byte(value)
		value >>= 8
	}
}
