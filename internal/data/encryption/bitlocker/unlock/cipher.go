package unlock

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"math/bits"

	"github.com/laenix/ewfgo/internal/data/encryption/bitlocker"
)

// Sector cipher selection.
//
// AES-XTS (0x8004/0x8005) uses one 32-byte or 64-byte key and takes the
// physical sector number as the little-endian first eight bytes of the tweak
// block. AES-CBC (0x8002/0x8003) sets the IV to
// AES-ECB-Encrypt(FVEK, LE64(physical_offset) || 0) and resets the cipher state
// at every sector. The Elephant variants (0x8000/0x8001) add a 32-byte sector
// key derived from the separate tweak key, then Diffuser B, Diffuser A and a
// cyclic XOR after AES-CBC decryption.

func sectorCipherKeyBytes(method uint16) int {
	switch method {
	case bitlocker.MethodAES128CBCElephant, bitlocker.MethodAES256CBCElephant:
		return 64
	case bitlocker.MethodAES128CBC:
		return 16
	case bitlocker.MethodAES256CBC:
		return 32
	case bitlocker.MethodAES128XTS:
		return 32
	case bitlocker.MethodAES256XTS:
		return 64
	default:
		return 0
	}
}

type sectorCipher struct {
	method uint16
	xts    *xtsCipher
	cbc    *cbcCipher
}

func newSectorCipher(method uint16, data []byte) (*sectorCipher, error) {
	wanted := sectorCipherKeyBytes(method)
	if wanted == 0 {
		return nil, unsupportedMethod(method)
	}
	if len(data) != wanted {
		return nil, fmt.Errorf("%w: %d bytes do not fit %s", ErrKeySize, len(data), bitlocker.EncryptionLabel(method))
	}
	switch method {
	case bitlocker.MethodAES128XTS, bitlocker.MethodAES256XTS:
		xts, err := newXTSCipher(data)
		if err != nil {
			return nil, err
		}
		return &sectorCipher{method: method, xts: xts}, nil
	case bitlocker.MethodAES128CBC:
		cbc, err := newCBCCipher(data[:16], nil)
		if err != nil {
			return nil, err
		}
		return &sectorCipher{method: method, cbc: cbc}, nil
	case bitlocker.MethodAES256CBC:
		cbc, err := newCBCCipher(data[:32], nil)
		if err != nil {
			return nil, err
		}
		return &sectorCipher{method: method, cbc: cbc}, nil
	case bitlocker.MethodAES128CBCElephant:
		cbc, err := newCBCCipher(data[:16], data[32:48])
		if err != nil {
			return nil, err
		}
		return &sectorCipher{method: method, cbc: cbc}, nil
	case bitlocker.MethodAES256CBCElephant:
		cbc, err := newCBCCipher(data[:32], data[32:64])
		if err != nil {
			return nil, err
		}
		return &sectorCipher{method: method, cbc: cbc}, nil
	default:
		return nil, unsupportedMethod(method)
	}
}

// decrypt decrypts one sector whose first byte is the physical offset in the
// encrypted volume.
func (c *sectorCipher) decrypt(physical uint64, sector []byte) error {
	if c.xts != nil {
		return c.xts.decrypt(physical, sector)
	}
	return c.cbc.decrypt(physical, sector)
}

// ---------------------------------------------------------------------------
// AES-XTS
// ---------------------------------------------------------------------------

type xtsCipher struct {
	data  cipher.Block
	tweak cipher.Block
}

func newXTSCipher(key []byte) (*xtsCipher, error) {
	if len(key) != 32 && len(key) != 64 {
		return nil, fmt.Errorf("%w: XTS key of %d bytes is not 32 or 64", ErrKeySize, len(key))
	}
	half := len(key) / 2
	data, err := aes.NewCipher(key[:half])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeySize, err)
	}
	tweak, err := aes.NewCipher(key[half:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeySize, err)
	}
	return &xtsCipher{data: data, tweak: tweak}, nil
}

func (x *xtsCipher) decrypt(physical uint64, unit []byte) error {
	return x.run(physical, unit, x.data.Decrypt)
}

// encrypt is kept for round-trip tests; unlocking only decrypts.
func (x *xtsCipher) encrypt(physical uint64, unit []byte) error {
	return x.run(physical, unit, x.data.Encrypt)
}

func (x *xtsCipher) run(physical uint64, unit []byte, direction func(dst, src []byte)) error {
	if len(unit) == 0 || len(unit)%aes.BlockSize != 0 {
		return fmt.Errorf("XTS data unit of %d bytes is not a non-zero multiple of 16", len(unit))
	}
	var mask [aes.BlockSize]byte
	binary.LittleEndian.PutUint64(mask[:8], physical/SectorBytes)
	x.tweak.Encrypt(mask[:], mask[:])
	var block [aes.BlockSize]byte
	for at := 0; at < len(unit); at += aes.BlockSize {
		for i := 0; i < aes.BlockSize; i++ {
			block[i] = unit[at+i] ^ mask[i]
		}
		direction(block[:], block[:])
		for i := 0; i < aes.BlockSize; i++ {
			unit[at+i] = block[i] ^ mask[i]
		}
		multiplyAlpha(&mask)
	}
	return nil
}

// multiplyAlpha multiplies the tweak by x in GF(2^128), little-endian, with the
// reduction polynomial x^128 + x^7 + x^2 + x + 1.
func multiplyAlpha(tweak *[aes.BlockSize]byte) {
	carry := tweak[aes.BlockSize-1] >> 7
	for i := aes.BlockSize - 1; i > 0; i-- {
		tweak[i] = tweak[i]<<1 | tweak[i-1]>>7
	}
	tweak[0] <<= 1
	if carry != 0 {
		tweak[0] ^= 0x87
	}
}

// ---------------------------------------------------------------------------
// AES-CBC, optionally with the Elephant diffuser
// ---------------------------------------------------------------------------

type cbcCipher struct {
	block    cipher.Block
	elephant cipher.Block
}

func newCBCCipher(key, elephantKey []byte) (*cbcCipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeySize, err)
	}
	c := &cbcCipher{block: block}
	if elephantKey != nil {
		tweak, err := aes.NewCipher(elephantKey)
		if err != nil {
			return nil, fmt.Errorf("%w: Elephant tweak: %v", ErrKeySize, err)
		}
		c.elephant = tweak
	}
	return c, nil
}

func (c *cbcCipher) decrypt(physical uint64, sector []byte) error {
	if len(sector) == 0 || len(sector)%aes.BlockSize != 0 {
		return fmt.Errorf("CBC sector of %d bytes is not a non-zero multiple of 16", len(sector))
	}
	// The IV is the FVEK's encryption of the little-endian physical byte
	// address, zero-padded to a block. The unencrypted block is also the input
	// for the Elephant sector key, so it is kept separately.
	var block [aes.BlockSize]byte
	binary.LittleEndian.PutUint64(block[:8], physical)
	iv := block
	c.block.Encrypt(iv[:], iv[:])
	cipher.NewCBCDecrypter(c.block, iv[:]).CryptBlocks(sector, sector)

	if c.elephant == nil {
		return nil
	}
	first := block
	c.elephant.Encrypt(first[:], first[:])
	second := block
	second[aes.BlockSize-1] = 0x80
	c.elephant.Encrypt(second[:], second[:])
	var sectorKey [32]byte
	copy(sectorKey[:16], first[:])
	copy(sectorKey[16:], second[:])
	if err := diffuserBDecrypt(sector); err != nil {
		return err
	}
	if err := diffuserADecrypt(sector); err != nil {
		return err
	}
	for i := range sector {
		sector[i] ^= sectorKey[i%32]
	}
	return nil
}

// Rotation amounts and cycle counts from dislocker's diffuser.c.
var (
	diffuserRA = [4]uint32{9, 0, 13, 0}
	diffuserRB = [4]uint32{0, 10, 0, 25}
)

func diffuserADecrypt(sector []byte) error {
	words, err := diffuserWords(sector)
	if err != nil {
		return err
	}
	for cycle := 0; cycle < 5; cycle++ {
		for i := 0; i < words; i++ {
			left := readWord(sector, (i+words-2)%words)
			rotated := bits.RotateLeft32(readWord(sector, (i+words-5)%words), int(diffuserRA[i%4]))
			writeWord(sector, i, readWord(sector, i)+(left^rotated))
		}
	}
	return nil
}

func diffuserBDecrypt(sector []byte) error {
	words, err := diffuserWords(sector)
	if err != nil {
		return err
	}
	for cycle := 0; cycle < 3; cycle++ {
		for i := 0; i < words; i++ {
			left := readWord(sector, (i+2)%words)
			rotated := bits.RotateLeft32(readWord(sector, (i+5)%words), int(diffuserRB[i%4]))
			writeWord(sector, i, readWord(sector, i)+(left^rotated))
		}
	}
	return nil
}

func diffuserWords(sector []byte) (int, error) {
	if len(sector)%4 != 0 {
		return 0, fmt.Errorf("diffuser sector of %d bytes is not a multiple of four", len(sector))
	}
	words := len(sector) / 4
	if words < 5 {
		return 0, fmt.Errorf("diffuser sector holds %d words, fewer than five", words)
	}
	return words, nil
}

func readWord(sector []byte, index int) uint32 {
	return binary.LittleEndian.Uint32(sector[index*4:])
}

func writeWord(sector []byte, index int, value uint32) {
	binary.LittleEndian.PutUint32(sector[index*4:], value)
}
