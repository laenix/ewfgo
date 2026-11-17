package unlock

// AES sector ciphers for LUKS payload and key-slot areas.
//
// The supported modes are the ones the format states in full:
//
//   - aes-xts-plain64    IEEE 1619 XTS with the 64-bit little-endian sector
//   - aes-xts-plain64be  XTS with the 64-bit big-endian sector
//   - aes-xts-plain      XTS with the 32-bit little-endian sector
//   - aes-cbc-essiv:sha256  CBC, IV = AES-ECB(SHA-256(key), LE64(sector))
//   - aes-cbc-plain64    CBC, IV = LE64(sector) in a zero block
//   - aes-cbc-plain      CBC, IV = LE32(sector) in a zero block
//
// XTS takes a 32- or 64-byte key pair; a CBC mode takes one AES-128/192/256
// key. Every other cipher or IV mode is refused by name rather than run with a
// guessed IV.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
)

const aesBlockBytes = 16

type cipherMode uint8

const (
	modeXTSPlain64 cipherMode = iota + 1
	modeXTSPlain64BE
	modeXTSPlain
	modeCBCEssivSHA256
	modeCBCPlain64
	modeCBCPlain
)

// cipherSpec is a parsed encryption string.
type cipherSpec struct {
	mode cipherMode
	name string
}

func (s cipherSpec) acceptsKey(bytes int) bool {
	switch s.mode {
	case modeXTSPlain64, modeXTSPlain64BE, modeXTSPlain:
		return bytes == 32 || bytes == 64
	case modeCBCEssivSHA256, modeCBCPlain64, modeCBCPlain:
		return bytes == 16 || bytes == 24 || bytes == 32
	default:
		return false
	}
}

// parseEncryption splits an `aes-<mode>` string and refuses anything this
// package does not implement.
func parseEncryption(encryption string) (cipherSpec, error) {
	parts := strings.SplitN(encryption, "-", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "aes") {
		return cipherSpec{}, fmt.Errorf("%w: %q is not an aes encryption string", ErrUnsupportedCipher, encryption)
	}
	mode := strings.ToLower(parts[1])
	switch mode {
	case "xts-plain64":
		return cipherSpec{mode: modeXTSPlain64, name: "xts-plain64"}, nil
	case "xts-plain64be":
		return cipherSpec{mode: modeXTSPlain64BE, name: "xts-plain64be"}, nil
	case "xts-plain":
		return cipherSpec{mode: modeXTSPlain, name: "xts-plain"}, nil
	case "cbc-essiv:sha256":
		return cipherSpec{mode: modeCBCEssivSHA256, name: "cbc-essiv:sha256"}, nil
	case "cbc-plain64":
		return cipherSpec{mode: modeCBCPlain64, name: "cbc-plain64"}, nil
	case "cbc-plain":
		return cipherSpec{mode: modeCBCPlain, name: "cbc-plain"}, nil
	default:
		return cipherSpec{}, fmt.Errorf("%w: aes-%s is not an implemented IV mode", ErrUnsupportedCipher, mode)
	}
}

// sectorCipher decrypts one dm-crypt data unit.
type sectorCipher struct {
	spec   cipherSpec
	data   cipher.Block
	tweak  cipher.Block
	essiv  cipher.Block
	keyLen int
}

func newSectorCipher(spec cipherSpec, key []byte) (*sectorCipher, error) {
	if !spec.acceptsKey(len(key)) {
		return nil, fmt.Errorf("%w: a %d-byte key is not usable with %s", ErrKeyBytes, len(key), spec.name)
	}
	c := &sectorCipher{spec: spec, keyLen: len(key)}
	switch spec.mode {
	case modeXTSPlain64, modeXTSPlain64BE, modeXTSPlain:
		half := len(key) / 2
		data, err := aes.NewCipher(key[:half])
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnsupportedCipher, err)
		}
		tweak, err := aes.NewCipher(key[half:])
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnsupportedCipher, err)
		}
		c.data, c.tweak = data, tweak
	case modeCBCEssivSHA256:
		data, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnsupportedCipher, err)
		}
		digest := sha256.Sum256(key)
		essiv, err := aes.NewCipher(digest[:])
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnsupportedCipher, err)
		}
		c.data, c.essiv = data, essiv
	default:
		data, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnsupportedCipher, err)
		}
		c.data = data
	}
	return c, nil
}

// decryptSector decrypts the whole 16-byte blocks of a data unit in place.
func (c *sectorCipher) decryptSector(sector uint64, unit []byte) error {
	switch c.spec.mode {
	case modeXTSPlain64, modeXTSPlain64BE, modeXTSPlain:
		tweak, err := c.xtsTweak(sector)
		if err != nil {
			return err
		}
		return c.xtsRun(tweak, unit, false)
	case modeCBCEssivSHA256:
		iv, err := c.essivIV(sector)
		if err != nil {
			return err
		}
		cbcDecrypt(c.data, iv, unit)
		return nil
	case modeCBCPlain64, modeCBCPlain:
		iv, err := c.plainIV(sector)
		if err != nil {
			return err
		}
		cbcDecrypt(c.data, iv, unit)
		return nil
	default:
		return fmt.Errorf("%w: unknown cipher mode", ErrUnsupportedCipher)
	}
}

// encryptSector is the inverse, used to build fixtures and to round-trip.
func (c *sectorCipher) encryptSector(sector uint64, unit []byte) error {
	switch c.spec.mode {
	case modeXTSPlain64, modeXTSPlain64BE, modeXTSPlain:
		tweak, err := c.xtsTweak(sector)
		if err != nil {
			return err
		}
		return c.xtsRun(tweak, unit, true)
	case modeCBCEssivSHA256:
		iv, err := c.essivIV(sector)
		if err != nil {
			return err
		}
		cbcEncrypt(c.data, iv, unit)
		return nil
	case modeCBCPlain64, modeCBCPlain:
		iv, err := c.plainIV(sector)
		if err != nil {
			return err
		}
		cbcEncrypt(c.data, iv, unit)
		return nil
	default:
		return fmt.Errorf("%w: unknown cipher mode", ErrUnsupportedCipher)
	}
}

func (c *sectorCipher) xtsTweak(sector uint64) ([aesBlockBytes]byte, error) {
	var tweak [aesBlockBytes]byte
	switch c.spec.mode {
	case modeXTSPlain64:
		binary.LittleEndian.PutUint64(tweak[:8], sector)
	case modeXTSPlain64BE:
		binary.BigEndian.PutUint64(tweak[:8], sector)
	case modeXTSPlain:
		if sector > uint64(^uint32(0)) {
			return tweak, fmt.Errorf("%w: sector %d does not fit the 32-bit IV of %s", ErrIVSector, sector, c.spec.name)
		}
		binary.LittleEndian.PutUint32(tweak[:4], uint32(sector))
	default:
		return tweak, fmt.Errorf("%w: not an XTS mode", ErrUnsupportedCipher)
	}
	return tweak, nil
}

func (c *sectorCipher) plainIV(sector uint64) ([aesBlockBytes]byte, error) {
	var iv [aesBlockBytes]byte
	if c.spec.mode == modeCBCPlain {
		if sector > uint64(^uint32(0)) {
			return iv, fmt.Errorf("%w: sector %d does not fit the 32-bit IV of %s", ErrIVSector, sector, c.spec.name)
		}
		binary.LittleEndian.PutUint32(iv[:4], uint32(sector))
		return iv, nil
	}
	binary.LittleEndian.PutUint64(iv[:8], sector)
	return iv, nil
}

func (c *sectorCipher) essivIV(sector uint64) ([aesBlockBytes]byte, error) {
	var iv [aesBlockBytes]byte
	binary.LittleEndian.PutUint64(iv[:8], sector)
	c.essiv.Encrypt(iv[:], iv[:])
	return iv, nil
}

// xtsRun applies XTS to a whole data unit. A trailing partial block is left
// untouched: callers pass only the bytes a cipher can state.
func (c *sectorCipher) xtsRun(tweak [aesBlockBytes]byte, unit []byte, encrypt bool) error {
	if len(unit) == 0 || len(unit)%aesBlockBytes != 0 {
		return fmt.Errorf("%w: XTS data unit of %d bytes is not a whole number of %d-byte blocks",
			ErrCipherBlockSize, len(unit), aesBlockBytes)
	}
	var mask [aesBlockBytes]byte
	c.tweak.Encrypt(mask[:], tweak[:])
	for offset := 0; offset < len(unit); offset += aesBlockBytes {
		block := unit[offset : offset+aesBlockBytes]
		for index := range block {
			block[index] ^= mask[index]
		}
		if encrypt {
			c.data.Encrypt(block, block)
		} else {
			c.data.Decrypt(block, block)
		}
		for index := range block {
			block[index] ^= mask[index]
		}
		mulAlpha(&mask)
	}
	return nil
}

func cbcDecrypt(block cipher.Block, iv [aesBlockBytes]byte, unit []byte) {
	previous := iv
	for offset := 0; offset+aesBlockBytes <= len(unit); offset += aesBlockBytes {
		chunk := unit[offset : offset+aesBlockBytes]
		var saved [aesBlockBytes]byte
		copy(saved[:], chunk)
		block.Decrypt(chunk, chunk)
		for index := range chunk {
			chunk[index] ^= previous[index]
		}
		previous = saved
	}
}

func cbcEncrypt(block cipher.Block, iv [aesBlockBytes]byte, unit []byte) {
	previous := iv
	for offset := 0; offset+aesBlockBytes <= len(unit); offset += aesBlockBytes {
		chunk := unit[offset : offset+aesBlockBytes]
		for index := range chunk {
			chunk[index] ^= previous[index]
		}
		block.Encrypt(chunk, chunk)
		copy(previous[:], chunk)
	}
}

// mulAlpha multiplies the XTS tweak by x in GF(2^128), little-endian bytes,
// with the reduction polynomial x^128 + x^7 + x^2 + x + 1.
func mulAlpha(tweak *[aesBlockBytes]byte) {
	carry := tweak[aesBlockBytes-1] >> 7
	var shifted [aesBlockBytes]byte
	for index := aesBlockBytes - 1; index > 0; index-- {
		shifted[index] = tweak[index]<<1 | tweak[index-1]>>7
	}
	shifted[0] = tweak[0] << 1
	if carry != 0 {
		shifted[0] ^= 0x87
	}
	*tweak = shifted
}
