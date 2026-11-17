package unlock

// Hermetic LUKS1/LUKS2 fixtures.
//
// Each fixture builds a genuine volume in memory: a header, a JSON document,
// an encrypted anti-forensic key-slot area, a correctly derived digest, and an
// AES-encrypted payload. Nothing is read from disk, and the primitive
// correctness is pinned separately by the RFC/OpenSSL vectors in the other
// test files.

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func putBE16(buffer []byte, at int, value uint16) {
	binary.BigEndian.PutUint16(buffer[at:], value)
}

func putBE32(buffer []byte, at int, value uint32) {
	binary.BigEndian.PutUint32(buffer[at:], value)
}

func putBE64(buffer []byte, at int, value uint64) {
	binary.BigEndian.PutUint64(buffer[at:], value)
}

func patternBytes(count int, seed byte) []byte {
	out := make([]byte, count)
	for index := range out {
		out[index] = byte((int(seed) + index*7) & 0xff)
	}
	return out
}

func deterministicFill(seed *uint32) func([]byte) {
	return func(out []byte) {
		for index := range out {
			*seed = *seed*1103515245 + 12345
			out[index] = byte(*seed >> 16)
		}
	}
}

func encryptSectors(plain []byte, key []byte, spec cipherSpec, sectorSize uint32, ivTweak uint64, sectorBase uint64) ([]byte, error) {
	out := append([]byte(nil), plain...)
	cipher, err := newSectorCipher(spec, key)
	if err != nil {
		return nil, err
	}
	for offset := 0; offset < len(out); offset += int(sectorSize) {
		end := offset + int(sectorSize)
		if end > len(out) {
			end = len(out)
		}
		sector := ivTweak + sectorBase + uint64(offset/int(sectorSize))
		if err := cipher.encryptSector(sector, out[offset:end]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

type segmentSpec struct {
	offset     uint64
	size       uint64
	ivTweak    uint64
	sectorSize uint32
	encryption string
	plaintext  []byte
}

type luks2Options struct {
	passphrase []byte
	masterKey  []byte

	keySize     int
	areaKeySize int
	areaEnc     string
	areaOffset  uint64
	stripes     int
	slotType    string
	areaType    string
	afHash      string

	kdfType         string
	kdfHash         string
	kdfIterations   uint32
	argonPasses     uint32
	argonMemoryKiB  uint32
	argonLanes      uint32
	salt            []byte
	kdfKindOverride string

	digestType       string
	digestHash       string
	digestIterations uint32
	digestSalt       []byte
	digestSize       int

	segments   []segmentSpec
	headerSize uint64
	hdrOffset  uint64
}

func defaultLUKS2Options(plain []byte) luks2Options {
	return luks2Options{
		passphrase:       []byte("correct horse battery staple"),
		masterKey:        patternBytes(32, 0x11),
		keySize:          32,
		areaKeySize:      64,
		areaEnc:          "aes-xts-plain64",
		areaOffset:       16384,
		stripes:          4,
		slotType:         "luks2",
		areaType:         "raw",
		afHash:           "sha256",
		kdfType:          "pbkdf2",
		kdfHash:          "sha256",
		kdfIterations:    1000,
		argonPasses:      1,
		argonMemoryKiB:   32,
		argonLanes:       1,
		salt:             patternBytes(32, 0x20),
		digestType:       "pbkdf2",
		digestHash:       "sha256",
		digestIterations: 100,
		digestSalt:       patternBytes(32, 0x30),
		digestSize:       32,
		segments: []segmentSpec{{
			offset:     32768,
			size:       uint64(len(plain)),
			ivTweak:    9,
			sectorSize: 512,
			encryption: "aes-xts-plain64",
			plaintext:  append([]byte(nil), plain...),
		}},
		headerSize: 12288,
	}
}

func (o luks2Options) kdfJSON() string {
	if o.kdfKindOverride != "" {
		return fmt.Sprintf(`{"type":%q}`, o.kdfKindOverride)
	}
	if strings.HasPrefix(o.kdfType, "argon2") {
		return fmt.Sprintf(
			`{"type":%q,"time":%d,"memory":%d,"cpus":%d,"salt":%q}`,
			o.kdfType, o.argonPasses, o.argonMemoryKiB, o.argonLanes,
			base64.StdEncoding.EncodeToString(o.salt))
	}
	return fmt.Sprintf(
		`{"type":"pbkdf2","hash":%q,"iterations":%d,"salt":%q}`,
		o.kdfHash, o.kdfIterations, base64.StdEncoding.EncodeToString(o.salt))
}

func (o luks2Options) segmentJSON(segments []segmentSpec) string {
	parts := make([]string, 0, len(segments))
	for index, segment := range segments {
		parts = append(parts, fmt.Sprintf(
			`%q:{"type":"crypt","offset":"%d","size":"%d","iv_tweak":"%d","encryption":%q,"sector_size":%d}`,
			fmt.Sprintf("%d", index), segment.offset, segment.size, segment.ivTweak,
			segment.encryption, segment.sectorSize))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// buildLUKS2 builds a complete, internally consistent LUKS2 volume.
func buildLUKS2(t *testing.T, options luks2Options) []byte {
	t.Helper()
	if len(options.masterKey) != options.keySize {
		t.Fatalf("master key is %d bytes, key_size is %d", len(options.masterKey), options.keySize)
	}
	if options.stripes < 2 {
		t.Fatalf("stripes = %d", options.stripes)
	}

	var slotKey []byte
	var err error
	if options.kdfKindOverride == "" {
		if strings.HasPrefix(options.kdfType, "argon2") {
			var variant argon2Variant
			var ok bool
			variant, ok = argon2VariantByName(options.kdfType)
			if !ok {
				t.Fatalf("unknown argon2 type %q", options.kdfType)
			}
			slotKey, err = argon2Hash(argon2Params{
				variant:   variant,
				passes:    options.argonPasses,
				memoryKiB: options.argonMemoryKiB,
				lanes:     options.argonLanes,
				tagBytes:  options.areaKeySize,
			}, options.passphrase, options.salt, nil, nil)
		} else {
			// A fixture whose declared hash is deliberately unsupported still
			// needs bytes; the unlock must refuse before it derives anything.
			hash, ok := pbkdf2HashByName(options.kdfHash, false)
			if !ok {
				hash, _ = pbkdf2HashByName("sha256", false)
			}
			slotKey, err = pbkdf2Key(hash.new, options.passphrase, options.salt,
				options.kdfIterations, options.areaKeySize)
		}
		if err != nil {
			t.Fatalf("deriving the slot key: %v", err)
		}
	} else {
		slotKey = make([]byte, options.areaKeySize)
	}

	areaSpec, err := parseEncryption(options.areaEnc)
	if err != nil {
		// Deliberately unsupported area ciphers are still written as bytes so
		// the unlock can refuse them by name.
		areaSpec, _ = parseEncryption("aes-xts-plain64")
	}
	needed := uint64(options.keySize * options.stripes)
	needed = (needed + DMSectorBytes - 1) / DMSectorBytes * DMSectorBytes

	seed := uint32(0xabcdef01)
	stripes, err := afSplit(options.masterKey, options.stripes, deterministicFill(&seed))
	if err != nil {
		t.Fatalf("afSplit: %v", err)
	}
	areaPlain := make([]byte, needed)
	copy(areaPlain, stripes)
	areaCiphertext, err := encryptSectors(areaPlain, slotKey, areaSpec, 512, 0, options.areaOffset/512)
	if err != nil {
		t.Fatalf("encrypting the key slot area: %v", err)
	}

	digest := patternBytes(options.digestSize, 0x90)
	if strings.EqualFold(options.digestType, "pbkdf2") {
		hash, ok := pbkdf2HashByName(options.digestHash, false)
		if ok {
			digest, err = pbkdf2Key(hash.new, options.masterKey, options.digestSalt,
				options.digestIterations, options.digestSize)
			if err != nil {
				t.Fatalf("computing the digest: %v", err)
			}
		}
	}

	document := fmt.Sprintf(`{
  "keyslots": {
    "0": {
      "type": %q,
      "key_size": %d,
      "kdf": %s,
      "af": {"type": "luks1", "stripes": %d, "hash": %q},
      "area": {"type": %q, "offset": "%d", "size": "%d",
               "encryption": %q, "key_size": %d}
    }
  },
  "digests": {
    "0": {"type": %q, "keyslots": ["0"], "hash": %q, "iterations": %d,
          "salt": %q, "digest": %q}
  },
  "segments": %s,
  "tokens": {},
  "config": {"flags": []}
}`,
		options.slotType,
		options.keySize,
		options.kdfJSON(),
		options.stripes,
		options.afHash,
		options.areaType,
		options.areaOffset,
		needed,
		options.areaEnc,
		options.areaKeySize,
		options.digestType,
		options.digestHash,
		options.digestIterations,
		base64.StdEncoding.EncodeToString(options.digestSalt),
		base64.StdEncoding.EncodeToString(digest),
		options.segmentJSON(options.segments),
	)

	length := options.headerSize
	if end := options.areaOffset + needed; end > length {
		length = end
	}
	for _, segment := range options.segments {
		if end := segment.offset + segment.size; end > length {
			length = end
		}
	}
	image := make([]byte, length)
	copy(image, buildLUKS2Header(options.headerSize, document, options.hdrOffset))
	copy(image[options.areaOffset:], areaCiphertext)

	for _, segment := range options.segments {
		spec, err := parseEncryption(segment.encryption)
		if err != nil {
			// As above: the declared string stays in the JSON, but the bytes
			// are written with a cipher the unlock will refuse.
			spec, _ = parseEncryption("aes-xts-plain64")
		}
		encryptSectorSize := segment.sectorSize
		if encryptSectorSize < 512 || encryptSectorSize&(encryptSectorSize-1) != 0 ||
			encryptSectorSize%16 != 0 {
			encryptSectorSize = 512
		}
		ciphertext, err := encryptSectors(segment.plaintext, options.masterKey, spec,
			encryptSectorSize, segment.ivTweak, 0)
		if err != nil {
			t.Fatalf("encrypting a segment: %v", err)
		}
		copy(image[segment.offset:], ciphertext)
	}
	return image
}

func buildLUKS2Header(headerSize uint64, document string, hdrOffset uint64) []byte {
	header := make([]byte, headerSize)
	copy(header, []byte("LUKS\xba\xbe"))
	putBE16(header, 6, 2)
	putBE64(header, 8, headerSize)
	putBE64(header, 0x10, 7)
	copy(header[0x18:], "fixture")
	copy(header[0x48:], "sha256")
	copy(header[0x68:], patternBytes(64, 0x44))
	copy(header[0xa8:], "33333333-4444-5555-6666-777777777777")
	putBE64(header, 0x100, hdrOffset)
	copy(header[4096:], document)
	return header
}

type luks1Options struct {
	passphrase           []byte
	masterKey            []byte
	cipher               string
	mode                 string
	hash                 string
	keyBytes             int
	stripes              int
	iterations           uint32
	salt                 []byte
	areaSector           uint32
	payloadOffsetSectors uint32
	payload              []byte
	digestIterations     uint32
	digestSalt           []byte
}

func defaultLUKS1Options(plain []byte) luks1Options {
	return luks1Options{
		passphrase:           []byte("correct horse battery staple"),
		masterKey:            patternBytes(32, 0x11),
		cipher:               "aes",
		mode:                 "xts-plain64",
		hash:                 "sha256",
		keyBytes:             32,
		stripes:              4,
		iterations:           1000,
		salt:                 patternBytes(32, 0x20),
		areaSector:           8,
		payloadOffsetSectors: 40,
		payload:              append([]byte(nil), plain...),
		digestIterations:     100,
		digestSalt:           patternBytes(32, 0x30),
	}
}

func buildLUKS1(t *testing.T, options luks1Options) []byte {
	t.Helper()
	header := make([]byte, 592)
	copy(header, []byte("LUKS\xba\xbe"))
	putBE16(header, 6, 1)
	copy(header[0x08:], options.cipher)
	copy(header[0x28:], options.mode)
	copy(header[0x48:], options.hash)
	putBE32(header, 0x68, options.payloadOffsetSectors)
	putBE32(header, 0x6c, uint32(options.keyBytes))
	putBE32(header, 0xa4, options.digestIterations)
	copy(header[0x84:], options.digestSalt)
	copy(header[0xa8:], "11111111-2222-3333-4444-555555555555")

	hash, ok := pbkdf2HashByName(options.hash, true)
	if !ok {
		t.Fatalf("unknown LUKS1 hash %q", options.hash)
	}
	digest, err := pbkdf2Key(hash.new, options.masterKey, options.digestSalt,
		options.digestIterations, LUKS1DigestBytes)
	if err != nil {
		t.Fatalf("master-key digest: %v", err)
	}
	copy(header[0x70:], digest)

	spec, err := parseEncryption(options.cipher + "-" + options.mode)
	if err != nil {
		t.Fatalf("mode %q: %v", options.mode, err)
	}
	slotKey, err := pbkdf2Key(hash.new, options.passphrase, options.salt,
		options.iterations, options.keyBytes)
	if err != nil {
		t.Fatalf("slot key: %v", err)
	}
	seed := uint32(0x13572468)
	stripes, err := afSplit(options.masterKey, options.stripes, deterministicFill(&seed))
	if err != nil {
		t.Fatalf("afSplit: %v", err)
	}
	needed := uint64(options.keyBytes * options.stripes)
	needed = (needed + DMSectorBytes - 1) / DMSectorBytes * DMSectorBytes
	areaPlain := make([]byte, needed)
	copy(areaPlain, stripes)
	areaCiphertext, err := encryptSectors(areaPlain, slotKey, spec, 512, 0, uint64(options.areaSector))
	if err != nil {
		t.Fatalf("encrypting the LUKS1 area: %v", err)
	}

	base := 0xd0
	putBE32(header, base, 0x00ac71f3)
	putBE32(header, base+4, options.iterations)
	copy(header[base+8:], options.salt)
	putBE32(header, base+40, options.areaSector)
	putBE32(header, base+44, uint32(options.stripes))

	payloadOffset := uint64(options.payloadOffsetSectors) * DMSectorBytes
	length := payloadOffset + uint64(len(options.payload))
	if end := uint64(options.areaSector)*DMSectorBytes + needed; end > length {
		length = end
	}
	image := make([]byte, length)
	copy(image, header)
	copy(image[uint64(options.areaSector)*DMSectorBytes:], areaCiphertext)
	payloadCiphertext, err := encryptSectors(options.payload, options.masterKey, spec, 512, 0, 0)
	if err != nil {
		t.Fatalf("encrypting the LUKS1 payload: %v", err)
	}
	copy(image[payloadOffset:], payloadCiphertext)
	return image
}
