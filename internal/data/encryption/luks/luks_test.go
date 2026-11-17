package luks

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/encryption/errs"
	"github.com/laenix/ewfgo/internal/data/source"
)

func putBE16(b []byte, at int, v uint16) { binary.BigEndian.PutUint16(b[at:], v) }
func putBE32(b []byte, at int, v uint32) { binary.BigEndian.PutUint32(b[at:], v) }
func putBE64(b []byte, at int, v uint64) { binary.BigEndian.PutUint64(b[at:], v) }

func buildLUKS1() []byte {
	b := make([]byte, LUKS1HeaderBytes)
	copy(b, Magic)
	putBE16(b, 6, 1)
	copy(b[0x08:], "aes")
	copy(b[0x28:], "xts-plain64")
	copy(b[0x48:], "sha256")
	putBE32(b, 0x68, 4096)
	putBE32(b, 0x6c, 32)
	for i := 0; i < 20; i++ {
		b[0x70+i] = byte(0xa0 + i)
	}
	for i := 0; i < 32; i++ {
		b[0x84+i] = byte(0x10 + i)
	}
	putBE32(b, 0xa4, 1000)
	copy(b[0xa8:], "11111111-2222-3333-4444-555555555555")

	base := 0xd0
	putBE32(b, base, LUKS1KeyslotActive)
	putBE32(b, base+4, 200000)
	for i := 0; i < 32; i++ {
		b[base+8+i] = byte(i)
	}
	putBE32(b, base+40, 8192)
	putBE32(b, base+44, 4000)
	return b
}

const luks2Metadata = `{
  "keyslots": {
    "0": {"type": "luks2", "key_size": 32,
          "kdf": {"type": "argon2id", "time": 6, "memory": 1048576, "cpus": 4,
                  "salt": "c29tZXNhbHRhbmQtc29tZXNhbHQ="},
          "af": {"type": "luks1", "stripes": 1000, "hash": "sha256"},
          "area": {"type": "raw", "offset": "32768", "size": "32000",
                   "encryption": "aes-xts-plain64", "key_size": 32}},
    "1": {"type": "luks2", "key_size": 64,
          "kdf": {"type": "pbkdf2", "hash": "sha256", "iterations": 400000,
                  "salt": "c29tZXNhbHRhbmQtc29tZXNhbHQ="},
          "af": {"type": "luks1", "stripes": 4000, "hash": "sha256"},
          "area": {"type": "raw", "offset": "290816", "size": "258048",
                   "encryption": "aes-xts-plain64", "key_size": 64}}
  },
  "segments": {"0": {"type": "crypt", "offset": "16777216", "size": "dynamic",
                     "iv_tweak": "7", "encryption": "aes-xts-plain64", "sector_size": 4096}},
  "digests": {"0": {"type": "pbkdf2", "keyslots": ["0"], "hash": "sha256",
                    "iterations": 1000, "salt": "c29tZXNhbHRhbmQtc29tZXNhbHQ=",
                    "digest": "c29tZWRpZ2VzdA=="}},
  "tokens": {},
  "config": {"flags": ["allow-discards"]}
}`

func buildLUKS2(metadata string, headerSize int, secondary bool) []byte {
	if headerSize == 0 {
		headerSize = 12288
	}
	total := headerSize
	if secondary {
		total += headerSize
	}
	b := make([]byte, total)
	copy(b, Magic)
	putBE16(b, 6, 2)
	putBE64(b, 8, uint64(headerSize))
	putBE64(b, 0x10, 5)
	copy(b[0x18:], "vol-label")
	copy(b[0x48:], "sha256")
	for i := 0; i < 64; i++ {
		b[0x68+i] = byte(i + 1)
	}
	copy(b[0xa8:], "22222222-3333-4444-5555-666666666666")
	copy(b[0xd0:], "subsys")
	putBE64(b, 0x100, 0)
	copy(b[LUKS2BinaryHeaderBytes:], metadata)

	hash := sha256.New()
	hash.Write(b[0x68:0xa8])
	hash.Write(b[:0x1c0])
	hash.Write(make([]byte, 64))
	hash.Write(b[0x200:headerSize])
	copy(b[0x1c0:0x200], hash.Sum(nil))
	if secondary {
		copy(b[headerSize:], Magic)
	}
	return b
}

func TestReadLUKS1(t *testing.T) {
	info, err := Read(source.NewMemorySource(1, buildLUKS1()))
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if info == nil || info.Version != 1 {
		t.Fatalf("info = %+v", info)
	}
	if info.Cipher != "aes" || info.Mode != "xts-plain64" || info.Hash != "sha256" {
		t.Fatalf("cipher/mode/hash = %q/%q/%q", info.Cipher, info.Mode, info.Hash)
	}
	if info.EncryptionMethod() != "aes-xts-plain64" {
		t.Fatalf("EncryptionMethod = %q", info.EncryptionMethod())
	}
	if info.PayloadOffset != 4096*512 || info.KeyBytes != 32 {
		t.Fatalf("payload/key bytes = %d/%d", info.PayloadOffset, info.KeyBytes)
	}
	if info.UUID != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("UUID = %q", info.UUID)
	}
	if !info.MKDigestPresent || info.MKDigestBytes != 20 ||
		!info.MKDigestSaltPresent || info.MKDigestSaltBytes != 32 ||
		info.MKDigestIterations != 1000 {
		t.Fatalf("mk digest metadata = %+v", info)
	}
	if len(info.Keyslots) != 8 || info.ActiveKeyslots != 1 {
		t.Fatalf("keyslots = %d active %d", len(info.Keyslots), info.ActiveKeyslots)
	}
	slot := info.Keyslots[0]
	if !slot.Active || slot.KDF != "pbkdf2" || slot.Hash != "sha256" ||
		slot.Iterations != 200000 || slot.Stripes != 4000 ||
		slot.AreaOffset != 8192 || slot.KeySize != 0 {
		t.Fatalf("slot 0 = %+v", slot)
	}
	if !slot.SaltPresent || slot.SaltBytes != 32 {
		t.Fatalf("slot salt = present %v, %d bytes", slot.SaltPresent, slot.SaltBytes)
	}
	if info.Keyslots[1].Active {
		t.Fatal("slot 1 active without the LUKS1 active marker")
	}
}

func TestReadLUKS1Truncated(t *testing.T) {
	header := buildLUKS1()
	_, err := Read(source.NewMemorySource(1, header[:100]))
	if !errors.Is(err, errs.ErrTruncated) {
		t.Fatalf("Read error = %v, want ErrTruncated", err)
	}
}

func TestReadLUKS2(t *testing.T) {
	info, err := Read(source.NewMemorySource(1, buildLUKS2(luks2Metadata, 0, true)))
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if info.Version != 2 || info.HeaderBytes != 12288 {
		t.Fatalf("version/header = %d/%d", info.Version, info.HeaderBytes)
	}
	if info.ChecksumAlgorithm != "sha256" || info.Checksum != ChecksumValid {
		t.Fatalf("checksum = %q/%v", info.ChecksumAlgorithm, info.Checksum)
	}
	if !info.SecondaryHeader {
		t.Fatal("secondary header not detected")
	}
	if info.Label != "vol-label" || info.Subsystem != "subsys" ||
		info.UUID != "22222222-3333-4444-5555-666666666666" {
		t.Fatalf("identity = %q/%q/%q", info.Label, info.Subsystem, info.UUID)
	}
	if info.Sequence != 5 || !info.SequenceSet || info.HeaderOffset != 0 || !info.HeaderOffsetSet {
		t.Fatalf("sequence/header offset = %d/%d", info.Sequence, info.HeaderOffset)
	}
	if len(info.Keyslots) != 2 || info.ActiveKeyslots != 2 {
		t.Fatalf("keyslots = %d active %d", len(info.Keyslots), info.ActiveKeyslots)
	}
	argon := info.Keyslots[0]
	if argon.KDF != "argon2id" || argon.Iterations != 6 || argon.MemoryKiB != 1048576 ||
		argon.Parallelism != 4 || argon.Stripes != 1000 || argon.Hash != "sha256" {
		t.Fatalf("argon2 keyslot = %+v", argon)
	}
	if !argon.SaltPresent || argon.SaltBytes != 20 {
		t.Fatalf("argon2 salt = present %v, %d bytes", argon.SaltPresent, argon.SaltBytes)
	}
	if argon.AreaOffset != 32768 || argon.AreaSize != 32000 || argon.KeySize != 32 {
		t.Fatalf("argon2 area = %+v", argon)
	}
	pbkdf2 := info.Keyslots[1]
	if pbkdf2.KDF != "pbkdf2" || pbkdf2.Iterations != 400000 ||
		pbkdf2.AreaOffset != 290816 || pbkdf2.AreaSize != 258048 {
		t.Fatalf("pbkdf2 keyslot = %+v", pbkdf2)
	}
	if len(info.Digests) != 1 || !info.Digests[0].DigestPresent ||
		info.Digests[0].DigestBytes != len("somedigest") ||
		!info.Digests[0].SaltPresent || info.Digests[0].SaltBytes != 20 {
		t.Fatalf("digest = %+v", info.Digests)
	}
	if len(info.Segments) != 1 {
		t.Fatalf("segments = %d", len(info.Segments))
	}
	segment := info.Segments[0]
	if segment.Offset != 16777216 || !segment.SizeDynamic || segment.IVTweak != 7 ||
		segment.SectorSize != 4096 || segment.Encryption != "aes-xts-plain64" {
		t.Fatalf("segment = %+v", segment)
	}
	if info.PayloadOffset != 16777216 || !info.PayloadOffsetSet {
		t.Fatalf("payload offset = %d", info.PayloadOffset)
	}
	if info.SectorSize != 4096 {
		t.Fatalf("sector size = %d", info.SectorSize)
	}
	if info.Tokens != 0 || len(info.Digests) != 1 || len(info.Segments) != 1 {
		t.Fatalf("counts = tokens %d digests %d segments %d",
			info.Tokens, len(info.Digests), len(info.Segments))
	}
	if len(info.Flags) != 1 || info.Flags[0] != "allow-discards" {
		t.Fatalf("flags = %v", info.Flags)
	}
	if info.VolumeBytes != uint64(len(buildLUKS2(luks2Metadata, 0, true))) {
		t.Fatalf("volume bytes = %d", info.VolumeBytes)
	}
}

func TestReadLUKS2ChecksumMismatch(t *testing.T) {
	image := buildLUKS2(luks2Metadata, 0, false)
	image[0x180] ^= 0xff // binary header bytes are covered by the checksum
	info, err := Read(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if info.Checksum != ChecksumMismatch {
		t.Fatalf("checksum = %v, want mismatch", info.Checksum)
	}
}

func TestReadLUKS2BadJSON(t *testing.T) {
	_, err := Read(source.NewMemorySource(1, buildLUKS2(`{"keyslots":`, 0, false)))
	if !errors.Is(err, errs.ErrMalformed) {
		t.Fatalf("Read error = %v, want ErrMalformed", err)
	}
}

func TestReadLUKS2MissingKeyslots(t *testing.T) {
	_, err := Read(source.NewMemorySource(1, buildLUKS2(`{"segments":{}}`, 0, false)))
	if !errors.Is(err, errs.ErrMalformed) {
		t.Fatalf("Read error = %v, want ErrMalformed", err)
	}
}

func TestReadLUKS2TruncatedBinaryHeader(t *testing.T) {
	b := make([]byte, 100)
	copy(b, Magic)
	putBE16(b, 6, 2)
	_, err := Read(source.NewMemorySource(1, b))
	if !errors.Is(err, errs.ErrTruncated) {
		t.Fatalf("Read error = %v, want ErrTruncated", err)
	}
}

func TestReadLUKS2HeaderSizeTooSmall(t *testing.T) {
	b := buildLUKS2(luks2Metadata, 0, false)
	putBE64(b, 8, 1024)
	_, err := Read(source.NewMemorySource(1, b))
	if !errors.Is(err, errs.ErrMalformed) {
		t.Fatalf("Read error = %v, want ErrMalformed", err)
	}
}

func TestReadLUKS2HeaderDeclaredPastSource(t *testing.T) {
	b := buildLUKS2(luks2Metadata, 0, false)
	putBE64(b, 8, 65536)
	_, err := Read(source.NewMemorySource(1, b))
	if !errors.Is(err, errs.ErrTruncated) {
		t.Fatalf("Read error = %v, want ErrTruncated", err)
	}
}

func TestReadUnknownKDFIsKeptByName(t *testing.T) {
	metadata := luks2Metadata
	metadata = replaceOnce(metadata, "argon2id", "scrypt")
	info, err := Read(source.NewMemorySource(1, buildLUKS2(metadata, 0, false)))
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if info.Keyslots[0].KDF != "scrypt" {
		t.Fatalf("kdf = %q", info.Keyslots[0].KDF)
	}
}

func TestReadBadBase64SaltIsRefused(t *testing.T) {
	metadata := replaceOnce(luks2Metadata, "c29tZXNhbHRhbmQtc29tZXNhbHQ=", "not base64!")
	_, err := Read(source.NewMemorySource(1, buildLUKS2(metadata, 0, false)))
	if !errors.Is(err, errs.ErrBadBase64) {
		t.Fatalf("Read error = %v, want ErrBadBase64", err)
	}
}

func replaceOnce(text, old, new string) string {
	for i := 0; i+len(old) <= len(text); i++ {
		if text[i:i+len(old)] == old {
			return text[:i] + new + text[i+len(old):]
		}
	}
	return text
}
