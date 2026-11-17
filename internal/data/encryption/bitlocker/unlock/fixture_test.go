package unlock

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"math/bits"
	"sync"

	"github.com/laenix/ewfgo/internal/data/encryption/bitlocker"
)

// The fixtures below are built entirely in Go. Every key, salt and nonce is a
// constant, and AES-CCM is deterministic given them, so an image compares
// byte-for-byte between runs. The payload is a tiny NTFS-like volume whose
// boot sector makes the data-area search succeed.

const (
	fixtureRecoveryPassword = "135795-258016-380237-502458-624679-720885-100001-550000"
	fixtureWrongPassword    = "135795-258016-380237-502458-624679-720885-100001-550011"
	fixtureUserPassword     = "bitlocker-fixture-user-password"
	fixtureWrongUser        = "bitlocker-fixture-user-password!"
	fixtureMetadataOffset   = 0x2000
	fixtureDataOffset       = 0x8000
	fixtureSectors          = 32
	fixtureVolumeBytes      = fixtureSectors * 512
)

var (
	fixtureSalt         = [16]byte{'B', 'L', 'F', 'I', 'X', 'T', 'U', 'R', 'E', '-', 'S', 'A', 'L', 'T', '0', '1'}
	fixturePasswordSalt = [16]byte{'B', 'L', 'F', 'I', 'X', 'T', 'U', 'R', 'E', '-', 'P', 'W', '-', '0', '0', '2'}
	fixtureVMK          = []byte("0123456789ABCDEF0123456789ABCDEF")
	fixtureFVEK         = []byte("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
	fixtureFVEK128      = []byte("0123456789ABCDEF0123456789ABCDEF")
	fixtureCBCKey128    = []byte("BLFIXTURE-CBC128")
	fixtureCBCKey256    = []byte("BLFIXTURE-CBC-AES-256-KEY-000001")
	fixtureElephant128  = []byte("BLELEPHANT-128KY")
	fixtureElephant256  = []byte("BLELEPHANT-AES-256-TWEAK-KEY-001")
	fixtureStartupKey   = []byte{
		0x9e, 0x1d, 0x7c, 0x55, 0x2b, 0x8a, 0x03, 0xf4, 0x61, 0xc9, 0x0d, 0x77, 0xba, 0x28, 0x5e, 0x90,
		0x13, 0xef, 0x44, 0x6c, 0xd8, 0x31, 0xa2, 0x0b, 0x75, 0x8d, 0x19, 0xc0, 0x56, 0xb3, 0xe1, 0x2f,
	}
	fixtureWrongStartupKey = append([]byte(nil), fixtureStartupKey...)
)

func init() {
	fixtureWrongStartupKey[31] ^= 0x01
}

var (
	recoveryOnce      sync.Once
	recoveryStretched [StretchedBytes]byte
	passwordOnce      sync.Once
	passwordStretched [StretchedBytes]byte
)

func recoveryStretch() [StretchedBytes]byte {
	recoveryOnce.Do(func() {
		key, err := RecoveryKey(fixtureRecoveryPassword)
		if err != nil {
			panic(err)
		}
		recoveryStretched = StretchKey(key, fixtureSalt, StretchIterations)
	})
	return recoveryStretched
}

func passwordStretch() [StretchedBytes]byte {
	passwordOnce.Do(func() {
		stretched, err := StretchPassword([]byte(fixtureUserPassword), fixturePasswordSalt)
		if err != nil {
			panic(err)
		}
		passwordStretched = stretched
	})
	return passwordStretched
}

// ---------------------------------------------------------------------------
// Entry construction
// ---------------------------------------------------------------------------

func putLE16(b []byte, at int, value uint16) { binary.LittleEndian.PutUint16(b[at:], value) }
func putLE32(b []byte, at int, value uint32) { binary.LittleEndian.PutUint32(b[at:], value) }
func putLE64(b []byte, at int, value uint64) { binary.LittleEndian.PutUint64(b[at:], value) }

func fixtureEntry(kind, valueType, version uint16, payload []byte) []byte {
	out := make([]byte, entryHeaderBytes+len(payload))
	putLE16(out, 0, uint16(len(out)))
	putLE16(out, 2, kind)
	putLE16(out, 4, valueType)
	putLE16(out, 6, version)
	copy(out[entryHeaderBytes:], payload)
	return out
}

func nilEntry() []byte { return fixtureEntry(0, 0, 0, nil) }

func fixtureUTF16(text string) []byte {
	out := make([]byte, 0, len(text)*2+2)
	for _, r := range text {
		unit := uint16(r)
		out = append(out, byte(unit), byte(unit>>8))
	}
	return append(out, 0, 0)
}

func fixtureKeyContainer(method uint16, key []byte) []byte {
	out := make([]byte, 12+len(key))
	putLE32(out, 0, uint32(len(out)))
	putLE16(out, 4, 1)
	putLE16(out, 8, method)
	copy(out[12:], key)
	return out
}

// fixtureCCMValue is nonce || tag || ciphertext, the on-disk BitLocker layout.
func fixtureCCMValue(key []byte, nonce [12]byte, plaintext []byte) []byte {
	ciphertext, tag, err := ccmSeal(key, nonce[:], nil, plaintext, 16)
	if err != nil {
		panic(err)
	}
	out := make([]byte, 0, 12+16+len(ciphertext))
	out = append(out, nonce[:]...)
	out = append(out, tag...)
	out = append(out, ciphertext...)
	return out
}

func fixtureCCMEntry(key []byte, nonce [12]byte, plaintext []byte) []byte {
	return fixtureEntry(0, bitlocker.ValueAESCCMKey, 1, fixtureCCMValue(key, nonce, plaintext))
}

func fixtureStretchValue(method uint16, salt [16]byte, nested []byte) []byte {
	out := make([]byte, 4+16, 4+16+len(nested))
	putLE32(out, 0, uint32(method))
	copy(out[4:], salt[:])
	return append(out, nested...)
}

func fixtureVMKPayload(id [16]byte, protection uint16, properties []byte) []byte {
	out := make([]byte, 28+len(properties))
	copy(out, id[:])
	putLE64(out, 16, 0x01d9a12345678900)
	putLE16(out, 26, protection)
	copy(out[28:], properties)
	return out
}

func fixtureVMKEntry(id [16]byte, protection uint16, properties []byte) []byte {
	return fixtureEntry(bitlocker.EntryVolumeMasterKey, bitlocker.ValueVolumeMasterKey, 1,
		fixtureVMKPayload(id, protection, properties))
}

func fixtureFVEKEntry(wrapKey []byte, nonce [12]byte, method uint16, fvek []byte) []byte {
	return fixtureEntry(bitlocker.EntryFullVolumeEncryptionKey, bitlocker.ValueAESCCMKey, 1,
		fixtureCCMValue(wrapKey, nonce, fixtureKeyContainer(method, fvek)))
}

func recoveryFixtureEntries(headerMethod, fvekMethod uint16, fvek []byte) []byte {
	stretched := recoveryStretch()
	var props []byte
	props = append(props, fixtureEntry(0, bitlocker.ValueUnicodeString, 1, fixtureUTF16("DiskPassword"))...)
	props = append(props, fixtureEntry(0, bitlocker.ValueStretchKey, 1,
		fixtureStretchValue(headerMethod, fixtureSalt,
			fixtureCCMEntry(stretched[:], [12]byte{0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24},
				fixtureKeyContainer(0x2000, fixtureVMK))))...)
	var out []byte
	out = append(out, fixtureVMKEntry([16]byte{0x8f, 0x1c, 0x2d, 0x3e, 0x4a, 0x5b, 0x6c, 0x7d,
		0x8e, 0x9f, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab},
		bitlocker.ProtectRecoveryPassword, props)...)
	out = append(out, fixtureFVEKEntry(fixtureVMK,
		[12]byte{0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42},
		fvekMethod, fvek)...)
	out = append(out, nilEntry()...)
	return out
}

func passwordFixtureEntries() []byte {
	stretched := passwordStretch()
	var props []byte
	props = append(props, fixtureEntry(0, bitlocker.ValueUnicodeString, 1, fixtureUTF16("UserPassword"))...)
	props = append(props, fixtureEntry(0, bitlocker.ValueStretchKey, 1,
		fixtureStretchValue(bitlocker.MethodAES256XTS, fixturePasswordSalt,
			fixtureCCMEntry(stretched[:], [12]byte{0x26, 0x26, 0x26, 0x26, 0x26, 0x26, 0x26, 0x26, 0x26, 0x26, 0x26, 0x26},
				fixtureKeyContainer(0x2000, fixtureVMK))))...)
	var out []byte
	out = append(out, fixtureVMKEntry([16]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99},
		bitlocker.ProtectPassword, props)...)
	out = append(out, fixtureFVEKEntry(fixtureVMK,
		[12]byte{0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42},
		bitlocker.MethodAES256XTS, fixtureFVEK)...)
	out = append(out, nilEntry()...)
	return out
}

func startupFixtureEntries() []byte {
	var props []byte
	external := make([]byte, 4+len(fixtureStartupKey))
	putLE32(external, 0, uint32(bitlocker.MethodAES256XTS))
	copy(external[4:], fixtureStartupKey)
	props = append(props, fixtureEntry(0, bitlocker.ValueKey, 1, external)...)
	props = append(props, fixtureCCMEntry(fixtureStartupKey,
		[12]byte{0x27, 0x27, 0x27, 0x27, 0x27, 0x27, 0x27, 0x27, 0x27, 0x27, 0x27, 0x27},
		fixtureKeyContainer(0x2000, fixtureVMK))...)
	var out []byte
	out = append(out, fixtureVMKEntry([16]byte{0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
		bitlocker.ProtectStartupKey, props)...)
	out = append(out, fixtureFVEKEntry(fixtureVMK,
		[12]byte{0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42},
		bitlocker.MethodAES256XTS, fixtureFVEK)...)
	out = append(out, nilEntry()...)
	return out
}

// ---------------------------------------------------------------------------
// Image construction
// ---------------------------------------------------------------------------

type imageOptions struct {
	method              uint16
	headerMethod        uint16
	fvekMethod          uint16
	fvek                []byte
	entries             []byte
	state               uint16
	declaredSize        uint32
	payload             []byte
	dataOffset          uint64
	bootCopyAt          uint64
	bootCopyBytes       uint64
	bootCopyPayload     []byte
	volumeHeaderOffset  uint64
	volumeHeaderSectors uint32
}

func fixturePayload() []byte {
	payload := make([]byte, fixtureVolumeBytes)
	copy(payload[3:], "NTFS    ")
	putLE16(payload, 0x0b, 512)
	putLE32(payload, 0x20, fixtureSectors)
	putLE64(payload, 0x28, fixtureSectors)
	payload[510], payload[511] = 0x55, 0xaa
	for i := 512; i < len(payload); i++ {
		payload[i] = byte(i*7 + 3)
	}
	return payload
}

func buildImage(opts imageOptions) []byte {
	if opts.method == 0 {
		opts.method = bitlocker.MethodAES256XTS
	}
	if opts.headerMethod == 0 {
		opts.headerMethod = opts.method
	}
	if opts.fvekMethod == 0 {
		opts.fvekMethod = opts.method
	}
	if opts.state == 0 {
		opts.state = VolumeFullyEncrypted
	}
	if opts.payload == nil {
		opts.payload = fixturePayload()
	}
	if opts.dataOffset == 0 {
		opts.dataOffset = fixtureDataOffset
	}
	imageLen := int(opts.dataOffset) + len(opts.payload)
	image := make([]byte, imageLen)
	writeFixtureVolumeHeader(image[:512], uint64(imageLen), opts.dataOffset)
	writeFixtureMetadata(image, opts)

	for at := 0; at+512 <= len(opts.payload); at += 512 {
		physical := opts.dataOffset + uint64(at)
		encrypted := encryptFixtureSector(opts.method, opts.fvek, physical, opts.payload[at:at+512])
		copy(image[physical:physical+512], encrypted)
	}
	if opts.bootCopyAt != 0 {
		copyPlain := opts.bootCopyPayload
		if copyPlain == nil {
			copyPlain = opts.payload
		}
		for at := 0; at < int(opts.bootCopyBytes) && at+512 <= len(copyPlain); at += 512 {
			physical := opts.bootCopyAt + uint64(at)
			encrypted := encryptFixtureSector(opts.method, opts.fvek, physical, copyPlain[at:at+512])
			copy(image[physical:physical+512], encrypted)
		}
	}
	return image
}

var (
	passwordImageOnce sync.Once
	passwordImage     []byte
	startupImageOnce  sync.Once
	startupImage      []byte
)

func passwordFixtureImage() []byte {
	passwordImageOnce.Do(func() {
		passwordImage = buildImage(imageOptions{
			method:  bitlocker.MethodAES256XTS,
			fvek:    fixtureFVEK,
			entries: passwordFixtureEntries(),
		})
	})
	return passwordImage
}

func startupFixtureImage() []byte {
	startupImageOnce.Do(func() {
		startupImage = buildImage(imageOptions{
			method:  bitlocker.MethodAES256XTS,
			fvek:    fixtureFVEK,
			entries: startupFixtureEntries(),
		})
	})
	return startupImage
}

func writeFixtureVolumeHeader(header []byte, totalBytes, dataOffset uint64) {
	copy(header[3:], "-FVE-FS-")
	putLE16(header, 0x0b, 512)
	header[0x0d] = 8
	totalSectors := totalBytes / 512
	putLE16(header, 0x13, uint16(totalSectors))
	putLE32(header, 0x20, uint32(totalSectors))
	putLE64(header, 0x28, totalSectors)
	putLE32(header, 0x43, 0x11223344)
	copy(header[0x47:], "EVIDENCE   ")
	copy(header[0x52:], "NTFS    ")
	putLE64(header, 0x99, fixtureMetadataOffset)
	_ = dataOffset
	header[0x1fe], header[0x1ff] = 0x55, 0xaa
}

func writeFixtureMetadata(image []byte, opts imageOptions) {
	block := fixtureMetadataOffset
	copy(image[block:], "-FVE-FS-")
	putLE16(image, block+8, uint16(uint64(len(opts.entries))+bitlocker.MetadataHeaderBytes))
	putLE16(image, block+10, 2)
	putLE16(image, block+12, opts.state)
	putLE16(image, block+14, opts.state)
	putLE64(image, block+32, uint64(block))
	putLE64(image, block+40, uint64(block))
	putLE64(image, block+48, uint64(block))
	putLE32(image, block+28, opts.volumeHeaderSectors)
	putLE64(image, block+56, opts.volumeHeaderOffset)

	header := block + bitlocker.BlockHeaderBytes
	size := opts.declaredSize
	if size == 0 {
		size = uint32(bitlocker.MetadataHeaderBytes) + uint32(len(opts.entries))
	}
	putLE32(image, header+0, size)
	putLE32(image, header+4, 1)
	putLE32(image, header+8, bitlocker.MetadataHeaderBytes)
	putLE32(image, header+12, size)
	for i := 0; i < 16; i++ {
		image[header+16+i] = byte(i + 1)
	}
	putLE32(image, header+32, 9)
	putLE16(image, header+36, opts.headerMethod)
	putLE16(image, header+38, opts.headerMethod)
	putLE64(image, header+40, 0x01d9a12345678900)
	copy(image[header+bitlocker.MetadataHeaderBytes:], opts.entries)
}

// ---------------------------------------------------------------------------
// Fixture sector encryption, written independently of the reader's cipher
// ---------------------------------------------------------------------------

func encryptFixtureSector(method uint16, fvek []byte, physical uint64, plain []byte) []byte {
	switch method {
	case bitlocker.MethodAES128CBC, bitlocker.MethodAES256CBC,
		bitlocker.MethodAES128CBCElephant, bitlocker.MethodAES256CBCElephant:
		return fixtureCBCEncrypt(method, fvek, physical, plain)
	default:
		return fixtureXTSEncrypt(fvek, physical, plain)
	}
}

func fixtureXTSEncrypt(key []byte, physical uint64, plain []byte) []byte {
	half := len(key) / 2
	data, err := aes.NewCipher(key[:half])
	if err != nil {
		panic(err)
	}
	tweak, err := aes.NewCipher(key[half:])
	if err != nil {
		panic(err)
	}
	var mask [16]byte
	binary.LittleEndian.PutUint64(mask[:8], physical/512)
	tweak.Encrypt(mask[:], mask[:])
	out := append([]byte(nil), plain...)
	var block [16]byte
	for at := 0; at < len(out); at += 16 {
		for i := 0; i < 16; i++ {
			block[i] = out[at+i] ^ mask[i]
		}
		data.Encrypt(block[:], block[:])
		for i := 0; i < 16; i++ {
			out[at+i] = block[i] ^ mask[i]
		}
		fixtureMultiplyAlpha(&mask)
	}
	return out
}

func fixtureMultiplyAlpha(tweak *[16]byte) {
	carry := tweak[15] >> 7
	for i := 15; i > 0; i-- {
		tweak[i] = tweak[i]<<1 | tweak[i-1]>>7
	}
	tweak[0] <<= 1
	if carry != 0 {
		tweak[0] ^= 0x87
	}
}

func fixtureCBCEncrypt(method uint16, fvek []byte, physical uint64, plain []byte) []byte {
	var key, tweakKey []byte
	switch method {
	case bitlocker.MethodAES128CBC:
		key = fvek[:16]
	case bitlocker.MethodAES256CBC:
		key = fvek[:32]
	case bitlocker.MethodAES128CBCElephant:
		key, tweakKey = fvek[:16], fvek[32:48]
	case bitlocker.MethodAES256CBCElephant:
		key, tweakKey = fvek[:32], fvek[32:64]
	default:
		panic("not a CBC method")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	var base [16]byte
	binary.LittleEndian.PutUint64(base[:8], physical)
	iv := base
	block.Encrypt(iv[:], iv[:])
	data := append([]byte(nil), plain...)
	if tweakKey != nil {
		tweak, err := aes.NewCipher(tweakKey)
		if err != nil {
			panic(err)
		}
		first := base
		tweak.Encrypt(first[:], first[:])
		second := base
		second[15] = 0x80
		tweak.Encrypt(second[:], second[:])
		var sectorKey [32]byte
		copy(sectorKey[:16], first[:])
		copy(sectorKey[16:], second[:])
		for i := range data {
			data[i] ^= sectorKey[i%32]
		}
		fixtureDiffuserAEncrypt(data)
		fixtureDiffuserBEncrypt(data)
	}
	cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(data, data)
	return data
}

func fixtureDiffuserAEncrypt(sector []byte) {
	words := len(sector) / 4
	for cycle := 0; cycle < 5; cycle++ {
		for i := words - 1; i >= 0; i-- {
			left := binary.LittleEndian.Uint32(sector[((i+words-2)%words)*4:])
			rotated := rotl32(binary.LittleEndian.Uint32(sector[((i+words-5)%words)*4:]), [4]uint32{9, 0, 13, 0}[i%4])
			value := binary.LittleEndian.Uint32(sector[i*4:]) - (left ^ rotated)
			binary.LittleEndian.PutUint32(sector[i*4:], value)
		}
	}
}

func fixtureDiffuserBEncrypt(sector []byte) {
	words := len(sector) / 4
	for cycle := 0; cycle < 3; cycle++ {
		for i := words - 1; i >= 0; i-- {
			left := binary.LittleEndian.Uint32(sector[((i+2)%words)*4:])
			rotated := rotl32(binary.LittleEndian.Uint32(sector[((i+5)%words)*4:]), [4]uint32{0, 10, 0, 25}[i%4])
			value := binary.LittleEndian.Uint32(sector[i*4:]) - (left ^ rotated)
			binary.LittleEndian.PutUint32(sector[i*4:], value)
		}
	}
}

func rotl32(value uint32, by uint32) uint32 {
	return bits.RotateLeft32(value, int(by))
}
