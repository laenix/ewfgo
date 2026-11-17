package unlock

import (
	"bytes"
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/encryption/bitlocker"
	"github.com/laenix/ewfgo/internal/data/encryption/errs"
	"github.com/laenix/ewfgo/internal/data/source"
)

func fixtureInfo(t *testing.T, image []byte) (source.ByteSource, *bitlocker.Info) {
	t.Helper()
	src := source.NewMemorySourceWithImage(1, 7, image)
	info, err := bitlocker.Read(src)
	if err != nil {
		t.Fatalf("bitlocker.Read: %v", err)
	}
	if info == nil {
		t.Fatal("fixture is not recognised as a BitLocker volume")
	}
	if info.Metadata == nil {
		t.Fatalf("fixture metadata did not parse: %s", info.MetadataError)
	}
	return src, info
}

func recoveryImage(method uint16, fvek []byte) []byte {
	return buildImage(imageOptions{
		method:  method,
		fvek:    fvek,
		entries: recoveryFixtureEntries(method, method, fvek),
	})
}

func readAll(t *testing.T, opened *Source) []byte {
	t.Helper()
	out := make([]byte, opened.Len())
	n, err := opened.ReadAt(0, out)
	if err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if n != len(out) {
		t.Fatalf("ReadAt returned %d bytes, want %d", n, len(out))
	}
	return out
}

func TestUnlockWithRecoveryPassword(t *testing.T) {
	image := recoveryImage(bitlocker.MethodAES256XTS, fixtureFVEK)
	src, info := fixtureInfo(t, image)

	unlocked, err := Unlock(src, info, []byte(fixtureRecoveryPassword))
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if unlocked.Method() != bitlocker.MethodAES256XTS {
		t.Fatalf("method = 0x%04x", unlocked.Method())
	}
	if got, want := unlocked.MethodLabel(), "AES-256-XTS"; got != want {
		t.Fatalf("method label = %q, want %q", got, want)
	}
	if got, want := unlocked.CipherMode(), "aes-256-xts"; got != want {
		t.Fatalf("cipher mode = %q, want %q", got, want)
	}
	if unlocked.KeyBytes() != len(fixtureFVEK) {
		t.Fatalf("key bytes = %d, want %d", unlocked.KeyBytes(), len(fixtureFVEK))
	}
	if unlocked.CipherKeyBits() != 256 {
		t.Fatalf("key bits = %d, want 256", unlocked.CipherKeyBits())
	}
	if unlocked.Protectors() != 1 {
		t.Fatalf("protectors = %d, want 1", unlocked.Protectors())
	}
	if unlocked.ProtectorKind() != RecoveryPassword {
		t.Fatalf("protector kind = %v", unlocked.ProtectorKind())
	}
	if unlocked.DataOffset() != fixtureDataOffset {
		t.Fatalf("data offset = %d, want %d", unlocked.DataOffset(), fixtureDataOffset)
	}
	if !bytes.Equal(unlocked.VolumeMasterKey(), fixtureVMK) {
		t.Fatalf("VMK = %x, want %x", unlocked.VolumeMasterKey(), fixtureVMK)
	}
	if label := unlocked.Label(); label != "BitLocker AES-256-XTS (recovery password)" {
		t.Fatalf("label = %q", label)
	}

	opened, err := unlocked.Open(2, src)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if opened.SourceID() != 2 {
		t.Fatalf("source id = %d", opened.SourceID())
	}
	if opened.ImageID() != 7 {
		t.Fatalf("image id = %d, want 7", opened.ImageID())
	}
	if opened.SectorSize() != 512 {
		t.Fatalf("sector size = %d", opened.SectorSize())
	}
	if opened.Len() != fixtureVolumeBytes {
		t.Fatalf("len = %d, want %d", opened.Len(), fixtureVolumeBytes)
	}
	if opened.IsEmpty() {
		t.Fatal("decrypted source must not be empty")
	}
	if opened.Stats().Reads != 0 {
		t.Fatalf("fresh source already counted %d reads", opened.Stats().Reads)
	}
	if !bytes.Equal(readAll(t, opened), fixturePayload()) {
		t.Fatal("decrypted payload differs from the plaintext volume")
	}
	if opened.Stats().BytesRead < fixtureVolumeBytes {
		t.Fatalf("stats bytes = %d, want at least %d", opened.Stats().BytesRead, fixtureVolumeBytes)
	}

	// A partial, unaligned read decrypts the covering sector(s) and copies the
	// requested window.
	window := make([]byte, 100)
	n, err := opened.ReadAt(12345, window)
	if err != nil || n != 100 {
		t.Fatalf("unaligned ReadAt = %d, %v", n, err)
	}
	if !bytes.Equal(window, fixturePayload()[12345:12345+100]) {
		t.Fatal("unaligned read returned the wrong bytes")
	}
	lossy := make([]byte, 100)
	if n, err := opened.ReadAtLossy(12345, lossy); err != nil || n != 100 {
		t.Fatalf("ReadAtLossy = %d, %v", n, err)
	}
	if !bytes.Equal(lossy, window) {
		t.Fatal("lossy read differs from the strict read on a clean source")
	}

	// A read starting at the end is out of range; one crossing the end is a
	// short read without an error.
	if _, err := opened.ReadAt(opened.Len(), make([]byte, 16)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("read past end error = %v, want ErrOutOfRange", err)
	}
	tail := make([]byte, 200)
	if n, err := opened.ReadAt(opened.Len()-100, tail); err != nil || n != 100 {
		t.Fatalf("tail read = %d, %v", n, err)
	}

	// Provenance: extents point at the encrypted volume, and map_to_image
	// reaches the original image.
	extents, err := opened.Extents(0, 512)
	if err != nil {
		t.Fatalf("Extents: %v", err)
	}
	if len(extents) != 1 || extents[0].Parent != src.SourceID() ||
		extents[0].ParentOffset != fixtureDataOffset || extents[0].Len != 512 ||
		extents[0].Kind != source.RangeData {
		t.Fatalf("extents = %+v", extents)
	}
	images, err := opened.MapToImage(0, 512)
	if err != nil {
		t.Fatalf("MapToImage: %v", err)
	}
	if len(images) != 1 || images[0].ImageID != 7 ||
		images[0].ImageOffset != fixtureDataOffset || images[0].Len != 512 ||
		images[0].Kind != source.RangeData {
		t.Fatalf("image ranges = %+v", images)
	}
	if _, err := opened.Extents(0, opened.Len()+1); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("Extents past end error = %v", err)
	}
	if _, err := opened.MapToImage(opened.Len(), 1); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("MapToImage past end error = %v", err)
	}
}

func TestWrongRecoveryPasswordIsRefused(t *testing.T) {
	image := recoveryImage(bitlocker.MethodAES256XTS, fixtureFVEK)
	src, info := fixtureInfo(t, image)
	unlocked, err := Unlock(src, info, []byte(fixtureWrongPassword))
	if err == nil || unlocked != nil {
		t.Fatal("a wrong recovery password must not open the volume")
	}
	if !errors.Is(err, ErrWrongPassphrase) || !errors.Is(err, ErrWrongRecoveryPassword) {
		t.Fatalf("wrong password error = %v", err)
	}
}

func TestUnlockWithUserPassword(t *testing.T) {
	image := passwordFixtureImage()
	src, info := fixtureInfo(t, image)

	unlocked, err := UnlockWithPassword(src, info, []byte(fixtureUserPassword))
	if err != nil {
		t.Fatalf("UnlockWithPassword: %v", err)
	}
	if unlocked.ProtectorKind() != Password {
		t.Fatalf("protector kind = %v", unlocked.ProtectorKind())
	}
	if !bytes.Equal(unlocked.VolumeMasterKey(), fixtureVMK) {
		t.Fatal("VMK differs")
	}
	if unlocked.DataOffset() != fixtureDataOffset {
		t.Fatalf("data offset = %d", unlocked.DataOffset())
	}
	opened, err := unlocked.Open(2, src)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(readAll(t, opened), fixturePayload()) {
		t.Fatal("password-unlocked payload differs")
	}

	wrong, err := UnlockWithPassword(src, info, []byte(fixtureWrongUser))
	if err == nil || wrong != nil {
		t.Fatal("a wrong user password must not open the volume")
	}
	if !errors.Is(err, ErrWrongPassphrase) || !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password error = %v", err)
	}

	// A non-text password is refused before the volume is consulted.
	if _, err := UnlockWithPassword(nil, nil, []byte{0xff, 0xfe}); !errors.Is(err, ErrPasswordText) {
		t.Fatalf("non-UTF-8 password error = %v", err)
	}
}

func TestTamperedUserPasswordTagKeepsTheVolumeClosed(t *testing.T) {
	image := append([]byte(nil), passwordFixtureImage()...)
	nonce := []byte{0x26, 0x26, 0x26, 0x26, 0x26, 0x26, 0x26, 0x26, 0x26, 0x26, 0x26, 0x26}
	hits := 0
	for at := 0; at+28 <= len(image); at++ {
		if bytes.Equal(image[at:at+12], nonce) {
			image[at+12] ^= 0x80
			hits++
		}
	}
	if hits != 1 {
		t.Fatalf("found %d password nonces, want 1", hits)
	}
	src, info := fixtureInfo(t, image)
	unlocked, err := UnlockWithPassword(src, info, []byte(fixtureUserPassword))
	if err == nil || unlocked != nil {
		t.Fatal("a tampered tag must not open the volume")
	}
	if !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("tampered tag error = %v, want ErrWrongPassword", err)
	}
}

func TestUnlockWithStartupKey(t *testing.T) {
	image := startupFixtureImage()
	src, info := fixtureInfo(t, image)

	unlocked, err := UnlockWithStartupKey(src, info, fixtureStartupKey)
	if err != nil {
		t.Fatalf("UnlockWithStartupKey: %v", err)
	}
	if unlocked.ProtectorKind() != StartupKey {
		t.Fatalf("protector kind = %v", unlocked.ProtectorKind())
	}
	if !bytes.Equal(unlocked.VolumeMasterKey(), fixtureVMK) {
		t.Fatal("VMK differs")
	}
	opened, err := unlocked.Open(2, src)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(readAll(t, opened), fixturePayload()) {
		t.Fatal("startup-key payload differs")
	}

	wrong, err := UnlockWithStartupKey(src, info, fixtureWrongStartupKey)
	if err == nil || wrong != nil {
		t.Fatal("a wrong startup key must not open the volume")
	}
	if !errors.Is(err, ErrWrongPassphrase) || !errors.Is(err, ErrWrongStartupKey) {
		t.Fatalf("wrong startup key error = %v", err)
	}

	// The length check runs before the volume is consulted.
	if _, err := UnlockWithStartupKey(nil, nil, make([]byte, 16)); !errors.Is(err, ErrStartupKeySize) {
		t.Fatalf("short startup key error = %v, want ErrStartupKeySize", err)
	}
}

func elephantFVEK(key, tweak []byte) []byte {
	out := make([]byte, 64)
	copy(out, key)
	copy(out[32:], tweak)
	return out
}

func TestCBCCipherPayloadModes(t *testing.T) {
	cases := []struct {
		name    string
		method  uint16
		fvek    []byte
		keySize int
		bits    uint32
		mode    string
	}{
		{"aes-128-cbc", bitlocker.MethodAES128CBC, fixtureCBCKey128, 16, 128, "aes-128-cbc"},
		{"aes-256-cbc", bitlocker.MethodAES256CBC, fixtureCBCKey256, 32, 256, "aes-256-cbc"},
		{"aes-128-cbc-elephant", bitlocker.MethodAES128CBCElephant,
			elephantFVEK(fixtureCBCKey128, fixtureElephant128), 64, 128, "aes-128-cbc-elephant"},
		{"aes-256-cbc-elephant", bitlocker.MethodAES256CBCElephant,
			elephantFVEK(fixtureCBCKey256, fixtureElephant256), 64, 256, "aes-256-cbc-elephant"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			image := recoveryImage(tc.method, tc.fvek)
			src, info := fixtureInfo(t, image)
			unlocked, err := Unlock(src, info, []byte(fixtureRecoveryPassword))
			if err != nil {
				t.Fatalf("Unlock: %v", err)
			}
			if unlocked.Method() != tc.method {
				t.Fatalf("method = 0x%04x", unlocked.Method())
			}
			if got := unlocked.CipherMode(); got != tc.mode {
				t.Fatalf("cipher mode = %q, want %q", got, tc.mode)
			}
			if unlocked.KeyBytes() != tc.keySize {
				t.Fatalf("key bytes = %d, want %d", unlocked.KeyBytes(), tc.keySize)
			}
			if unlocked.CipherKeyBits() != tc.bits {
				t.Fatalf("key bits = %d, want %d", unlocked.CipherKeyBits(), tc.bits)
			}
			opened, err := unlocked.Open(2, src)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(readAll(t, opened), fixturePayload()) {
				t.Fatalf("%s payload differs", tc.name)
			}
			if _, err := Unlock(src, info, []byte(fixtureWrongPassword)); !errors.Is(err, ErrWrongRecoveryPassword) {
				t.Fatalf("%s wrong password error = %v", tc.name, err)
			}
		})
	}
}

func TestUnsupportedCipherAndMethodMismatch(t *testing.T) {
	t.Run("header-method", func(t *testing.T) {
		image := buildImage(imageOptions{
			method:  0x8006,
			fvek:    fixtureFVEK,
			entries: recoveryFixtureEntries(0x8006, 0x8006, fixtureFVEK),
		})
		src, info := fixtureInfo(t, image)
		if _, err := Unlock(src, info, []byte(fixtureRecoveryPassword)); !errors.Is(err, ErrUnsupportedMethod) {
			t.Fatalf("error = %v, want ErrUnsupportedMethod", err)
		}
	})
	t.Run("fvek-method", func(t *testing.T) {
		image := buildImage(imageOptions{
			method:  bitlocker.MethodAES256XTS,
			fvek:    fixtureFVEK,
			entries: recoveryFixtureEntries(bitlocker.MethodAES256XTS, 0x8006, fixtureFVEK),
		})
		src, info := fixtureInfo(t, image)
		if _, err := Unlock(src, info, []byte(fixtureRecoveryPassword)); !errors.Is(err, ErrUnsupportedMethod) {
			t.Fatalf("error = %v, want ErrUnsupportedMethod", err)
		}
	})
	t.Run("mismatch", func(t *testing.T) {
		image := buildImage(imageOptions{
			method:  bitlocker.MethodAES256XTS,
			fvek:    fixtureFVEK,
			entries: recoveryFixtureEntries(bitlocker.MethodAES256XTS, bitlocker.MethodAES128XTS, fixtureFVEK128),
		})
		src, info := fixtureInfo(t, image)
		if _, err := Unlock(src, info, []byte(fixtureRecoveryPassword)); !errors.Is(err, ErrMethodMismatch) {
			t.Fatalf("error = %v, want ErrMethodMismatch", err)
		}
	})
	t.Run("key-size", func(t *testing.T) {
		image := buildImage(imageOptions{
			method:  bitlocker.MethodAES256XTS,
			fvek:    fixtureFVEK,
			entries: recoveryFixtureEntries(bitlocker.MethodAES256XTS, bitlocker.MethodAES256XTS, fixtureFVEK128),
		})
		src, info := fixtureInfo(t, image)
		if _, err := Unlock(src, info, []byte(fixtureRecoveryPassword)); !errors.Is(err, ErrKeySize) {
			t.Fatalf("error = %v, want ErrKeySize", err)
		}
	})
}

func TestUnfinishedConversionIsRefused(t *testing.T) {
	image := buildImage(imageOptions{
		method:  bitlocker.MethodAES256XTS,
		fvek:    fixtureFVEK,
		state:   5,
		entries: recoveryFixtureEntries(bitlocker.MethodAES256XTS, bitlocker.MethodAES256XTS, fixtureFVEK),
	})
	src, info := fixtureInfo(t, image)
	if _, err := Unlock(src, info, []byte(fixtureRecoveryPassword)); !errors.Is(err, ErrUnfinishedConversion) {
		t.Fatalf("error = %v, want ErrUnfinishedConversion", err)
	}
}

func TestProtectorFailuresAreExplicit(t *testing.T) {
	t.Run("no-startup-protector", func(t *testing.T) {
		image := recoveryImage(bitlocker.MethodAES256XTS, fixtureFVEK)
		src, info := fixtureInfo(t, image)
		if _, err := UnlockWithStartupKey(src, info, fixtureStartupKey); !errors.Is(err, ErrNoStartupKeyProtector) {
			t.Fatalf("error = %v, want ErrNoStartupKeyProtector", err)
		}
	})
	t.Run("no-stretch-key", func(t *testing.T) {
		// A recovery protector that carries a wrapped key but no stretch key.
		stretched := recoveryStretch()
		props := fixtureCCMEntry(stretched[:],
			[12]byte{0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24},
			fixtureKeyContainer(0x2000, fixtureVMK))
		entries := fixtureVMKEntry([16]byte{1}, bitlocker.ProtectRecoveryPassword, props)
		entries = append(entries, fixtureFVEKEntry(fixtureVMK,
			[12]byte{0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42},
			bitlocker.MethodAES256XTS, fixtureFVEK)...)
		entries = append(entries, nilEntry()...)
		image := buildImage(imageOptions{method: bitlocker.MethodAES256XTS, fvek: fixtureFVEK, entries: entries})
		src, info := fixtureInfo(t, image)
		if _, err := Unlock(src, info, []byte(fixtureRecoveryPassword)); !errors.Is(err, ErrNoStretchKey) {
			t.Fatalf("error = %v, want ErrNoStretchKey", err)
		}
	})
	t.Run("no-wrapped-key", func(t *testing.T) {
		props := fixtureEntry(0, bitlocker.ValueStretchKey, 1,
			fixtureStretchValue(bitlocker.MethodAES256XTS, fixtureSalt, nil))
		entries := fixtureVMKEntry([16]byte{1}, bitlocker.ProtectRecoveryPassword, props)
		entries = append(entries, nilEntry()...)
		image := buildImage(imageOptions{method: bitlocker.MethodAES256XTS, fvek: fixtureFVEK, entries: entries})
		src, info := fixtureInfo(t, image)
		if _, err := Unlock(src, info, []byte(fixtureRecoveryPassword)); !errors.Is(err, ErrNoWrappedKey) {
			t.Fatalf("error = %v, want ErrNoWrappedKey", err)
		}
	})
}

func TestFVEKTagMismatchKeepsTheVolumeClosed(t *testing.T) {
	image := append([]byte(nil), recoveryImage(bitlocker.MethodAES256XTS, fixtureFVEK)...)
	nonce := []byte{0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42}
	hits := 0
	for at := 0; at+28 <= len(image); at++ {
		if bytes.Equal(image[at:at+12], nonce) {
			image[at+12] ^= 0x40
			hits++
		}
	}
	if hits != 1 {
		t.Fatalf("found %d FVEK nonces, want 1", hits)
	}
	src, info := fixtureInfo(t, image)
	unlocked, err := Unlock(src, info, []byte(fixtureRecoveryPassword))
	if err == nil || unlocked != nil {
		t.Fatal("a tampered FVEK tag must not open the volume")
	}
	if !errors.Is(err, ErrKeyContainer) {
		t.Fatalf("error = %v, want ErrKeyContainer", err)
	}
}

func TestMalformedAndTruncatedMetadata(t *testing.T) {
	t.Run("declared-size-past-source", func(t *testing.T) {
		image := buildImage(imageOptions{
			method:       bitlocker.MethodAES256XTS,
			fvek:         fixtureFVEK,
			declaredSize: 200_000,
			entries:      recoveryFixtureEntries(bitlocker.MethodAES256XTS, bitlocker.MethodAES256XTS, fixtureFVEK),
		})
		src, info := fixtureInfo(t, image)
		_, err := Unlock(src, info, []byte(fixtureRecoveryPassword))
		if !errors.Is(err, ErrMalformedMetadata) {
			t.Fatalf("error = %v, want ErrMalformedMetadata", err)
		}
		if !errors.Is(err, errs.ErrTruncated) {
			t.Fatalf("error = %v, want it to wrap errs.ErrTruncated", err)
		}
	})
	t.Run("entry-area-does-not-tile", func(t *testing.T) {
		image := buildImage(imageOptions{
			method:  bitlocker.MethodAES256XTS,
			fvek:    fixtureFVEK,
			entries: []byte{1, 0, 2, 0, 8, 0, 1, 0},
		})
		src, info := fixtureInfo(t, image)
		if _, err := Unlock(src, info, []byte(fixtureRecoveryPassword)); !errors.Is(err, ErrMalformedMetadata) {
			t.Fatalf("error = %v, want ErrMalformedMetadata", err)
		}
	})
}

func TestNoMetadataIsExplicit(t *testing.T) {
	src := source.NewMemorySource(1, nil)
	if _, err := Unlock(src, nil, []byte(fixtureRecoveryPassword)); !errors.Is(err, ErrNoMetadata) {
		t.Fatalf("nil info error = %v, want ErrNoMetadata", err)
	}
	if _, err := UnlockWithPassword(src, nil, []byte(fixtureUserPassword)); !errors.Is(err, ErrNoMetadata) {
		t.Fatalf("nil info password error = %v, want ErrNoMetadata", err)
	}
}

func TestRelocatedVolumeHeaderFallback(t *testing.T) {
	// The payload does not begin with a boot record, so the in-place scan
	// cannot find the data area. A relocated boot copy does, and the data area
	// then starts after the last metadata block (0x2000 + 64 KiB = 0x12000).
	payload := make([]byte, fixtureVolumeBytes)
	for i := range payload {
		payload[i] = byte(i*3 + 1)
	}
	// The relocated boot record declares a volume far larger than the image,
	// so no in-place candidate passes the fit test; only the metadata's
	// relocated-header fallback can open the volume.
	boot := fixturePayload()
	putLE32(boot, 0x20, 4096)
	putLE64(boot, 0x28, 4096)
	const (
		copyOffset = 0x3000
		copyBytes  = 16 * 512
		dataOffset = 0x12000
	)
	image := buildImage(imageOptions{
		method:              bitlocker.MethodAES256XTS,
		fvek:                fixtureFVEK,
		entries:             recoveryFixtureEntries(bitlocker.MethodAES256XTS, bitlocker.MethodAES256XTS, fixtureFVEK),
		payload:             payload,
		dataOffset:          dataOffset,
		bootCopyAt:          copyOffset,
		bootCopyBytes:       copyBytes,
		bootCopyPayload:     boot[:copyBytes],
		volumeHeaderOffset:  copyOffset,
		volumeHeaderSectors: 16,
	})
	src, info := fixtureInfo(t, image)
	unlocked, err := Unlock(src, info, []byte(fixtureRecoveryPassword))
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if unlocked.DataOffset() != dataOffset {
		t.Fatalf("data offset = 0x%x, want 0x%x", unlocked.DataOffset(), dataOffset)
	}
	opened, err := unlocked.Open(2, src)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if opened.Len() != uint64(len(payload)) {
		t.Fatalf("len = %d, want %d", opened.Len(), len(payload))
	}
	got := readAll(t, opened)
	want := append(append([]byte(nil), boot[:copyBytes]...), payload[copyBytes:]...)
	if !bytes.Equal(got, want) {
		t.Fatal("relocated-header volume did not decrypt to the expected bytes")
	}

	// A read straddling the boot-copy boundary is split into two physical runs.
	extents, err := opened.Extents(copyBytes-512, 1024)
	if err != nil {
		t.Fatalf("Extents: %v", err)
	}
	if len(extents) != 2 ||
		extents[0].ParentOffset != copyOffset+copyBytes-512 ||
		extents[1].ParentOffset != dataOffset+copyBytes {
		t.Fatalf("straddling extents = %+v", extents)
	}
}
