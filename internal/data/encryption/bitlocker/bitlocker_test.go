package bitlocker

import (
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/encryption/errs"
	"github.com/laenix/ewfgo/internal/data/source"
)

func putLE16(b []byte, at int, v uint16) {
	b[at], b[at+1] = byte(v), byte(v>>8)
}

func putLE32(b []byte, at int, v uint32) {
	b[at], b[at+1], b[at+2], b[at+3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}

func putLE64(b []byte, at int, v uint64) {
	putLE32(b, at, uint32(v))
	putLE32(b, at+4, uint32(v>>32))
}

func entry(kind, valueType, version uint16, payload []byte) []byte {
	b := make([]byte, EntryHeaderBytes+len(payload))
	putLE16(b, 0, uint16(len(b)))
	putLE16(b, 2, kind)
	putLE16(b, 4, valueType)
	putLE16(b, 6, version)
	copy(b[EntryHeaderBytes:], payload)
	return b
}

func vmkPayload(first byte, protection uint16) []byte {
	p := make([]byte, 28)
	for i := 0; i < 16; i++ {
		p[i] = first + byte(i)
	}
	putLE64(p, 16, 0x01d9a00000000000)
	putLE16(p, 26, protection)
	return p
}

const metaOffset = 512

// buildVolume lays out a Windows 7 volume header, a metadata block header and
// an FVE metadata header followed by the given entry bytes.
func buildVolume(entries []byte) []byte {
	volume := make([]byte, metaOffset+BlockHeaderBytes+int(MetadataHeaderBytes)+len(entries))
	copy(volume[3:], VolumeSignature)
	putLE16(volume, 0x0b, 512) // bytes per sector
	volume[0x0d] = 8           // sectors per cluster
	putLE64(volume, 0x28, 2048)
	putLE32(volume, 0x43, 0x12345678)
	copy(volume[0x47:], "TESTVOL    ")
	copy(volume[0x52:], "NTFS    ")
	putLE64(volume, 0x99, metaOffset)

	block := metaOffset
	copy(volume[block:], VolumeSignature)
	putLE16(volume, block+10, 2)
	putLE16(volume, block+12, 4)
	putLE16(volume, block+14, 4)
	putLE64(volume, block+32, metaOffset)

	header := block + int(BlockHeaderBytes)
	size := int(MetadataHeaderBytes) + len(entries)
	putLE32(volume, header+0, uint32(size))
	putLE32(volume, header+4, 1)
	putLE32(volume, header+8, uint32(MetadataHeaderBytes))
	putLE32(volume, header+12, uint32(size))
	for i := 0; i < 16; i++ {
		volume[header+16+i] = byte(i + 1)
	}
	putLE32(volume, header+32, 7)
	putLE16(volume, header+36, MethodAES256XTS)
	putLE16(volume, header+38, MethodAES256XTS)
	putLE64(volume, header+40, 0x01d9a12345678900)
	copy(volume[header+int(MetadataHeaderBytes):], entries)
	return volume
}

func sampleEntries() []byte {
	protections := []uint16{
		ProtectTPM,
		ProtectTPMPIN,
		ProtectRecoveryPassword,
		ProtectPassword,
		ProtectStartupKey,
	}
	var out []byte
	for index, protection := range protections {
		payload := vmkPayload(byte(index*16), protection)
		if index == 0 {
			// A wrapped key nested after the 28-byte VMK header exercises
			// the recursive entry walk; only its size may be reported.
			wrapped := make([]byte, NonceBytes+16+32)
			payload = append(payload,
				entry(EntryVolumeMasterKey, ValueAESCCMKey, 1, wrapped)...)
		}
		out = append(out, entry(EntryVolumeMasterKey, ValueVolumeMasterKey, 1, payload)...)
	}
	fvek := make([]byte, 4+32)
	putLE16(fvek, 0, MethodAES256XTS)
	for i := 4; i < len(fvek); i++ {
		fvek[i] = byte(i)
	}
	out = append(out, entry(EntryFullVolumeEncryptionKey, ValueKey, 1, fvek)...)
	description := make([]byte, 0, 40)
	for _, r := range "system volume" {
		description = append(description, byte(r), 0)
	}
	out = append(out, entry(EntryDescription, ValueUnicodeString, 1, description)...)
	return out
}

func TestReadValidVolumeAndMetadata(t *testing.T) {
	volume := buildVolume(sampleEntries())
	info, err := Read(source.NewMemorySource(1, volume))
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if info == nil {
		t.Fatal("Read returned nil for a signed volume")
	}
	if info.Volume.BytesPerSector != 512 || info.Volume.SectorsPerCluster != 8 {
		t.Fatalf("geometry = %d/%d, want 512/8", info.Volume.BytesPerSector, info.Volume.SectorsPerCluster)
	}
	if info.Volume.TotalSectors != 2048 || info.VolumeBytes != 2048*512 {
		t.Fatalf("volume size = %d sectors / %d bytes", info.Volume.TotalSectors, info.VolumeBytes)
	}
	if info.SectorSize != 512 {
		t.Fatalf("sector size = %d, want 512", info.SectorSize)
	}
	if info.Volume.VolumeLabel != "TESTVOL" || info.Volume.FileSystem != "NTFS" {
		t.Fatalf("label/fs = %q/%q", info.Volume.VolumeLabel, info.Volume.FileSystem)
	}
	if info.Metadata == nil {
		t.Fatalf("metadata not read: %s", info.MetadataError)
	}
	if info.Metadata.Header.EncryptionMethod != MethodAES256XTS ||
		info.Metadata.Header.EncryptionMethodCopy != MethodAES256XTS {
		t.Fatalf("method = %#04x/%#04x", info.Metadata.Header.EncryptionMethod, info.Metadata.Header.EncryptionMethodCopy)
	}
	if info.EncryptionMethod != "AES-256-XTS" {
		t.Fatalf("EncryptionMethod = %q", info.EncryptionMethod)
	}
	if info.Metadata.Header.VolumeIdentifier != "0102030405060708090a0b0c0d0e0f10" {
		t.Fatalf("volume identifier = %q", info.Metadata.Header.VolumeIdentifier)
	}
	if len(info.Protectors) != 5 {
		t.Fatalf("protectors = %d, want 5", len(info.Protectors))
	}
	wantLabels := []string{"TPM", "TPM and PIN", "recovery password", "password", "startup key"}
	for i, want := range wantLabels {
		if info.ProtectorLabels[i] != want {
			t.Fatalf("protector %d label = %q, want %q", i, info.ProtectorLabels[i], want)
		}
	}
	if !info.HasRecoveryPassword() {
		t.Fatal("HasRecoveryPassword = false")
	}
	var fvekKey *KeyData
	for i := range info.KeyData {
		if info.KeyData[i].EntryType == EntryFullVolumeEncryptionKey {
			fvekKey = &info.KeyData[i]
		}
	}
	if fvekKey == nil || !fvekKey.Present || fvekKey.Bytes != 32 {
		t.Fatalf("FVEK key data = %+v, want present with 32 bytes", fvekKey)
	}
	wrappedFound := false
	for _, key := range info.KeyData {
		if key.ValueType == ValueAESCCMKey {
			wrappedFound = key.Present && key.Wrapped && key.Bytes == NonceBytes+16+32
		}
	}
	if !wrappedFound {
		t.Fatalf("nested AES-CCM key data not reported: %+v", info.KeyData)
	}
	if info.Metadata.Entries[len(info.Metadata.Entries)-1].Text != "system volume" {
		t.Fatalf("description text = %q", info.Metadata.Entries[len(info.Metadata.Entries)-1].Text)
	}
}

func TestReadBackupVolumeHeader(t *testing.T) {
	volume := buildVolume(sampleEntries())
	backup := make([]byte, VolumeHeaderBytes)
	copy(backup[3:], VolumeSignature)
	putLE16(backup, 0x0b, 512)
	backup[0x0d] = 8
	putLE64(backup, 0x28, 2048)
	volume = append(volume, backup...)

	info, err := Read(source.NewMemorySource(1, volume))
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if info.Backup == nil {
		t.Fatal("backup volume header not read")
	}
}

func TestReadWithoutSignatureIsNotBitlocker(t *testing.T) {
	info, err := Read(source.NewMemorySource(1, make([]byte, 4096)))
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if info != nil {
		t.Fatalf("Read = %+v, want nil", info)
	}
}

func TestReadTruncatedVolumeHeader(t *testing.T) {
	head := make([]byte, 300)
	copy(head[3:], VolumeSignature)
	_, err := Read(source.NewMemorySource(1, head))
	if !errors.Is(err, errs.ErrTruncated) {
		t.Fatalf("Read error = %v, want ErrTruncated", err)
	}
}

func TestReadDamagedMetadataIsReported(t *testing.T) {
	volume := buildVolume(sampleEntries())
	// The metadata size field, at block header + 64, must cover its own
	// 48-byte header; zero is a structural error.
	putLE32(volume, metaOffset+int(BlockHeaderBytes), 0)
	info, err := Read(source.NewMemorySource(1, volume))
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if info.Metadata != nil {
		t.Fatal("damaged metadata was accepted")
	}
	if info.MetadataError == "" {
		t.Fatal("MetadataError is empty")
	}
}

func TestEntryLabelCoverage(t *testing.T) {
	if got := ProtectionLabel(ProtectTPMPIN); got != "TPM and PIN" {
		t.Fatalf("ProtectionLabel = %q", got)
	}
	if got := EncryptionLabel(0xffff); got != "unknown method" {
		t.Fatalf("EncryptionLabel = %q", got)
	}
}
