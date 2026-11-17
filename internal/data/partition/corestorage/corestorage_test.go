package corestorage

import (
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	testBlockSize          uint32 = 4096
	testMetadataBlockNum   uint64 = 512
	testMetadataOffset            = testMetadataBlockNum * uint64(testBlockSize)
	testImageBytes                = int(testMetadataOffset) + MetadataBlockBytes
	testHeaderMetadataSize uint32 = 4096
)

func putU16(t *testing.T, b []byte, at int, v uint16) {
	t.Helper()
	if at+2 > len(b) {
		t.Fatalf("putU16 at %d out of %d bytes", at, len(b))
	}
	b[at], b[at+1] = byte(v), byte(v>>8)
}

func putU32(t *testing.T, b []byte, at int, v uint32) {
	t.Helper()
	if at+4 > len(b) {
		t.Fatalf("putU32 at %d out of %d bytes", at, len(b))
	}
	b[at], b[at+1], b[at+2], b[at+3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}

func putU64(t *testing.T, b []byte, at int, v uint64) {
	t.Helper()
	if at+8 > len(b) {
		t.Fatalf("putU64 at %d out of %d bytes", at, len(b))
	}
	for i := 0; i < 8; i++ {
		b[at+i] = byte(v >> (8 * i))
	}
}

// syntheticImage builds a minimal valid CoreStorage physical volume: a
// 512-byte header, a 8192-byte metadata section at
// metadata_block_numbers[0]*block_size, and a volume-group descriptor.
func syntheticImage(t *testing.T) []byte {
	t.Helper()
	image := make([]byte, testImageBytes)

	header := image[:HeaderBytes]
	putU32(t, header, 4, ChecksumSeed)
	putU16(t, header, 8, 1)
	putU16(t, header, 10, HeaderBlockType)
	putU32(t, header, 12, 0x12345678)
	putU32(t, header, 48, 512)
	putU64(t, header, 64, uint64(testImageBytes))
	copy(header[SignatureOffset:SignatureOffset+len(Signature)], Signature)
	putU32(t, header, 90, ChecksumAlgorithmCRC32C)
	putU16(t, header, 94, 4)
	putU32(t, header, 96, testBlockSize)
	putU32(t, header, 100, testHeaderMetadataSize)
	putU64(t, header, 104, testMetadataBlockNum)
	putU32(t, header, 168, 16)
	putU32(t, header, 172, EncryptionMethodAESXTS)
	for i := 176; i < 192; i++ {
		header[i] = 0x11
	}
	copy(header[304:320], []byte{
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
	})
	copy(header[320:336], []byte{
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
	})
	putU32(t, header, 0, foundation.CRC32CSeeded(ChecksumSeed, header[8:HeaderBytes]))

	block := image[testMetadataOffset : testMetadataOffset+MetadataBlockBytes]
	putU32(t, block, 4, ChecksumSeed)
	putU16(t, block, 8, 1)
	putU16(t, block, 10, MetadataBlockType)
	putU32(t, block, 48, MetadataBlockBytes)
	putU32(t, block, 64, testHeaderMetadataSize)
	putU32(t, block, 220, MinVolumeGroupDescriptorOffset)
	vgd := int(MinVolumeGroupDescriptorOffset)
	putU64(t, block, vgd, 1)       // conversion state: encrypted
	putU64(t, block, vgd+8, 6144)  // encrypted metadata block count
	putU64(t, block, vgd+32, 2049) // primary encrypted metadata block
	putU32(t, block, 0, foundation.CRC32CSeeded(ChecksumSeed, block[8:]))

	return image
}

func parseImage(t *testing.T, image []byte) (*Volume, error) {
	t.Helper()
	return Read(source.NewMemorySource(source.ID(1), image))
}

func mustParse(t *testing.T, image []byte) *Volume {
	t.Helper()
	volume, err := parseImage(t, image)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return volume
}

func TestReadsHeaderAndMetadataSection(t *testing.T) {
	volume := mustParse(t, syntheticImage(t))

	if volume.Version != 1 {
		t.Errorf("Version = %d, want 1", volume.Version)
	}
	if volume.BlockType != HeaderBlockType {
		t.Errorf("BlockType = 0x%04X, want 0x%04X", volume.BlockType, HeaderBlockType)
	}
	if volume.BytesPerSector != 512 {
		t.Errorf("BytesPerSector = %d, want 512", volume.BytesPerSector)
	}
	if volume.BlockSize != testBlockSize {
		t.Errorf("BlockSize = %d, want %d", volume.BlockSize, testBlockSize)
	}
	if volume.MetadataSize != testHeaderMetadataSize {
		t.Errorf("MetadataSize = %d, want %d", volume.MetadataSize, testHeaderMetadataSize)
	}
	if volume.MetadataBlockNumbers[0] != testMetadataBlockNum {
		t.Errorf("MetadataBlockNumbers[0] = %d, want %d", volume.MetadataBlockNumbers[0], testMetadataBlockNum)
	}
	if !volume.ChecksumOK {
		t.Error("ChecksumOK = false, want true")
	}
	if volume.ChecksumComputed != volume.Checksum {
		t.Errorf("ChecksumComputed = 0x%08X, stored 0x%08X", volume.ChecksumComputed, volume.Checksum)
	}
	if volume.EncryptionMethod != EncryptionMethodAESXTS {
		t.Errorf("EncryptionMethod = %d, want %d", volume.EncryptionMethod, EncryptionMethodAESXTS)
	}
	if got := volume.EncryptionMethodLabel(); got != "AES-XTS" {
		t.Errorf("EncryptionMethodLabel() = %q, want AES-XTS", got)
	}
	if !volume.KeyDataPresent {
		t.Error("KeyDataPresent = false, want true")
	}
	if volume.KeyDataSize != 16 {
		t.Errorf("KeyDataSize = %d, want 16", volume.KeyDataSize)
	}
	if got, want := volume.PhysicalVolumeUUID, "11223344-5566-7788-99aa-bbccddeeff00"; got != want {
		t.Errorf("PhysicalVolumeUUID = %q, want %q", got, want)
	}
	if got, want := volume.VolumeGroupUUID, "21222324-2526-2728-292a-2b2c2d2e2f30"; got != want {
		t.Errorf("VolumeGroupUUID = %q, want %q", got, want)
	}

	metadata := volume.Metadata
	if metadata == nil {
		t.Fatal("Metadata = nil, want a section")
	}
	if metadata.Offset != testMetadataOffset {
		t.Errorf("Metadata.Offset = %d, want %d", metadata.Offset, testMetadataOffset)
	}
	if metadata.BlockNumber != testMetadataBlockNum {
		t.Errorf("Metadata.BlockNumber = %d, want %d", metadata.BlockNumber, testMetadataBlockNum)
	}
	if metadata.BlockType != MetadataBlockType {
		t.Errorf("Metadata.BlockType = 0x%04X, want 0x%04X", metadata.BlockType, MetadataBlockType)
	}
	if !metadata.ChecksumOK {
		t.Error("Metadata.ChecksumOK = false, want true")
	}
	if !metadata.MetadataSizeMatches {
		t.Error("Metadata.MetadataSizeMatches = false, want true")
	}

	group := metadata.VolumeGroup
	if group == nil {
		t.Fatal("Metadata.VolumeGroup = nil, want a descriptor")
	}
	if group.State != ConversionEncrypted {
		t.Errorf("State = %v, want encrypted", group.State)
	}
	if group.StateRaw != 1 {
		t.Errorf("StateRaw = %d, want 1", group.StateRaw)
	}
	if group.EncryptedMetadataBlockCount != 6144 {
		t.Errorf("EncryptedMetadataBlockCount = %d, want 6144", group.EncryptedMetadataBlockCount)
	}
	if group.PrimaryEncryptedMetadata == nil {
		t.Fatal("PrimaryEncryptedMetadata = nil, want a block")
	}
	if group.PrimaryEncryptedMetadata.BlockNumber != 2049 {
		t.Errorf("Primary.BlockNumber = %d, want 2049", group.PrimaryEncryptedMetadata.BlockNumber)
	}
	if group.PrimaryEncryptedMetadata.VolumeIndex != 0 {
		t.Errorf("Primary.VolumeIndex = %d, want 0", group.PrimaryEncryptedMetadata.VolumeIndex)
	}
	if !group.EncryptedMetadataPresent {
		t.Error("EncryptedMetadataPresent = false, want true")
	}
	if !volume.EncryptedMetadataPresent() {
		t.Error("Volume.EncryptedMetadataPresent() = false, want true")
	}
}

func TestRolesAndLabels(t *testing.T) {
	volume := mustParse(t, syntheticImage(t))
	roles := volume.Roles()
	if len(roles) != 2 || roles[0] != "physical-volume" || roles[1] != "volume-group" {
		t.Errorf("Roles() = %v, want [physical-volume volume-group]", roles)
	}
	if got := ConversionStateFromRaw(0).Label(); got != "unencrypted" {
		t.Errorf("state 0 label = %q, want unencrypted", got)
	}
	if got := ConversionStateFromRaw(2).Label(); got != "decrypting" {
		t.Errorf("state 2 label = %q, want decrypting", got)
	}
	if got := ConversionStateFromRaw(7).Label(); got != "unknown" {
		t.Errorf("state 7 label = %q, want unknown", got)
	}
	if got := ConversionStateFromRaw(7); got != ConversionUnknown {
		t.Errorf("state 7 = %v, want ConversionUnknown", got)
	}
	if got := (&Volume{EncryptionMethod: 999}).EncryptionMethodLabel(); got != "unknown" {
		t.Errorf("unknown method label = %q, want unknown", got)
	}
}

func TestBadSignatureIsUnrouted(t *testing.T) {
	image := syntheticImage(t)
	copy(image[SignatureOffset:SignatureOffset+2], "XX")
	_, err := parseImage(t, image)
	if !errors.Is(err, ErrUnrouted) {
		t.Fatalf("err = %v, want ErrUnrouted", err)
	}
}

func TestTruncatedHeaderIsNamed(t *testing.T) {
	image := syntheticImage(t)
	image = image[:256]
	_, err := parseImage(t, image)
	var truncated *TruncatedError
	if !errors.As(err, &truncated) {
		t.Fatalf("err = %v, want TruncatedError", err)
	}
	if truncated.Offset != 0 || truncated.Need != HeaderBytes || truncated.Have != 256 {
		t.Errorf("TruncatedError = %+v, want offset 0 need 512 have 256", truncated)
	}
}

func TestShortSourceWithoutSignatureIsUnrouted(t *testing.T) {
	_, err := Read(source.NewMemorySource(source.ID(1), make([]byte, 89)))
	if !errors.Is(err, ErrUnrouted) {
		t.Fatalf("err = %v, want ErrUnrouted", err)
	}
}

func TestUnknownVersionIsNamed(t *testing.T) {
	image := syntheticImage(t)
	putU16(t, image, 8, 2)
	_, err := parseImage(t, image)
	var version *UnknownVersionError
	if !errors.As(err, &version) {
		t.Fatalf("err = %v, want UnknownVersionError", err)
	}
	if version.Version != 2 {
		t.Errorf("Version = %d, want 2", version.Version)
	}
}

func TestSignatureOnlyHeaderIsClassifiedNotAccepted(t *testing.T) {
	// A header that only carries "CS" at offset 88 is not routable. Read still
	// recognises the signature and names the first invariant it violates.
	head := make([]byte, HeaderBytes)
	copy(head[SignatureOffset:], Signature)

	if LooksLikeVolumeHeader(head) {
		t.Error("LooksLikeVolumeHeader = true for a signature-only header")
	}
	_, err := Read(source.NewMemorySource(source.ID(1), head))
	var version *UnknownVersionError
	if !errors.As(err, &version) {
		t.Fatalf("err = %v, want UnknownVersionError", err)
	}
	if version.Version != 0 {
		t.Errorf("Version = %d, want 0", version.Version)
	}
}

func TestBadHeaderConstantsAreRefused(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, image []byte)
	}{
		{"block type", func(t *testing.T, image []byte) { putU16(t, image, 10, 0x0011) }},
		{"checksum seed", func(t *testing.T, image []byte) { putU32(t, image, 4, 0) }},
		{"checksum algorithm", func(t *testing.T, image []byte) { putU32(t, image, 90, 2) }},
		{"zero sector size", func(t *testing.T, image []byte) { putU32(t, image, 48, 0) }},
		{"zero block size", func(t *testing.T, image []byte) { putU32(t, image, 96, 0) }},
		{"non power of two block size", func(t *testing.T, image []byte) { putU32(t, image, 96, 1000) }},
		{"block size below a sector", func(t *testing.T, image []byte) { putU32(t, image, 96, 256) }},
		{"zero metadata size", func(t *testing.T, image []byte) { putU32(t, image, 100, 0) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			image := syntheticImage(t)
			test.mutate(t, image)
			_, err := parseImage(t, image)
			var bad *HeaderError
			if !errors.As(err, &bad) {
				t.Fatalf("err = %v, want HeaderError", err)
			}
		})
	}
}

func TestOversizedBlockSizeIsCapped(t *testing.T) {
	image := syntheticImage(t)
	putU32(t, image, 96, MaxBlockSize*2)
	_, err := parseImage(t, image)
	var capped *CapError
	if !errors.As(err, &capped) {
		t.Fatalf("err = %v, want CapError", err)
	}
}

func TestOversizedMetadataSizeIsCapped(t *testing.T) {
	image := syntheticImage(t)
	putU32(t, image, 100, MaxMetadataSize+1)
	_, err := parseImage(t, image)
	var capped *CapError
	if !errors.As(err, &capped) {
		t.Fatalf("err = %v, want CapError", err)
	}
}

func TestMetadataBlockPastEndIsOutOfBounds(t *testing.T) {
	image := syntheticImage(t)
	putU64(t, image, 104, ^uint64(0))
	_, err := parseImage(t, image)
	var out *OutOfBoundsError
	if !errors.As(err, &out) {
		t.Fatalf("err = %v, want OutOfBoundsError", err)
	}
}

func TestMetadataBeyondSourceIsOutOfBounds(t *testing.T) {
	image := syntheticImage(t)
	image = image[:testMetadataOffset+4096]
	_, err := parseImage(t, image)
	var out *OutOfBoundsError
	if !errors.As(err, &out) {
		t.Fatalf("err = %v, want OutOfBoundsError", err)
	}
}

func TestWrongMetadataBlockTypeIsRefused(t *testing.T) {
	image := syntheticImage(t)
	putU16(t, image, int(testMetadataOffset)+10, 0x0012)
	_, err := parseImage(t, image)
	var bad *HeaderError
	if !errors.As(err, &bad) {
		t.Fatalf("err = %v, want HeaderError", err)
	}
}

func TestWrongMetadataBlockSizeIsRefused(t *testing.T) {
	image := syntheticImage(t)
	putU32(t, image, int(testMetadataOffset)+48, 4096)
	_, err := parseImage(t, image)
	var bad *HeaderError
	if !errors.As(err, &bad) {
		t.Fatalf("err = %v, want HeaderError", err)
	}
}

func TestMetadataSizeMismatchIsRefused(t *testing.T) {
	image := syntheticImage(t)
	putU32(t, image, int(testMetadataOffset)+64, testHeaderMetadataSize+1)
	_, err := parseImage(t, image)
	var bad *HeaderError
	if !errors.As(err, &bad) {
		t.Fatalf("err = %v, want HeaderError", err)
	}
}

func TestDescriptorBeforeFixedFieldsIsRefused(t *testing.T) {
	image := syntheticImage(t)
	putU32(t, image, int(testMetadataOffset)+220, MinVolumeGroupDescriptorOffset-1)
	_, err := parseImage(t, image)
	var bad *HeaderError
	if !errors.As(err, &bad) {
		t.Fatalf("err = %v, want HeaderError", err)
	}
}

func TestDescriptorOutsideBlockIsOutOfBounds(t *testing.T) {
	image := syntheticImage(t)
	putU32(t, image, int(testMetadataOffset)+220, MetadataBlockBytes-8)
	_, err := parseImage(t, image)
	var out *OutOfBoundsError
	if !errors.As(err, &out) {
		t.Fatalf("err = %v, want OutOfBoundsError", err)
	}
}

func TestOversizedEncryptedMetadataCountIsCapped(t *testing.T) {
	image := syntheticImage(t)
	vgd := int(testMetadataOffset) + int(MinVolumeGroupDescriptorOffset)
	putU64(t, image, vgd+8, MaxEncryptedMetadataBlocks+1)
	_, err := parseImage(t, image)
	var capped *CapError
	if !errors.As(err, &capped) {
		t.Fatalf("err = %v, want CapError", err)
	}
}

func TestBadChecksumIsReportedNotHidden(t *testing.T) {
	image := syntheticImage(t)
	image[0] ^= 0xFF
	volume := mustParse(t, image)
	if volume.ChecksumOK {
		t.Error("ChecksumOK = true, want false")
	}
	if LooksLikeVolumeHeader(image[:HeaderBytes]) {
		t.Error("LooksLikeVolumeHeader must reject a bad checksum")
	}
}

func TestMetadataChecksumBadButBlockStillReported(t *testing.T) {
	image := syntheticImage(t)
	image[testMetadataOffset] ^= 0xFF
	volume := mustParse(t, image)
	if volume.Metadata == nil {
		t.Fatal("Metadata = nil, want a section")
	}
	if volume.Metadata.ChecksumOK {
		t.Error("Metadata.ChecksumOK = true, want false")
	}
}

func TestLooksLikeVolumeHeader(t *testing.T) {
	image := syntheticImage(t)
	if !LooksLikeVolumeHeader(image[:HeaderBytes]) {
		t.Fatal("LooksLikeVolumeHeader(valid) = false, want true")
	}
	if LooksLikeVolumeHeader(image[:200]) {
		t.Error("LooksLikeVolumeHeader(short) = true, want false")
	}

	forged := append([]byte(nil), image[:HeaderBytes]...)
	forged[0] ^= 0xFF
	if LooksLikeVolumeHeader(forged) {
		t.Error("LooksLikeVolumeHeader(bad checksum) = true, want false")
	}
	forged[0] ^= 0xFF
	copy(forged[SignatureOffset:], "XX")
	if LooksLikeVolumeHeader(forged) {
		t.Error("LooksLikeVolumeHeader(bad signature) = true, want false")
	}
}

func TestNoMetadataBlockNumbersYieldsNoMetadata(t *testing.T) {
	image := syntheticImage(t)
	putU64(t, image, 104, 0)
	image = image[:HeaderBytes]
	volume := mustParse(t, image)
	if volume.Metadata != nil {
		t.Errorf("Metadata = %+v, want nil when metadata_block_numbers[0] is zero", volume.Metadata)
	}
	if volume.Metadata.HasVolumeGroup() {
		t.Error("nil Metadata.HasVolumeGroup() = true")
	}
	if volume.EncryptedMetadataPresent() {
		t.Error("EncryptedMetadataPresent = true without metadata")
	}
	if roles := volume.Roles(); len(roles) != 1 || roles[0] != "physical-volume" {
		t.Errorf("Roles() = %v, want [physical-volume]", roles)
	}
}

func TestWipedMetadataBlockHasNoPayload(t *testing.T) {
	image := syntheticImage(t)
	at := int(testMetadataOffset)
	copy(image[at:at+8], WipedMarker)
	putU16(t, image, at+10, 0x0024)
	volume := mustParse(t, image)
	metadata := volume.Metadata
	if metadata == nil {
		t.Fatal("Metadata = nil, want a section")
	}
	if !metadata.Wiped {
		t.Error("Metadata.Wiped = false, want true")
	}
	if !metadata.ChecksumOK {
		t.Error("Metadata.ChecksumOK = false, want true for a wiped block")
	}
	if metadata.VolumeGroup != nil {
		t.Errorf("Metadata.VolumeGroup = %+v, want nil for a wiped block", metadata.VolumeGroup)
	}
	if volume.EncryptedMetadataPresent() {
		t.Error("EncryptedMetadataPresent = true for a wiped block")
	}
}

func TestZeroKeyDataIsReportedAbsent(t *testing.T) {
	image := syntheticImage(t)
	clear(image[176:192])
	volume := mustParse(t, image)
	if volume.KeyDataPresent {
		t.Error("KeyDataPresent = true, want false")
	}
}
