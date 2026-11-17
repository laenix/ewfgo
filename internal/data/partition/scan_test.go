package partition

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

// Synthetic-disk helpers shared by scan_test.go and verify_test.go.  They
// write real header fields at the offsets the formats use; nothing here
// fabricates a candidate outside the bytes the test places.
const (
	testSectorSize = 512
	testMiB        = 1024 * 1024
)

func scanTestSource(image []byte) *source.MemorySource {
	return source.NewMemorySource(1, image)
}

func scanTestPut(image []byte, at uint64, data []byte) {
	copy(image[int(at):int(at)+len(data)], data)
}

func sp16(b []byte, at int, v uint16) { binary.LittleEndian.PutUint16(b[at:], v) }
func sp32(b []byte, at int, v uint32) { binary.LittleEndian.PutUint32(b[at:], v) }
func sp64(b []byte, at int, v uint64) { binary.LittleEndian.PutUint64(b[at:], v) }

func sp16be(b []byte, at int, v uint16) { binary.BigEndian.PutUint16(b[at:], v) }
func sp32be(b []byte, at int, v uint32) { binary.BigEndian.PutUint32(b[at:], v) }
func sp64be(b []byte, at int, v uint64) { binary.BigEndian.PutUint64(b[at:], v) }

// scanTestNTFSBoot is a boot sector the signature and confirm checks accept.
func scanTestNTFSBoot(totalSectors uint64) []byte {
	sector := make([]byte, testSectorSize)
	copy(sector[0:3], []byte{0xEB, 0x52, 0x90})
	copy(sector[3:11], []byte("NTFS    "))
	sp16(sector, 11, testSectorSize)
	sector[13] = 8
	sp64(sector, 40, totalSectors)
	sp64(sector, 48, 4) // $MFT at LCN 4
	sp64(sector, 56, 8) // $MFTMirr at LCN 8
	sector[64] = 0xF6   // -10, 1024-byte records
	sector[68] = 0xF6
	sector[510] = 0x55
	sector[511] = 0xAA
	return sector
}

// scanTestExtSuperblock is a synthetic ext superblock without metadata_csum.
func scanTestExtSuperblock(blocks, logBlock uint32) []byte {
	sb := make([]byte, 1024)
	sp32(sb, 0x04, blocks)
	sp32(sb, 0x18, logBlock)
	sp32(sb, 0x20, 8192) // blocks per group
	sp32(sb, 0x28, 256)  // inodes per group
	sp16(sb, 0x38, 0xEF53)
	return sb
}

// scanTestSealedExtSuperblock sets metadata_csum and seals the CRC-32C.
func scanTestSealedExtSuperblock(blocks, logBlock uint32) []byte {
	sb := scanTestExtSuperblock(blocks, logBlock)
	sp32(sb, 0x64, 0x0400) // RO_COMPAT_METADATA_CSUM
	sb[0x175] = 1          // CHECKSUM_TYPE_CRC32C
	for i := 0x68; i < 0x78; i++ {
		sb[i] = 0x11
	}
	sp32(sb, 0x3FC, foundation.CRC32CSeeded(0xFFFFFFFF, sb[:0x3FC]))
	return sb
}

func xfsSealCRC(sb []byte) {
	const crcAt = 0xE0
	copyBytes := append([]byte(nil), sb[:testSectorSize]...)
	clear(copyBytes[crcAt : crcAt+4])
	sp32(sb, crcAt, foundation.CRC32C(copyBytes))
}

// scanTestXFS5 is a version-5 superblock that passes the Rust geometry checks.
func scanTestXFS5(dataBlocks uint64) []byte {
	sb := make([]byte, testSectorSize)
	copy(sb[0:4], []byte("XFSB"))
	sp32be(sb, 0x04, 4096) // block size
	sp64be(sb, 0x08, dataBlocks)
	sp64be(sb, 0x38, 128) // root inode
	sp32be(sb, 0x54, uint32(dataBlocks))
	sp32be(sb, 0x58, 1) // one allocation group
	sp16be(sb, 0x64, 5) // version 5
	sp16be(sb, 0x66, testSectorSize)
	sp16be(sb, 0x68, 256) // inode size
	sp16be(sb, 0x6A, 16)  // inodes per block
	sb[0x78] = 12         // block log
	sb[0x79] = 9          // sector log
	sb[0x7A] = 8          // inode log
	sb[0x7B] = 4          // inodes-per-block log
	sb[0x7C] = 10         // allocation-group block log
	sb[0x7E] = 0          // sb_inprogress clear
	xfsSealCRC(sb)
	return sb
}

// scanTestXFS4 is the same geometry in the version-4 layout (no CRC).
func scanTestXFS4(dataBlocks uint64) []byte {
	sb := scanTestXFS5(dataBlocks)
	sp16be(sb, 0x64, 4)
	clear(sb[0xE0 : 0xE0+4])
	return sb
}

func btrfsSeal(sb []byte) {
	sp32(sb, 0, foundation.CRC32C(sb[32:]))
}

// scanTestBtrfsSuperblock is a checksummed 4096-byte superblock copy.
func scanTestBtrfsSuperblock(bytenr, totalBytes uint64) []byte {
	sb := make([]byte, 4096)
	sp64(sb, 48, bytenr)
	copy(sb[64:72], []byte("_BHRfS_M"))
	sp64(sb, 80, 4096) // tree of trees root
	sp64(sb, 88, 8192) // chunk tree root
	sp64(sb, 112, totalBytes)
	sp32(sb, 144, 4096) // sector size
	sp32(sb, 148, 4096) // node size
	sp32(sb, 156, 4096) // stripe size
	sp16(sb, 196, 0)    // CRC32C
	btrfsSeal(sb)
	return sb
}

// scanTestJFFS2Node is a first node header with a matching CRCs.
func scanTestJFFS2Node(totlen uint32) []byte {
	node := make([]byte, 12)
	sp16(node, 0, 0x1985)
	sp16(node, 2, 0xE001)
	sp32(node, 4, totlen)
	sp32(node, 8, foundation.CRC32(node[0:8]))
	return node
}

// scanTestLVMLabel builds a LABELONE sector whose CRC is valid unless corrupt.
func scanTestLVMLabel(corrupt bool) []byte {
	label := make([]byte, 512)
	copy(label[0:8], []byte("LABELONE"))
	sp64(label, 8, 1)
	copy(label[24:32], []byte("LVM2 001"))
	sp32(label, 20, 32) // pv_header offset
	copy(label[32:64], []byte("0123456789abcdefghijklmnopqrstuv"))
	sp64(label, 64, testMiB) // device size
	// Two empty NULL-terminated area lists.
	sp64(label, 72, 0)
	sp64(label, 80, 0)
	sp64(label, 88, 0)
	sp64(label, 96, 0)

	crcInput := append([]byte(nil), label...)
	clear(crcInput[16:20])
	sp32(label, 16, foundation.CRC32(crcInput))
	if corrupt {
		label[16] ^= 0xFF
	}
	return label
}

// scanTestCoreStorageHeader builds a physical-volume header with a valid CRC
// unless corrupt.
func scanTestCoreStorageHeader(corrupt bool) []byte {
	header := make([]byte, 512)
	sp32(header, 4, 0xFFFFFFFF)
	sp16(header, 8, 1)
	sp16(header, 10, 0x0010)
	copy(header[88:90], []byte("CS"))
	sp32(header, 90, 1)
	sp32(header, 96, 4096)
	sp32(header, 0, foundation.CRC32CSeeded(0xFFFFFFFF, header[8:512]))
	if corrupt {
		header[100] ^= 0xFF
	}
	return header
}

func insideOf(c Candidate, want uint64) bool {
	return c.InsideOf != nil && *c.InsideOf == want
}

func TestScanFindsVolumesBehindAnMBR(t *testing.T) {
	image := make([]byte, 8*testMiB)
	// A DOS boot sector.  The scanner reads filesystem magics at sector
	// boundaries; it does not need the partition table to describe them.
	image[510] = 0x55
	image[511] = 0xAA

	scanTestPut(image, 1*testMiB+1024, scanTestSealedExtSuperblock(256, 2))
	scanTestPut(image, 2*testMiB, scanTestXFS5(1024))
	scanTestPut(image, 3*testMiB+65536, scanTestBtrfsSuperblock(65536, testMiB))
	scanTestPut(image, 4*testMiB, scanTestNTFSBoot(2048))

	report, err := Scan(scanTestSource(image), DefaultScanOptions())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if report.SectorSize != testSectorSize {
		t.Fatalf("sector size = %d, want %d", report.SectorSize, testSectorSize)
	}
	if report.BytesScanned != uint64(len(image)) {
		t.Fatalf("bytes scanned = %d, want %d", report.BytesScanned, len(image))
	}
	if report.Truncated {
		t.Fatal("report is truncated")
	}
	if report.RejectedHits != 0 {
		t.Fatalf("rejected hits = %d, want 0", report.RejectedHits)
	}

	wantOffsets := []uint64{1 * testMiB, 2 * testMiB, 3 * testMiB, 4 * testMiB}
	wantIDs := []string{"ext-volume", "xfs-volume", "btrfs-volume", "ntfs-volume"}
	if len(report.Candidates) != len(wantOffsets) {
		t.Fatalf("candidates = %d, want %d: %#v", len(report.Candidates), len(wantOffsets), report.Candidates)
	}
	for i, c := range report.Candidates {
		if c.Offset != wantOffsets[i] {
			t.Errorf("candidate %d offset = %d, want %d", i, c.Offset, wantOffsets[i])
		}
		if c.ID != wantIDs[i] {
			t.Errorf("candidate %d id = %q, want %q", i, c.ID, wantIDs[i])
		}
	}

	// The three formats whose checksums this port verifies are Verified; NTFS
	// has no ported parser yet, so it is explicitly Unverified.
	if report.Candidates[0].Status != CandidateStatusVerified {
		t.Errorf("ext status = %s, want verified", report.Candidates[0].Status)
	}
	if report.Candidates[1].Status != CandidateStatusVerified {
		t.Errorf("xfs status = %s, want verified", report.Candidates[1].Status)
	}
	if report.Candidates[2].Status != CandidateStatusVerified {
		t.Errorf("btrfs status = %s, want verified", report.Candidates[2].Status)
	}
	if report.Candidates[3].Status != CandidateStatusUnverified {
		t.Errorf("ntfs status = %s, want unverified", report.Candidates[3].Status)
	}
	if !strings.Contains(report.Candidates[3].Reason, "not ported") {
		t.Errorf("ntfs reason = %q, want a truthful not-ported reason", report.Candidates[3].Reason)
	}
}

func TestScanCandidateInsideAnotherIsMarked(t *testing.T) {
	image := make([]byte, 4*testMiB)
	// A 2 MiB volume at the start and a 512 KiB volume 1 MiB in, inside it.
	scanTestPut(image, 0, scanTestNTFSBoot(4096))
	scanTestPut(image, 2*testMiB-512, scanTestNTFSBoot(4096)) // its backup boot sector
	scanTestPut(image, testMiB, scanTestNTFSBoot(1024))
	scanTestPut(image, testMiB+1024*512-512, scanTestNTFSBoot(1024))

	report, err := Scan(scanTestSource(image), DefaultScanOptions())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(report.Candidates) != 4 {
		t.Fatalf("candidates = %d, want 4: %#v", len(report.Candidates), report.Candidates)
	}

	c := report.Candidates
	if c[0].Offset != 0 || c[0].InsideOf != nil {
		t.Errorf("candidate 0 = offset %d inside_of %v, want 0 and top-level", c[0].Offset, c[0].InsideOf)
	}
	if c[1].Offset != testMiB || !insideOf(c[1], 0) {
		t.Errorf("candidate 1 = offset %d inside_of %v, want %d inside 0", c[1].Offset, c[1].InsideOf, testMiB)
	}
	if c[2].Offset != testMiB+1024*512-512 || !insideOf(c[2], testMiB) {
		t.Errorf("candidate 2 = offset %d inside_of %v, want %d inside %d",
			c[2].Offset, c[2].InsideOf, testMiB+1024*512-512, testMiB)
	}
	if c[3].Offset != 2*testMiB-512 || !insideOf(c[3], 0) {
		t.Errorf("candidate 3 = offset %d inside_of %v, want %d inside 0",
			c[3].Offset, c[3].InsideOf, 2*testMiB-512)
	}
	if got := len(report.TopLevel()); got != 1 {
		t.Errorf("top-level candidates = %d, want 1", got)
	}
}

func TestScanIgnoresUnalignedSignature(t *testing.T) {
	image := make([]byte, testMiB)
	scanTestPut(image, 1001, []byte("NTFS    "))

	report, err := Scan(scanTestSource(image), DefaultScanOptions())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(report.Candidates) != 0 {
		t.Fatalf("candidates = %d, want 0", len(report.Candidates))
	}
	if report.RejectedHits != 0 {
		t.Fatalf("rejected hits = %d, want 0", report.RejectedHits)
	}
}

func TestScanAnchorWithoutConfirmIsRejected(t *testing.T) {
	image := make([]byte, testMiB)
	sector := make([]byte, testSectorSize)
	copy(sector[3:11], []byte("NTFS    "))
	sp16(sector, 11, 0) // sector size zero is not a size
	scanTestPut(image, 4096, sector)

	report, err := Scan(scanTestSource(image), DefaultScanOptions())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(report.Candidates) != 0 {
		t.Fatalf("candidates = %d, want 0", len(report.Candidates))
	}
	if report.RejectedHits != 1 {
		t.Fatalf("rejected hits = %d, want 1", report.RejectedHits)
	}
}

func TestScanCandidateCapTruncates(t *testing.T) {
	image := make([]byte, 4*testMiB)
	for step := uint64(0); step < 4; step++ {
		scanTestPut(image, step*testMiB, scanTestNTFSBoot(8))
	}

	report, err := Scan(scanTestSource(image), ScanOptions{MaxCandidates: 2})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(report.Candidates) != 2 {
		t.Fatalf("candidates = %d, want 2", len(report.Candidates))
	}
	if !report.Truncated {
		t.Fatal("report is not truncated")
	}
}

func TestScanLimitBoundsBytesRead(t *testing.T) {
	image := make([]byte, 4*testMiB)
	scanTestPut(image, 3*testMiB, scanTestNTFSBoot(8))
	limit := uint64(2 * testMiB)

	report, err := Scan(scanTestSource(image), ScanOptions{Limit: &limit})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if report.BytesScanned != limit {
		t.Fatalf("bytes scanned = %d, want %d", report.BytesScanned, limit)
	}
	if len(report.Candidates) != 0 {
		t.Fatalf("candidates = %d, want 0", len(report.Candidates))
	}
}

func TestScanVolumeAfterChunkBoundary(t *testing.T) {
	// The first read covers exactly 8 MiB.  This volume starts on the next
	// sector and its Btrfs magic 64 KiB later crosses into the following read.
	volumeStart := uint64(scanChunk)
	image := make([]byte, int(volumeStart)+testMiB)
	scanTestPut(image, volumeStart+65536, scanTestBtrfsSuperblock(65536, testMiB))

	report, err := Scan(scanTestSource(image), DefaultScanOptions())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if report.BytesScanned != uint64(len(image)) {
		t.Fatalf("bytes scanned = %d, want %d", report.BytesScanned, len(image))
	}
	if len(report.Candidates) != 1 {
		t.Fatalf("candidates = %d, want 1: %#v", len(report.Candidates), report.Candidates)
	}
	if report.Candidates[0].Offset != volumeStart {
		t.Errorf("offset = %d, want %d", report.Candidates[0].Offset, volumeStart)
	}
	if report.Candidates[0].VolumeLen != testMiB {
		t.Errorf("volume length = %d, want %d", report.Candidates[0].VolumeLen, testMiB)
	}
}

func TestScanBtrfsMirrorIsNotASecondVolume(t *testing.T) {
	image := make([]byte, 2*testMiB)
	primary := scanTestBtrfsSuperblock(65536, 2*testMiB)
	scanTestPut(image, 65536, primary)

	// A copy that was moved without being rewritten: its own address field
	// still names the primary's position, which is what confirm rejects.
	mirror := append([]byte(nil), primary...)
	sp64(mirror, 48, testMiB)
	scanTestPut(image, testMiB, mirror)

	report, err := Scan(scanTestSource(image), DefaultScanOptions())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(report.Candidates) != 1 {
		t.Fatalf("candidates = %d, want 1: %#v", len(report.Candidates), report.Candidates)
	}
	if report.Candidates[0].Offset != 0 || report.Candidates[0].ID != "btrfs-volume" {
		t.Errorf("candidate = offset %d id %q, want 0 btrfs-volume",
			report.Candidates[0].Offset, report.Candidates[0].ID)
	}
	if report.Candidates[0].VolumeLen != 2*testMiB {
		t.Errorf("volume length = %d, want %d", report.Candidates[0].VolumeLen, 2*testMiB)
	}
	if report.RejectedHits != 1 {
		t.Errorf("rejected hits = %d, want 1", report.RejectedHits)
	}
}

func TestScanFindsLVM(t *testing.T) {
	image := make([]byte, 4*testMiB)
	// LABELONE is the signature; the label sector belongs to the volume at
	// 1 MiB, so it is placed 512 bytes into it.  CoreStorage has no anchor in
	// the Rust table, so it is only reachable through VolumeSignature and is
	// exercised by the direct verifier test instead.
	scanTestPut(image, testMiB+512, scanTestLVMLabel(false))

	report, err := Scan(scanTestSource(image), DefaultScanOptions())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(report.Candidates) != 1 {
		t.Fatalf("candidates = %d, want 1: %#v", len(report.Candidates), report.Candidates)
	}
	c := report.Candidates[0]
	if c.Offset != testMiB || c.ID != "lvm-volume" {
		t.Errorf("candidate = offset %d id %q, want %d lvm-volume", c.Offset, c.ID, testMiB)
	}
	if c.Status != CandidateStatusVerified || !strings.Contains(c.Reason, "CRC-32") {
		t.Errorf("candidate = %s %q, want verified CRC-32", c.Status, c.Reason)
	}
}

func TestScanExtVerificationStatuses(t *testing.T) {
	image := make([]byte, 8*testMiB)
	scanTestPut(image, 2*testMiB+1024, scanTestExtSuperblock(256, 2))
	scanTestPut(image, 3*testMiB+1024, scanTestSealedExtSuperblock(256, 2))
	corrupt := scanTestSealedExtSuperblock(256, 2)
	corrupt[0x3FC] ^= 0xFF
	scanTestPut(image, 4*testMiB+1024, corrupt)
	scanTestPut(image, 5*testMiB+1024, scanTestExtSuperblock(4096, 2))

	report, err := Scan(scanTestSource(image), DefaultScanOptions())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(report.Candidates) != 4 {
		t.Fatalf("candidates = %d, want 4: %#v", len(report.Candidates), report.Candidates)
	}

	c := report.Candidates
	if c[0].Status != CandidateStatusUnverified || !strings.Contains(c[0].Reason, "metadata_csum is off") {
		t.Errorf("candidate 0 = %s %q, want unverified metadata_csum is off", c[0].Status, c[0].Reason)
	}
	if c[1].Status != CandidateStatusVerified || !strings.Contains(c[1].Reason, "CRC-32C") {
		t.Errorf("candidate 1 = %s %q, want verified CRC-32C", c[1].Status, c[1].Reason)
	}
	if c[2].Status != CandidateStatusRejected || !strings.Contains(c[2].Reason, "crc32c") {
		t.Errorf("candidate 2 = %s %q, want rejected crc32c", c[2].Status, c[2].Reason)
	}
	if c[3].Status != CandidateStatusRejected || !strings.Contains(c[3].Reason, "declares") {
		t.Errorf("candidate 3 = %s %q, want rejected declares", c[3].Status, c[3].Reason)
	}
	if c[0].VolumeLen != testMiB || c[0].SizeBasis != "block count x block size" {
		t.Errorf("candidate 0 length = %d (%q), want %d (block count x block size)",
			c[0].VolumeLen, c[0].SizeBasis, testMiB)
	}
}

func TestScanZeroedSource(t *testing.T) {
	report, err := Scan(scanTestSource(make([]byte, testMiB)), DefaultScanOptions())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(report.Candidates) != 0 || report.RejectedHits != 0 || report.Truncated {
		t.Fatalf("unexpected report: %#v", report)
	}
}
