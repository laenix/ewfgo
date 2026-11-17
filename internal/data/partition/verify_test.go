package partition

import (
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/foundation"
)

// verifyHead returns a full scan head (the first 68 KiB of a candidate) with
// the given superblock placed at `at`.
func verifyHead(size int, at int, block []byte) []byte {
	head := make([]byte, size)
	copy(head[at:], block)
	return head
}

func TestVerifyBtrfsChecksum(t *testing.T) {
	superblock := scanTestBtrfsSuperblock(65536, testMiB)
	head := verifyHead(scanHeadLen, 65536, superblock)
	src := scanTestSource(head)

	got := VerifyCandidate(src, 0, "btrfs-volume", "Btrfs", head, testMiB)
	if got.Status != CandidateStatusVerified {
		t.Fatalf("status = %s (%q), want verified", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "crc32c") {
		t.Errorf("reason = %q, want crc32c named", got.Reason)
	}

	damaged := append([]byte(nil), superblock...)
	damaged[100] ^= 0xFF // covered by the checksum, not a geometry field
	head = verifyHead(scanHeadLen, 65536, damaged)
	got = VerifyCandidate(scanTestSource(head), 0, "btrfs-volume", "Btrfs", head, testMiB)
	if got.Status != CandidateStatusRejected {
		t.Fatalf("damaged status = %s (%q), want rejected", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "crc32c") {
		t.Errorf("damaged reason = %q, want crc32c named", got.Reason)
	}

	// A head that stops before the superblock cannot be verified.
	got = VerifyCandidate(scanTestSource(head), 0, "btrfs-volume", "Btrfs", head[:65536], testMiB)
	if got.Status != CandidateStatusRejected || !strings.Contains(got.Reason, "ends before") {
		t.Errorf("short head = %s (%q), want rejected ends before", got.Status, got.Reason)
	}
}

func TestVerifyLVMLabelCRC(t *testing.T) {
	label := scanTestLVMLabel(false)
	head := make([]byte, 1024)
	copy(head[512:], label)

	got := VerifyCandidate(scanTestSource(head), 0, "lvm-volume", "LVM2", head, testMiB)
	if got.Status != CandidateStatusVerified {
		t.Fatalf("status = %s (%q), want verified", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "CRC-32") {
		t.Errorf("reason = %q, want CRC-32 named", got.Reason)
	}

	corrupt := scanTestLVMLabel(true)
	head = make([]byte, 1024)
	copy(head[512:], corrupt)
	got = VerifyCandidate(scanTestSource(head), 0, "lvm-volume", "LVM2", head, testMiB)
	if got.Status != CandidateStatusRejected {
		t.Fatalf("corrupt status = %s (%q), want rejected", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "CRC-32") {
		t.Errorf("corrupt reason = %q, want CRC-32 named", got.Reason)
	}

	// The signature can be seen in a short head, but the label sector cannot
	// be checked: say so rather than inventing a verdict.
	got = VerifyCandidate(scanTestSource(head[:600]), 0, "lvm-volume", "LVM2", head[:600], testMiB)
	if got.Status != CandidateStatusUnverified || !strings.Contains(got.Reason, "truncated") {
		t.Errorf("short head = %s (%q), want unverified truncated", got.Status, got.Reason)
	}
}

func TestVerifyCoreStorageCRC(t *testing.T) {
	header := scanTestCoreStorageHeader(false)
	got := VerifyCandidate(scanTestSource(header), 0, "corestorage-volume", "Apple CoreStorage", header, testMiB)
	if got.Status != CandidateStatusVerified {
		t.Fatalf("status = %s (%q), want verified", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "CRC-32C") {
		t.Errorf("reason = %q, want CRC-32C named", got.Reason)
	}

	corrupt := scanTestCoreStorageHeader(true)
	got = VerifyCandidate(scanTestSource(corrupt), 0, "corestorage-volume", "Apple CoreStorage", corrupt, testMiB)
	if got.Status != CandidateStatusRejected {
		t.Fatalf("corrupt status = %s (%q), want rejected", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "CRC-32C") {
		t.Errorf("corrupt reason = %q, want CRC-32C named", got.Reason)
	}

	got = VerifyCandidate(scanTestSource(header[:256]), 0, "corestorage-volume", "Apple CoreStorage", header[:256], testMiB)
	if got.Status != CandidateStatusUnverified || !strings.Contains(got.Reason, "truncated") {
		t.Errorf("short head = %s (%q), want unverified truncated", got.Status, got.Reason)
	}
}

func TestVerifyXFSVersion5CRC(t *testing.T) {
	superblock := scanTestXFS5(1024)
	available := uint64(1024 * 4096)

	got := VerifyCandidate(scanTestSource(superblock), 0, "xfs-volume", "XFS", superblock, available)
	if got.Status != CandidateStatusVerified {
		t.Fatalf("status = %s (%q), want verified", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "version-5") || !strings.Contains(got.Reason, "CRC-32C") {
		t.Errorf("reason = %q, want version-5 CRC-32C", got.Reason)
	}

	damaged := append([]byte(nil), superblock...)
	damaged[0x40] ^= 0xFF // covered by the CRC, not a geometry field
	got = VerifyCandidate(scanTestSource(damaged), 0, "xfs-volume", "XFS", damaged, available)
	if got.Status != CandidateStatusRejected {
		t.Fatalf("damaged status = %s (%q), want rejected", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "crc32c") {
		t.Errorf("damaged reason = %q, want crc32c named", got.Reason)
	}

	// Version 4 has no CRC; the geometry fits, so it is unverified.
	v4 := scanTestXFS4(1024)
	got = VerifyCandidate(scanTestSource(v4), 0, "xfs-volume", "XFS", v4, available)
	if got.Status != CandidateStatusUnverified || !strings.Contains(got.Reason, "version 4") {
		t.Errorf("v4 = %s (%q), want unverified version 4", got.Status, got.Reason)
	}
}

func TestVerifyExtMetadataCsum(t *testing.T) {
	unsealed := scanTestExtSuperblock(256, 2)
	head := verifyHead(2048, 1024, unsealed)
	available := uint64(256 * 4096)
	got := VerifyCandidate(scanTestSource(head), 0, "ext-volume", "ext2/3/4", head, available)
	if got.Status != CandidateStatusUnverified || !strings.Contains(got.Reason, "metadata_csum is off") {
		t.Fatalf("unsealed = %s (%q), want unverified metadata_csum is off", got.Status, got.Reason)
	}

	sealed := scanTestSealedExtSuperblock(256, 2)
	head = verifyHead(2048, 1024, sealed)
	got = VerifyCandidate(scanTestSource(head), 0, "ext-volume", "ext2/3/4", head, available)
	if got.Status != CandidateStatusVerified || !strings.Contains(got.Reason, "CRC-32C") {
		t.Fatalf("sealed = %s (%q), want verified CRC-32C", got.Status, got.Reason)
	}

	corrupt := scanTestSealedExtSuperblock(256, 2)
	corrupt[0x3FC] ^= 0xFF
	head = verifyHead(2048, 1024, corrupt)
	got = VerifyCandidate(scanTestSource(head), 0, "ext-volume", "ext2/3/4", head, available)
	if got.Status != CandidateStatusRejected || !strings.Contains(got.Reason, "crc32c") {
		t.Fatalf("corrupt = %s (%q), want rejected crc32c", got.Status, got.Reason)
	}

	// A declared size the candidate cannot hold is a rejection.
	overrun := scanTestExtSuperblock(4096, 2) // 16 MiB
	head = verifyHead(2048, 1024, overrun)
	got = VerifyCandidate(scanTestSource(head), 0, "ext-volume", "ext2/3/4", head, testMiB)
	if got.Status != CandidateStatusRejected || !strings.Contains(got.Reason, "declares") {
		t.Fatalf("overrun = %s (%q), want rejected declares", got.Status, got.Reason)
	}
}

func TestVerifyJFFS2NodeCRC(t *testing.T) {
	node := scanTestJFFS2Node(40)
	got := VerifyCandidate(scanTestSource(node), 0, "jffs2-volume", "JFFS2", node, testMiB)
	if got.Status != CandidateStatusVerified || !strings.Contains(got.Reason, "CRC-32") {
		t.Fatalf("node = %s (%q), want verified CRC-32", got.Status, got.Reason)
	}

	bad := append([]byte(nil), node...)
	bad[8] ^= 0xFF
	got = VerifyCandidate(scanTestSource(bad), 0, "jffs2-volume", "JFFS2", bad, testMiB)
	if got.Status != CandidateStatusRejected || !strings.Contains(got.Reason, "CRC") {
		t.Fatalf("bad = %s (%q), want rejected CRC", got.Status, got.Reason)
	}

	got = VerifyCandidate(scanTestSource(node), 0, "jffs2-volume", "JFFS2", node, 20)
	if got.Status != CandidateStatusRejected || !strings.Contains(got.Reason, "declares") {
		t.Fatalf("overrun = %s (%q), want rejected declares", got.Status, got.Reason)
	}
}

func TestVerifyUnportedAndUnknownFormats(t *testing.T) {
	head := make([]byte, 1024)

	// A format verify.rs handles but whose Go parser is not ported yet.
	got := VerifyCandidate(scanTestSource(head), 0, "ntfs-volume", "NTFS", head, testMiB)
	if got.Status != CandidateStatusUnverified || !strings.Contains(got.Reason, "not ported") {
		t.Errorf("ntfs = %s (%q), want unverified not ported", got.Status, got.Reason)
	}

	// A signature verify.rs has no branch for: the Rust default reason.
	got = VerifyCandidate(scanTestSource(head), 0, "luks-volume", "LUKS", head, testMiB)
	if got.Status != CandidateStatusUnverified ||
		!strings.Contains(got.Reason, "no internal consistency check is implemented") {
		t.Errorf("luks = %s (%q), want unverified default reason", got.Status, got.Reason)
	}

	if CandidateStatusVerified.String() != "verified" ||
		CandidateStatusUnverified.String() != "unverified" ||
		CandidateStatusRejected.String() != "rejected" {
		t.Errorf("status strings are wrong: %q %q %q",
			CandidateStatusVerified, CandidateStatusUnverified, CandidateStatusRejected)
	}
}

// Guard the CRC primitive selection: the Btrfs seal must be the standard
// CRC-32C and the ext seal the un-inverted seeded form, or a real image would
// never verify.
func TestVerifyChecksumPrimitivesMatchTheFormats(t *testing.T) {
	block := make([]byte, 4096)
	for i := range block {
		block[i] = byte(i)
	}
	if got, want := foundation.CRC32C(block), foundation.CRC32CSeeded(0xFFFFFFFF, block); got != ^want {
		t.Fatalf("CRC32C = %#x, want inverted seeded %#x", got, ^want)
	}
}
