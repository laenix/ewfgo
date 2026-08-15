package filesystem

import (
	"math/rand"
	"testing"
)

// Probe regression tests for DetectFileSystem. They build small in-memory
// sector windows (hermetic, no fixtures) and pin the corrected HFS+/APFS/ext4
// probes to the real on-disk layouts, asserting both the positive (correct
// magic -> correct type) and negative (old-bug bytes / non-standard offsets ->
// NOT that type) directions so the probes cannot silently regress into false
// positives.

// TestProbeHFSPlus verifies the HFS+ volume-header probe.
//
// Apple TN1150 "HFS Plus Volume Format" places the volume header at byte 1024:
// a 16-bit big-endian signature "H+" (0x482B) for HFS+ / "HX" (0x4858) for
// HFSX, followed by a 16-bit big-endian version (0x0004 / 0x0005). The old
// probe compared the whole 32-bit word to 0x482B0000 (version 0), which no
// real volume carries; the corrected probe requires the real version.
func TestProbeHFSPlus(t *testing.T) {
	// Positive: HFS+ signature "H+" + version 4 -> bytes 0x48 0x2B 0x00 0x04.
	buf := make([]byte, 5120)
	copy(buf[1024:1028], []byte{0x48, 0x2B, 0x00, 0x04})
	if got := DetectFileSystem(buf); got != FS_HFS {
		t.Fatalf("HFS+ header at 1024: DetectFileSystem = %q, want %q", got, FS_HFS)
	}

	// Positive: HFSX signature "HX" + version 5 -> bytes 0x48 0x58 0x00 0x05.
	bufX := make([]byte, 5120)
	copy(bufX[1024:1028], []byte{0x48, 0x58, 0x00, 0x05})
	if got := DetectFileSystem(bufX); got != FS_HFS {
		t.Fatalf("HFSX header at 1024: DetectFileSystem = %q, want %q", got, FS_HFS)
	}

	// Negative: version 0x0000 (old bug 0x482B0000) never occurs on a real
	// volume; the strict probe must NOT claim HFS+.
	bad := make([]byte, 5120)
	copy(bad[1024:1028], []byte{0x48, 0x2B, 0x00, 0x00})
	if got := DetectFileSystem(bad); got == FS_HFS {
		t.Fatalf("0x482B0000 (version 0) must not detect HFS+; got %q", got)
	}
}

// TestProbeAPFS verifies the APFS container-superblock probe.
//
// Apple File System Reference (nx_superblock): the container superblock starts
// at partition offset 0; after the 32-byte obj_phys header the 4-byte nx_magic
// literal "NXSB" (0x4E 0x58 0x53 0x42) sits at offset 0x20. The old probe read
// an 8-byte little-endian word at 4096 and compared against
// 0x4141504653455250 (on-disk bytes "PRESFPAA") — a constant that can never
// match a real volume and was dead code for the 4096-byte GPT caller window
// anyway.
func TestProbeAPFS(t *testing.T) {
	// Positive: "NXSB" at offset 0x20 in a 512-byte window.
	buf := make([]byte, 512)
	copy(buf[0x20:0x24], []byte{'N', 'X', 'S', 'B'})
	if got := DetectFileSystem(buf); got != FS_APFS {
		t.Fatalf("NXSB at 0x20: DetectFileSystem = %q, want %q", got, FS_APFS)
	}

	// Negative: the old probe's constant decodes to on-disk bytes "PRESFPAA";
	// placed at the corrected probe's location it must not claim APFS.
	bad := make([]byte, 512)
	copy(bad[0x20:0x28], []byte("PRESFPAA"))
	if got := DetectFileSystem(bad); got == FS_APFS {
		t.Fatalf("old PRESFPAA constant must not detect APFS; got %q", got)
	}

	// Negative: the old probe's location (4096..4104) is dead — no probe may
	// consult it. A 4104-byte window with the old constant bytes there must
	// not claim APFS.
	bad2 := make([]byte, 4104)
	copy(bad2[4096:4104], []byte("PRESFPAA"))
	if got := DetectFileSystem(bad2); got == FS_APFS {
		t.Fatalf("PRESFPAA at offset 4096 must not detect APFS; got %q", got)
	}
}

// TestProbeExt4 verifies the ext2/3/4 superblock probe.
//
// The ext4 superblock always sits at byte 1024 from the partition start (for
// every block size, block 0 holds the 1024-byte boot block then the
// superblock); its s_magic 0xEF53 (little-endian) is at 1024+0x38. The old
// probe also consulted 2048 and 4096, which are not superblock locations and
// can false-positive on stray 0xEF53 bytes.
func TestProbeExt4(t *testing.T) {
	// Positive: s_magic at 1024+0x38.
	buf := make([]byte, 4096)
	buf[1024+0x38] = 0x53
	buf[1024+0x39] = 0xEF
	if got := DetectFileSystem(buf); got != FS_EXT4 {
		t.Fatalf("ext4 s_magic at 1024+0x38: DetectFileSystem = %q, want %q", got, FS_EXT4)
	}

	// Negative: s_magic at 2048+0x38 / 4096+0x38 (old false-positive offsets).
	for _, sbOff := range []int{2048, 4096} {
		b := make([]byte, 4096+sbOff) // >= sbOff+0x3A
		b[sbOff+0x38] = 0x53
		b[sbOff+0x39] = 0xEF
		if got := DetectFileSystem(b); got == FS_EXT4 {
			t.Fatalf("s_magic at offset %d must not detect ext4; got %q", sbOff, got)
		}
	}
}

// TestProbeSanity asserts neutral data claims no filesystem: an all-zero
// window and a deterministic random-fill window must not be one of the three
// corrected types.
func TestProbeSanity(t *testing.T) {
	if got := DetectFileSystem(make([]byte, 4096)); got != FS_UNKNOWN {
		t.Fatalf("all-zero buffer: DetectFileSystem = %q, want %q", got, FS_UNKNOWN)
	}

	rng := rand.New(rand.NewSource(42))
	rnd := make([]byte, 4096)
	rng.Read(rnd)
	if got := DetectFileSystem(rnd); got == FS_HFS || got == FS_APFS || got == FS_EXT4 {
		t.Fatalf("random-fill buffer claimed corrected type %q", got)
	}
}
