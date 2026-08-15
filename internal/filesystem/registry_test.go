package filesystem_test

import (
	"encoding/binary"
	"testing"

	"github.com/laenix/ewfgo/internal/filesystem"

	// Blank-import every filesystem subpackage so its init() registers the
	// reader-less factory (defabrication gate) and the reader-based handler in
	// the parent filesystem package. This mirrors how the root ewf package wires
	// them in; the parent package itself cannot import the subpackages (cycle).
	_ "github.com/laenix/ewfgo/internal/filesystem/apfs"
	_ "github.com/laenix/ewfgo/internal/filesystem/btrfs"
	_ "github.com/laenix/ewfgo/internal/filesystem/detect"
	_ "github.com/laenix/ewfgo/internal/filesystem/exfat"
	_ "github.com/laenix/ewfgo/internal/filesystem/ext4"
	_ "github.com/laenix/ewfgo/internal/filesystem/fat"
	_ "github.com/laenix/ewfgo/internal/filesystem/ntfs"
	_ "github.com/laenix/ewfgo/internal/filesystem/xfs"
)

// --- 解析红线 sweep (no fabricated data) ---

// TestNoFabricatedListings is the enforcement gate for the "解析红线": every
// registered filesystem, when produced by its registry factory (i.e. a fresh
// handler with no reader set), MUST return an explicit error from
// ListDirectory/GetFile/GetFileByPath/SearchFiles. No handler may produce
// directory or file data without a reader — canned listings are forbidden.
func TestNoFabricatedListings(t *testing.T) {
	for _, fsType := range filesystem.RegisteredFileSystems() {
		fs, err := filesystem.NewFileSystem(fsType)
		if err != nil {
			t.Errorf("%s: NewFileSystem: %v", fsType, err)
			continue
		}

		entries, err := fs.ListDirectory("/")
		if err == nil {
			t.Errorf("%s: ListDirectory returned nil error with %d entries on a reader-less handler", fsType, len(entries))
		}

		if _, err := fs.GetFile("/"); err == nil {
			t.Errorf("%s: GetFile returned nil error on a reader-less handler", fsType)
		}
		if _, err := fs.GetFileByPath("/"); err == nil {
			t.Errorf("%s: GetFileByPath returned nil error on a reader-less handler", fsType)
		}
		if _, err := fs.SearchFiles("/", func(fi filesystem.FileInfo) bool { return true }); err == nil {
			t.Errorf("%s: SearchFiles returned nil error on a reader-less handler", fsType)
		}
	}
}

// TestNoFabricatedListingsCoversAll pins that the defabrication-gate scan above
// really sweeps every registered filesystem type — an empty registry would make
// the gate vacuously pass.
func TestNoFabricatedListingsCoversAll(t *testing.T) {
	if n := len(filesystem.RegisteredFileSystems()); n == 0 {
		t.Fatal("no filesystem registered: the defabrication gate would be vacuous")
	}
}

// --- FAT12/16/32 registration ---

// TestNewFileSystemFATHonestError pins that the registry factory for the FAT
// family yields an honest-error handler: Open() may validate the boot sector,
// but directory data without a reader is impossible.
func TestNewFileSystemFATHonestError(t *testing.T) {
	for _, ft := range []filesystem.FileSystemType{filesystem.FS_FAT12, filesystem.FS_FAT16, filesystem.FS_FAT32} {
		fs, err := filesystem.NewFileSystem(ft)
		if err != nil {
			t.Fatalf("NewFileSystem(%s): %v", ft, err)
		}
		if entries, err := fs.ListDirectory("/"); err == nil {
			t.Fatalf("NewFileSystem(%s).ListDirectory should error (reader-less), got %d entries", ft, len(entries))
		}
	}
}

// --- DetectFileSystem probes ---

// TestDetectBtrfsMagicAtRealOffset pins the surviving detection path against
// the real btrfs superblock magic location (byte offset 0x10040), which is what
// a >=129-sector read window exposes.
func TestDetectBtrfsMagicAtRealOffset(t *testing.T) {
	buf := make([]byte, 0x10048)
	copy(buf[0x10040:0x10048], "_BHRfS_M")
	if got := filesystem.DetectFileSystem(buf); got != filesystem.FS_BTRFS {
		t.Fatalf("DetectFileSystem with btrfs magic at 0x10040 = %s, want %s", got, filesystem.FS_BTRFS)
	}
}

// TestDetectBtrfsRejectsLegacyOffsets guards against a regression to the
// pre-P0 probe, which checked offsets {64,1024,2048} and produced false
// FS_UNKNOWN / false Btrfs results. A magic planted at those offsets is not a
// real btrfs superblock and must never be reported as one.
func TestDetectBtrfsRejectsLegacyOffsets(t *testing.T) {
	for _, off := range []int{64, 1024, 2048} {
		buf := make([]byte, 0x10048)
		copy(buf[off:off+8], "_BHRfS_M")
		if got := filesystem.DetectFileSystem(buf); got == filesystem.FS_BTRFS {
			t.Fatalf("DetectFileSystem reported Btrfs for magic at legacy offset %d", off)
		}
	}
}

// TestDetectExt4LittleEndianMagic pins the consolidated path still detects
// ext4 via the little-endian s_magic (0xEF53) at offset 0x38 within the
// superblock (byte 1024 for 1K-block filesystems).
func TestDetectExt4LittleEndianMagic(t *testing.T) {
	buf := make([]byte, 2048)
	buf[1024+0x38] = 0x53
	buf[1024+0x39] = 0xEF
	if got := filesystem.DetectFileSystem(buf); got != filesystem.FS_EXT4 {
		t.Fatalf("DetectFileSystem ext4 = %s, want %s", got, filesystem.FS_EXT4)
	}
}

// --- ext4 registration ---

// TestExt4Registered pins that the registry can now construct ext4 (it was the
// one handler left unregistered after the XFS fix): NewFileSystem(FS_EXT4)
// returns a handler whose Type is ext4.
func TestExt4Registered(t *testing.T) {
	fs, err := filesystem.NewFileSystem(filesystem.FS_EXT4)
	if err != nil {
		t.Fatalf("NewFileSystem(FS_EXT4): %v", err)
	}
	if fs.Type() != filesystem.FS_EXT4 {
		t.Fatalf("Type() = %s, want ext4", fs.Type())
	}
}

// TestExt4ReaderlessHonestError pins that the registry factory's reader-less
// handler errors loudly on data operations instead of nil-dereferencing or
// fabricating a listing. The real listing path is ext4.NewExt4Handler (reader-based).
func TestExt4ReaderlessHonestError(t *testing.T) {
	fs, err := filesystem.NewFileSystem(filesystem.FS_EXT4)
	if err != nil {
		t.Fatalf("NewFileSystem(FS_EXT4): %v", err)
	}
	if _, err := fs.ListDirectory("/"); err == nil {
		t.Fatal("reader-less ext4 ListDirectory must return an explicit error")
	}
	if _, err := fs.GetFile("/etc/passwd"); err == nil {
		t.Fatal("reader-less ext4 GetFile must return an explicit error")
	}
}

// TestDetectAndOpen_Ext4Magic runs the full detection pipeline on a minimal
// valid ext4 superblock: the magic 0x53EF at offset 1024+0x38 must detect ext4
// and DetectAndOpen must return a constructible handler.
func TestDetectAndOpen_Ext4Magic(t *testing.T) {
	sb := make([]byte, 2048) // cover superblock at byte 1024
	binary.LittleEndian.PutUint16(sb[1024+0x38:], 0xEF53) // ext4 s_magic

	fs, err := filesystem.DetectAndOpen(sb)
	if err != nil {
		t.Fatalf("DetectAndOpen on ext4 superblock: %v", err)
	}
	if fs.Type() != filesystem.FS_EXT4 {
		t.Fatalf("Type() = %s, want ext4", fs.Type())
	}
}

// --- XFS registration ---

func TestXFSRegistered(t *testing.T) {
	fs, err := filesystem.NewFileSystem(filesystem.FS_XFS)
	if err != nil {
		t.Fatalf("NewFileSystem(FS_XFS): %v", err)
	}
	if fs.Type() != filesystem.FS_XFS {
		t.Fatalf("Type() = %s, want XFS", fs.Type())
	}
}

func TestDetectAndOpen_XFSMagic(t *testing.T) {
	// A minimal valid XFS superblock: "XFSB" + the real big-endian field
	// offsets (see xfs.go: agcount@0x58, agblocks@0x54, rootino@0x38,
	// inodesize@0x68, inopblock@0x6a). blocksize=4096 and agblocks=1000 also
	// satisfy DetectFileSystem's detection validation.
	sb := make([]byte, 512)
	copy(sb[0:4], "XFSB")
	binary.BigEndian.PutUint32(sb[0x04:], 4096)         // blocksize
	binary.BigEndian.PutUint64(sb[0x08:], 65536)        // dblocks
	binary.BigEndian.PutUint64(sb[0x38:], 128)          // rootino
	binary.BigEndian.PutUint32(sb[0x54:], 1000)         // agblocks
	binary.BigEndian.PutUint32(sb[0x58:], 1)            // agcount
	binary.BigEndian.PutUint16(sb[0x68:], 512)          // inodesize
	binary.BigEndian.PutUint16(sb[0x6a:], 8)            // inopblock
	copy(sb[0x6c:0x78], "FIXTURE")                     // fname
	sb[0x78], sb[0x79], sb[0x7a], sb[0x7b] = 12, 9, 9, 3 // blocklog, sectlog, inodelog, inopblog

	fs, err := filesystem.DetectAndOpen(sb)
	if err != nil {
		t.Fatalf("DetectAndOpen on XFS superblock: %v", err)
	}
	if fs.Type() != filesystem.FS_XFS {
		t.Fatalf("Type() = %s, want XFS", fs.Type())
	}
}
