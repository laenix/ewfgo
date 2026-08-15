package ewf

// This file implements the public Evidence bridge: it exposes a single
// partition's filesystem through the forensic-engine Evidence method set
// (Size / ReadBlock / ListDir / ReadFile).
//
// ewfgo deliberately does NOT import forensic-engine. The two libraries stay
// dependency-free; a consumer adapts structurally. FileEntry is declared here
// with field shapes identical to forensic-engine's FileEntry, so the adapter
// is a trivial field copy.
//
// Correctness contract (forensics): a read that cannot be served correctly
// MUST return an error, never wrong bytes. In particular:
//   - All sector reads route through readerAdapter -> internal ReadSectorData
//     for exact decompression. The public EWFImage.ReadSectors simply forwards
//     to that same exact-decompression path (read.go) and is used only by the
//     convenience API (ReadSector, MBR, GPT); it never returns raw EWF
//     container bytes as disk data.
//   - Reads that extend past the partition size return the readable prefix
//     plus io.EOF; the tail is never fabricated.
//   - Unsupported filesystems and unimplemented file interfaces return
//     explicit errors.

import (
	"fmt"
	"io"
	"path"
	"strings"
	"sync"

	"github.com/laenix/ewfgo/internal"
	"github.com/laenix/ewfgo/internal/filesystem"

	// Blank-importing every filesystem subpackage fires each one's init(), which
	// registers its reader-less factory (the defabrication gate behind
	// NewFileSystem) and its reader-based constructor (the handler registry
	// behind NewHandler) in the parent filesystem package. The parent never
	// imports the subpackages itself — every subpackage imports the parent, so
	// a direct import would be a cycle.
	_ "github.com/laenix/ewfgo/internal/filesystem/apfs"
	_ "github.com/laenix/ewfgo/internal/filesystem/btrfs"
	_ "github.com/laenix/ewfgo/internal/filesystem/detect"
	_ "github.com/laenix/ewfgo/internal/filesystem/exfat"
	_ "github.com/laenix/ewfgo/internal/filesystem/ext4"
	_ "github.com/laenix/ewfgo/internal/filesystem/fat"
	_ "github.com/laenix/ewfgo/internal/filesystem/ntfs"
	_ "github.com/laenix/ewfgo/internal/filesystem/xfs"
)

// FileEntry describes one file or directory inside a partition's filesystem.
// Its field shapes are deliberately identical to forensic-engine's FileEntry
// so a consumer can adapt with a trivial field-by-field copy.
type FileEntry struct {
	Name    string
	Path    string
	Size    int64
	IsDir   bool
	ModTime int64
}

// ImageFS exposes one partition's filesystem through the Evidence method set.
// All reads are guarded by a mutex because consumers parse concurrently.
//
// fs holds the real reader-based handler for the partition's filesystem (FAT32,
// exFAT, NTFS, ext4, XFS, Btrfs or APFS); it is nil only for a closed ImageFS.
type ImageFS struct {
	mu         sync.Mutex
	img        *EWFImage
	part       PartitionInfo
	fs         filesystem.FileSystem
	sectorSize uint32
	fsType     filesystem.FileSystemType
}

// readerAdapter adapts the internal EWF decompressor to filesystem.Reader.
// All sector reads go through internal ReadSectorData, the exact-decompression
// path; raw EWF container bytes are never surfaced as disk data.
type readerAdapter struct {
	img *internal.EWFImage
}

// ReadSectors implements filesystem.Reader using exact decompression.
func (r readerAdapter) ReadSectors(lba uint64, count uint64) ([]byte, error) {
	if r.img == nil {
		return nil, fmt.Errorf("read source closed")
	}
	return r.img.ReadSectorData(lba, count)
}

// OpenFileSystem opens the filesystem of the partition with the given Index,
// where Index is the zero-based position of the partition in the slice returned
// by ScanFileSystems (PartitionInfo.Index). index <= 0 selects the first
// partition.
//
// Every supported filesystem is wired to its real reader-based handler, which
// reads and validates the on-disk structures itself (all sector reads go
// through readerAdapter -> internal ReadSectorData for exact decompression).
// The handler for fsType is looked up in filesystem.NewHandler, populated by
// the filesystem subpackage init()s (see the blank imports above): fat, ntfs,
// ext4, xfs, btrfs, apfs and exfat register reader-based constructors, while
// the detect-only types (HFS+, F2FS, ReFS, ZFS, SquashFS, RAID, BitLocker,
// LUKS) have no reader-based handler and resolve to an explicit error.
//
// An unsupported filesystem label returns an explicit error; nothing is faked.
func (e *EWFImage) OpenFileSystem(index int) (*ImageFS, error) {
	if e == nil || e.ewf == nil || e.ewf.Filepath() == "" {
		return nil, fmt.Errorf("no EWF image opened")
	}

	parts, err := e.ScanFileSystems()
	if err != nil {
		return nil, fmt.Errorf("failed to scan filesystems: %w", err)
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("no partitions found in image")
	}

	var part *PartitionInfo
	if index <= 0 {
		part = &parts[0]
	} else {
		for i := range parts {
			if parts[i].Index == index {
				part = &parts[i]
				break
			}
		}
		if part == nil {
			return nil, fmt.Errorf("partition index %d not found (image has %d partitions)", index, len(parts))
		}
	}

	fsType := resolveFSType(*part)
	sectorSize := e.SectorSize()
	if sectorSize == 0 {
		sectorSize = 512
	}
	reader := readerAdapter{img: e.ewf}

	fs := &ImageFS{
		img:        e,
		part:       *part,
		sectorSize: sectorSize,
		fsType:     fsType,
	}

	h, err := filesystem.NewHandler(fsType, reader, part.StartSector, part.SizeSectors*uint64(sectorSize))
	if err != nil {
		return nil, fmt.Errorf("partition %d: init %s filesystem at sector %d: %w", part.Index, fsType, part.StartSector, err)
	}
	fs.fs = h

	// ScanFileSystems never populates PartitionInfo.FilesystemType, so fill it
	// from the resolved type.
	fs.part.FilesystemType = fsType
	return fs, nil
}

// resolveFSType returns the filesystem type to open. ScanFileSystems leaves
// PartitionInfo.FilesystemType unset and only fills the FileSystem label, so
// we prefer the typed field (future-proof) and fall back to the label.
func resolveFSType(part PartitionInfo) filesystem.FileSystemType {
	if part.FilesystemType != "" {
		return part.FilesystemType
	}
	return filesystem.FileSystemType(part.FileSystem)
}

// Size returns the logical size of the partition in bytes.
func (fs *ImageFS) Size() int64 {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return int64(fs.part.SizeSectors) * int64(fs.sectorSize)
}

// ReadBlock reads raw partition-relative bytes at offset off into p.
// It returns io.EOF when off is at or past the end of the partition, and
// when the requested range extends past the partition end it copies the
// readable prefix and returns n < len(p) together with io.EOF. Bytes past the
// partition are never fabricated. off need not be sector-aligned.
func (fs *ImageFS) ReadBlock(off int64, p []byte) (int, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.img == nil {
		return 0, fmt.Errorf("filesystem closed")
	}
	size := int64(fs.part.SizeSectors) * int64(fs.sectorSize)
	if off < 0 {
		return 0, fmt.Errorf("negative read offset %d", off)
	}
	if off >= size {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}

	// Bytes we can actually serve starting at off, clamped to the partition.
	want := int64(len(p))
	if want > size-off {
		want = size - off
	}
	if want <= 0 {
		return 0, io.EOF
	}

	ss := int64(fs.sectorSize)
	startSector := off / ss
	intra := off % ss
	endSector := (off + want + ss - 1) / ss
	count := endSector - startSector

	raw, err := fs.img.ewf.ReadSectorData(fs.part.StartSector+uint64(startSector), uint64(count))
	if err != nil {
		return 0, fmt.Errorf("partition %d: read sectors %d..%d (image LBA %d..%d): %w",
			fs.part.Index, startSector, endSector,
			fs.part.StartSector+uint64(startSector), fs.part.StartSector+uint64(endSector), err)
	}
	if expected := count * ss; int64(len(raw)) < expected {
		return 0, fmt.Errorf("partition %d: short decompressed read: got %d bytes, want %d",
			fs.part.Index, len(raw), expected)
	}

	avail := raw[intra:]
	n := int(want)
	if len(avail) < n {
		return 0, fmt.Errorf("partition %d: decompressed data truncated at offset %d", fs.part.Index, off)
	}
	copy(p[:n], avail[:n])

	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// ListDir returns the entries of the directory at path ("" or "/" is the
// root). The path may be given with '/' or '\' separators; it is normalized
// to '/' before delegation so the same call behaves identically on every OS.
// Each returned entry's Path is rewritten to
// path.Join(listingPath, entry.Name) so a consumer's WalkTree can recurse by
// calling ListDir on it.
func (fs *ImageFS) ListDir(listingPath string) ([]FileEntry, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.img == nil {
		return nil, fmt.Errorf("filesystem closed")
	}

	// Normalize '\'-separated caller paths to '/' before the handler splits on
	// "/" (see normalizeInternalPath), so a Windows-style path works on every OS.
	// The returned entry Paths are built from the normalized form so a consumer's
	// recursion sees consistent '/'-separated paths.
	listingPath = normalizeInternalPath(listingPath)
	raw, err := fs.fs.ListDirectory(listingPath)
	if err != nil {
		return nil, fmt.Errorf("partition %d: list %q: %w", fs.part.Index, listingPath, err)
	}

	entries := make([]FileEntry, 0, len(raw))
	for _, e := range raw {
		entries = append(entries, FileEntry{
			Name:    e.Name,
			Path:    path.Join(listingPath, e.Name),
			Size:    int64(e.Size),
			IsDir:   e.IsDir,
			ModTime: e.ModTime,
		})
	}
	return entries, nil
}

// ReadFile returns the full content of the file at path.
func (fs *ImageFS) ReadFile(filePath string) ([]byte, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.img == nil {
		return nil, fmt.Errorf("filesystem closed")
	}

	// Normalize '\'-separated caller paths to '/' (see normalizeInternalPath).
	data, err := fs.fs.GetFile(normalizeInternalPath(filePath))
	if err != nil {
		return nil, fmt.Errorf("partition %d: read %q: %w", fs.part.Index, filePath, err)
	}
	return data, nil
}

// OpenFile opens the file at path for streaming reads, returning a lazy,
// seekable io.ReadSeekCloser. Reads touch only the clusters/extents
// intersecting the accessed byte range, so memory is O(read block), not
// O(file) — the path for GB-scale files (sqlite databases) that ReadFile
// cannot hold in memory. The reader is independent of this ImageFS mutex: it
// reads through the same exact-decompression sector path, so several open
// files may be read concurrently, and each handle's ReadAt is safe for
// concurrent use on that handle.
//
// FAT12/16/32, exFAT and NTFS implement streaming today; every other filesystem
// returns an explicit unsupported error (errors.Is(err, ewf.ErrUnsupported)).
func (fs *ImageFS) OpenFile(filePath string) (io.ReadSeekCloser, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.img == nil {
		return nil, fmt.Errorf("filesystem closed")
	}
	opener, ok := fs.fs.(filesystem.FileOpener)
	if !ok {
		return nil, fmt.Errorf("partition %d: streaming reads not supported for %s: %w",
			fs.part.Index, fs.fsType, filesystem.ErrUnsupported)
	}
	r, err := opener.OpenFile(normalizeInternalPath(filePath))
	if err != nil {
		return nil, fmt.Errorf("partition %d: open %q: %w", fs.part.Index, filePath, err)
	}
	return r, nil
}

// StoredHashes returns the acquisition hashes stored in the underlying E01
// image, exposing evidence seal verification at the filesystem layer. A nil
// slice means the image carries no such hash.
func (fs *ImageFS) StoredHashes() (md5Hash, sha1Hash []byte) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.img == nil {
		return nil, nil
	}
	return fs.img.StoredHashes()
}

// VerifyImageHash streams the entire media data of the underlying E01 image
// through the exact-decompression read path and compares the computed MD5/SHA1
// against the acquisition hashes stored in the image. This is the end-to-end
// integrity check at the filesystem layer: a match means every byte this
// ImageFS can serve is byte for byte the data the forensic tool acquired.
func (fs *ImageFS) VerifyImageHash() (*HashVerifyResult, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.img == nil {
		return nil, fmt.Errorf("filesystem closed")
	}
	return fs.img.VerifyImageHash()
}

// Close releases the filesystem handler and drops the reference to the image.
// All further calls return an error.
func (fs *ImageFS) Close() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	var err error
	if fs.fs != nil {
		err = fs.fs.Close()
		fs.fs = nil
	}
	fs.img = nil
	return err
}

// FSType returns the resolved filesystem type of this ImageFS.
func (fs *ImageFS) FSType() filesystem.FileSystemType {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.fsType
}

// normalizeInternalPath converts a caller-supplied directory or file path into
// the '/' -separated form the filesystem handlers expect. EWF image contents are
// OS-neutral, but a consumer (especially on Windows) may pass a '\'-separated
// path; the handlers split paths on '/' and join with path.Join, so a literal
// backslash must be translated before any handler sees it. Root ("" , "/" , "\")
// normalizes to "/". This is a pure string transform: it never touches the host
// filesystem, so it is byte-identical on every OS.
func normalizeInternalPath(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}
