package forensic

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/laenix/ewfgo/internal/data/filesystems/cramfs"
	"github.com/laenix/ewfgo/internal/data/filesystems/erofs"
	"github.com/laenix/ewfgo/internal/data/filesystems/f2fs"
	"github.com/laenix/ewfgo/internal/data/filesystems/hfsplus"
	"github.com/laenix/ewfgo/internal/data/filesystems/iso9660"
	"github.com/laenix/ewfgo/internal/data/filesystems/jfs"
	"github.com/laenix/ewfgo/internal/data/filesystems/minix"
	"github.com/laenix/ewfgo/internal/data/filesystems/probe"
	"github.com/laenix/ewfgo/internal/data/filesystems/reiserfs"
	"github.com/laenix/ewfgo/internal/data/filesystems/squashfs"
	"github.com/laenix/ewfgo/internal/data/filesystems/sysv"
	"github.com/laenix/ewfgo/internal/data/filesystems/udf"
	"github.com/laenix/ewfgo/internal/data/filesystems/ufs"
	"github.com/laenix/ewfgo/internal/data/filesystems/vmfs"
	"github.com/laenix/ewfgo/internal/data/filesystems/volume"
	"github.com/laenix/ewfgo/internal/data/source"
	"github.com/laenix/ewfgo/internal/filesystem"
)

// Entry describes one directory entry. Path is absolute and '/'-separated,
// independent of the host OS.
type Entry struct {
	Name string
	Path string

	Size uint64

	IsDir     bool
	IsSymlink bool
	// Deleted marks an entry recovered from deleted metadata. Live entries are
	// false.
	Deleted bool

	// Mode holds POSIX permission/type bits when the filesystem records them;
	// 0 when it does not (FAT, exFAT, NTFS).
	Mode uint32
	UID  uint32
	GID  uint32
	// Inode is the filesystem's native handle (inode number, MFT record or
	// first cluster); 0 when the format has none.
	Inode uint64

	// Times are zero when the filesystem records no such timestamp.
	Modified time.Time
	Accessed time.Time
	Created  time.Time

	SymlinkTarget string
}

// FSInfo describes a mounted filesystem.
type FSInfo struct {
	Type       string
	Label      string
	UUID       string
	BlockSize  uint32
	SectorSize uint32
	ReadOnly   bool
}

// WalkFunc receives every entry below a walk root, in depth-first order. Return
// ErrSkipDir to skip a directory's children; any other error stops the walk.
type WalkFunc func(entry Entry) error

// ErrSkipDir stops the walk below the current directory.
var ErrSkipDir = errors.New("forensic: skip directory")

// FileSystem is a read-only filesystem view. All paths are '/'-separated and
// absolute; a leading '\' is accepted and normalized.
type FileSystem interface {
	// Type returns the filesystem type label ("NTFS", "ext4", "HFS+", ...).
	Type() string
	// Info returns volume metadata captured at open.
	Info() FSInfo
	// ListDir returns the direct children of a directory.
	ListDir(ctx context.Context, dir string) ([]Entry, error)
	// Stat returns one entry.
	Stat(ctx context.Context, path string) (*Entry, error)
	// Open opens a regular file for streaming reads.
	Open(ctx context.Context, path string) (*File, error)
	// Walk visits every entry below root, depth first. It does not follow
	// symbolic links. Writes directories to a filesystem are not possible.
	Walk(ctx context.Context, root string, fn WalkFunc) error
	// Close releases parser resources. The image source stays open.
	Close() error
}

// openFilesystem routes a detected volume to its reader.
func openFilesystem(src ByteSource, kind probe.Kind, sector uint32, limits Limits) (FileSystem, error) {
	if src == nil {
		return nil, fmt.Errorf("%w: nil volume source", ErrInvalidArgument)
	}
	if sector < 512 || sector&(sector-1) != 0 {
		return nil, fmt.Errorf("%w: invalid sector size %d", ErrInvalidArgument, sector)
	}
	if kind.Encrypted() {
		return nil, fmt.Errorf("%w: %s volume is encrypted and no key was supplied", ErrDecrypt, kind.Label())
	}

	switch kind {
	case probe.NTFS, probe.ExFAT, probe.FAT, probe.Ext, probe.XFS, probe.Btrfs, probe.APFS:
		v, err := volume.Open(src, sector)
		if err != nil {
			return nil, err
		}
		return newOldFS(v, sector, limits), nil

	case probe.HFSPlus:
		return openHFSPlus(src, sector, limits)
	case probe.F2FS:
		return openF2FS(src, sector, limits)
	case probe.SquashFS:
		return openSquashFS(src, sector, limits)
	case probe.ISO9660:
		return openISO9660(src, sector, limits)
	case probe.UDF:
		return openUDF(src, sector, limits)
	case probe.CramFS:
		return openCramFS(src, sector, limits)
	case probe.EROFS:
		return openEROFS(src, sector, limits)
	case probe.JFS:
		return openJFS(src, sector, limits)
	case probe.ReiserFS:
		return openReiserFS(src, sector, limits)
	case probe.VMFS:
		return openVMFS(src, sector, limits)
	case probe.Minix:
		return openMinix(src, sector, limits)
	case probe.SysV:
		return openSysV(src, sector, limits)
	case probe.UFS:
		return openUFS(src, sector, limits)
	case probe.HPFS:
		return openHPFS(src, sector, limits)
	case probe.GFS2:
		return openGFS2(src, sector, limits)
	case probe.NILFS2:
		return openNILFS2(src, sector, limits)
	case probe.OCFS2:
		return openOCFS2(src, sector, limits)
	case probe.BeFS:
		return openBeFS(src, sector, limits)
	case probe.UBIFS:
		return openUBIFS(src, sector, limits)
	case probe.HFSClassic:
		return openHFSClassic(src, sector, limits)
	case probe.YAFFS:
		return openYAFFS(src, sector, limits)
	case probe.JFFS2:
		return openJFFS2(src, sector, limits)
	case probe.HAMMER2:
		return openHAMMER2(src, sector, limits)
	case probe.ZFS:
		return openZFS(src, sector, limits)
	case probe.QNX6:
		return openQNX6(src, sector, limits)

	case probe.None:
		return nil, fmt.Errorf("%w: no filesystem signature at the volume start", ErrUnsupported)
	default:
		return nil, fmt.Errorf("%w: %s filesystem reads are not implemented yet", ErrUnsupported, kind.Label())
	}
}

// volumeLabel refines a probe result into the display label of the concrete
// reader: FAT becomes FAT12/16/32 and ext becomes ext4, matching the handler
// that OpenFilesystem selects. Formats with no reader keep the probe label.
func volumeLabel(src ByteSource, kind probe.Kind) string {
	switch kind {
	case probe.NTFS, probe.ExFAT, probe.FAT, probe.Ext, probe.XFS, probe.Btrfs, probe.APFS:
		if typ, err := volume.Detect(src); err == nil && typ != filesystem.FS_UNKNOWN {
			return string(typ)
		}
	}
	return kind.Label()
}

// normalizePath converts a caller path to the '/'-separated form the parsers
// expect. Root ("" and "\\") stays "" here; each parser treats "" as root.
func normalizePath(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

func entryPath(dir, name string) string {
	return path.Join("/", dir, name)
}

func unixTime(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}

var nextMaterializedID atomic.Uint64

// --- File ------------------------------------------------------------------

// File is a streaming read-only file handle. It implements io.ReadSeekCloser
// and io.ReaderAt. Reads outside the file return io.EOF and never fabricate
// bytes.
type File struct {
	entry Entry
	size  uint64
	max   uint64

	mu     sync.Mutex
	pos    int64
	src    ByteSource
	stream io.ReadSeekCloser
	closer io.Closer
	closed bool
}

// Entry returns the file's directory entry.
func (f *File) Entry() Entry { return f.entry }

// Source returns the byte source backing the file when the filesystem reader
// exposes one. Legacy stream-only handles return nil; use OpenSource for a
// materialized source in that case.
func (f *File) Source() ByteSource { return f.src }

// OpenSource returns a byte source over the file's content. Readers that expose
// a source (the byte-source filesystem readers and archive entries) return it
// directly. A legacy stream-only handle is materialized through ReadAll (and
// therefore Limits.MaxFileBytes). The returned source never contains invented
// bytes.
func (f *File) OpenSource() (ByteSource, error) {
	if f.src != nil {
		return f.src, nil
	}
	data, err := f.ReadAll()
	if err != nil {
		return nil, err
	}
	id := source.ID(nextMaterializedID.Add(1) + 1_000_000)
	return source.NewMemorySourceWithImage(id, 0, data), nil
}

// Size returns the file's byte length.
func (f *File) Size() uint64 { return f.size }

// Read implements io.Reader from the current seek position.
func (f *File) Read(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, os.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	if f.pos < 0 || uint64(f.pos) >= f.size {
		return 0, io.EOF
	}
	want := uint64(len(p))
	if want > f.size-uint64(f.pos) {
		want = f.size - uint64(f.pos)
	}
	var (
		n   int
		err error
	)
	if f.stream != nil {
		// ReadAt/Seek move the underlying stream, so re-sync it to the logical
		// read position before every Read.
		if _, err = f.stream.Seek(f.pos, io.SeekStart); err == nil {
			n, err = f.stream.Read(p[:want])
		}
	} else {
		n, err = f.src.ReadAt(uint64(f.pos), p[:want])
		if errors.Is(err, ErrOutOfRange) {
			err = io.EOF
		}
	}
	f.pos += int64(n)
	if err == nil && uint64(n) < uint64(len(p)) {
		err = io.EOF
	}
	return n, err
}

// ReadAt implements io.ReaderAt. It does not change the seek position.
func (f *File) ReadAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, os.ErrClosed
	}
	if off < 0 {
		return 0, fmt.Errorf("%w: negative offset %d", ErrInvalidArgument, off)
	}
	if uint64(off) >= f.size {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	want := uint64(len(p))
	if want > f.size-uint64(off) {
		want = f.size - uint64(off)
	}
	var (
		n   int
		err error
	)
	if f.stream != nil {
		if _, err = f.stream.Seek(off, io.SeekStart); err == nil {
			n, err = f.stream.Read(p[:want])
		}
	} else {
		n, err = f.src.ReadAt(uint64(off), p[:want])
		if errors.Is(err, ErrOutOfRange) {
			err = io.EOF
		}
	}
	if err == nil && uint64(n) < uint64(len(p)) {
		err = io.EOF
	}
	return n, err
}

// Seek implements io.Seeker.
func (f *File) Seek(offset int64, whence int) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, os.ErrClosed
	}
	var next int64
	switch whence {
	case io.SeekStart:
		next = offset
	case io.SeekCurrent:
		next = f.pos + offset
	case io.SeekEnd:
		next = int64(f.size) + offset
	default:
		return 0, fmt.Errorf("%w: invalid whence %d", ErrInvalidArgument, whence)
	}
	if next < 0 {
		return 0, fmt.Errorf("%w: negative seek position", ErrInvalidArgument)
	}
	if f.stream != nil {
		n, err := f.stream.Seek(next, io.SeekStart)
		if err != nil {
			return 0, err
		}
		f.pos = n
		return n, nil
	}
	f.pos = next
	return next, nil
}

// defaultReadAllLimit bounds a whole-file read when the caller set no explicit
// MaxFileBytes. It prevents a metadata-declared (attacker-influenced) size from
// forcing an unbounded allocation; raise Limits.MaxFileBytes to read more.
const defaultReadAllLimit = 1 << 30

// ReadAll returns the whole file. It errors rather than allocate more than the
// configured MaxFileBytes limit (1 GiB when unset).
func (f *File) ReadAll() ([]byte, error) {
	limit := f.max
	if limit == 0 {
		limit = defaultReadAllLimit
	}
	if f.size > limit {
		return nil, fmt.Errorf("%w: file is %d bytes, MaxFileBytes limit is %d",
			ErrUnsupported, f.size, limit)
	}
	buf := make([]byte, f.size)
	n, err := f.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf[:n], nil
}

// Close releases the handle. It is idempotent.
func (f *File) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	var firstErr error
	if f.stream != nil {
		firstErr = f.stream.Close()
	}
	if f.closer != nil {
		if err := f.closer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		f.closer = nil
	}
	return firstErr
}

var (
	_ io.ReaderAt       = (*File)(nil)
	_ io.ReadSeekCloser = (*File)(nil)
)

// --- walk ------------------------------------------------------------------

const defaultWalkDepth = 1024

func walkTree(ctx context.Context, fs FileSystem, root string, limits Limits, fn WalkFunc) error {
	depthLimit := limits.MaxDepth
	if depthLimit <= 0 {
		depthLimit = defaultWalkDepth
	}
	var walk func(dir string, depth int) error
	walk = func(dir string, depth int) error {
		if err := checkContext(ctx); err != nil {
			return err
		}
		entries, err := fs.ListDir(ctx, dir)
		if err != nil {
			return err
		}
		if limits.MaxEntries != 0 && uint64(len(entries)) > limits.MaxEntries {
			return fmt.Errorf("%w: directory %q has %d entries, MaxEntries limit is %d",
				ErrUnsupported, dir, len(entries), limits.MaxEntries)
		}
		for _, entry := range entries {
			if entry.Name == "." || entry.Name == ".." {
				continue
			}
			if err := fn(entry); err != nil {
				if errors.Is(err, ErrSkipDir) {
					continue
				}
				return err
			}
			if !entry.IsDir || entry.IsSymlink {
				continue
			}
			if depth+1 > depthLimit {
				return fmt.Errorf("%w: directory depth exceeds %d at %q", ErrUnsupported, depthLimit, entry.Path)
			}
			if err := walk(entry.Path, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(root, 0)
}

// --- legacy reader-based handlers ------------------------------------------

// oldFS adapts the reader-based filesystem handlers (FAT/exFAT/NTFS/ext4/XFS/
// Btrfs/APFS) onto the ByteSource data plane through volume.Open.
type oldFS struct {
	mu      sync.Mutex
	volume  *volume.Volume
	handler filesystem.FileSystem
	typ     filesystem.FileSystemType
	sector  uint32
	limits  Limits
	closed  bool
}

func newOldFS(v *volume.Volume, sector uint32, limits Limits) *oldFS {
	return &oldFS{volume: v, handler: v.FS, typ: v.Type, sector: sector, limits: limits}
}

func (f *oldFS) Type() string { return string(f.typ) }

func (f *oldFS) Info() FSInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	info := FSInfo{Type: string(f.typ), SectorSize: f.sector, ReadOnly: true}
	if f.handler != nil {
		info.Label = f.handler.GetVolumeLabel()
	}
	return info
}

func (f *oldFS) ListDir(ctx context.Context, dir string) ([]Entry, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, os.ErrClosed
	}
	dir = normalizePath(dir)
	raw, err := f.handler.ListDirectory(dir)
	if err != nil {
		return nil, fmt.Errorf("list %q: %w", dir, err)
	}
	if f.limits.MaxEntries != 0 && uint64(len(raw)) > f.limits.MaxEntries {
		return nil, fmt.Errorf("%w: directory %q has %d entries, MaxEntries limit is %d",
			ErrUnsupported, dir, len(raw), f.limits.MaxEntries)
	}
	entries := make([]Entry, 0, len(raw))
	for _, e := range raw {
		inode := e.Inode
		if inode == 0 {
			inode = uint64(e.Cluster)
		}
		entries = append(entries, Entry{
			Name:     e.Name,
			Path:     entryPath(dir, e.Name),
			Size:     e.Size,
			IsDir:    e.IsDir,
			Inode:    inode,
			Modified: unixTime(e.ModTime),
			Accessed: unixTime(e.AccessTime),
			Created:  unixTime(e.CreateTime),
		})
	}
	return entries, nil
}

func (f *oldFS) Stat(ctx context.Context, filePath string) (*Entry, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, os.ErrClosed
	}
	filePath = normalizePath(filePath)
	info, err := f.handler.GetFileByPath(filePath)
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", filePath, err)
	}
	return &Entry{
		Name:     info.Name,
		Path:     entryPath("", filePath),
		Size:     info.Size,
		IsDir:    info.IsDir,
		Mode:     uint32(info.Mode),
		Modified: unixTime(info.ModTime),
		Accessed: unixTime(info.AccessTime),
		Created:  unixTime(info.CreateTime),
	}, nil
}

func (f *oldFS) Open(ctx context.Context, filePath string) (*File, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	filePath = normalizePath(filePath)

	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil, os.ErrClosed
	}
	info, err := f.handler.GetFileByPath(filePath)
	if err != nil {
		f.mu.Unlock()
		return nil, fmt.Errorf("open %q: %w", filePath, err)
	}
	if info.IsDir {
		f.mu.Unlock()
		return nil, fmt.Errorf("%w: %q is a directory", ErrInvalidArgument, filePath)
	}
	entry := Entry{
		Name:     info.Name,
		Path:     entryPath("", filePath),
		Size:     info.Size,
		Mode:     uint32(info.Mode),
		Modified: unixTime(info.ModTime),
		Accessed: unixTime(info.AccessTime),
		Created:  unixTime(info.CreateTime),
	}
	var (
		stream    io.ReadSeekCloser
		streamErr error
	)
	if opener, ok := f.handler.(filesystem.FileOpener); ok {
		stream, streamErr = opener.OpenFile(filePath)
		if streamErr != nil && !errors.Is(streamErr, filesystem.ErrUnsupported) {
			f.mu.Unlock()
			return nil, fmt.Errorf("open %q: %w", filePath, streamErr)
		}
	}
	f.mu.Unlock()

	file := &File{entry: entry, size: info.Size, max: f.limits.MaxFileBytes, stream: stream}
	if stream == nil {
		// The handler has no streaming reader, or its stream path refuses this
		// file (APFS transparent compression is the common case): read the
		// file once and serve it from memory. This is real on-disk data, never
		// a fabricated buffer.
		f.mu.Lock()
		data, err := f.handler.GetFile(filePath)
		f.mu.Unlock()
		if err != nil {
			if streamErr != nil {
				return nil, fmt.Errorf("open %q: %w", filePath, streamErr)
			}
			return nil, fmt.Errorf("open %q: %w", filePath, err)
		}
		if max := f.limits.MaxFileBytes; max != 0 && uint64(len(data)) > max {
			return nil, fmt.Errorf("%w: file is %d bytes, MaxFileBytes limit is %d",
				ErrUnsupported, len(data), max)
		}
		file.src = source.NewMemorySourceWithImage(source.ID(1), 0, data)
		file.size = uint64(len(data))
		file.entry.Size = file.size
	}
	return file, nil
}

// FreeSpace reports that the legacy sector handlers do not expose allocation
// maps through this API.
func (f *oldFS) FreeSpace(ctx context.Context) (*FreeSpaceMap, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%w: free-space maps are not implemented for %s", ErrUnsupported, f.typ)
}

func (f *oldFS) Walk(ctx context.Context, root string, fn WalkFunc) error {
	return walkTree(ctx, f, root, f.limits, fn)
}

func (f *oldFS) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	if f.volume != nil {
		return f.volume.Close()
	}
	return nil
}

var _ FileSystem = (*oldFS)(nil)

// --- byte-source filesystem readers ---------------------------------------

// dataFS adapts one of the byte-source filesystem readers (HFS+, F2FS,
// SquashFS, ISO 9660, UDF) through per-reader conversion closures.
type dataFS struct {
	typ    string
	info   FSInfo
	limits Limits
	list   func(string) ([]Entry, error)
	stat   func(string) (*Entry, error)
	open   func(string) (source.ByteSource, uint64, error)
	free   func() (*FreeSpaceMap, error)
}

func (f *dataFS) Type() string { return f.typ }
func (f *dataFS) Info() FSInfo { return f.info }

func (f *dataFS) ListDir(ctx context.Context, dir string) ([]Entry, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	dir = normalizePath(dir)
	entries, err := f.list(dir)
	if err != nil {
		return nil, err
	}
	if f.limits.MaxEntries != 0 && uint64(len(entries)) > f.limits.MaxEntries {
		return nil, fmt.Errorf("%w: directory %q has %d entries, MaxEntries limit is %d",
			ErrUnsupported, dir, len(entries), f.limits.MaxEntries)
	}
	return entries, nil
}

func (f *dataFS) Stat(ctx context.Context, filePath string) (*Entry, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	return f.stat(normalizePath(filePath))
}

func (f *dataFS) Open(ctx context.Context, filePath string) (*File, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	filePath = normalizePath(filePath)
	entry, err := f.stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", filePath, err)
	}
	if entry.IsDir {
		return nil, fmt.Errorf("%w: %q is a directory", ErrInvalidArgument, filePath)
	}
	src, size, err := f.open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", filePath, err)
	}
	entry.Size = size
	return &File{entry: *entry, size: size, max: f.limits.MaxFileBytes, src: src}, nil
}

func (f *dataFS) Walk(ctx context.Context, root string, fn WalkFunc) error {
	return walkTree(ctx, f, root, f.limits, fn)
}

// FreeSpace returns the volume's free-space map when the reader implements one.
func (f *dataFS) FreeSpace(ctx context.Context) (*FreeSpaceMap, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if f.free == nil {
		return nil, fmt.Errorf("%w: free-space maps are not implemented for %s", ErrUnsupported, f.typ)
	}
	return f.free()
}

func (f *dataFS) Close() error { return nil }

var _ FileSystem = (*dataFS)(nil)

func openHFSPlus(src ByteSource, sector uint32, limits Limits) (FileSystem, error) {
	v, err := hfsplus.Open(src)
	if err != nil {
		return nil, err
	}
	fs := &dataFS{typ: "HFS+", limits: limits}
	fs.info = FSInfo{Type: fs.typ, SectorSize: sector, ReadOnly: true}
	if info, err := v.Info(); err == nil {
		fs.info.Label = info.Name
		fs.info.UUID = info.UUID
		fs.info.BlockSize = info.BlockSize
	}
	fs.list = func(dir string) ([]Entry, error) {
		raw, err := v.ListDir(dir)
		if err != nil {
			return nil, err
		}
		out := make([]Entry, 0, len(raw))
		for _, e := range raw {
			out = append(out, Entry{
				Name:      e.Name,
				Path:      e.Path,
				Size:      e.Size,
				IsDir:     e.IsDir,
				IsSymlink: e.IsSymlink,
				Deleted:   e.Deleted,
				Mode:      uint32(e.Mode),
				UID:       e.UID,
				GID:       e.GID,
				Inode:     uint64(e.Inode),
				Modified:  hfsTime(e.ModTime),
				Accessed:  hfsTime(e.AccessTime),
				Created:   hfsTime(e.CreateTime),
			})
		}
		return out, nil
	}
	fs.stat = func(filePath string) (*Entry, error) {
		e, err := v.Stat(filePath)
		if err != nil {
			return nil, err
		}
		return &Entry{
			Name:      e.Name,
			Path:      e.Path,
			Size:      e.Size,
			IsDir:     e.IsDir,
			IsSymlink: e.IsSymlink,
			Deleted:   e.Deleted,
			Mode:      uint32(e.Mode),
			UID:       e.UID,
			GID:       e.GID,
			Inode:     uint64(e.Inode),
			Modified:  hfsTime(e.ModTime),
			Accessed:  hfsTime(e.AccessTime),
			Created:   hfsTime(e.CreateTime),
		}, nil
	}
	fs.open = func(filePath string) (source.ByteSource, uint64, error) {
		src, err := v.OpenFile(filePath)
		if err != nil {
			return nil, 0, err
		}
		return src, src.Len(), nil
	}
	return fs, nil
}

func hfsTime(t hfsplus.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}
	return time.Unix(t.Unix(), 0).UTC()
}

func openF2FS(src ByteSource, sector uint32, limits Limits) (FileSystem, error) {
	v, err := f2fs.Open(src)
	if err != nil {
		return nil, err
	}
	info := v.Info()
	fs := &dataFS{
		typ:    "F2FS",
		limits: limits,
		info: FSInfo{
			Type: "F2FS", Label: info.VolumeName, UUID: info.UUID,
			BlockSize: info.BlockSize, SectorSize: sector, ReadOnly: true,
		},
	}
	convert := func(e f2fs.Entry) Entry {
		return Entry{
			Name: e.Name, Path: e.Path, Size: e.Size, IsDir: e.IsDir,
			IsSymlink: e.IsSymlink, Deleted: e.Deleted, Mode: uint32(e.Mode),
			UID: e.UID, GID: e.GID, Inode: uint64(e.Inode),
			Modified: e.Mtime, Accessed: e.Atime, Created: e.Crtime,
		}
	}
	fs.list = func(dir string) ([]Entry, error) {
		raw, err := v.ListDir(dir)
		if err != nil {
			return nil, err
		}
		out := make([]Entry, 0, len(raw))
		for _, e := range raw {
			out = append(out, convert(e))
		}
		return out, nil
	}
	fs.stat = func(filePath string) (*Entry, error) {
		e, err := v.Stat(filePath)
		if err != nil {
			return nil, err
		}
		entry := convert(*e)
		return &entry, nil
	}
	fs.open = func(filePath string) (source.ByteSource, uint64, error) {
		src, err := v.OpenFile(filePath)
		if err != nil {
			return nil, 0, err
		}
		return src, src.Len(), nil
	}
	return fs, nil
}

func openSquashFS(src ByteSource, sector uint32, limits Limits) (FileSystem, error) {
	v, err := squashfs.Open(src)
	if err != nil {
		return nil, err
	}
	info := v.Info()
	fs := &dataFS{
		typ:    "SquashFS",
		limits: limits,
		info: FSInfo{
			Type: "SquashFS", BlockSize: info.BlockSize,
			SectorSize: sector, ReadOnly: true,
		},
	}
	convert := func(e squashfs.Entry) Entry {
		return Entry{
			Name: e.Name, Path: e.Path, Size: e.Size, IsDir: e.IsDir,
			IsSymlink: e.IsSymlink, Mode: uint32(e.Mode), UID: e.UID, GID: e.GID,
			Inode: uint64(e.InodeNumber), Modified: e.Modified,
			SymlinkTarget: e.SymlinkTarget,
		}
	}
	fs.list = func(dir string) ([]Entry, error) {
		raw, err := v.ListDir(dir)
		if err != nil {
			return nil, err
		}
		out := make([]Entry, 0, len(raw))
		for _, e := range raw {
			out = append(out, convert(e))
		}
		return out, nil
	}
	fs.stat = func(filePath string) (*Entry, error) {
		e, err := v.Stat(filePath)
		if err != nil {
			return nil, err
		}
		entry := convert(*e)
		return &entry, nil
	}
	fs.open = func(filePath string) (source.ByteSource, uint64, error) {
		src, err := v.OpenFile(filePath)
		if err != nil {
			return nil, 0, err
		}
		return src, src.Len(), nil
	}
	return fs, nil
}

func openISO9660(src ByteSource, sector uint32, limits Limits) (FileSystem, error) {
	v, err := iso9660.Open(src)
	if err != nil {
		return nil, err
	}
	info := v.Info()
	fs := &dataFS{
		typ:    "ISO9660",
		limits: limits,
		info: FSInfo{
			Type: "ISO9660", Label: info.Label, BlockSize: info.BlockSize,
			SectorSize: sector, ReadOnly: true,
		},
	}
	convert := func(e iso9660.Entry) Entry {
		return Entry{
			Name: e.Name, Path: e.Path, Size: e.Size, IsDir: e.IsDir,
			IsSymlink: e.IsSymlink, Mode: e.Mode, UID: e.UID, GID: e.GID,
			Modified: e.Modified, Accessed: e.Accessed, Created: e.Created,
			SymlinkTarget: e.SymlinkTarget,
		}
	}
	fs.list = func(dir string) ([]Entry, error) {
		raw, err := v.ListDir(dir)
		if err != nil {
			return nil, err
		}
		out := make([]Entry, 0, len(raw))
		for _, e := range raw {
			out = append(out, convert(e))
		}
		return out, nil
	}
	fs.stat = func(filePath string) (*Entry, error) {
		e, err := v.Stat(filePath)
		if err != nil {
			return nil, err
		}
		entry := convert(*e)
		return &entry, nil
	}
	fs.open = func(filePath string) (source.ByteSource, uint64, error) {
		src, err := v.OpenFile(filePath)
		if err != nil {
			return nil, 0, err
		}
		return src, src.Len(), nil
	}
	return fs, nil
}

func openUDF(src ByteSource, sector uint32, limits Limits) (FileSystem, error) {
	v, err := udf.Open(src)
	if err != nil {
		return nil, err
	}
	info := v.Info()
	fs := &dataFS{
		typ:    "UDF",
		limits: limits,
		info: FSInfo{
			Type: "UDF", Label: info.VolumeID, UUID: info.VolumeSetID,
			BlockSize: info.BlockSize, SectorSize: sector, ReadOnly: true,
		},
	}
	convert := func(e udf.Entry) Entry {
		entry := Entry{
			Name: e.Name, Path: e.Path, Size: e.Size, IsDir: e.IsDir,
			IsSymlink: e.IsSymlink, Mode: e.Mode, UID: e.UID, GID: e.GID,
			SymlinkTarget: e.SymlinkTarget,
		}
		if e.HasModified {
			entry.Modified = e.Modified
		}
		if e.HasAccessed {
			entry.Accessed = e.Accessed
		}
		if e.HasCreated {
			entry.Created = e.Created
		}
		return entry
	}
	fs.list = func(dir string) ([]Entry, error) {
		raw, err := v.ListDir(dir)
		if err != nil {
			return nil, err
		}
		out := make([]Entry, 0, len(raw))
		for _, e := range raw {
			out = append(out, convert(e))
		}
		return out, nil
	}
	fs.stat = func(filePath string) (*Entry, error) {
		e, err := v.Stat(filePath)
		if err != nil {
			return nil, err
		}
		entry := convert(*e)
		return &entry, nil
	}
	fs.open = func(filePath string) (source.ByteSource, uint64, error) {
		src, err := v.OpenFile(filePath)
		if err != nil {
			return nil, 0, err
		}
		return src, src.Len(), nil
	}
	return fs, nil
}

func openCramFS(src ByteSource, sector uint32, limits Limits) (FileSystem, error) {
	v, err := cramfs.Open(src)
	if err != nil {
		return nil, err
	}
	info := v.Info()
	fs := &dataFS{
		typ:    "CramFS",
		limits: limits,
		info: FSInfo{
			Type: "CramFS", Label: info.Name, BlockSize: info.BlockSize,
			SectorSize: sector, ReadOnly: true,
		},
	}
	convert := func(e cramfs.Entry) Entry {
		return Entry{
			Name: e.Name, Path: e.Path, Size: e.Size, IsDir: e.IsDir,
			IsSymlink: e.IsSymlink, Mode: uint32(e.Mode), UID: e.UID, GID: e.GID,
			Inode: e.Handle, SymlinkTarget: e.SymlinkTarget,
		}
	}
	fs.list = func(dir string) ([]Entry, error) {
		raw, err := v.ListDir(dir)
		if err != nil {
			return nil, err
		}
		out := make([]Entry, 0, len(raw))
		for _, e := range raw {
			out = append(out, convert(e))
		}
		return out, nil
	}
	fs.stat = func(filePath string) (*Entry, error) {
		e, err := v.Stat(filePath)
		if err != nil {
			return nil, err
		}
		entry := convert(*e)
		return &entry, nil
	}
	fs.open = func(filePath string) (source.ByteSource, uint64, error) {
		file, err := v.OpenFile(filePath)
		if err != nil {
			return nil, 0, err
		}
		return file, file.Len(), nil
	}
	return fs, nil
}

func openEROFS(src ByteSource, sector uint32, limits Limits) (FileSystem, error) {
	v, err := erofs.Open(src)
	if err != nil {
		return nil, err
	}
	info := v.Info()
	fs := &dataFS{
		typ:    "EROFS",
		limits: limits,
		info: FSInfo{
			Type: "EROFS", Label: info.VolumeName, UUID: info.UUID,
			BlockSize: info.BlockSize, SectorSize: sector, ReadOnly: true,
		},
	}
	convert := func(e erofs.Entry) Entry {
		entry := Entry{
			Name: e.Name, Path: e.Path, Size: e.Size, IsDir: e.IsDir,
			IsSymlink: e.IsSymlink, Mode: uint32(e.Mode), UID: e.UID, GID: e.GID,
			Inode: e.Inode, SymlinkTarget: e.SymlinkTarget,
		}
		if e.HasModified {
			entry.Modified = e.Modified
		}
		if e.HasChanged {
			entry.Accessed = e.Changed
		}
		return entry
	}
	fs.list = func(dir string) ([]Entry, error) {
		raw, err := v.ListDir(dir)
		if err != nil {
			return nil, err
		}
		out := make([]Entry, 0, len(raw))
		for _, e := range raw {
			out = append(out, convert(e))
		}
		return out, nil
	}
	fs.stat = func(filePath string) (*Entry, error) {
		e, err := v.Stat(filePath)
		if err != nil {
			return nil, err
		}
		entry := convert(*e)
		return &entry, nil
	}
	fs.open = func(filePath string) (source.ByteSource, uint64, error) {
		file, err := v.OpenFile(filePath)
		if err != nil {
			return nil, 0, err
		}
		return file, file.Len(), nil
	}
	return fs, nil
}

func openJFS(src ByteSource, sector uint32, limits Limits) (FileSystem, error) {
	v, err := jfs.Open(src)
	if err != nil {
		return nil, err
	}
	info := v.Info()
	fs := &dataFS{
		typ:    "JFS",
		limits: limits,
		info: FSInfo{
			Type: "JFS", Label: info.Label, UUID: info.UUID,
			BlockSize: info.BlockSize, SectorSize: sector, ReadOnly: true,
		},
	}
	convert := func(e jfs.Entry) Entry {
		return Entry{
			Name: e.Name, Path: e.Path, Size: e.Size, IsDir: e.IsDir,
			IsSymlink: e.IsSymlink, Deleted: e.Deleted, Mode: e.Mode,
			UID: e.UID, GID: e.GID, Inode: uint64(e.Inode),
			Modified: e.Mtime, Accessed: e.Atime, Created: e.Otime,
			SymlinkTarget: e.SymlinkTarget,
		}
	}
	fs.list = func(dir string) ([]Entry, error) {
		raw, err := v.ListDir(dir)
		if err != nil {
			return nil, err
		}
		out := make([]Entry, 0, len(raw))
		for _, e := range raw {
			out = append(out, convert(e))
		}
		return out, nil
	}
	fs.stat = func(filePath string) (*Entry, error) {
		e, err := v.Stat(filePath)
		if err != nil {
			return nil, err
		}
		entry := convert(*e)
		return &entry, nil
	}
	fs.open = func(filePath string) (source.ByteSource, uint64, error) {
		file, err := v.OpenFile(filePath)
		if err != nil {
			return nil, 0, err
		}
		return file, file.Len(), nil
	}
	fs.free = func() (*FreeSpaceMap, error) {
		m, err := v.FreeSpace()
		if err != nil {
			return nil, err
		}
		runs := make([]FreeRun, 0, len(m.Space.Runs()))
		for _, r := range m.Space.Runs() {
			runs = append(runs, FreeRun{Offset: r.Offset, Length: r.Len})
		}
		return &FreeSpaceMap{
			FreeBytes: m.Space.FreeBytes(), Covered: m.Space.Covered(),
			Basis: m.Space.Basis(), Runs: runs, Notes: m.Space.Notes(),
		}, nil
	}
	return fs, nil
}

func openReiserFS(src ByteSource, sector uint32, limits Limits) (FileSystem, error) {
	v, err := reiserfs.Open(src)
	if err != nil {
		return nil, err
	}
	info := v.Info()
	fs := &dataFS{
		typ:    "ReiserFS",
		limits: limits,
		info: FSInfo{
			Type: "ReiserFS", Label: info.Label, UUID: info.UUID,
			BlockSize: info.BlockSize, SectorSize: sector, ReadOnly: true,
		},
	}
	convert := func(e reiserfs.Entry) Entry {
		return Entry{
			Name: e.Name, Path: e.Path, Size: e.Size, IsDir: e.IsDir,
			IsSymlink: e.IsSymlink, Deleted: e.Deleted, Mode: uint32(e.Mode),
			UID: e.UID, GID: e.GID, Inode: uint64(e.Inode),
			Modified: e.Mtime, Accessed: e.Atime, Created: e.Ctime,
			SymlinkTarget: e.SymlinkTarget,
		}
	}
	fs.list = func(dir string) ([]Entry, error) {
		raw, err := v.ListDir(dir)
		if err != nil {
			return nil, err
		}
		out := make([]Entry, 0, len(raw))
		for _, e := range raw {
			out = append(out, convert(e))
		}
		return out, nil
	}
	fs.stat = func(filePath string) (*Entry, error) {
		e, err := v.Stat(filePath)
		if err != nil {
			return nil, err
		}
		entry := convert(*e)
		return &entry, nil
	}
	fs.open = func(filePath string) (source.ByteSource, uint64, error) {
		file, err := v.OpenFile(filePath)
		if err != nil {
			return nil, 0, err
		}
		return file, file.Len(), nil
	}
	fs.free = func() (*FreeSpaceMap, error) {
		m, err := v.FreeSpace()
		if err != nil {
			return nil, err
		}
		runs := make([]FreeRun, 0, len(m.Space.Runs()))
		for _, r := range m.Space.Runs() {
			runs = append(runs, FreeRun{Offset: r.Offset, Length: r.Len})
		}
		return &FreeSpaceMap{
			FreeBytes: m.Space.FreeBytes(), Covered: m.Space.Covered(),
			Basis: m.Space.Basis(), Runs: runs, Notes: m.Space.Notes(),
		}, nil
	}
	return fs, nil
}

func openVMFS(src ByteSource, sector uint32, limits Limits) (FileSystem, error) {
	v, err := vmfs.Open(src)
	if err != nil {
		return nil, err
	}
	info := v.Info()
	label := info.VolumeLabel
	if label == "" {
		label = info.VolumeName
	}
	fs := &dataFS{
		typ:    "VMFS",
		limits: limits,
		info: FSInfo{
			Type: "VMFS", Label: label, UUID: info.UUID,
			BlockSize: info.BlockSize, SectorSize: sector, ReadOnly: true,
		},
	}
	convert := func(e vmfs.Entry) Entry {
		return Entry{
			Name: e.Name, Path: e.Path, Size: e.Size, IsDir: e.IsDir,
			IsSymlink: e.IsSymlink, Mode: uint32(e.Mode), UID: e.UID, GID: e.GID,
			Inode: uint64(e.InodeNumber), Modified: e.Modified,
			Accessed: e.Accessed, Created: e.Changed,
			SymlinkTarget: e.SymlinkTarget,
		}
	}
	fs.list = func(dir string) ([]Entry, error) {
		raw, err := v.ListDir(dir)
		if err != nil {
			return nil, err
		}
		out := make([]Entry, 0, len(raw))
		for _, e := range raw {
			out = append(out, convert(e))
		}
		return out, nil
	}
	fs.stat = func(filePath string) (*Entry, error) {
		e, err := v.Stat(filePath)
		if err != nil {
			return nil, err
		}
		entry := convert(*e)
		return &entry, nil
	}
	fs.open = func(filePath string) (source.ByteSource, uint64, error) {
		file, err := v.OpenFile(filePath)
		if err != nil {
			return nil, 0, err
		}
		return file, file.Len(), nil
	}
	return fs, nil
}

func openMinix(src ByteSource, sector uint32, limits Limits) (FileSystem, error) {
	v, err := minix.Open(src)
	if err != nil {
		return nil, err
	}
	info := v.Info()
	fs := &dataFS{
		typ:    "Minix",
		limits: limits,
		info: FSInfo{
			Type: "Minix", Label: info.Type + " v" + info.Version,
			BlockSize: info.BlockSize, SectorSize: sector, ReadOnly: true,
		},
	}
	convert := func(e minix.Entry) Entry {
		entry := Entry{
			Name: e.Name, Path: e.Path, Size: e.Size, IsDir: e.IsDir,
			IsSymlink: e.IsSymlink, Mode: uint32(e.Mode), UID: e.UID, GID: e.GID,
			Inode: uint64(e.InodeNumber), Modified: e.Mtime,
			Accessed: e.Atime, Created: e.Ctime,
		}
		if e.SymlinkTargetKnown {
			entry.SymlinkTarget = e.SymlinkTarget
		}
		return entry
	}
	fs.list = func(dir string) ([]Entry, error) {
		raw, err := v.ListDir(dir)
		if err != nil {
			return nil, err
		}
		out := make([]Entry, 0, len(raw))
		for _, e := range raw {
			out = append(out, convert(e))
		}
		return out, nil
	}
	fs.stat = func(filePath string) (*Entry, error) {
		e, err := v.Stat(filePath)
		if err != nil {
			return nil, err
		}
		entry := convert(*e)
		return &entry, nil
	}
	fs.open = func(filePath string) (source.ByteSource, uint64, error) {
		file, err := v.OpenFile(filePath)
		if err != nil {
			return nil, 0, err
		}
		return file, file.Len(), nil
	}
	return fs, nil
}

func openSysV(src ByteSource, sector uint32, limits Limits) (FileSystem, error) {
	v, err := sysv.Open(src)
	if err != nil {
		return nil, err
	}
	info := v.Info()
	label := info.VolumeName
	if label == "" {
		label = info.PackName
	}
	fs := &dataFS{
		typ:    "System V",
		limits: limits,
		info: FSInfo{
			Type: "System V", Label: label,
			BlockSize: info.BlockSize, SectorSize: sector, ReadOnly: true,
		},
	}
	convert := func(e sysv.Entry) Entry {
		entry := Entry{
			Name: e.Name, Path: e.Path, Size: e.Size, IsDir: e.IsDir,
			IsSymlink: e.IsSymlink, Mode: uint32(e.Mode), UID: uint32(e.UID),
			GID: uint32(e.GID), Inode: uint64(e.InodeNumber),
			Modified: e.Mtime, Accessed: e.Atime, Created: e.Ctime,
		}
		if e.SymlinkTargetKnown {
			entry.SymlinkTarget = e.SymlinkTarget
		}
		return entry
	}
	fs.list = func(dir string) ([]Entry, error) {
		raw, err := v.ListDir(dir)
		if err != nil {
			return nil, err
		}
		out := make([]Entry, 0, len(raw))
		for _, e := range raw {
			out = append(out, convert(e))
		}
		return out, nil
	}
	fs.stat = func(filePath string) (*Entry, error) {
		e, err := v.Stat(filePath)
		if err != nil {
			return nil, err
		}
		entry := convert(*e)
		return &entry, nil
	}
	fs.open = func(filePath string) (source.ByteSource, uint64, error) {
		file, err := v.OpenFile(filePath)
		if err != nil {
			return nil, 0, err
		}
		return file, file.Len(), nil
	}
	fs.free = func() (*FreeSpaceMap, error) {
		space, err := v.FreeSpace()
		if err != nil {
			return nil, err
		}
		runs := make([]FreeRun, 0, len(space.Runs()))
		for _, r := range space.Runs() {
			runs = append(runs, FreeRun{Offset: r.Offset, Length: r.Len})
		}
		return &FreeSpaceMap{
			FreeBytes: space.FreeBytes(), Covered: space.Covered(),
			AreaStart: space.AreaStart(),
			Basis:     space.Basis(), Runs: runs, Notes: space.Notes(),
		}, nil
	}
	return fs, nil
}

func openUFS(src ByteSource, sector uint32, limits Limits) (FileSystem, error) {
	v, err := ufs.Open(src)
	if err != nil {
		return nil, err
	}
	info := v.Info()
	fs := &dataFS{
		typ:    "UFS",
		limits: limits,
		info: FSInfo{
			Type: "UFS", Label: info.VolumeName, BlockSize: info.BlockSize,
			SectorSize: sector, ReadOnly: true,
		},
	}
	convert := func(e ufs.Entry) Entry {
		entry := Entry{
			Name: e.Name, Path: e.Path, Size: e.Size, IsDir: e.IsDir,
			IsSymlink: e.IsSymlink, Deleted: e.Deleted, Mode: uint32(e.Mode),
			UID: e.UID, GID: e.GID, Inode: uint64(e.Inode),
			Modified: e.Mtime, Accessed: e.Atime,
			SymlinkTarget: e.SymlinkTarget,
		}
		if e.HasCreationTime {
			entry.Created = e.CreationTime
		}
		return entry
	}
	fs.list = func(dir string) ([]Entry, error) {
		raw, err := v.ListDir(dir)
		if err != nil {
			return nil, err
		}
		out := make([]Entry, 0, len(raw))
		for _, e := range raw {
			out = append(out, convert(e))
		}
		return out, nil
	}
	fs.stat = func(filePath string) (*Entry, error) {
		e, err := v.Stat(filePath)
		if err != nil {
			return nil, err
		}
		entry := convert(*e)
		return &entry, nil
	}
	fs.open = func(filePath string) (source.ByteSource, uint64, error) {
		file, err := v.OpenFile(filePath)
		if err != nil {
			return nil, 0, err
		}
		return file, file.Len(), nil
	}
	fs.free = func() (*FreeSpaceMap, error) {
		space, err := v.FreeSpace()
		if err != nil {
			return nil, err
		}
		runs := make([]FreeRun, 0, len(space.Runs()))
		for _, r := range space.Runs() {
			runs = append(runs, FreeRun{Offset: r.Offset, Length: r.Len})
		}
		return &FreeSpaceMap{
			FreeBytes: space.FreeBytes(), Covered: space.Covered(),
			Basis: "ufs.cg.bitmap", Runs: runs, Notes: space.Notes(),
		}, nil
	}
	return fs, nil
}
