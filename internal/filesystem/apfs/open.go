package apfs

import (
	"fmt"
	"io"
	"strings"

	"github.com/laenix/ewfgo/internal/filesystem"
)

// OpenFile opens the file at path for streaming reads. It returns a lazy,
// seekable io.ReadSeekCloser whose reads touch only the blocks intersecting the
// accessed byte range — memory is O(read block), not O(file). This is the
// streaming path for GB-scale files (sqlite databases etc.) that ReadFile
// cannot hold in memory.
//
// Only regular files with a real data fork are streamable. A directory resolves
// to ErrIsDirectory, a missing path to ErrNotFound, a path that descends through
// a non-directory to ErrNotDirectory, and a symlink or other non-regular inode
// to ErrUnsupported — nothing is fabricated. Two special cases are explicit
// errors rather than fabricated streams:
//
//   - Symlinks: their content is the target string, not a byte stream.
//   - Transparently-compressed (com.apple.decmpfs) files: the data fork is
//     dataless, so streaming its raw fork would return zeros, not the content.
//     The decompressed content is available via GetFile.
//
// The file's FILE_EXTENT records (the extent map, O(extents)) are resolved at
// open; only the data blocks are read lazily. Unallocated gaps within the
// declared size read as zeros, matching APFS sparse-file semantics.
//
// Concurrency: the reader's state (size, block size, extent list) is immutable
// after open, and every data read goes through apfsReadBlock / apfsReadBlocks,
// which only read via the handler's readFunc (concurrency-safe). ReadAt is
// therefore safe for concurrent use on the same handle without internal locking;
// Read/Seek share a cursor and are not concurrent-safe.
func (apfs *APFS) OpenFile(path string) (io.ReadSeekCloser, error) {
	if apfs.readFunc == nil {
		return nil, fmt.Errorf("APFS: handler has no reader")
	}
	if err := apfs.ensureIndex(); err != nil {
		return nil, err
	}
	clean := strings.Trim(path, "/")
	ino, err := apfs.resolvePath(clean, false)
	if err != nil {
		return nil, err
	}
	return apfs.openInode(ino)
}

// OpenInode opens a file by its inode number, skipping the path walk (see
// filesystem.InodeOpener). The inode comes from a prior ListDirectory
// (DirectoryEntry.Inode); APFS reads its own inode record, so the size param
// is ignored.
func (apfs *APFS) OpenInode(inode uint64, _ int64) (io.ReadSeekCloser, error) {
	if apfs.readFunc == nil {
		return nil, fmt.Errorf("APFS: handler has no reader")
	}
	if err := apfs.ensureIndex(); err != nil {
		return nil, err
	}
	return apfs.openInode(inode)
}

func (apfs *APFS) openInode(ino uint64) (io.ReadSeekCloser, error) {
	in, ok := apfs.index.inodes[ino]
	if !ok {
		return nil, fmt.Errorf("APFS: inode %d has no inode record", ino)
	}
	switch mode := in.mode & 0xf000; mode {
	case 0x4000:
		return nil, fmt.Errorf("APFS: inode %d is a directory: %w", ino, filesystem.ErrIsDirectory)
	case 0x8000:
		// regular file: stream via its data fork
	case 0xa000:
		return nil, fmt.Errorf("APFS: inode %d is a symlink: %w", ino, filesystem.ErrUnsupported)
	default:
		return nil, fmt.Errorf("APFS: inode %d is not a regular file (mode 0x%04X): %w", ino, mode, filesystem.ErrUnsupported)
	}
	// macOS transparently compresses most system files: a com.apple.decmpfs xattr
	// makes the data fork dataless, so streaming the raw fork would fabricate
	// zeros. The decompressed content is available via GetFile (EWF 红线).
	for _, xa := range apfs.index.xattrs[ino] {
		if xa.name == "com.apple.decmpfs" {
			return nil, fmt.Errorf("APFS: inode %d is transparently compressed (decmpfs), streaming unsupported: %w", ino, filesystem.ErrUnsupported)
		}
	}
	size := in.size
	// The streaming reader is extent-driven and bounded by the caller's buffer,
	// so a huge logical size is safe: reads touch only allocated extents and
	// holes read as zeros. macOS Spotlight sparse indexes legitimately report
	// 16-64 TiB logical sizes. Only the int64 boundary matters — a size at or
	// past 2^63 would overflow the reader's EOF arithmetic, which is corrupt,
	// not legitimate.
	if size >= uint64(1)<<63 {
		return nil, fmt.Errorf("APFS: inode %d size %d overflows int64: %w", ino, size, filesystem.ErrUnsupported)
	}
	// The extents live under the inode's data-stream oid: the ino itself, or the
	// DSTREAM_ID record's dstream oid when the stream is shared/cloned.
	extKey := ino
	if doid, ok := apfs.index.dstream[ino]; ok && doid != 0 {
		extKey = doid
	}
	return &apfsFileReader{h: apfs, size: int64(size), blockSize: apfs.blocksize, exts: apfs.index.extents[extKey]}, nil
}

// apfsFileReader is a lazy, seekable reader over an APFS file's FILE_EXTENT
// records (byte-addressed, paddr = physical block number).
type apfsFileReader struct {
	h         *APFS
	size      int64
	blockSize uint64
	exts      []apfsExtent
	pos       int64
}

// extentAt returns the FILE_EXTENT covering the logical file byte off, if any.
// A missing extent within the declared size is a sparse hole and reads as zeros.
func apfsExtentAt(exts []apfsExtent, off uint64) (apfsExtent, bool) {
	for _, ext := range exts {
		if off >= ext.laddr && off < ext.laddr+ext.length {
			return ext, true
		}
	}
	return apfsExtent{}, false
}

// readAt copies into p the bytes of the file starting at off. It returns io.EOF
// when off is at or past the end of the file, and n < len(p) with io.EOF for a
// range that runs past the end (the readable prefix is real data; nothing past
// the end is fabricated). Holes zero-fill, matching APFS sparse-file semantics.
func (r *apfsFileReader) readAt(p []byte, off int64) (int, error) {
	if off >= r.size {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	remaining := r.size - off
	want := int64(len(p))
	atEOF := false
	if want > remaining {
		want = remaining
		atEOF = true
	}
	if want <= 0 {
		return 0, io.EOF
	}
	if r.blockSize == 0 {
		return 0, fmt.Errorf("APFS: reader has no block size")
	}

	n := 0
	for n < int(want) {
		o := off + int64(n)
		ext, ok := apfsExtentAt(r.exts, uint64(o))
		if !ok {
			// Sparse hole: a byte with no FILE_EXTENT record within the declared
			// size is genuinely zero on disk (APFS unallocated gaps). Zero-fill up
			// to the next extent start (or the end of the request).
			next := uint64(r.size)
			for _, e := range r.exts {
				if e.laddr > uint64(o) && e.laddr < next {
					next = e.laddr
				}
			}
			take := int64(next) - o
			if take > int64(want)-int64(n) {
				take = int64(want) - int64(n)
			}
			clear(p[n : n+int(take)])
			n += int(take)
			continue
		}
		within := uint64(o) - ext.laddr
		block := ext.paddr + within/r.blockSize
		blockOff := within % r.blockSize
		take := int64(r.blockSize) - int64(blockOff)
		if uint64(take) > ext.length-within {
			take = int64(ext.length - within)
		}
		if take > int64(want)-int64(n) {
			take = int64(want) - int64(n)
		}
		data, err := r.h.apfsReadBlock(block)
		if err != nil {
			return n, err
		}
		copy(p[n:], data[blockOff:blockOff+uint64(take)])
		n += int(take)
	}
	if atEOF {
		// The requested range ran past the end of the file: the prefix above is
		// real data, but the caller must see io.EOF so it knows the read was
		// truncated (io.ReaderAt requires a non-nil error when n < len(p)).
		return n, io.EOF
	}
	return n, nil
}

// Read implements io.Reader.
func (r *apfsFileReader) Read(p []byte) (int, error) {
	if r.pos >= r.size {
		return 0, io.EOF
	}
	n, err := r.readAt(p, r.pos)
	r.pos += int64(n)
	if err == io.EOF && n > 0 {
		// Final bytes: report them cleanly; the next call returns io.EOF.
		return n, nil
	}
	return n, err
}

// ReadAt implements io.ReaderAt. It is position-independent and safe for
// concurrent use on the same handle (the io.ReaderAt contract a VFS layer such
// as sqlite's would drive a database through).
func (r *apfsFileReader) ReadAt(p []byte, off int64) (int, error) {
	return r.readAt(p, off)
}

// Seek implements io.Seeker. Seeking is lazy: no block is read until a
// subsequent Read/ReadAt touches it. It shares the cursor with Read, so it is
// not safe for concurrent use; use ReadAt for concurrent access.
func (r *apfsFileReader) Seek(offset int64, whence int) (int64, error) {
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = r.pos + offset
	case io.SeekEnd:
		abs = r.size + offset
	default:
		return 0, fmt.Errorf("invalid whence %d", whence)
	}
	if abs < 0 {
		return 0, fmt.Errorf("negative seek position %d", abs)
	}
	r.pos = abs
	return abs, nil
}

// Close releases the reader. The shared handler/image stay open (owned by the
// caller); this reader holds no resources beyond the extent list slice.
func (r *apfsFileReader) Close() error { return nil }

var _ io.ReadSeekCloser = (*apfsFileReader)(nil)
var _ io.ReaderAt = (*apfsFileReader)(nil)
var _ filesystem.FileOpener = (*APFS)(nil)
var _ filesystem.InodeOpener = (*APFS)(nil)
