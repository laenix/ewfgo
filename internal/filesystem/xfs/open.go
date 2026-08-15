package xfs

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/laenix/ewfgo/internal/filesystem"
)

// OpenFile opens the file at path for streaming reads. It returns a lazy,
// seekable io.ReadSeekCloser whose reads touch only the blocks intersecting the
// accessed byte range — memory is O(read block), not O(file). This is the
// streaming path for GB-scale files (sqlite databases etc.) that ReadFile
// cannot hold in memory.
//
// Only regular files are streamable. A directory resolves to ErrIsDirectory, a
// missing path to ErrNotFound, and a symlink or other non-regular inode to
// ErrUnsupported — nothing is fabricated. The data-fork extent map (local /
// extents / bmbt) is resolved at open (O(extents) eager, exactly like
// readExtents); only the data blocks are read lazily. Holes within the declared
// size read as zeros, matching XFS's sparse-file semantics.
//
// Concurrency: the reader's state (size, block size, extent list or local
// bytes) is immutable after open, and every data read goes through readBytes /
// readBlock, which only read via the handler's readFunc (concurrency-safe).
// ReadAt is therefore safe for concurrent use on the same handle without
// internal locking; Read/Seek share a cursor and are not concurrent-safe.
func (xfs *XFS) OpenFile(path string) (io.ReadSeekCloser, error) {
	if xfs.readFunc == nil {
		return nil, fmt.Errorf("XFS: file reading requires a reader")
	}
	inoData, inoNum, err := xfs.resolvePathNoFollow(path)
	if err != nil {
		return nil, err
	}
	return xfs.openInodeData(inoData, inoNum, path)
}

// OpenInode opens a file by its inode number, skipping the path walk (see
// filesystem.InodeOpener). The inode comes from a prior ListDirectory
// (DirectoryEntry.Inode); XFS reads its own inode record, so the size param is
// ignored.
func (xfs *XFS) OpenInode(inode uint64, _ int64) (io.ReadSeekCloser, error) {
	if xfs.readFunc == nil {
		return nil, fmt.Errorf("XFS: file reading requires a reader")
	}
	if inode == 0 || inode > 0xFFFFFFFF {
		return nil, fmt.Errorf("XFS: inode number %d out of range", inode)
	}
	inoData, err := xfs.readInode(inode)
	if err != nil {
		return nil, err
	}
	return xfs.openInodeData(inoData, inode, "")
}

// openInodeData builds the streaming reader from an already-read inode. what is
// the path for OpenFile's directory error, or "" for OpenInode (which reports
// the inode number).
func (xfs *XFS) openInodeData(inoData []byte, inoNum uint64, what string) (io.ReadSeekCloser, error) {
	if len(inoData) < xfsInodeDataForkOffset {
		return nil, fmt.Errorf("XFS: inode %d too small", inoNum)
	}

	// di_mode file-type bits (0xF000): 0x4000 = directory, 0x8000 = regular,
	// 0xA000 = symlink (its content is the target string, not a stream).
	switch mode := binary.BigEndian.Uint16(inoData[xfsInodeModeOffset : xfsInodeModeOffset+2]); mode & 0xF000 {
	case 0x4000:
		if what != "" {
			return nil, fmt.Errorf("path is a directory: %s: %w", what, filesystem.ErrIsDirectory)
		}
		return nil, fmt.Errorf("XFS: inode %d is a directory: %w", inoNum, filesystem.ErrIsDirectory)
	case 0x8000:
		// regular file: stream via its data fork
	case 0xA000:
		return nil, fmt.Errorf("XFS: inode %d is a symlink: %w", inoNum, filesystem.ErrUnsupported)
	default:
		return nil, fmt.Errorf("XFS: inode %d is not a regular file (mode 0x%04X): %w",
			inoNum, mode, filesystem.ErrUnsupported)
	}

	size := binary.BigEndian.Uint64(inoData[xfsInodeSizeOffset : xfsInodeSizeOffset+8])
	if size == 0 {
		return &xfsFileReader{h: xfs}, nil
	}

	limit, err := xfs.dataForkLimit(inoData)
	if err != nil {
		return nil, err
	}
	fork := inoData[xfsInodeDataForkOffset:limit]

	switch format := inoData[xfsInodeFormatOffset]; format {
	case xfsDinodeFormatLocal:
		if uint64(len(fork)) < size {
			return nil, fmt.Errorf("XFS: local data %d bytes shorter than size %d", len(fork), size)
		}
		return &xfsFileReader{h: xfs, size: int64(size), local: fork[:size]}, nil
	case xfsDinodeFormatExtents:
		nextents := binary.BigEndian.Uint32(inoData[xfsInodeNextentsOffset : xfsInodeNextentsOffset+4])
		exts, err := parseExtents(fork, nextents)
		if err != nil {
			return nil, err
		}
		return &xfsFileReader{h: xfs, size: int64(size), blockSize: uint64(xfs.blocksize), exts: exts}, nil
	case xfsDinodeFormatBtree:
		// The bmbt tree is the extent map (O(extents) blocks); resolving it here
		// keeps data reads lazy and per-block.
		exts, err := xfs.readBtreeExtents(inoData, inoNum)
		if err != nil {
			return nil, err
		}
		return &xfsFileReader{h: xfs, size: int64(size), blockSize: uint64(xfs.blocksize), exts: exts}, nil
	default:
		return nil, fmt.Errorf("XFS: unsupported data fork format %d", format)
	}
}

// xfsFileReader is a lazy, seekable reader over an XFS file's data fork. When
// the fork is local the content is inline (local); otherwise it is assembled
// block by block through the extent list.
type xfsFileReader struct {
	h         *XFS
	size      int64
	blockSize uint64
	local     []byte       // inline data (format local), nil for extent-backed forks
	exts      []xfsExtent  // extent list (formats extents / btree)
	pos       int64
}

// extentAt returns the extent covering logical block block, if any. A missing
// extent within the declared size is a sparse hole and reads as zeros.
func extentAt(exts []xfsExtent, block uint64) (xfsExtent, bool) {
	for _, ext := range exts {
		if block >= ext.startoff && block < ext.startoff+ext.blockCount {
			return ext, true
		}
	}
	return xfsExtent{}, false
}

// readAt copies into p the bytes of the file starting at off. It returns io.EOF
// when off is at or past the end of the file, and n < len(p) with io.EOF for a
// range that runs past the end (the readable prefix is real data; nothing past
// the end is fabricated). Holes zero-fill, matching XFS sparse-file semantics.
func (r *xfsFileReader) readAt(p []byte, off int64) (int, error) {
	// EOF is checked before the blockSize guard so an empty file (size 0, whose
	// reader carries no block size) reads cleanly as io.EOF rather than erroring.
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

	if r.local != nil {
		n := copy(p[:want], r.local[off:off+want])
		if atEOF {
			return n, io.EOF
		}
		return n, nil
	}
	if r.blockSize == 0 {
		return 0, fmt.Errorf("XFS: reader has no block size")
	}

	n := 0
	for n < int(want) {
		o := off + int64(n)
		blockIdx := uint64(o) / r.blockSize
		within := uint64(o) % r.blockSize

		take := int64(r.blockSize) - int64(within)
		if take > int64(want)-int64(n) {
			take = int64(want) - int64(n)
		}

		ext, ok := extentAt(r.exts, blockIdx)
		if !ok {
			// Sparse hole: an unallocated block within the declared size is
			// genuinely zero on a live mount. Zero-fill the readable part and
			// move on — this is the on-disk semantics, not fabricated data.
			clear(p[n : n+int(take)])
			n += int(take)
			continue
		}
		fsb := r.h.fsbToFsb(ext.startBlock) + (blockIdx - ext.startoff)
		if fsb > 1<<40 {
			return n, fmt.Errorf("XFS: data block %d out of range", fsb)
		}
		data, err := r.h.readBytes(fsb*r.blockSize, r.blockSize)
		if err != nil {
			return n, err
		}
		copy(p[n:], data[within:within+uint64(take)])
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
func (r *xfsFileReader) Read(p []byte) (int, error) {
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
func (r *xfsFileReader) ReadAt(p []byte, off int64) (int, error) {
	return r.readAt(p, off)
}

// Seek implements io.Seeker. Seeking is lazy: no block is read until a
// subsequent Read/ReadAt touches it. It shares the cursor with Read, so it is
// not safe for concurrent use; use ReadAt for concurrent access.
func (r *xfsFileReader) Seek(offset int64, whence int) (int64, error) {
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
func (r *xfsFileReader) Close() error { return nil }

var _ io.ReadSeekCloser = (*xfsFileReader)(nil)
var _ io.ReaderAt = (*xfsFileReader)(nil)
var _ filesystem.FileOpener = (*XFS)(nil)
var _ filesystem.InodeOpener = (*XFS)(nil)
