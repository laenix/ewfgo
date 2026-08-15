package ext4

import (
	"encoding/binary"
	"errors"
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
// Only extent-mapped regular files are streamable. A directory resolves to
// ErrIsDirectory, a missing path to ErrNotFound, and a non-regular inode
// (legacy block mapping, symlink, device) to an explicit error — nothing is
// fabricated.
//
// Concurrency: the reader's state (size, block size, extent root, tree depth)
// is immutable after open, and every data read goes through resolveExtent /
// readBlockBytes, which only read via the handler's reader.ReadSectors
// (concurrency-safe). ReadAt is therefore safe for concurrent use on the same
// handle without internal locking; Read/Seek share a cursor and are not
// concurrent-safe.
func (h *Ext4Handler) OpenFile(path string) (io.ReadSeekCloser, error) {
	if h.reader == nil {
		return nil, fmt.Errorf("ext4: handler has no reader (construct with NewExt4Handler)")
	}
	inodeNum, err := h.resolvePathToInode(path)
	if err != nil {
		return nil, err
	}
	return h.openInode(inodeNum)
}

// OpenInode opens a file by its inode number, skipping the path walk. The
// inode comes from a prior ListDirectory (DirectoryEntry.Inode), so a walk +
// extract pipeline opens each file with one inode-table read instead of
// re-resolving the full path through every directory block — the dominant cost
// on large trees.
func (h *Ext4Handler) OpenInode(inode uint64, _ int64) (io.ReadSeekCloser, error) {
	if h.reader == nil {
		return nil, fmt.Errorf("ext4: handler has no reader (construct with NewExt4Handler)")
	}
	if inode == 0 || inode > 0xFFFFFFFF {
		return nil, fmt.Errorf("ext4: inode number %d out of range", inode)
	}
	return h.openInode(uint32(inode))
}

func (h *Ext4Handler) openInode(inodeNum uint32) (io.ReadSeekCloser, error) {
	inodeData, err := h.readInode(inodeNum)
	if err != nil {
		return nil, fmt.Errorf("ext4: inode %d: %w", inodeNum, err)
	}
	if len(inodeData) < 0x28+12 {
		return nil, fmt.Errorf("ext4: inode %d too small for extent root", inodeNum)
	}

	// i_mode file-type bits (0xF000): 0x4000 = directory, 0x8000 = regular.
	switch mode := binary.LittleEndian.Uint16(inodeData[0x00:]); mode & 0xF000 {
	case 0x4000:
		return nil, fmt.Errorf("ext4: inode %d is a directory: %w", inodeNum, filesystem.ErrIsDirectory)
	case 0x8000:
		// regular file: stream via its extent tree
	default:
		return nil, fmt.Errorf("ext4: inode %d is not a regular file (mode 0x%04X): %w",
			inodeNum, mode, filesystem.ErrUnsupported)
	}

	size := h.inodeSizeOf(inodeData)
	if size == 0 {
		return &ext4FileReader{h: h}, nil
	}

	flags := binary.LittleEndian.Uint32(inodeData[0x20:])
	if flags&ext4ExtentsFlag == 0 {
		return nil, fmt.Errorf("ext4: inode %d uses unsupported (non-extent) block mapping", inodeNum)
	}
	root := inodeData[0x28:]
	if magic := binary.LittleEndian.Uint16(root[0:2]); magic != ext4ExtentMagic {
		return nil, fmt.Errorf("ext4: inode %d bad extent magic 0x%04X", inodeNum, magic)
	}
	depth := binary.LittleEndian.Uint16(root[6:8])
	if depth > ext4MaxExtentDepth {
		return nil, fmt.Errorf("ext4: inode %d extent depth %d exceeds max %d", inodeNum, depth, ext4MaxExtentDepth)
	}
	return &ext4FileReader{
		h:         h,
		size:      int64(size),
		blockSize: uint64(h.blockSize),
		root:      root,
		depth:     depth,
	}, nil
}

// ext4FileReader is a lazy, seekable reader over an ext4 file's extent tree.
type ext4FileReader struct {
	h         *Ext4Handler
	size      int64
	blockSize uint64
	root      []byte // extent tree root (12-byte header + entries) from the inode
	depth     uint16
	pos       int64
}

// readAt copies into p the bytes of the file starting at off, resolving each
// logical file block through the extent tree and reading only the blocks that
// intersect the range. It returns io.EOF when off is at or past the end of the
// file, and n < len(p) with io.EOF for a range that runs past the end (the
// readable prefix is real data; nothing past the end is fabricated).
func (r *ext4FileReader) readAt(p []byte, off int64) (int, error) {
	// EOF is checked before the blockSize guard so an empty file (size 0, whose
	// reader carries no block size) reads cleanly as io.EOF rather than erroring.
	if off >= r.size {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	if r.blockSize == 0 {
		return 0, fmt.Errorf("ext4: reader has no block size")
	}
	remaining := r.size - off
	want := int64(len(p))
	atEOF := false
	if want > remaining {
		want = remaining
		atEOF = true
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

		phys, err := r.h.resolveExtent(r.root, blockIdx, r.depth)
		if err != nil {
			if errors.Is(err, errExt4Hole) {
				// Sparse hole: ext4 defines an unallocated block within the
				// declared size as zero bytes (lastlog/wtmp are mostly holes).
				// Zero-fill the readable part of this block and move on — this
				// is the on-disk semantics, not fabricated data.
				clear(p[n : n+int(take)])
				n += int(take)
				continue
			}
			return n, err
		}
		data, err := r.h.readBlockBytes(phys)
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
func (r *ext4FileReader) Read(p []byte) (int, error) {
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
func (r *ext4FileReader) ReadAt(p []byte, off int64) (int, error) {
	return r.readAt(p, off)
}

// Seek implements io.Seeker. Seeking is lazy: no block is read until a
// subsequent Read/ReadAt touches it. It shares the cursor with Read, so it is
// not safe for concurrent use; use ReadAt for concurrent access.
func (r *ext4FileReader) Seek(offset int64, whence int) (int64, error) {
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
// caller); this reader holds no resources beyond the extent root slice.
func (r *ext4FileReader) Close() error { return nil }

var _ io.ReadSeekCloser = (*ext4FileReader)(nil)
var _ io.ReaderAt = (*ext4FileReader)(nil)
var _ filesystem.FileOpener = (*Ext4Handler)(nil)
var _ filesystem.InodeOpener = (*Ext4Handler)(nil)
