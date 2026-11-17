package btrfs

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/laenix/ewfgo/internal/filesystem"
)

// btrfsExtentData is the lazy handle for one EXTENT_DATA item of the opened
// file. For an inline item (typ 0) the file bytes ride in inline; for a REG or
// PREALLOC disk extent (typ 1/2) the bytes live at disk_bytenr+extentOff, with
// disk_bytenr 0 meaning a prealloc'd hole that reads as zeros.
type btrfsExtentData struct {
	offset uint64 // logical file byte offset (the item's key.offset)
	span   uint64 // byte length covered at offset
	typ    byte   // 0 inline, 1 REG, 2 PREALLOC

	inline []byte // inline file bytes (typ 0)

	diskBytenr   uint64
	diskNumBytes uint64
	extentOff    uint64
}

// btrfsExtentSpan returns the byte span an EXTENT_DATA item's payload covers,
// using the same rules as maxExtentEnd: len(data)-21 for inline, num_bytes for
// REG/PREALLOC, 0 when malformed or oversized (readExtent would error on it).
func btrfsExtentSpan(data []byte) uint64 {
	if len(data) < 21 {
		return 0
	}
	switch data[20] {
	case 0: // BTRFS_FILE_EXTENT_INLINE
		return uint64(len(data) - 21)
	case 1, 2: // BTRFS_FILE_EXTENT_REG / PREALLOC
		if len(data) < 53 {
			return 0
		}
		n := binary.LittleEndian.Uint64(data[45:53])
		if n > 1<<30 {
			return 0
		}
		return n
	}
	return 0
}

// OpenFile opens the file at path for streaming reads. It returns a lazy,
// seekable io.ReadSeekCloser whose reads touch only the extent bytes
// intersecting the accessed byte range — memory is O(read block), not O(file).
// This is the streaming path for GB-scale files (sqlite databases etc.) that
// ReadFile cannot hold in memory.
//
// Only regular files are streamable. A directory resolves to ErrIsDirectory, a
// missing path to ErrNotFound, and a path that descends through a non-directory
// to ErrNotDirectory — nothing is fabricated. The inode's EXTENT_DATA items
// (the extent map, O(extents)) are resolved at open; only the file bytes are
// read lazily. Gaps without an EXTENT_DATA item, and prealloc'd holes without
// backing data, read as zeros, matching btrfs's sparse-file semantics.
// Compression and encryption are unsupported and error explicitly (mirroring
// readExtent): a compressed extent's raw bytes are not the file content.
//
// Concurrency: the reader's state (size, extent list) is immutable after open,
// and every data read goes through translate / readBytes, which only read via
// the handler's readFunc (concurrency-safe). ReadAt is therefore safe for
// concurrent use on the same handle without internal locking; Read/Seek share
// a cursor and are not concurrent-safe.
func (btrfs *Btrfs) OpenFile(path string) (io.ReadSeekCloser, error) {
	if btrfs.readFunc == nil {
		return nil, fmt.Errorf("btrfs: handler has no reader")
	}
	if err := btrfs.ensureFsTree(); err != nil {
		return nil, err
	}
	clean := strings.Trim(path, "/")
	var inode uint64
	if clean == "" {
		// The FS tree root directory (objectid 256).
		inode = uint64(btrfsFirstFreeObjectid)
	} else {
		var err error
		inode, err = btrfs.resolveInodeFromItems(btrfs.fsItems, clean)
		if err != nil {
			return nil, err
		}
	}
	return btrfs.openInode(inode)
}

// OpenInode opens a file by its inode number, skipping the path walk (see
// filesystem.InodeOpener). The inode comes from a prior ListDirectory
// (DirectoryEntry.Inode); btrfs reads its own INODE_ITEM, so the size param is
// ignored.
func (btrfs *Btrfs) OpenInode(inode uint64, _ int64) (io.ReadSeekCloser, error) {
	if btrfs.readFunc == nil {
		return nil, fmt.Errorf("btrfs: handler has no reader")
	}
	if err := btrfs.ensureFsTree(); err != nil {
		return nil, err
	}
	return btrfs.openInode(inode)
}

func (btrfs *Btrfs) openInode(inode uint64) (io.ReadSeekCloser, error) {
	in, ok := btrfs.fsInodes[inode]
	if !ok {
		return nil, fmt.Errorf("btrfs: inode %d has no INODE_ITEM", inode)
	}
	if in.mode&0xF000 == 0x4000 {
		return nil, fmt.Errorf("btrfs: inode %d is a directory: %w", inode, filesystem.ErrIsDirectory)
	}
	if in.mode&0xF000 != 0x8000 {
		return nil, fmt.Errorf("btrfs: inode %d is not a regular file: %w", inode, filesystem.ErrUnsupported)
	}
	// The INODE_ITEM's st_size is an untrusted on-disk field: a crafted value
	// must never drive a giant allocation. Bound it by the inode's extent-backed
	// coverage, then by a hard cap (same policy as GetFile).
	size := in.size
	if maxEnd := btrfs.maxExtentEnd(inode); size > maxEnd {
		size = maxEnd
	}
	const maxBtrfsFileBytes = uint64(1) << 40
	if size > maxBtrfsFileBytes {
		return nil, fmt.Errorf("btrfs: file inode %d size %d exceeds the supported maximum", inode, size)
	}

	extents := make([]btrfsExtentData, 0, 8)
	for _, it := range btrfs.fsItems {
		if it.key.typ != btrfsExtentDataKey || it.key.objectid != inode {
			continue
		}
		span := btrfsExtentSpan(it.data)
		if span == 0 {
			continue
		}
		ed := btrfsExtentData{offset: it.key.offset, span: span}
		if it.data[20] == 0 {
			ed.typ = 0
			ed.inline = it.data[21:]
			extents = append(extents, ed)
			continue
		}
		if len(it.data) < 53 {
			continue
		}
		ed.typ = it.data[20]
		ed.diskBytenr = binary.LittleEndian.Uint64(it.data[21:29])
		ed.diskNumBytes = binary.LittleEndian.Uint64(it.data[29:37])
		ed.extentOff = binary.LittleEndian.Uint64(it.data[37:45])
		// Compression/encryption is unsupported: a compressed extent's raw bytes
		// are not the file content, so streaming them would fabricate data. This
		// mirrors readExtent (which rejects them explicitly).
		if it.data[16] != 0 || it.data[17] != 0 {
			return nil, fmt.Errorf("btrfs: inode %d extent at offset %d is compressed or encrypted, unsupported", inode, ed.offset)
		}
		if ed.diskBytenr != 0 {
			// Disk geometry sanity (mirrors readExtent): a malformed extent is an
			// explicit error, never fabricated bytes.
			if ed.diskNumBytes == 0 || ed.diskNumBytes > 1<<30 ||
				ed.extentOff > 1<<40 || ed.diskBytenr > 1<<40 ||
				ed.extentOff+ed.span > ed.diskNumBytes {
				return nil, fmt.Errorf("btrfs: inode %d extent at offset %d has invalid disk geometry", inode, ed.offset)
			}
		}
		extents = append(extents, ed)
	}
	return &btrfsFileReader{h: btrfs, size: int64(size), extents: extents}, nil
}

// btrfsFileReader is a lazy, seekable reader over a btrfs file's EXTENT_DATA
// items.
type btrfsFileReader struct {
	h       *Btrfs
	size    int64
	extents []btrfsExtentData
	pos     int64
}

// extentAt returns the EXTENT_DATA item covering the logical file byte off, if
// any. Items are iterated in key order (the order they appear in the leaves),
// so the first match is the one GetFile would copy last for overlapping ranges.
func extentAt(exts []btrfsExtentData, off uint64) (btrfsExtentData, bool) {
	for _, e := range exts {
		if off >= e.offset && off < e.offset+e.span {
			return e, true
		}
	}
	return btrfsExtentData{}, false
}

// readAt copies into p the bytes of the file starting at off. It returns io.EOF
// when off is at or past the end of the file, and n < len(p) with io.EOF for a
// range that runs past the end (the readable prefix is real data; nothing past
// the end is fabricated). Gaps and prealloc'd holes read as zeros, matching
// btrfs sparse-file semantics.
func (r *btrfsFileReader) readAt(p []byte, off int64) (int, error) {
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

	n := 0
	for n < int(want) {
		o := off + int64(n)
		ext, ok := extentAt(r.extents, uint64(o))
		if !ok {
			// Hole: no EXTENT_DATA item covers this byte. Zero-fill up to the
			// next extent start (or the end of the request), matching btrfs.
			next := uint64(r.size)
			for _, e := range r.extents {
				if e.offset > uint64(o) && e.offset < next {
					next = e.offset
				}
			}
			take := int64(next - uint64(o))
			if take > int64(want)-int64(n) {
				take = int64(want) - int64(n)
			}
			clear(p[n : n+int(take)])
			n += int(take)
			continue
		}
		within := uint64(o) - ext.offset
		avail := ext.span - within
		take := int64(avail)
		if take > int64(want)-int64(n) {
			take = int64(want) - int64(n)
		}
		if ext.typ == 0 {
			// Inline extent: the file bytes are part of the node item.
			copy(p[n:], ext.inline[within:within+uint64(take)])
		} else if ext.diskBytenr == 0 {
			// Prealloc'd extent with no backing data: a hole, reads as zeros.
			clear(p[n : n+int(take)])
		} else {
			src := ext.diskBytenr + ext.extentOff + within
			phys, err := r.h.translate(src)
			if err != nil {
				return n, fmt.Errorf("btrfs: file offset %d: %w", o, err)
			}
			data, err := r.h.readBytes(phys, uint64(take))
			if err != nil {
				return n, err
			}
			copy(p[n:], data)
		}
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
func (r *btrfsFileReader) Read(p []byte) (int, error) {
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
func (r *btrfsFileReader) ReadAt(p []byte, off int64) (int, error) {
	return r.readAt(p, off)
}

// Seek implements io.Seeker. Seeking is lazy: no byte is read until a
// subsequent Read/ReadAt touches it. It shares the cursor with Read, so it is
// not safe for concurrent use; use ReadAt for concurrent access.
func (r *btrfsFileReader) Seek(offset int64, whence int) (int64, error) {
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
func (r *btrfsFileReader) Close() error { return nil }

var _ io.ReadSeekCloser = (*btrfsFileReader)(nil)
var _ io.ReaderAt = (*btrfsFileReader)(nil)
var _ filesystem.FileOpener = (*Btrfs)(nil)
var _ filesystem.InodeOpener = (*Btrfs)(nil)
