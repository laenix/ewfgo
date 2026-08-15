package ntfs

import (
	"bytes"
	"fmt"
	"io"

	"github.com/laenix/ewfgo/internal/filesystem"
)

// OpenFile opens the file at path for streaming reads. It returns a lazy,
// seekable io.ReadSeekCloser whose reads touch only the clusters intersecting
// the accessed byte range — memory is O(read block), not O(file). This is the
// streaming path for GB-scale files (sqlite databases etc.) that GetFile
// cannot hold in memory.
//
// Resident files (data inline in the MFT record) are served from the record
// bytes already read. Non-resident files are served through a lazy reader over
// the data-run list. The file's MFT record and $DATA attribute are read once at
// open; only the cluster data is fetched on demand through the same
// reader.ReadSectors exact-decompression path as GetFile, so the red line
// holds: real on-disk data or an explicit error, never fabricated bytes.
func (h *NTFSHandler) OpenFile(path string) (io.ReadSeekCloser, error) {
	if h.reader == nil {
		return nil, fmt.Errorf("NTFS handler has no reader")
	}
	if err := h.ensureIndex(); err != nil {
		return nil, err
	}
	rec, err := h.resolvePath(path)
	if err != nil {
		return nil, err
	}
	entry := h.fileIndex[rec]
	if entry.isDir {
		return nil, fmt.Errorf("path is a directory: %s: %w", path, filesystem.ErrIsDirectory)
	}

	recBytes, err := h.readRecord(rec)
	if err != nil {
		return nil, err
	}
	attrs, err := h.parseAttrs(recBytes)
	if err != nil {
		return nil, err
	}
	var hasAttrList, hasUnnamedData bool
	for i := range attrs {
		a := &attrs[i]
		if a.typ == attrAttributeList {
			hasAttrList = true
		}
		if a.typ != attrData || a.nameLen != 0 {
			continue
		}
		hasUnnamedData = true
		if !a.nonResident {
			// Resident: data lives inline in the MFT record.
			data := recBytes[a.valueOffset : a.valueOffset+int(a.valueLen)]
			return &byteFileReader{Reader: bytes.NewReader(data)}, nil
		}
		runs, err := h.parseRuns(recBytes[a.runDataOff:a.runDataEnd])
		if err != nil {
			return nil, fmt.Errorf("data runs for %s: %w", path, err)
		}
		return &ntfsFileReader{h: h, runs: runs, size: int64(a.realSize)}, nil
	}
	// Same classification as GetFile: an $ATTRIBUTE_LIST with no local unnamed
	// $DATA holds its data in external records this parser does not follow.
	if hasAttrList && !hasUnnamedData {
		return nil, fmt.Errorf("attribute list not supported for %s: %w", path, filesystem.ErrUnsupported)
	}
	// No unnamed $DATA stream: the file is empty.
	return &byteFileReader{Reader: bytes.NewReader(nil)}, nil
}

// byteFileReader adapts a fixed byte slice to io.ReadSeekCloser.
type byteFileReader struct {
	*bytes.Reader
}

// Close releases the reader. The shared image/reader stay open (owned by the
// caller); this reader holds no resources beyond the in-memory byte slice.
func (r *byteFileReader) Close() error {
	return nil
}

// ntfsFileReader is a lazy, seekable reader over a non-resident NTFS $DATA
// stream's data-run list.
type ntfsFileReader struct {
	h    *NTFSHandler
	runs []ntfsRun
	size int64
	pos  int64
}

// runAt returns the data run that maps vcn, and whether it exists.
func runAt(runs []ntfsRun, vcn uint64) (ntfsRun, bool) {
	for _, r := range runs {
		if vcn >= r.vcnStart && vcn < r.vcnStart+r.length {
			return r, true
		}
	}
	return ntfsRun{}, false
}

// readAt copies into p the bytes of the file starting at off, following the
// data-run list and reading only the clusters intersecting the range. It
// returns io.EOF when off is at or past the end of the file, and n < len(p)
// with io.EOF for a range that runs past the end (the readable prefix is real
// data; nothing past the end is fabricated). Sparse runs return zeros, matching
// a live mount where the hole is genuinely empty.
func (r *ntfsFileReader) readAt(p []byte, off int64) (int, error) {
	if off >= r.size {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	remaining := r.size - off
	atEOF := false
	want := int64(len(p))
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
		vcn := uint64(o) / r.h.clusterSize
		within := uint64(o) % r.h.clusterSize
		run, ok := runAt(r.runs, vcn)
		if !ok {
			return n, fmt.Errorf("file offset %d: VCN %d not mapped by data runs", o, vcn)
		}
		var data []byte
		if run.lcnStart < 0 {
			// Sparse run: the logical bytes are all zero.
			data = make([]byte, r.h.clusterSize)
		} else {
			lcn := run.lcnStart + int64(vcn-run.vcnStart)
			cl, err := r.h.readClustersAtLCN(lcn, 1)
			if err != nil {
				return n, err
			}
			data = cl
		}
		take := int64(len(data)) - int64(within)
		if take > int64(want)-int64(n) {
			take = int64(want) - int64(n)
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
func (r *ntfsFileReader) Read(p []byte) (int, error) {
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
// as sqlite's would drive a database through); the data-run list is parsed once
// at open and never mutated, so reads only touch read-only state. A read that
// ends past EOF returns the readable prefix plus io.EOF (io.ReaderAt requires a
// non-nil error when n < len(p)); a read that ends exactly at EOF returns n
// bytes with a nil error.
func (r *ntfsFileReader) ReadAt(p []byte, off int64) (int, error) {
	return r.readAt(p, off)
}

// Seek implements io.Seeker. Seeking is lazy: no cluster is read until a
// subsequent Read/ReadAt touches it. It shares the cursor with Read, so it is
// not safe for concurrent use; use ReadAt for concurrent access.
func (r *ntfsFileReader) Seek(offset int64, whence int) (int64, error) {
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

// Close releases the reader. The shared image/reader stay open (owned by the
// caller); this reader holds no resources beyond the parsed run list.
func (r *ntfsFileReader) Close() error {
	return nil
}

var _ io.ReadSeekCloser = (*ntfsFileReader)(nil)
var _ io.ReadSeekCloser = (*byteFileReader)(nil)
var _ filesystem.FileOpener = (*NTFSHandler)(nil)
