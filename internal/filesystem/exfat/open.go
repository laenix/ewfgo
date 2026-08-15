package exfat

import (
	"fmt"
	"io"
	"sync"

	"github.com/laenix/ewfgo/internal/filesystem"
)

// OpenFile opens the file at path for streaming reads. It returns a lazy,
// seekable io.ReadSeekCloser whose reads touch only the clusters intersecting
// the accessed byte range — memory is O(read block), not O(file). This is the
// streaming path for GB-scale files (sqlite databases etc.) that GetFile
// cannot hold in memory.
//
// The cluster chain is still resolved on demand as reads reach deeper clusters
// (it is O(num clusters accessed), not O(file bytes)); only the data reads are
// lazy. Every data byte comes from the same readFunc exact-decompression path
// as GetFile, so the red line holds: real on-disk data or an explicit error,
// never fabricated bytes.
func (exfat *EXFAT) OpenFile(path string) (io.ReadSeekCloser, error) {
	if exfat.readFunc == nil {
		return nil, fmt.Errorf("exFAT handler has no reader")
	}
	entry, err := exfat.resolveEntry(path)
	if err != nil {
		return nil, err
	}
	if entry.IsDir {
		return nil, fmt.Errorf("path is a directory: %s: %w", path, filesystem.ErrIsDirectory)
	}
	return newEXFATFileReader(exfat, entry.Cluster, entry.Size)
}

// exfatFileReader is a lazy, seekable reader over an exFAT file's cluster chain.
//
// Concurrency: ReadAt is safe for concurrent use on the same handle — the
// mutable cluster-chain state (chain/seen/next/done) is guarded by mu, and the
// per-cluster element is immutable once written. Read/Seek share a cursor (pos)
// and are NOT concurrent-safe; use ReadAt (position-independent) for concurrent
// access, or one handle per goroutine.
type exfatFileReader struct {
	x           *EXFAT
	size        int64
	clusterSize uint64
	pos         int64

	// mu guards chain/seen/next/done. It is held only across the
	// extend-then-lookup section of readAt, never during the cluster data read
	// (readFunc), so concurrent ReadAt calls at different offsets do not
	// serialize on I/O.
	mu sync.Mutex

	// chain holds the resolved prefix of the cluster chain; chain[0] is the
	// file's start cluster. It is extended lazily as reads/seeks reach deeper
	// clusters, so memory scales with bytes actually accessed, not file size.
	chain []uint32
	seen  map[uint32]bool
	next  uint32 // the cluster to resolve when chain grows
	done  bool   // chain fully resolved (end-of-chain marker seen)
}

// newEXFATFileReader builds a lazy reader. An empty file returns a reader whose
// reads immediately hit io.EOF regardless of its (possibly 0) start cluster.
func newEXFATFileReader(x *EXFAT, start uint32, size uint64) (*exfatFileReader, error) {
	r := &exfatFileReader{
		x:           x,
		size:        int64(size),
		clusterSize: x.clusterSize,
		seen:        make(map[uint32]bool),
		next:        start,
	}
	if size == 0 {
		r.done = true
		return r, nil
	}
	if start < 2 {
		return nil, fmt.Errorf("file has size %d but invalid start cluster %d", size, start)
	}
	return r, nil
}

// extendTo ensures chain has at least clusterIdx+1 resolved clusters, walking
// the exFAT FAT table on demand. It stops at an end-of-chain marker and rejects
// bad clusters, truncated chains, cycles and over-long chains.
//
// It mutates the shared chain state (chain/seen/next/done) and must be called
// with r.mu held; readAt satisfies this and reads the resolved element back
// before releasing the lock.
func (r *exfatFileReader) extendTo(clusterIdx int) error {
	for len(r.chain) <= clusterIdx && !r.done {
		cl := r.next
		if r.seen[cl] {
			return fmt.Errorf("cycle detected in cluster chain at cluster %d", cl)
		}
		if len(r.chain) >= maxClusterChain {
			return fmt.Errorf("cluster chain exceeds %d clusters", maxClusterChain)
		}
		r.seen[cl] = true
		r.chain = append(r.chain, cl)

		next, err := r.x.fatEntry(cl)
		if err != nil {
			return fmt.Errorf("FAT entry for cluster %d: %w", cl, err)
		}
		switch {
		case next == exfatBadCluster:
			return fmt.Errorf("bad cluster marker at cluster %d", cl)
		case next == 0:
			return fmt.Errorf("truncated cluster chain: cluster %d has no next/EOC entry", cl)
		case next == exfatEOC:
			r.done = true
		default:
			r.next = next
		}
	}
	return nil
}

// readAt copies into p the bytes of the file starting at off, following the
// cluster chain. It reads only the clusters intersecting the range. It returns
// io.EOF when off is at or past the end of the file, and n < len(p) with
// io.EOF for a range that runs past the end (the readable prefix is real data;
// nothing past the end is fabricated).
func (r *exfatFileReader) readAt(p []byte, off int64) (int, error) {
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
		clusterIdx := int(o / int64(r.clusterSize))
		within := uint64(o % int64(r.clusterSize))

		// Extend-then-lookup under mu: extendTo appends to chain and mutates
		// seen/next/done, and the resolved element is read back below, so both
		// must happen under the same lock. The element itself is immutable once
		// written (later extends only append beyond it), so the data read that
		// follows is safe outside the lock.
		r.mu.Lock()
		err := r.extendTo(clusterIdx)
		var cl uint32
		if err == nil && clusterIdx >= len(r.chain) {
			// The chain ended before the file's declared size: the allocation
			// is truncated. Serving the readable prefix would fabricate the
			// missing tail as if it existed, so this is an explicit error.
			err = fmt.Errorf("file size %d exceeds %d bytes allocated by cluster chain", r.size, uint64(len(r.chain))*r.clusterSize)
		}
		if err == nil {
			cl = r.chain[clusterIdx]
		}
		r.mu.Unlock()
		if err != nil {
			return n, err
		}

		lba := r.x.clusterToLBA(cl)
		data, err := r.x.readSectors(lba, uint64(r.x.sectorsPerCluster))
		if err != nil {
			return n, fmt.Errorf("failed to read data cluster %d (LBA %d): %w", cl, lba, err)
		}
		if uint64(len(data)) < r.clusterSize {
			return n, fmt.Errorf("short read for data cluster %d: got %d bytes, want %d", cl, len(data), r.clusterSize)
		}
		take := int64(r.clusterSize) - int64(within)
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
func (r *exfatFileReader) Read(p []byte) (int, error) {
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
// as sqlite's would drive a database through). A read that ends past EOF
// returns the readable prefix plus io.EOF (io.ReaderAt requires a non-nil
// error when n < len(p)); a read that ends exactly at EOF returns n bytes with
// a nil error.
func (r *exfatFileReader) ReadAt(p []byte, off int64) (int, error) {
	return r.readAt(p, off)
}

// Seek implements io.Seeker. Seeking is lazy: no cluster is read until a
// subsequent Read/ReadAt touches it. It shares the cursor with Read, so it is
// not safe for concurrent use; use ReadAt for concurrent access.
func (r *exfatFileReader) Seek(offset int64, whence int) (int64, error) {
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

// Close releases the reader. The shared image/reader stay open (they are owned
// by the caller); this reader holds no resources beyond the resolved chain.
func (r *exfatFileReader) Close() error {
	return nil
}

var _ io.ReadSeekCloser = (*exfatFileReader)(nil)
var _ filesystem.FileOpener = (*EXFAT)(nil)
