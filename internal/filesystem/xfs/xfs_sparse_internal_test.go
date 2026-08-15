package xfs

import (
	"errors"
	"testing"
)

var errTestShortRead = errors.New("xfs: read past end of buffer")

// xfsSparseReader returns an XFS handler whose reader serves a buffer where fsb
// 0 is filled with 0xAA and fsb 2 with 0xBB (fsb 1 is never allocated). This is
// the on-disk shape of a sparse file: the extent list simply omits the hole.
func xfsSparseReader() *XFS {
	buf := make([]byte, 3*4096)
	for i := range buf[:4096] {
		buf[i] = 0xAA
	}
	for i := 4096 * 2; i < 4096*3; i++ {
		buf[i] = 0xBB
	}
	return &XFS{
		startLBA:  0,
		blocksize: 4096,
		agblklog:  15,
		agblocks:  1 << 15, // fsbToFsb is the identity for this geometry
		readFunc: func(lba, count uint64) ([]byte, error) {
			start := lba * 512
			end := start + count*512
			if end > uint64(len(buf)) {
				return nil, errTestShortRead
			}
			return buf[start:end], nil
		},
	}
}

// TestXFSReadExtentsSparse proves readExtents honors each extent's logical
// startoff: a gap between extents (and past the last one) is a hole whose real
// content is zeros. Regression: readExtents concatenated extents back-to-back,
// misassembling sparse files and erroring "extents cover N bytes, short of size
// M" on real images (server.E01 /etc/openldap/certs/cert8.db and friends).
func TestXFSReadExtentsSparse(t *testing.T) {
	xfs := xfsSparseReader()

	// Extent list: fsb0 at block 0, fsb2 at block 2 — block 1 is a hole.
	exts := []xfsExtent{
		{startoff: 0, startBlock: 0, blockCount: 1},
		{startoff: 2, startBlock: 2, blockCount: 1},
	}
	out, err := xfs.readExtents(exts, 3*4096)
	if err != nil {
		t.Fatalf("readExtents(sparse): %v", err)
	}
	if len(out) != 3*4096 {
		t.Fatalf("readExtents len = %d, want %d", len(out), 3*4096)
	}
	// Block 0 = 0xAA, block 1 = hole (zeros), block 2 = 0xBB.
	if out[0] != 0xAA || out[4095] != 0xAA {
		t.Errorf("extent 0 not 0xAA: out[0]=%02x out[4095]=%02x", out[0], out[4095])
	}
	for i := 4096; i < 8192; i++ {
		if out[i] != 0x00 {
			t.Fatalf("hole at offset %d = %02x, want 0x00", i, out[i])
		}
	}
	if out[8192] != 0xBB || out[12287] != 0xBB {
		t.Errorf("extent 2 not 0xBB: out[8192]=%02x out[12287]=%02x", out[8192], out[12287])
	}
}

// TestXFSReadExtentsTrailingHole covers a file whose declared size extends past
// the last allocated extent — a trailing hole must zero-fill, not error.
func TestXFSReadExtentsTrailingHole(t *testing.T) {
	xfs := xfsSparseReader()
	exts := []xfsExtent{{startoff: 0, startBlock: 0, blockCount: 1}}
	out, err := xfs.readExtents(exts, 8192)
	if err != nil {
		t.Fatalf("readExtents(trailing hole): %v", err)
	}
	if len(out) != 8192 {
		t.Fatalf("len = %d, want 8192", len(out))
	}
	if out[4095] != 0xAA || out[4096] != 0x00 || out[8191] != 0x00 {
		t.Errorf("trailing hole not zero-filled: out[4095]=%02x out[4096]=%02x out[8191]=%02x",
			out[4095], out[4096], out[8191])
	}
}
