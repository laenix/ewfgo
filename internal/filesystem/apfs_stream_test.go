package filesystem_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"

	"github.com/laenix/ewfgo/internal/filesystem"
	"github.com/laenix/ewfgo/internal/filesystem/apfs"
)

// ---------------------------------------------------------------------------
// Hermetic fake APFS container. There is no committed APFS E01 fixture, so the
// streaming reader is exercised end to end against a minimal in-memory APFS
// container: a block-0 NXSB, a live NXSB copy in the checkpoint descriptor
// area, a container object-map, an APSB volume superblock, a volume object-map
// and a single catalog root leaf holding every record type the reader must
// handle. All btree/record layouts mirror what apfs.go parses; the mount chain
// (ensureMounted → ensureIndex → walkCatalogNode) runs against real on-disk
// bytes.
// ---------------------------------------------------------------------------

// memAPFSReader is a fake Reader over an in-memory container.
type memAPFSReader struct {
	data []byte
}

func (r *memAPFSReader) ReadSectors(lba, count uint64) ([]byte, error) {
	start := lba * 512
	end := start + count*512
	if end > uint64(len(r.data)) {
		return nil, fmt.Errorf("read past end of image")
	}
	return r.data[start:end], nil
}

const (
	fakeAPFSBlock     = 4096
	fakeAPFSImageSize = 0x300 * 4096 // 0x300 blocks
)

const (
	apfsBlkNXSB        = 0 // block-0 container superblock
	apfsBlkDesc        = 1 // descriptor-area live NXSB copy (scan blocks 1..2)
	apfsBlkContOmap    = 3 // container object-map _phys header
	apfsBlkContTree    = 4 // container object-map btree root leaf
	apfsBlkAPSB        = 5 // volume superblock
	apfsBlkVolOmap     = 6 // volume object-map _phys header
	apfsBlkVolTree     = 7 // volume object-map btree root leaf
	apfsBlkCatalog     = 8 // catalog root leaf
	apfsBlkDataStart   = 0x200
)

func apfsPutU16(b []byte, off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }

// apfsCatKey builds a catalog key from a record type and object id, optionally
// followed by the record's key tail (name bytes, laddr, etc.).
func apfsCatKey(typ, id uint64, tail ...byte) []byte {
	v := typ<<60 | id
	k := make([]byte, 8, 8+len(tail))
	binary.LittleEndian.PutUint64(k, v)
	return append(k, tail...)
}

func apfsDirRecKey(parent uint64, name string) []byte {
	// {obj_id_and_type, name_len_and_hash u32, name} — name includes the NUL.
	nlh := uint32(len(name) + 1)
	var tail [4]byte
	binary.LittleEndian.PutUint32(tail[:], nlh)
	k := apfsCatKey(0x9, parent, tail[:]...)
	return append(k, append([]byte(name), 0)...)
}

func apfsXattrKey(ino uint64, name string) []byte {
	// {obj_id_and_type, name_len u16, name} — name includes the NUL.
	var tail [2]byte
	binary.LittleEndian.PutUint16(tail[:], uint16(len(name)+1))
	k := apfsCatKey(0x4, ino, tail[:]...)
	return append(k, append([]byte(name), 0)...)
}

func apfsFileExtKey(stream uint64, laddr uint64) []byte {
	var tail [8]byte
	binary.LittleEndian.PutUint64(tail[:], laddr)
	return apfsCatKey(0x8, stream, tail[:]...)
}

func apfsInodeVal(size uint64, mode uint16) []byte {
	b := make([]byte, 96)
	binary.LittleEndian.PutUint64(b[8:16], 1)     // private_id (unused by GetFile)
	binary.LittleEndian.PutUint16(b[80:82], mode) // mode
	binary.LittleEndian.PutUint64(b[84:92], size) // uncompressed_size (no dstream xfield → authoritative)
	return b
}

func apfsDirRecVal(child uint64) []byte {
	b := make([]byte, 20)
	binary.LittleEndian.PutUint64(b[0:8], child) // target ino
	binary.LittleEndian.PutUint32(b[8:12], 1)    // added (best effort)
	b[16] = 8                                    // DT_REG
	return b
}

func apfsFileExtentVal(length, paddr uint64) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint64(b[0:8], length) // len_and_flags (low 56 bits)
	binary.LittleEndian.PutUint64(b[8:16], paddr) // physical block number
	return b
}

func apfsDstreamIdVal(doid uint64) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint64(b[8:16], doid) // dstream_id
	return b
}

func apfsXattrVal(xdata []byte) []byte {
	b := make([]byte, 4+len(xdata))
	apfsPutU16(b, 2, uint16(len(xdata)))
	copy(b[4:], xdata)
	return b
}

// buildAPFSCatLeaf builds a catalog root leaf (btnRoot, level 0) holding the
// given records. Key data grows upward from the TOC; values grow downward from
// the 40-byte root footer — the exact geometry walkCatalogNode expects.
func buildAPFSCatLeaf(keys, vals [][]byte) []byte {
	n := len(keys)
	if n != len(vals) {
		panic("key/value count mismatch")
	}
	block := make([]byte, fakeAPFSBlock)
	apfsPutU16(block, 0x20, 0x3) // btnRoot | btnLeaf
	apfsPutU16(block, 0x22, 0)   // level 0
	putU32(block, 0x24, uint32(n))
	tableLen := 8 * n
	apfsPutU16(block, 0x2a, uint16(tableLen))
	// Keys: 8-byte TOC entries, key area starting at 56+tableLen.
	off := 0
	for i, key := range keys {
		apfsPutU16(block, 0x38+8*i, uint16(off))
		apfsPutU16(block, 0x38+8*i+2, uint16(len(key)))
		copy(block[56+tableLen+off:], key)
		off += len(key)
	}
	// Values from the block end (40-byte root footer below them).
	pos := fakeAPFSBlock - 40
	for i := n - 1; i >= 0; i-- {
		v := vals[i]
		pos -= len(v)
		apfsPutU16(block, 0x38+8*i+4, uint16(fakeAPFSBlock-pos-40))
		apfsPutU16(block, 0x38+8*i+6, uint16(len(v)))
		copy(block[pos:], v)
	}
	return block
}

// buildAPFSOmapLeaf builds an object-map root leaf mapping oids (→paddr). The
// 4-byte TOC layout and {pad, paddr} value shape mirror resolveOmapOidAt.
func buildAPFSOmapLeaf(pairs [][2]uint64) []byte {
	n := len(pairs)
	block := make([]byte, fakeAPFSBlock)
	apfsPutU16(block, 0x20, 0x3) // btnRoot | btnLeaf
	apfsPutU16(block, 0x22, 0)
	putU32(block, 0x24, uint32(n))
	tableLen := 4 * n
	apfsPutU16(block, 0x2a, uint16(tableLen))
	for i, p := range pairs {
		apfsPutU16(block, 0x38+4*i, uint16(16*i)) // keyOff
		apfsPutU16(block, 0x38+4*i+2, 16)         // valOff (overwritten below)
		keyPos := 56 + tableLen + 16*i
		putU64(block, keyPos, p[0]) // oid
		putU64(block, keyPos+8, 1)  // xid (<= maxXid)
	}
	// Values from the block end: {pad u64, paddr u64}.
	pos := fakeAPFSBlock - 40
	for i := n - 1; i >= 0; i-- {
		pos -= 16
		apfsPutU16(block, 0x38+4*i+2, uint16(fakeAPFSBlock-pos-40))
		putU64(block, pos+8, pairs[i][1])
	}
	return block
}

// buildFakeAPFSStreamImage builds a full fake APFS container (see the header
// comment) whose root directory lists every streaming case: multi.bin (two
// extents), sparse.bin (extent + hole + extent), local.txt (one short extent),
// empty.txt (size 0), link (a symlink), decmpfs.bin (decmpfs xattr) and
// dstream.bin (extents keyed by a separate dstream oid).
func buildFakeAPFSStreamImage() *memAPFSReader {
	img := make([]byte, fakeAPFSImageSize)
	blk := func(n int) []byte { return img[n*fakeAPFSBlock : (n+1)*fakeAPFSBlock] }

	// Block 0 NXSB: geometry for the descriptor scan.
	nx0 := blk(apfsBlkNXSB)
	copy(nx0[0x20:0x24], "NXSB")
	putU32(nx0, 0x24, fakeAPFSBlock)
	putU32(nx0, 0x68, 2) // descBlocks (scan blocks 1..2)
	putU64(nx0, 0x70, 1) // descBase

	// Descriptor-area live NXSB (block 1, xid 2 — highest in the scan).
	live := blk(apfsBlkDesc)
	copy(live[0x20:0x24], "NXSB")
	putU32(live, 0x18, 0x80000001)      // NX_SUPERBLOCK
	putU64(live, 0x10, 2)               // xid
	putU64(live, 0x60, 2)               // container max_xid (→ maxXid 1)
	putU64(live, 0xa0, apfsBlkContOmap) // container object-map oid
	putU32(live, 0xb4, 1)               // max_fs
	putU64(live, 0xb8, 5)               // fs_oid[0] = 5 (arbitrary volume oid)

	// Container object-map: _phys header (tree root at 0x30) + root leaf mapping
	// volume oid 5 → APSB block.
	putU64(blk(apfsBlkContOmap), 0x30, apfsBlkContTree)
	copy(blk(apfsBlkContTree), buildAPFSOmapLeaf([][2]uint64{{5, apfsBlkAPSB}}))

	// Volume superblock (APSB) at block 5.
	apb := blk(apfsBlkAPSB)
	copy(apb[0x20:0x24], "APSB")
	putU64(apb, 0x10, 1)               // checkpoint xid (→ volume maxXid 1)
	putU64(apb, 0x80, apfsBlkVolOmap)  // volume object-map oid
	putU64(apb, 0x88, apfsBlkCatalog)  // catalog root oid
	copy(apb[0x29e:0x29e+6], "FIXTURE")

	// Volume object-map: _phys header + root leaf mapping catalog oid → block 8.
	putU64(blk(apfsBlkVolOmap), 0x30, apfsBlkVolTree)
	copy(blk(apfsBlkVolTree), buildAPFSOmapLeaf([][2]uint64{{apfsBlkCatalog, apfsBlkCatalog}}))

	// Catalog records.
	const (
		rootIno   = 2
		multiIno  = 100
		sparseIno = 101
		localIno  = 102
		emptyIno  = 103
		linkIno   = 104
		decmpfsIno = 105
		dstreamIno = 106
		dstreamOID = 900
	)
	type rec struct {
		key []byte
		val []byte
	}
	recs := []rec{
		{apfsCatKey(0x3, rootIno), apfsInodeVal(0, 0x41ed)},
		{apfsDirRecKey(rootIno, "multi.bin"), apfsDirRecVal(multiIno)},
		{apfsDirRecKey(rootIno, "sparse.bin"), apfsDirRecVal(sparseIno)},
		{apfsDirRecKey(rootIno, "local.txt"), apfsDirRecVal(localIno)},
		{apfsDirRecKey(rootIno, "empty.txt"), apfsDirRecVal(emptyIno)},
		{apfsDirRecKey(rootIno, "link"), apfsDirRecVal(linkIno)},
		{apfsDirRecKey(rootIno, "decmpfs.bin"), apfsDirRecVal(decmpfsIno)},
		{apfsDirRecKey(rootIno, "dstream.bin"), apfsDirRecVal(dstreamIno)},

		// multi.bin: two 4096-byte extents at blocks 0x200 / 0x201.
		{apfsCatKey(0x3, multiIno), apfsInodeVal(8192, 0x81a4)},
		{apfsFileExtKey(multiIno, 0), apfsFileExtentVal(4096, apfsBlkDataStart)},
		{apfsFileExtKey(multiIno, 4096), apfsFileExtentVal(4096, apfsBlkDataStart+1)},

		// sparse.bin: extent, 4096-byte hole, extent.
		{apfsCatKey(0x3, sparseIno), apfsInodeVal(12288, 0x81a4)},
		{apfsFileExtKey(sparseIno, 0), apfsFileExtentVal(4096, apfsBlkDataStart+2)},
		{apfsFileExtKey(sparseIno, 8192), apfsFileExtentVal(4096, apfsBlkDataStart+3)},

		// local.txt: a single 6-byte extent (short of one block).
		{apfsCatKey(0x3, localIno), apfsInodeVal(6, 0x81a4)},
		{apfsFileExtKey(localIno, 0), apfsFileExtentVal(6, apfsBlkDataStart+4)},

		// empty.txt: size 0, no extents.
		{apfsCatKey(0x3, emptyIno), apfsInodeVal(0, 0x81a4)},

		// link: a symlink inode (mode 0120777); its content is a target string.
		{apfsCatKey(0x3, linkIno), apfsInodeVal(0, 0xa1ff)},

		// decmpfs.bin: a decmpfs xattr makes the data fork dataless.
		{apfsCatKey(0x3, decmpfsIno), apfsInodeVal(0, 0x81a4)},
		{apfsXattrKey(decmpfsIno, "com.apple.decmpfs"), apfsXattrVal(make([]byte, 16))},

		// dstream.bin: DSTREAM_ID → 900, extents keyed by 900.
		{apfsCatKey(0x3, dstreamIno), apfsInodeVal(4096, 0x81a4)},
		{apfsCatKey(0x6, dstreamIno), apfsDstreamIdVal(dstreamOID)},
		{apfsFileExtKey(dstreamOID, 0), apfsFileExtentVal(4096, apfsBlkDataStart+5)},
	}
	keys := make([][]byte, len(recs))
	vals := make([][]byte, len(recs))
	for i, r := range recs {
		keys[i] = r.key
		vals[i] = r.val
	}
	copy(blk(apfsBlkCatalog), buildAPFSCatLeaf(keys, vals))

	// Data blocks: 0x200=0xAA, 0x201=0xBB, 0x202=0xCC, 0x203=0xDD,
	// 0x204="hello\n", 0x205=0xEE.
	fill := func(block int, val byte) {
		start := block * fakeAPFSBlock
		for i := start; i < start+fakeAPFSBlock; i++ {
			img[i] = val
		}
	}
	fill(apfsBlkDataStart, 0xAA)
	fill(apfsBlkDataStart+1, 0xBB)
	fill(apfsBlkDataStart+2, 0xCC)
	fill(apfsBlkDataStart+3, 0xDD)
	copy(img[(apfsBlkDataStart+4)*fakeAPFSBlock:], "hello\n")
	fill(apfsBlkDataStart+5, 0xEE)

	return &memAPFSReader{data: img}
}

func apfsStreamHandler(t *testing.T) *apfs.APFS {
	t.Helper()
	h, err := apfs.NewAPFSHandler(buildFakeAPFSStreamImage(), 0)
	if err != nil {
		t.Fatalf("NewAPFSHandler: %v", err)
	}
	return h
}

// TestAPFSOpenFileStreamsMultiBlock verifies a two-extent file streams byte for
// byte, including a ReadAt that crosses the extent boundary.
func TestAPFSOpenFileStreamsMultiBlock(t *testing.T) {
	h := apfsStreamHandler(t)

	rc, err := h.OpenFile("multi.bin")
	if err != nil {
		t.Fatalf("OpenFile(multi.bin): %v", err)
	}
	defer rc.Close()

	want := make([]byte, 8192)
	for i := 0; i < 4096; i++ {
		want[i] = 0xAA
	}
	for i := 4096; i < 8192; i++ {
		want[i] = 0xBB
	}
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("multi.bin content mismatch: got %d bytes", len(got))
	}

	ra := rc.(io.ReaderAt)
	buf := make([]byte, 8)
	if n, err := ra.ReadAt(buf, 4093); n != 8 || err != nil {
		t.Fatalf("ReadAt(4093): n=%d err=%v", n, err)
	}
	if !bytes.Equal(buf, []byte{0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB}) {
		t.Fatalf("cross-boundary ReadAt = %x", buf)
	}
}

// TestAPFSOpenFileSparse verifies the gap between two FILE_EXTENT records reads
// as zeros, matching APFS sparse-file semantics.
func TestAPFSOpenFileSparse(t *testing.T) {
	h := apfsStreamHandler(t)

	rc, err := h.OpenFile("sparse.bin")
	if err != nil {
		t.Fatalf("OpenFile(sparse.bin): %v", err)
	}
	defer rc.Close()

	want := make([]byte, 12288)
	for i := 0; i < 4096; i++ {
		want[i] = 0xCC
	}
	for i := 8192; i < 12288; i++ {
		want[i] = 0xDD
	}
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("sparse.bin mismatch (hole not zero): got %d bytes", len(got))
	}

	ra := rc.(io.ReaderAt)
	buf := make([]byte, 16)
	if n, err := ra.ReadAt(buf, 4100); n != 16 || err != nil {
		t.Fatalf("ReadAt(4100): n=%d err=%v", n, err)
	}
	for _, b := range buf {
		if b != 0 {
			t.Fatalf("hole ReadAt = %x, want zeros", buf)
		}
	}
}

// TestAPFSOpenFileLocal verifies a short (sub-block) extent streams.
func TestAPFSOpenFileLocal(t *testing.T) {
	h := apfsStreamHandler(t)

	rc, err := h.OpenFile("local.txt")
	if err != nil {
		t.Fatalf("OpenFile(local.txt): %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "hello\n" {
		t.Fatalf("local.txt = %q, want %q", string(got), "hello\n")
	}
}

// TestAPFSOpenFileDstream verifies extents keyed by a DSTREAM_ID dstream oid
// (a shared/cloned stream) stream through the same reader.
func TestAPFSOpenFileDstream(t *testing.T) {
	h := apfsStreamHandler(t)

	rc, err := h.OpenFile("dstream.bin")
	if err != nil {
		t.Fatalf("OpenFile(dstream.bin): %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != 4096 {
		t.Fatalf("dstream.bin = %d bytes, want 4096", len(got))
	}
	for i, b := range got {
		if b != 0xEE {
			t.Fatalf("dstream.bin[%d] = %02x, want 0xEE", i, b)
		}
	}
}

// TestAPFSOpenFileEmpty verifies a size-0 file reads cleanly as io.EOF.
func TestAPFSOpenFileEmpty(t *testing.T) {
	h := apfsStreamHandler(t)

	rc, err := h.OpenFile("empty.txt")
	if err != nil {
		t.Fatalf("OpenFile(empty.txt): %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll(empty.txt): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("empty.txt = %d bytes, want 0", len(got))
	}
	if _, err := rc.Seek(0, io.SeekEnd); err != nil {
		t.Fatalf("Seek end: %v", err)
	}
}

// TestAPFSOpenFileErrors verifies the sentinel errors unwrap through path
// resolution, and that symlinks / decmpfs files are not streamed.
func TestAPFSOpenFileErrors(t *testing.T) {
	h := apfsStreamHandler(t)

	if _, err := h.OpenFile("missing.txt"); !errors.Is(err, filesystem.ErrNotFound) {
		t.Errorf("OpenFile(missing.txt) err = %v, want ErrNotFound", err)
	}
	if _, err := h.OpenFile("/"); !errors.Is(err, filesystem.ErrIsDirectory) {
		t.Errorf("OpenFile(/) err = %v, want ErrIsDirectory", err)
	}
	if _, err := h.OpenFile("multi.bin/child"); !errors.Is(err, filesystem.ErrNotDirectory) {
		t.Errorf("OpenFile(multi.bin/child) err = %v, want ErrNotDirectory", err)
	}
	if _, err := h.OpenFile("link"); !errors.Is(err, filesystem.ErrUnsupported) {
		t.Errorf("OpenFile(link) err = %v, want ErrUnsupported", err)
	}
	if _, err := h.OpenFile("decmpfs.bin"); !errors.Is(err, filesystem.ErrUnsupported) {
		t.Errorf("OpenFile(decmpfs.bin) err = %v, want ErrUnsupported", err)
	}
}

// TestAPFSOpenFileConcurrentReadAt verifies concurrent ReadAt on the same handle
// returns byte-identical data (the io.ReaderAt contract sqlite asserts).
func TestAPFSOpenFileConcurrentReadAt(t *testing.T) {
	h := apfsStreamHandler(t)

	rc, err := h.OpenFile("multi.bin")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer rc.Close()
	ra := rc.(io.ReaderAt)

	want := make([]byte, 8192)
	for i := 0; i < 4096; i++ {
		want[i] = 0xAA
	}
	for i := 4096; i < 8192; i++ {
		want[i] = 0xBB
	}

	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				buf := make([]byte, 64)
				off := int64(i*13) % 8128
				n, err := ra.ReadAt(buf, off)
				if err != nil {
					errs <- fmt.Errorf("worker ReadAt(%d): %v", off, err)
					return
				}
				if n != len(buf) || !bytes.Equal(buf, want[off:off+64]) {
					errs <- fmt.Errorf("worker ReadAt(%d): data mismatch", off)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

// TestAPFSOpenFileIndependentHandles verifies two open handles share no cursor
// state: interleaved Read calls stay independent.
func TestAPFSOpenFileIndependentHandles(t *testing.T) {
	h := apfsStreamHandler(t)

	a, err := h.OpenFile("multi.bin")
	if err != nil {
		t.Fatalf("OpenFile(a): %v", err)
	}
	defer a.Close()
	b, err := h.OpenFile("multi.bin")
	if err != nil {
		t.Fatalf("OpenFile(b): %v", err)
	}
	defer b.Close()

	if _, err := a.Read(make([]byte, 4096)); err != nil {
		t.Fatalf("a.Read: %v", err)
	}
	// a is at offset 4096 (second extent, 0xBB); b is still at 0 (0xAA).
	ab := make([]byte, 4)
	if _, err := a.Read(ab); err != nil {
		t.Fatalf("a.Read(ab): %v", err)
	}
	if ab[0] != 0xBB {
		t.Fatalf("a offset 4096 = %02x, want 0xBB", ab[0])
	}
	bb := make([]byte, 4)
	if _, err := b.Read(bb); err != nil {
		t.Fatalf("b.Read(bb): %v", err)
	}
	if bb[0] != 0xAA {
		t.Fatalf("b offset 0 = %02x, want 0xAA", bb[0])
	}
}

// TestAPFSOpenFileStreamMatchesGetFile verifies the streaming reader and GetFile
// return byte-identical content on the same files — both resolve the same real
// FILE_EXTENT records.
func TestAPFSOpenFileStreamMatchesGetFile(t *testing.T) {
	h := apfsStreamHandler(t)

	for _, name := range []string{"multi.bin", "sparse.bin", "local.txt", "dstream.bin"} {
		rc, err := h.OpenFile(name)
		if err != nil {
			t.Fatalf("OpenFile(%s): %v", name, err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("ReadAll(%s): %v", name, err)
		}
		want, err := h.GetFile(name)
		if err != nil {
			t.Fatalf("GetFile(%s): %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("streamed %s (%d bytes) != GetFile (%d bytes)", name, len(got), len(want))
		}
	}
}
