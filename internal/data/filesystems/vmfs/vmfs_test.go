package vmfs

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

// ---- synthetic image builders -------------------------------------------

const (
	tMiB = 1 << 20

	tVolInfoOff = 0x100000
	tFSInfoOff  = 0x200000
	tFSInfoLen  = 221

	tFDCBlock = 25
	tFDCBase  = tFDCBlock * tMiB

	tFDCHeaderSize     = 65536
	tBmpEntriesPerArea = 8
	tItemsPerEntry     = 256
	tFDCAreaSize       = 4_259_840
	tFDCAreaCount      = 1
	tFDCTotalItems     = 2048

	tDataStartBlock = 3
)

var tUUID = [16]byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}

func putU16(b []byte, at int, v uint16) {
	b[at] = byte(v)
	b[at+1] = byte(v >> 8)
}

func putU32(b []byte, at int, v uint32) {
	b[at] = byte(v)
	b[at+1] = byte(v >> 8)
	b[at+2] = byte(v >> 16)
	b[at+3] = byte(v >> 24)
}

func putU64(b []byte, at int, v uint64) {
	for i := 0; i < 8; i++ {
		b[at+i] = byte(v >> (8 * i))
	}
}

func getU32(b []byte, at int) uint32 {
	return uint32(b[at]) | uint32(b[at+1])<<8 | uint32(b[at+2])<<16 | uint32(b[at+3])<<24
}

func getU64(b []byte, at int) uint64 {
	var v uint64
	for i := 7; i >= 0; i-- {
		v = v<<8 | uint64(b[at+i])
	}
	return v
}

type testOptions struct {
	version        uint8
	label          string
	name           string
	uuid           [16]byte
	volumeUUID     [16]byte
	subblock       uint32
	deviceBlock    uint32
	mode           uint32
	fdcBitmapCount uint32
	fdcHeaderSize  uint32
	fileBlockSize  uint64

	noPBC        bool
	pbcIndirect  bool
	pbcItemsEach uint32
}

func testDefaults(version uint8) testOptions {
	return testOptions{
		version:        version,
		label:          "datastore1",
		name:           "vol1",
		uuid:           tUUID,
		volumeUUID:     tUUID,
		subblock:       8192,
		deviceBlock:    512,
		mode:           1,
		fdcBitmapCount: 8,
		fdcHeaderSize:  tFDCHeaderSize,
		fileBlockSize:  tMiB,
		pbcItemsEach:   16,
	}
}

// testNode is one object in a synthetic image. Every node except an alias owns
// one file descriptor; an alias reuses an earlier node's descriptor so tests
// can prove directory-loop and hard-link handling.
type testNode struct {
	name string
	kind uint32 // 1 file, 2 directory, 3 symlink

	id2  uint32
	mode uint16
	uid  uint32
	gid  uint32

	mtime uint32
	ctime uint32
	atime uint32

	content  []byte // file or symlink data
	children []*testNode
	deleted  []string
	pad      int
	trailer  []byte
	indirect bool
	alias    *testNode

	// resolved by the builder
	item       int
	blockID    uint32
	dataBlocks []uint64
	stream     []byte
	fdOffset   int
}

var nextTestID = uint32(10)

func newTestNode(name string, kind uint32) *testNode {
	nextTestID++
	return &testNode{
		name:  name,
		kind:  kind,
		id2:   nextTestID,
		mode:  0o644,
		uid:   1000,
		gid:   1000,
		mtime: 1_700_000_000,
		ctime: 1_700_000_100,
		atime: 1_700_000_200,
	}
}

func tnFile(name, content string) *testNode {
	n := newTestNode(name, 1)
	n.content = []byte(content)
	return n
}

func tnFileBytes(name string, content []byte) *testNode {
	n := newTestNode(name, 1)
	n.content = content
	return n
}

func tnDir(name string, children ...*testNode) *testNode {
	n := newTestNode(name, 2)
	n.mode = 0o755
	n.children = children
	return n
}

func tnLink(name, target string) *testNode {
	n := newTestNode(name, 3)
	n.mode = 0o777
	n.content = []byte(target)
	return n
}

func tnAlias(name string, target *testNode) *testNode {
	n := newTestNode(name, target.kind)
	n.alias = target
	n.mode = target.mode
	return n
}

func fdBlockID(item int) uint32 {
	return uint32(item&0x3ff)<<22 | 4
}

func fileBlockID(block uint64) uint32 {
	return uint32(block<<3) | 1
}

func pointerBlockID(item int) uint32 {
	return uint32(item&0xf)<<28 | 3
}

func appendRecord(dst []byte, typ, id, recID uint32, name string) []byte {
	rec := make([]byte, 288)
	putU32(rec, 0, typ)
	putU32(rec, 4, id)
	putU32(rec, 8, recID)
	copy(rec[12:], name)
	return append(dst, rec...)
}

func writeSuperblock(img []byte, opts testOptions) {
	at := tVolInfoOff
	putU32(img, at+0, volumeMagic)
	putU32(img, at+4, 5) // volinfo.ver
	copy(img[at+18:at+46], opts.name)
	copy(img[at+130:at+146], opts.volumeUUID[:])

	at = tFSInfoOff
	putU32(img, at+0, fsMagic)
	putU32(img, at+4, 5) // fsinfo.volver
	img[at+8] = opts.version
	copy(img[at+9:at+25], opts.uuid[:])
	putU32(img, at+25, opts.mode)
	copy(img[at+29:at+157], opts.label)
	putU32(img, at+157, opts.deviceBlock)
	putU64(img, at+161, opts.fileBlockSize)
	copy(img[at+177:at+193], opts.uuid[:])
	putU32(img, at+209, opts.fdcHeaderSize)
	putU32(img, at+213, opts.fdcBitmapCount)
	putU32(img, at+217, opts.subblock)
}

func buildSuperblockImage(opts testOptions) []byte {
	img := make([]byte, tFSInfoOff+tFSInfoLen)
	writeSuperblock(img, opts)
	return img
}

func buildPBCContent(indirect []*testNode) []byte {
	const (
		pbcItemsPerEntry     = 16
		pbcBmpEntriesPerArea = 8
		pbcHdrSize           = 65536
		pbcItemSize          = 65536
		pbcTotalItems        = pbcItemsPerEntry * pbcBmpEntriesPerArea
	)
	n := len(indirect)
	size := pbcHdrSize + pbcBmpEntriesPerArea*0x400 + n*pbcItemSize
	out := make([]byte, size)
	putU32(out, 0, pbcItemsPerEntry)
	putU32(out, 4, pbcBmpEntriesPerArea)
	putU32(out, 8, pbcHdrSize)
	putU32(out, 12, pbcItemSize)
	putU32(out, 16, tFDCAreaSize)
	putU32(out, 20, pbcTotalItems)
	putU32(out, 24, 1)
	for i, node := range indirect {
		base := pbcHdrSize + pbcBmpEntriesPerArea*0x400 + i*pbcItemSize
		for j, block := range node.dataBlocks {
			if j >= 1024 {
				break
			}
			putU32(out, base+j*4, fileBlockID(block))
		}
	}
	return out
}

type testImage struct {
	data       []byte
	opts       testOptions
	fdSize     int
	metaHeader int
	entrySize  int
	wide       bool
	root       *testNode
	nodes      []*testNode
	pbc        *testNode
	pbcItemAbs int
}

func (b *testImage) fdOffset(item int) int {
	return tFDCBase + int(b.opts.fdcHeaderSize) + tBmpEntriesPerArea*0x400 + item*b.fdSize
}

func (b *testImage) find(name string) *testNode {
	for _, n := range b.nodes {
		if n.name == name && n.alias == nil {
			return n
		}
	}
	for _, n := range b.nodes {
		if n.name == name {
			return n
		}
	}
	return nil
}

func (b *testImage) blocksOffset(n *testNode) int {
	return n.fdOffset + b.fdSize - 256*b.entrySize
}

func (b *testImage) putBlock(n *testNode, index int, id uint32) {
	at := b.blocksOffset(n) + index*b.entrySize
	if b.entrySize == 8 {
		putU64(b.data, at, uint64(id))
	} else {
		putU32(b.data, at, id)
	}
}

func (b *testImage) dirRecordOffset(dir *testNode, index int) int {
	return int(dir.dataBlocks[0])*tMiB + index*288
}

func (b *testImage) pbcOffset(rel int) int {
	return int(b.pbc.dataBlocks[0])*tMiB + rel
}

func buildImage(t *testing.T, opts testOptions, root *testNode) *testImage {
	t.Helper()
	if root.kind != 2 {
		t.Fatalf("the root must be a directory")
	}
	b := &testImage{opts: opts, root: root}
	switch opts.version {
	case versionVMFS5:
		b.fdSize, b.metaHeader, b.entrySize, b.wide = 2048, 512, 4, false
	case versionVMFS6:
		b.fdSize, b.metaHeader, b.entrySize, b.wide = 8192, 4096, 8, true
	default:
		t.Fatalf("unsupported test version %d", opts.version)
	}
	if opts.pbcItemsEach == 0 {
		opts.pbcItemsEach = 16
	}

	// Find indirect files, then add the synthetic .pbc.sf carrier.
	var indirect []*testNode
	var scanIndirect func(*testNode)
	scanIndirect = func(n *testNode) {
		if n.alias != nil {
			return
		}
		if n.indirect && n.kind != 2 {
			indirect = append(indirect, n)
		}
		for _, c := range n.children {
			scanIndirect(c)
		}
	}
	scanIndirect(root)
	if len(indirect) > 0 && !opts.noPBC {
		b.pbc = &testNode{
			name:  ".pbc.sf",
			kind:  1,
			id2:   0x5151,
			mode:  0o644,
			mtime: 1_700_000_300,
			ctime: 1_700_000_300,
			atime: 1_700_000_300,
		}
		if opts.pbcIndirect {
			b.pbc.indirect = true
		}
		root.children = append(root.children, b.pbc)
	}

	// Preorder collection. An alias is listed but owns no descriptor and no
	// children.
	var all []*testNode
	parents := map[*testNode]*testNode{}
	var collect func(*testNode)
	collect = func(n *testNode) {
		all = append(all, n)
		if n.alias != nil {
			return
		}
		if n.kind == 2 {
			for _, c := range n.children {
				parents[c] = n
				collect(c)
			}
		}
	}
	collect(root)
	b.nodes = all

	item := 0
	for _, n := range all {
		if n.alias != nil {
			if n.alias.blockID == 0 {
				t.Fatalf("alias %q precedes its target", n.name)
			}
			n.blockID = n.alias.blockID
			n.id2 = n.alias.id2
			n.item = -1
			continue
		}
		if item > 1023 {
			t.Fatalf("too many file descriptors for the test builder")
		}
		n.item = item
		n.blockID = fdBlockID(item)
		item++
		if n.id2 == 0 {
			n.id2 = 1
		}
	}

	// Directory streams.
	var buildDir func(*testNode)
	buildDir = func(n *testNode) {
		if n.alias != nil || n.kind != 2 {
			return
		}
		parentID, parentRec := n.blockID, n.id2
		if p := parents[n]; p != nil {
			parentID, parentRec = p.blockID, p.id2
		}
		var stream []byte
		stream = appendRecord(stream, 2, n.blockID, n.id2, ".")
		stream = appendRecord(stream, 2, parentID, parentRec, "..")
		for _, c := range n.children {
			id, rec := c.blockID, c.id2
			if c.alias != nil {
				id, rec = c.alias.blockID, c.alias.id2
			}
			stream = appendRecord(stream, c.kind, id, rec, c.name)
		}
		for _, name := range n.deleted {
			stream = appendRecord(stream, 0, 0, 0, name)
		}
		for i := 0; i < n.pad; i++ {
			stream = appendRecord(stream, 0, 0, 0, "")
		}
		stream = append(stream, n.trailer...)
		n.stream = stream
		for _, c := range n.children {
			buildDir(c)
		}
	}
	buildDir(root)

	// Allocate data blocks. Block zero is reserved, the volume and filesystem
	// information occupy blocks one and two, and block 25 carries the FDC.
	next := tDataStartBlock
	alloc := func(count int) []uint64 {
		blocks := make([]uint64, 0, count)
		for i := 0; i < count; i++ {
			if next == tFDCBlock {
				next++
			}
			blocks = append(blocks, uint64(next))
			next++
		}
		return blocks
	}
	pbcIndex := map[*testNode]int{}
	for i, n := range indirect {
		pbcIndex[n] = i
	}
	for _, n := range all {
		if n.alias != nil {
			continue
		}
		if n == b.pbc {
			n.content = buildPBCContent(indirect)
		}
		var size int
		switch n.kind {
		case 2:
			size = len(n.stream)
		case 1, 3:
			size = len(n.content)
		}
		n.dataBlocks = alloc((size + tMiB - 1) / tMiB)
	}

	imageBlocks := next
	if imageBlocks < 26 {
		imageBlocks = 26
	}
	b.data = make([]byte, imageBlocks*tMiB)
	writeSuperblock(b.data, opts)

	// FDC bitmap header.
	at := tFDCBase
	putU32(b.data, at+0, tItemsPerEntry)
	putU32(b.data, at+4, tBmpEntriesPerArea)
	putU32(b.data, at+8, opts.fdcHeaderSize)
	putU32(b.data, at+12, uint32(b.fdSize))
	putU32(b.data, at+16, tFDCAreaSize)
	putU32(b.data, at+20, tFDCTotalItems)
	putU32(b.data, at+24, tFDCAreaCount)

	// Descriptors.
	for _, n := range all {
		if n.alias != nil {
			continue
		}
		n.fdOffset = b.fdOffset(n.item)
		if n.fdOffset+b.fdSize > len(b.data) {
			t.Fatalf("descriptor %d lands outside the test image", n.item)
		}
		fd := b.data[n.fdOffset : n.fdOffset+b.fdSize]
		putU32(fd, 0, inodeMagic)
		base := b.metaHeader
		links := uint32(1)
		if n.kind == 2 {
			links = 2
		}
		var size uint64
		if n.kind == 2 {
			size = uint64(len(n.stream))
		} else {
			size = uint64(len(n.content))
		}
		zla := uint32(blkTypeFB)
		var blocks []uint32
		if n.indirect {
			zla = blkTypePB
			needed := (len(n.dataBlocks) + 1023) / 1024
			for i := 0; i < needed; i++ {
				blocks = append(blocks, pointerBlockID(pbcIndex[n]))
			}
		} else {
			for _, block := range n.dataBlocks {
				blocks = append(blocks, fileBlockID(block))
			}
		}
		putU32(fd, base+0, n.blockID)
		putU32(fd, base+4, n.id2)
		putU32(fd, base+8, links)
		putU32(fd, base+12, n.kind)
		putU32(fd, base+16, 0)
		putU64(fd, base+20, size)
		putU64(fd, base+28, uint64(opts.fileBlockSize))
		putU64(fd, base+36, uint64(len(n.dataBlocks)))
		putU32(fd, base+44, n.mtime)
		putU32(fd, base+48, n.ctime)
		putU32(fd, base+52, n.atime)
		putU32(fd, base+56, n.uid)
		putU32(fd, base+60, n.gid)
		putU32(fd, base+64, uint32(n.mode))
		putU32(fd, base+68, zla)
		array := b.fdSize - 256*b.entrySize
		for i, id := range blocks {
			if b.entrySize == 8 {
				putU64(fd, array+i*8, uint64(id))
			} else {
				putU32(fd, array+i*4, id)
			}
		}
	}

	// Streams and file contents, block by block so a skipped FDC block is
	// handled.
	for _, n := range all {
		if n.alias != nil {
			continue
		}
		var src []byte
		switch n.kind {
		case 2:
			src = n.stream
		case 1, 3:
			src = n.content
		}
		for i, block := range n.dataBlocks {
			from := i * tMiB
			to := from + tMiB
			if to > len(src) {
				to = len(src)
			}
			copy(b.data[int(block)*tMiB:], src[from:to])
		}
	}

	if b.pbc != nil && len(b.pbc.dataBlocks) > 0 {
		b.pbcItemAbs = int(b.pbc.dataBlocks[0])*tMiB + tFDCHeaderSize + tBmpEntriesPerArea*0x400
	}
	return b
}

func openBuilt(t *testing.T, b *testImage) *Volume {
	t.Helper()
	v, err := Open(source.NewMemorySource(1, b.data))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return v
}

func openErr(t *testing.T, data []byte) error {
	t.Helper()
	_, err := Open(source.NewMemorySource(1, data))
	if err == nil {
		t.Fatalf("Open unexpectedly succeeded")
	}
	return err
}

func wantContains(t *testing.T, err error, parts ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error")
	}
	msg := err.Error()
	for _, part := range parts {
		if !strings.Contains(msg, part) {
			t.Errorf("error %q does not contain %q", msg, part)
		}
	}
}

// ---- tests ---------------------------------------------------------------

func TestDetect(t *testing.T) {
	valid5 := buildSuperblockImage(testDefaults(versionVMFS5))
	valid6 := buildSuperblockImage(testDefaults(versionVMFS6))

	cases := []struct {
		name  string
		data  []byte
		want  bool
		kind  error
		parts []string
	}{
		{name: "vmfs5", data: valid5, want: true},
		{name: "vmfs6", data: valid6, want: true},
		{name: "empty", data: nil, want: false},
		{name: "short", data: make([]byte, 0x100003), want: false},
		{name: "zeros", data: make([]byte, 3*tMiB), want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := Detect(source.NewMemorySource(1, tc.data))
			if tc.kind == nil {
				if err != nil {
					t.Fatalf("Detect: %v", err)
				}
				if ok != tc.want {
					t.Fatalf("Detect = %v, want %v", ok, tc.want)
				}
				return
			}
			if !errors.Is(err, tc.kind) {
				t.Fatalf("Detect error = %v, want %v", err, tc.kind)
			}
			wantContains(t, err, tc.parts...)
		})
	}

	t.Run("reversed volume magic", func(t *testing.T) {
		img := append([]byte(nil), valid5...)
		putU32(img, tVolInfoOff, reversedVolumeMagic)
		_, err := Detect(source.NewMemorySource(1, img))
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "byte-swapped")
	})

	t.Run("reversed filesystem magic", func(t *testing.T) {
		img := append([]byte(nil), valid5...)
		putU32(img, tFSInfoOff, reversedFSMagic)
		_, err := Detect(source.NewMemorySource(1, img))
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "byte-swapped")
	})

	t.Run("volume magic without filesystem block", func(t *testing.T) {
		img := append([]byte(nil), valid5...)
		putU32(img, tFSInfoOff, 0)
		_, err := Detect(source.NewMemorySource(1, img))
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "0x200000")
	})

	t.Run("vmfs3 by name", func(t *testing.T) {
		_, err := Detect(source.NewMemorySource(1, buildSuperblockImage(testDefaults(1))))
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "VMFS3")
	})

	t.Run("vmfs4 by name", func(t *testing.T) {
		_, err := Detect(source.NewMemorySource(1, buildSuperblockImage(testDefaults(2))))
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "VMFS4")
	})

	t.Run("unknown version", func(t *testing.T) {
		_, err := Detect(source.NewMemorySource(1, buildSuperblockImage(testDefaults(9))))
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "version byte 9")
	})
}

func TestSuperblockGeometry(t *testing.T) {
	for _, version := range []uint8{versionVMFS5, versionVMFS6} {
		opts := testDefaults(version)
		opts.label = "lbl-null"
		sb, err := readSuperblock(source.NewMemorySource(1, buildSuperblockImage(opts)))
		if err != nil {
			t.Fatalf("version %d: %v", version, err)
		}
		if sb.version != version {
			t.Errorf("version = %d", sb.version)
		}
		wantLabel, wantFD, wantHeader := "VMFS5", uint32(2048), uint32(512)
		if version == versionVMFS6 {
			wantLabel, wantFD, wantHeader = "VMFS6", 8192, 4096
		}
		if sb.versionLabel != wantLabel {
			t.Errorf("label = %q", sb.versionLabel)
		}
		if sb.blockSize != tMiB || sb.subblockSize != 8192 || sb.deviceBlockSize != 512 {
			t.Errorf("geometry = %+v", sb)
		}
		if sb.volumeLabel != "lbl-null" || sb.volumeName != "vol1" {
			t.Errorf("labels = %q/%q", sb.volumeLabel, sb.volumeName)
		}
		if sb.uuidHex() != "30313233343536373839616263646566" {
			t.Errorf("uuid = %q", sb.uuidHex())
		}
		if sb.volumeUUIDHex() != "30313233343536373839616263646566" {
			t.Errorf("volume uuid = %q", sb.volumeUUIDHex())
		}
		if sb.fdSize != wantFD || sb.metadataHeaderSize != wantHeader {
			t.Errorf("fd geometry = %d/%d", sb.fdSize, sb.metadataHeaderSize)
		}
		if sb.fileBlockEntries != 256 {
			t.Errorf("file block entries = %d", sb.fileBlockEntries)
		}
		if sb.fdcHeaderSize != tFDCHeaderSize || sb.fdcBitmapCount != 8 {
			t.Errorf("fdc = %+v", sb)
		}
		if sb.wideBlockAddresses != (version == versionVMFS6) {
			t.Errorf("wide = %v", sb.wideBlockAddresses)
		}
		if sb.blocks != 2 || sb.volumeBytes != 2*tMiB {
			t.Errorf("blocks = %d bytes = %d", sb.blocks, sb.volumeBytes)
		}
	}

	t.Run("label falls back to volume name", func(t *testing.T) {
		opts := testDefaults(versionVMFS5)
		opts.label = ""
		sb, err := readSuperblock(source.NewMemorySource(1, buildSuperblockImage(opts)))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if sb.volumeLabel != "vol1" {
			t.Errorf("label = %q", sb.volumeLabel)
		}
	})

	t.Run("unterminated fields are bounded", func(t *testing.T) {
		opts := testDefaults(versionVMFS5)
		opts.name = strings.Repeat("n", 28)
		opts.label = strings.Repeat("l", 128)
		img := buildSuperblockImage(opts)
		sb, err := readSuperblock(source.NewMemorySource(1, img))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if sb.volumeName != opts.name || sb.volumeLabel != opts.label {
			t.Errorf("name/label = %q/%q", sb.volumeName, sb.volumeLabel)
		}
	})

	badCases := []struct {
		name  string
		edit  func([]byte)
		kind  error
		parts []string
	}{
		{"zero block size", func(b []byte) { putU64(b, tFSInfoOff+161, 0) }, ErrCorrupt, []string{"zero file-block size"}},
		{"oversized block", func(b []byte) { putU64(b, tFSInfoOff+161, 1<<32) }, ErrCorrupt, []string{"32-bit"}},
		{"non power of two block", func(b []byte) { putU64(b, tFSInfoOff+161, 3*tMiB) }, ErrCorrupt, []string{"power of two"}},
		{"other block size", func(b []byte) { putU64(b, tFSInfoOff+161, 8*tMiB) }, ErrUnsupported, []string{"8388608-byte file block"}},
		{"zero subblock", func(b []byte) { putU32(b, tFSInfoOff+217, 0) }, ErrCorrupt, []string{"sub-block"}},
		{"non power subblock", func(b []byte) { putU32(b, tFSInfoOff+217, 3000) }, ErrCorrupt, []string{"sub-block"}},
		{"subblock larger than block", func(b []byte) { putU32(b, tFSInfoOff+217, 2*tMiB) }, ErrCorrupt, []string{"larger than"}},
		{"zero device block", func(b []byte) { putU32(b, tFSInfoOff+157, 0) }, ErrCorrupt, []string{"device block"}},
		{"non power device block", func(b []byte) { putU32(b, tFSInfoOff+157, 3000) }, ErrCorrupt, []string{"device block"}},
		{"zero fdc header", func(b []byte) { putU32(b, tFSInfoOff+209, 0) }, ErrCorrupt, []string{"zero FDC header"}},
		{"zero fdc bitmaps", func(b []byte) { putU32(b, tFSInfoOff+213, 0) }, ErrCorrupt, []string{"zero FDC bitmap"}},
		{"zero volume version", func(b []byte) { putU32(b, tFSInfoOff+4, 0) }, ErrCorrupt, []string{"volume version zero"}},
		{"missing fs magic", func(b []byte) { putU32(b, tFSInfoOff, 0) }, ErrCorrupt, []string{"0x200000"}},
	}
	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			img := buildSuperblockImage(testDefaults(versionVMFS5))
			tc.edit(img)
			_, err := readSuperblock(source.NewMemorySource(1, img))
			if !errors.Is(err, tc.kind) {
				t.Fatalf("error = %v", err)
			}
			wantContains(t, err, tc.parts...)
		})
	}

	t.Run("short volume information", func(t *testing.T) {
		img := buildSuperblockImage(testDefaults(versionVMFS5))
		_, err := readSuperblock(source.NewMemorySource(1, img[:tVolInfoOff+161]))
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "too short")
	})

	t.Run("short filesystem information", func(t *testing.T) {
		img := buildSuperblockImage(testDefaults(versionVMFS5))
		_, err := readSuperblock(source.NewMemorySource(1, img[:tFSInfoOff+220]))
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "0x200000")
	})

	t.Run("missing volume magic", func(t *testing.T) {
		img := buildSuperblockImage(testDefaults(versionVMFS5))
		putU32(img, tVolInfoOff, 0xdeadbeef)
		_, err := readSuperblock(source.NewMemorySource(1, img))
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "0xc001d00d")
	})
}

func TestOpenGeometryAndInfo(t *testing.T) {
	root := tnDir("/", tnFile("hello.txt", "hello vmfs"), tnDir("sub"))
	b := buildImage(t, testDefaults(versionVMFS5), root)
	vol := openBuilt(t, b)

	info := vol.Info()
	if info.Type != "VMFS" || info.Version != versionVMFS5 || info.VersionLabel != "VMFS5" {
		t.Errorf("version = %+v", info)
	}
	if info.BlockSize != tMiB || info.SubblockSize != 8192 || info.DeviceBlockSize != 512 {
		t.Errorf("geometry = %+v", info)
	}
	if info.VolumeLabel != "datastore1" || info.VolumeName != "vol1" {
		t.Errorf("labels = %q/%q", info.VolumeLabel, info.VolumeName)
	}
	if info.UUID != "30313233343536373839616263646566" || info.VolumeUUID != info.UUID {
		t.Errorf("uuids = %q/%q", info.UUID, info.VolumeUUID)
	}
	if info.FDSize != 2048 || info.MetadataHeaderSize != 512 || info.FileBlockEntries != 256 {
		t.Errorf("fd geometry = %+v", info)
	}
	if info.PointerBlockSize != 65536 || info.PointerBlockItems != 1024 {
		t.Errorf("pointer geometry = %+v", info)
	}
	if info.WideBlockAddresses {
		t.Errorf("VMFS5 must use narrow addresses")
	}
	if info.Blocks != 26 || info.VolumeBytes != 26*tMiB {
		t.Errorf("blocks = %d/%d", info.Blocks, info.VolumeBytes)
	}
	if info.RootInode != rootBlockID {
		t.Errorf("root inode = %d", info.RootInode)
	}
	if info.Entries != 3 || info.Directories != 2 || info.Files != 1 || info.Symlinks != 0 {
		t.Errorf("counts = %+v", info)
	}
	if info.ExtentLookups != 2 || info.NodesRead < 3 || info.BlocksRead < 3 {
		t.Errorf("counters = %+v", info)
	}
	if len(info.Warnings) == 0 || !strings.Contains(info.Warnings[0], "journal") {
		t.Errorf("warnings = %q", info.Warnings)
	}
	if info.FDCHeaderSize != tFDCHeaderSize || info.FDCBitmapCount != 8 || info.FDCItems != 2048 || info.FDCAreas != 1 {
		t.Errorf("fdc = %+v", info)
	}
}

func TestVMFS6ReadsWideDescriptors(t *testing.T) {
	root := tnDir("/", tnFile("wide.txt", "wide descriptor data"), tnDir("d", tnFile("nested", "n")))
	b := buildImage(t, testDefaults(versionVMFS6), root)
	vol := openBuilt(t, b)
	info := vol.Info()
	if info.Version != versionVMFS6 || info.VersionLabel != "VMFS6" || !info.WideBlockAddresses {
		t.Fatalf("info = %+v", info)
	}
	if info.FDSize != 8192 || info.MetadataHeaderSize != 4096 {
		t.Errorf("fd geometry = %+v", info)
	}
	file, err := vol.OpenFile("/wide.txt")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	buf := make([]byte, len("wide descriptor data"))
	if err := source.ReadExactAt(file, 0, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "wide descriptor data" {
		t.Errorf("data = %q", buf)
	}
	if _, err := vol.Stat("/d/nested"); err != nil {
		t.Fatalf("nested: %v", err)
	}
}

func TestRootAndNestedListing(t *testing.T) {
	longName := strings.Repeat("x", 275)
	root := tnDir("/",
		tnFile("hello.txt", "hello"),
		tnDir("sub",
			tnFile("nested.txt", "nested data"),
			tnDir("empty"),
		),
		tnFile("a name with spaces.txt", "spaces"),
		tnFile("unicode-☃.txt", "snow"),
		tnFile(longName, "long"),
	)
	vol := openBuilt(t, buildImage(t, testDefaults(versionVMFS5), root))

	for _, path := range []string{"", "/", "//", "/sub/../"} {
		entries, err := vol.ListDir(path)
		if err != nil {
			t.Fatalf("ListDir(%q): %v", path, err)
		}
		if len(entries) != 5 {
			t.Fatalf("ListDir(%q) = %d entries", path, len(entries))
		}
		want := []string{"hello.txt", "sub", "a name with spaces.txt", "unicode-☃.txt", longName}
		for i := range want {
			if entries[i].Name != want[i] {
				t.Errorf("entry %d = %q, want %q", i, entries[i].Name, want[i])
			}
		}
		for _, e := range entries {
			if e.Name == "." || e.Name == ".." {
				t.Errorf("dot entry listed: %q", e.Name)
			}
		}
	}

	rootEntry, err := vol.Stat("/")
	if err != nil {
		t.Fatalf("stat root: %v", err)
	}
	if !rootEntry.IsDir || rootEntry.IsFile || rootEntry.Name != "/" || rootEntry.Path != "/" {
		t.Errorf("root = %+v", rootEntry)
	}
	if rootEntry.HasParent {
		t.Errorf("root must not have a parent")
	}

	nested, err := vol.Stat("sub/nested.txt")
	if err != nil {
		t.Fatalf("stat nested: %v", err)
	}
	if !nested.IsFile || nested.Path != "/sub/nested.txt" || nested.Size != 11 {
		t.Errorf("nested = %+v", nested)
	}

	viaDotDot, err := vol.Stat("/sub/../hello.txt")
	if err != nil {
		t.Fatalf("stat cleaned: %v", err)
	}
	if viaDotDot.Path != "/hello.txt" {
		t.Errorf("cleaned path = %q", viaDotDot.Path)
	}

	empty, err := vol.ListDir("/sub/empty")
	if err != nil {
		t.Fatalf("list empty: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("empty dir = %+v", empty)
	}

	if _, err := vol.Stat("/nope"); !errors.Is(err, ErrPathNotFound) {
		t.Errorf("missing stat error = %v", err)
	}
	if _, err := vol.ListDir("/nope"); !errors.Is(err, ErrPathNotFound) {
		t.Errorf("missing list error = %v", err)
	}
	if _, err := vol.ListDir("/hello.txt"); !errors.Is(err, ErrNotDir) {
		t.Errorf("list file error = %v", err)
	}
	if _, err := vol.OpenFile("/sub"); !errors.Is(err, ErrNotAFile) {
		t.Errorf("open dir error = %v", err)
	}
	if got := normalizePath("/"); got != "/" {
		t.Errorf("normalize root = %q", got)
	}
}

func TestFileReadsAcrossBlocks(t *testing.T) {
	content := make([]byte, tMiB+12345)
	for i := range content {
		content[i] = byte(i*7 + 3)
	}
	root := tnDir("/", tnFileBytes("big.bin", content), tnFile("small.txt", "1234567890"), tnFile("empty", ""))
	vol := openBuilt(t, buildImage(t, testDefaults(versionVMFS5), root))

	entry, err := vol.Stat("/big.bin")
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if entry.Size != uint64(len(content)) || entry.Allocated != 2*tMiB || !entry.AllocatedKnown {
		t.Errorf("entry = %+v", entry)
	}

	file, err := vol.OpenFile("/big.bin")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if file.Len() != uint64(len(content)) || file.IsEmpty() {
		t.Errorf("len = %d", file.Len())
	}
	got := make([]byte, len(content))
	if err := source.ReadExactAt(file, 0, got); err != nil {
		t.Fatalf("read all: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("full read differs")
	}

	cross := make([]byte, 40)
	if err := source.ReadExactAt(file, tMiB-10, cross); err != nil {
		t.Fatalf("read crossing: %v", err)
	}
	if !bytes.Equal(cross, content[tMiB-10:tMiB+30]) {
		t.Errorf("crossing read = %x", cross)
	}

	n, err := file.ReadAt(uint64(len(content))-1, make([]byte, 2))
	if err != nil || n != 1 {
		t.Errorf("short tail read = %d, %v", n, err)
	}
	if _, err := file.ReadAt(uint64(len(content)), make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Errorf("past-end read = %v", err)
	}
	if n, err := file.ReadAt(0, nil); n != 0 || err != nil {
		t.Errorf("empty read = %d, %v", n, err)
	}

	ranges, err := file.Extents(0, uint64(len(content)))
	if err != nil {
		t.Fatalf("extents: %v", err)
	}
	if len(ranges) != 2 {
		t.Fatalf("extents = %+v", ranges)
	}
	if ranges[0].Kind != source.RangeData || ranges[0].Len != tMiB {
		t.Errorf("extent 0 = %+v", ranges[0])
	}
	if ranges[1].Kind != source.RangeData || ranges[1].Len != 12345 {
		t.Errorf("extent 1 = %+v", ranges[1])
	}
	if ranges[0].ParentOffset == ranges[1].ParentOffset {
		t.Errorf("both extents share a physical offset")
	}
	if _, err := file.Extents(uint64(len(content))-1, 2); !errors.Is(err, source.ErrOutOfRange) {
		t.Errorf("out-of-range extents = %v", err)
	}
	if ranges, err := file.Extents(0, 0); err != nil || len(ranges) != 0 {
		t.Errorf("empty extents = %+v, %v", ranges, err)
	}

	mapped, err := file.MapToImage(0, 100)
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if len(mapped) != 1 || mapped[0].ImageOffset != ranges[0].ParentOffset {
		t.Errorf("mapped = %+v", mapped)
	}

	if _, err := file.ReadAtLossy(uint64(len(content)), make([]byte, 4)); !errors.Is(err, source.ErrOutOfRange) {
		t.Errorf("lossy past end = %v", err)
	}
	lossy := make([]byte, 16)
	if n, err := file.ReadAtLossy(0, lossy); err != nil || n != 16 {
		t.Errorf("lossy = %d, %v", n, err)
	}
	if file.Stats().Reads == 0 {
		t.Errorf("stats did not count reads: %+v", file.Stats())
	}

	small, err := vol.OpenFile("/small.txt")
	if err != nil {
		t.Fatalf("open small: %v", err)
	}
	buf := make([]byte, 100)
	if n, err := small.ReadAt(0, buf); err != nil || n != 10 {
		t.Errorf("short read = %d, %v", n, err)
	}

	empty, err := vol.OpenFile("/empty")
	if err != nil {
		t.Fatalf("open empty: %v", err)
	}
	if empty.Len() != 0 || !empty.IsEmpty() {
		t.Errorf("empty len = %d", empty.Len())
	}
	if _, err := empty.ReadAt(0, make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Errorf("empty read error = %v", err)
	}
	if ranges, err := empty.Extents(0, 0); err != nil || len(ranges) != 0 {
		t.Errorf("empty extents = %+v, %v", ranges, err)
	}
	emptyEntry, err := vol.Stat("/empty")
	if err != nil {
		t.Fatalf("stat empty: %v", err)
	}
	if !emptyEntry.AllocatedKnown || emptyEntry.Allocated != 0 {
		t.Errorf("empty entry = %+v", emptyEntry)
	}
}

func TestSparseHoleRefused(t *testing.T) {
	root := tnDir("/", tnFile("hole.bin", "0123456789"))
	b := buildImage(t, testDefaults(versionVMFS5), root)
	fileNode := b.find("hole.bin")
	b.putBlock(fileNode, 0, 0)

	vol := openBuilt(t, b)
	info := vol.Info()
	if info.Undecodable != 1 {
		t.Errorf("undecodable = %d", info.Undecodable)
	}
	foundHoleWarning := false
	for _, w := range info.Warnings {
		if strings.Contains(w, "zero") && strings.Contains(w, "hole") {
			foundHoleWarning = true
		}
	}
	if !foundHoleWarning {
		t.Errorf("no hole warning: %q", info.Warnings)
	}

	entry, err := vol.Stat("/hole.bin")
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !entry.IsFile || entry.AllocatedKnown {
		t.Errorf("entry = %+v", entry)
	}
	_, err = vol.OpenFile("/hole.bin")
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("open error = %v", err)
	}
	wantContains(t, err, "zero", "hole")

	// A zero block address is never zero-filled.
	b2 := buildImage(t, testDefaults(versionVMFS5), tnDir("/", tnFile("hole.bin", "x")))
	b2.putBlock(b2.find("hole.bin"), 0, 0)
	if _, err := openBuilt(t, b2).OpenFile("/hole.bin"); !errors.Is(err, ErrCorrupt) {
		t.Errorf("second hole error = %v", err)
	}
}

func TestSymlinks(t *testing.T) {
	large := strings.Repeat("t", int(maxSymlinkBytes+1))
	root := tnDir("/",
		tnFile("hello.txt", "hello"),
		tnLink("link", "hello.txt"),
		tnLink("large", large),
		tnLink("broken", "x"),
	)
	b := buildImage(t, testDefaults(versionVMFS5), root)
	b.putBlock(b.find("broken"), 0, 0)
	vol := openBuilt(t, b)

	link, err := vol.Stat("/link")
	if err != nil {
		t.Fatalf("stat link: %v", err)
	}
	if !link.IsSymlink || link.IsFile || link.IsDir {
		t.Errorf("link flags = %+v", link)
	}
	if link.SymlinkTarget != "hello.txt" || link.Size != 9 || !link.AllocatedKnown {
		t.Errorf("link = %+v", link)
	}
	if link.SymlinkTargetTruncated {
		t.Errorf("short target marked truncated")
	}
	if _, err := vol.OpenFile("/link"); !errors.Is(err, ErrNotAFile) {
		t.Errorf("open symlink as file = %v", err)
	}
	stream, err := vol.OpenSymlink("/link")
	if err != nil {
		t.Fatalf("open symlink: %v", err)
	}
	buf := make([]byte, len("hello.txt"))
	if err := source.ReadExactAt(stream, 0, buf); err != nil {
		t.Fatalf("read symlink: %v", err)
	}
	if string(buf) != "hello.txt" {
		t.Errorf("symlink stream = %q", buf)
	}
	if _, err := vol.OpenSymlink("/hello.txt"); !errors.Is(err, ErrNotSymlink) {
		t.Errorf("open regular as symlink = %v", err)
	}

	largeEntry, err := vol.Stat("/large")
	if err != nil {
		t.Fatalf("stat large: %v", err)
	}
	if largeEntry.SymlinkTarget != "" || !largeEntry.SymlinkTargetTruncated {
		t.Errorf("large link = %+v", largeEntry)
	}
	largeStream, err := vol.OpenSymlink("/large")
	if err != nil {
		t.Fatalf("open large: %v", err)
	}
	if largeStream.Len() != uint64(len(large)) {
		t.Errorf("large stream len = %d", largeStream.Len())
	}

	broken, err := vol.Stat("/broken")
	if err != nil {
		t.Fatalf("stat broken: %v", err)
	}
	if broken.SymlinkTarget != "" {
		t.Errorf("broken target = %q", broken.SymlinkTarget)
	}
	if vol.Info().Undecodable != 1 {
		t.Errorf("undecodable = %d", vol.Info().Undecodable)
	}
	if _, err := vol.OpenSymlink("/broken"); !errors.Is(err, ErrCorrupt) {
		t.Errorf("broken open error = %v", err)
	}
}

func TestDeletedEntries(t *testing.T) {
	root := tnDir("/", tnFile("live.txt", "live"))
	root.deleted = []string{"gone.txt", "bad/name"}
	root.pad = 2
	vol := openBuilt(t, buildImage(t, testDefaults(versionVMFS5), root))

	entries, err := vol.ListDir("/")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "live.txt" {
		t.Fatalf("entries = %+v", entries)
	}

	rootEntry, err := vol.Stat("/")
	if err != nil {
		t.Fatalf("stat root: %v", err)
	}
	if rootEntry.UnusedSlots != 4 {
		t.Errorf("unused slots = %d", rootEntry.UnusedSlots)
	}
	if len(rootEntry.DeletedNames) != 1 || rootEntry.DeletedNames[0] != "gone.txt" {
		t.Errorf("deleted names = %q", rootEntry.DeletedNames)
	}
	if vol.Info().UnusedSlots != 4 {
		t.Errorf("info unused = %d", vol.Info().UnusedSlots)
	}

	names, err := vol.DeletedEntries("/")
	if err != nil {
		t.Fatalf("deleted entries: %v", err)
	}
	if len(names) != 1 || names[0] != "gone.txt" {
		t.Errorf("deleted = %q", names)
	}
	// The returned slice is a copy: mutating it must not affect the volume.
	names[0] = "changed"
	again, _ := vol.DeletedEntries("/")
	if again[0] != "gone.txt" {
		t.Errorf("deleted names leaked: %q", again)
	}

	found := false
	for _, w := range vol.Info().Warnings {
		if strings.Contains(w, "type-0") && strings.Contains(w, "gone.txt") {
			found = true
		}
	}
	if !found {
		t.Errorf("no deleted-slot warning: %q", vol.Info().Warnings)
	}

	if _, err := vol.DeletedEntries("/live.txt"); !errors.Is(err, ErrNotDir) {
		t.Errorf("deleted on file = %v", err)
	}
}

func TestDirectoryLoopAndHardlinks(t *testing.T) {
	inner := tnFile("inside.txt", "inside")
	dir := tnDir("d1", inner)
	alias := tnAlias("d2", dir)
	file := tnFile("a.txt", "shared")
	fileAlias := tnAlias("b.txt", file)
	root := tnDir("/", dir, alias, file, fileAlias)

	vol := openBuilt(t, buildImage(t, testDefaults(versionVMFS5), root))
	info := vol.Info()
	if info.DirectoryLoops != 1 {
		t.Errorf("directory loops = %d", info.DirectoryLoops)
	}
	if info.Entries != 6 {
		t.Errorf("entries = %d", info.Entries)
	}
	for _, path := range []string{"/d1", "/d2"} {
		entry, err := vol.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if !entry.IsDir {
			t.Errorf("%s not a directory", path)
		}
	}
	if _, err := vol.Stat("/d1/inside.txt"); err != nil {
		t.Errorf("d1 child: %v", err)
	}
	if _, err := vol.Stat("/d2/inside.txt"); !errors.Is(err, ErrPathNotFound) {
		t.Errorf("d2 should not be walked twice: %v", err)
	}
	if entries, err := vol.ListDir("/d2"); err != nil || len(entries) != 0 {
		t.Errorf("d2 listing = %+v, %v", entries, err)
	}

	a, err := vol.Stat("/a.txt")
	if err != nil {
		t.Fatalf("stat a: %v", err)
	}
	bEntry, err := vol.Stat("/b.txt")
	if err != nil {
		t.Fatalf("stat b: %v", err)
	}
	if a.InodeNumber != bEntry.InodeNumber || a.RecordID != bEntry.RecordID {
		t.Errorf("hardlink identities differ: %+v / %+v", a, bEntry)
	}
	for _, path := range []string{"/a.txt", "/b.txt"} {
		stream, err := vol.OpenFile(path)
		if err != nil {
			t.Fatalf("open %s: %v", path, err)
		}
		buf := make([]byte, 6)
		if err := source.ReadExactAt(stream, 0, buf); err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if string(buf) != "shared" {
			t.Errorf("%s = %q", path, buf)
		}
	}
}

func TestIndirectMap(t *testing.T) {
	indirect := tnFile("indirect.bin", "indirect payload")
	indirect.indirect = true
	root := tnDir("/", indirect, tnFile("plain.txt", "plain"))
	b := buildImage(t, testDefaults(versionVMFS5), root)
	vol := openBuilt(t, b)

	info := vol.Info()
	if info.PointerBlocks < 1 || info.PointerRecords < 1 {
		t.Errorf("pointer counters = %+v", info)
	}
	if !info.PBCLoaded {
		t.Fatalf("PBC was not loaded: %q", info.Warnings)
	}
	pbcEntry, err := vol.Stat("/.pbc.sf")
	if err != nil {
		t.Fatalf("stat pbc: %v", err)
	}
	if !pbcEntry.IsFile {
		t.Errorf("pbc entry = %+v", pbcEntry)
	}

	entry, err := vol.Stat("/indirect.bin")
	if err != nil {
		t.Fatalf("stat indirect: %v", err)
	}
	if entry.Size != 16 || entry.Allocated != tMiB || !entry.AllocatedKnown {
		t.Errorf("indirect entry = %+v", entry)
	}
	file, err := vol.OpenFile("/indirect.bin")
	if err != nil {
		t.Fatalf("open indirect: %v", err)
	}
	buf := make([]byte, 16)
	if err := source.ReadExactAt(file, 0, buf); err != nil {
		t.Fatalf("read indirect: %v", err)
	}
	if string(buf) != "indirect payload" {
		t.Errorf("data = %q", buf)
	}

	t.Run("missing cache", func(t *testing.T) {
		opts := testDefaults(versionVMFS5)
		opts.noPBC = true
		node := tnFile("indirect.bin", "payload")
		node.indirect = true
		v := openBuilt(t, buildImage(t, opts, tnDir("/", node)))
		entry, err := v.Stat("/indirect.bin")
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if entry.AllocatedKnown {
			t.Errorf("entry = %+v", entry)
		}
		_, err = v.OpenFile("/indirect.bin")
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, ".pbc.sf")
	})

	t.Run("wrong pointer header shape", func(t *testing.T) {
		opts := testDefaults(versionVMFS5)
		node := tnFile("indirect.bin", "payload")
		node.indirect = true
		img := buildImage(t, opts, tnDir("/", node))
		// 32 items per entry across 4 entries keeps the declared total of 128
		// valid, so the failure is the shape check, not the arithmetic check.
		putU32(img.data, img.pbcOffset(0), 32)
		putU32(img.data, img.pbcOffset(4), 4)
		v := openBuilt(t, img)
		if v.Info().PBCLoaded {
			t.Errorf("PBC loaded despite the wrong shape")
		}
		found := false
		for _, w := range v.Info().Warnings {
			if strings.Contains(w, "assumes 16") {
				found = true
			}
		}
		if !found {
			t.Errorf("no warning naming the 16-items-per-entry shape: %q", v.Info().Warnings)
		}
		if _, err := v.OpenFile("/indirect.bin"); !errors.Is(err, ErrUnsupported) {
			t.Errorf("error = %v", err)
		}
	})

	t.Run("pointer header total mismatch", func(t *testing.T) {
		node := tnFile("indirect.bin", "payload")
		node.indirect = true
		img := buildImage(t, testDefaults(versionVMFS5), tnDir("/", node))
		putU32(img.data, img.pbcOffset(20), 127)
		v := openBuilt(t, img)
		if v.Info().PBCLoaded {
			t.Errorf("PBC loaded despite an inconsistent total")
		}
		if _, err := v.OpenFile("/indirect.bin"); !errors.Is(err, ErrUnsupported) {
			t.Errorf("error = %v", err)
		}
	})

	t.Run("zero pointer record", func(t *testing.T) {
		node := tnFile("indirect.bin", "payload")
		node.indirect = true
		img := buildImage(t, testDefaults(versionVMFS5), tnDir("/", node))
		putU32(img.data, img.pbcItemAbs, 0)
		v := openBuilt(t, img)
		_, err := v.OpenFile("/indirect.bin")
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "zero", "hole")
	})

	t.Run("pointer block outside the cache", func(t *testing.T) {
		node := tnFile("indirect.bin", "payload")
		node.indirect = true
		img := buildImage(t, testDefaults(versionVMFS5), tnDir("/", node))
		// Point the descriptor at item 15; the cache declares only one area.
		img.putBlock(node, 0, pointerBlockID(15))
		v := openBuilt(t, img)
		_, err := v.OpenFile("/indirect.bin")
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "needs 65536")
	})

	t.Run("double indirect refused", func(t *testing.T) {
		node := tnFile("indirect.bin", "payload")
		node.indirect = true
		img := buildImage(t, testDefaults(versionVMFS5), tnDir("/", node))
		img.putBlock(node, 0, uint32(1)<<28|6)
		v := openBuilt(t, img)
		_, err := v.OpenFile("/indirect.bin")
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "double-indirect")
	})

	t.Run("sub-block indirect refused", func(t *testing.T) {
		node := tnFile("indirect.bin", "payload")
		node.indirect = true
		img := buildImage(t, testDefaults(versionVMFS5), tnDir("/", node))
		img.putBlock(node, 0, uint32(1)<<28|2)
		v := openBuilt(t, img)
		_, err := v.OpenFile("/indirect.bin")
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "sub-block")
	})

	t.Run("wrong pointer id type", func(t *testing.T) {
		node := tnFile("indirect.bin", "payload")
		node.indirect = true
		img := buildImage(t, testDefaults(versionVMFS5), tnDir("/", node))
		img.putBlock(node, 0, uint32(1)<<28|1)
		v := openBuilt(t, img)
		_, err := v.OpenFile("/indirect.bin")
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "not a pointer block")
	})

	t.Run("pbc itself indirect", func(t *testing.T) {
		opts := testDefaults(versionVMFS5)
		opts.pbcIndirect = true
		node := tnFile("indirect.bin", "payload")
		node.indirect = true
		v := openBuilt(t, buildImage(t, opts, tnDir("/", node)))
		if v.Info().PBCLoaded {
			t.Errorf("PBC loaded despite being indirect")
		}
		pbcEntry, err := v.Stat("/.pbc.sf")
		if err != nil {
			t.Fatalf("stat pbc: %v", err)
		}
		if pbcEntry.AllocatedKnown {
			t.Errorf("indirect pbc entry = %+v", pbcEntry)
		}
		if _, err := v.OpenFile("/indirect.bin"); !errors.Is(err, ErrUnsupported) {
			t.Errorf("error = %v", err)
		}
	})
}

func TestDirectoryRecordCorruption(t *testing.T) {
	base := func() *testImage {
		return buildImage(t, testDefaults(versionVMFS5), tnDir("/", tnFile("good.txt", "ok"), tnFile("victim", "v")))
	}
	// The root stream is: ".", "..", "good.txt", "victim". Record 3 is the
	// victim.
	const victimIndex = 3

	t.Run("non-fd block id", func(t *testing.T) {
		img := base()
		at := img.dirRecordOffset(img.root, victimIndex)
		putU32(img.data, at+4, 1)
		v := openBuilt(t, img)
		info := v.Info()
		if info.Unreadable != 1 || info.Malformed == 0 {
			t.Fatalf("info = %+v", info)
		}
		entries, err := v.ListDir("/")
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(entries) != 0 {
			t.Errorf("an unreadable directory must not list names: %+v", entries)
		}
	})

	t.Run("no nul in name", func(t *testing.T) {
		img := base()
		at := img.dirRecordOffset(img.root, victimIndex)
		for i := 0; i < 276; i++ {
			img.data[at+12+i] = 'n'
		}
		v := openBuilt(t, img)
		if v.Info().Malformed == 0 {
			t.Errorf("no NUL was not reported")
		}
	})

	t.Run("empty name", func(t *testing.T) {
		img := base()
		at := img.dirRecordOffset(img.root, victimIndex)
		img.data[at+12] = 0
		v := openBuilt(t, img)
		if v.Info().Malformed == 0 {
			t.Errorf("empty name was not reported")
		}
	})

	t.Run("slash in name", func(t *testing.T) {
		img := base()
		at := img.dirRecordOffset(img.root, victimIndex)
		copy(img.data[at+12:], "bad/name\x00")
		v := openBuilt(t, img)
		if v.Info().Malformed == 0 {
			t.Errorf("slash name was not reported")
		}
	})

	t.Run("unknown type", func(t *testing.T) {
		img := base()
		at := img.dirRecordOffset(img.root, victimIndex)
		putU32(img.data, at+0, 7)
		v := openBuilt(t, img)
		if v.Info().Malformed == 0 {
			t.Errorf("unknown type was not reported")
		}
	})

	t.Run("rdm type", func(t *testing.T) {
		img := base()
		at := img.dirRecordOffset(img.root, victimIndex)
		putU32(img.data, at+0, 4)
		v := openBuilt(t, img)
		if v.Info().Refusals == 0 {
			t.Errorf("RDM type was not refused")
		}
	})

	t.Run("trailing non-zero partial record", func(t *testing.T) {
		root := tnDir("/", tnFile("good.txt", "ok"))
		root.trailer = []byte{1, 2, 3}
		v := openBuilt(t, buildImage(t, testDefaults(versionVMFS5), root))
		if v.Info().Malformed == 0 {
			t.Errorf("trailing bytes were not reported")
		}
	})

	t.Run("trailing zero padding accepted", func(t *testing.T) {
		root := tnDir("/", tnFile("good.txt", "ok"))
		root.trailer = []byte{0, 0, 0}
		v := openBuilt(t, buildImage(t, testDefaults(versionVMFS5), root))
		if _, err := v.Stat("/good.txt"); err != nil {
			t.Errorf("padding broke the listing: %v", err)
		}
	})

	t.Run("zero-sized directory stream", func(t *testing.T) {
		img := base()
		putU64(img.data, img.root.fdOffset+img.metaHeader+20, 0)
		v := openBuilt(t, img)
		if v.Info().Unreadable != 1 {
			t.Errorf("zero-sized directory = %+v", v.Info())
		}
	})
}

func TestWalkUndecodableAndMismatch(t *testing.T) {
	t.Run("dangling descriptor", func(t *testing.T) {
		root := tnDir("/", tnFile("good.txt", "ok"), tnFile("dangling", "x"))
		img := buildImage(t, testDefaults(versionVMFS5), root)
		at := img.dirRecordOffset(img.root, 3)
		putU32(img.data, at+4, fdBlockID(300))
		v := openBuilt(t, img)
		info := v.Info()
		if info.Undecodable != 1 {
			t.Errorf("undecodable = %d", info.Undecodable)
		}
		if _, err := v.Stat("/dangling"); !errors.Is(err, ErrPathNotFound) {
			t.Errorf("dangling stat = %v", err)
		}
		if _, err := v.Stat("/good.txt"); err != nil {
			t.Errorf("good stat: %v", err)
		}
	})

	t.Run("descriptor type mismatch", func(t *testing.T) {
		root := tnDir("/", tnDir("victim"))
		img := buildImage(t, testDefaults(versionVMFS5), root)
		putU32(img.data, img.find("victim").fdOffset+img.metaHeader+12, 1)
		v := openBuilt(t, img)
		if v.Info().Malformed == 0 {
			t.Errorf("mismatch was not reported")
		}
		if _, err := v.Stat("/victim"); !errors.Is(err, ErrPathNotFound) {
			t.Errorf("victim stat = %v", err)
		}
	})

	t.Run("record id mismatch", func(t *testing.T) {
		root := tnDir("/", tnFile("victim", "x"))
		img := buildImage(t, testDefaults(versionVMFS5), root)
		at := img.dirRecordOffset(img.root, 2)
		putU32(img.data, at+8, getU32(img.data, at+8)+1)
		v := openBuilt(t, img)
		if v.Info().Malformed == 0 {
			t.Errorf("record mismatch was not reported")
		}
		if _, err := v.Stat("/victim"); !errors.Is(err, ErrPathNotFound) {
			t.Errorf("victim stat = %v", err)
		}
	})

	t.Run("zero record id accepted", func(t *testing.T) {
		root := tnDir("/", tnFile("victim", "x"))
		img := buildImage(t, testDefaults(versionVMFS5), root)
		at := img.dirRecordOffset(img.root, 2)
		putU32(img.data, at+8, 0)
		v := openBuilt(t, img)
		if _, err := v.Stat("/victim"); err != nil {
			t.Errorf("zero record id rejected: %v", err)
		}
	})

	t.Run("bad descriptor magic", func(t *testing.T) {
		root := tnDir("/", tnFile("victim", "x"))
		img := buildImage(t, testDefaults(versionVMFS5), root)
		putU32(img.data, img.find("victim").fdOffset, 0)
		v := openBuilt(t, img)
		if v.Info().Undecodable != 1 {
			t.Errorf("undecodable = %d", v.Info().Undecodable)
		}
	})

	t.Run("zero link count", func(t *testing.T) {
		root := tnDir("/", tnFile("victim", "x"))
		img := buildImage(t, testDefaults(versionVMFS5), root)
		putU32(img.data, img.find("victim").fdOffset+img.metaHeader+8, 0)
		v := openBuilt(t, img)
		if v.Info().Undecodable != 1 {
			t.Errorf("undecodable = %d", v.Info().Undecodable)
		}
	})

	for _, typ := range []uint32{0, 4, 5, 7} {
		typ := typ
		t.Run(fmt.Sprintf("descriptor type %d", typ), func(t *testing.T) {
			root := tnDir("/", tnFile("victim", "x"))
			img := buildImage(t, testDefaults(versionVMFS5), root)
			putU32(img.data, img.find("victim").fdOffset+img.metaHeader+12, typ)
			v := openBuilt(t, img)
			if v.Info().Undecodable != 1 {
				t.Errorf("undecodable = %d", v.Info().Undecodable)
			}
			switch typ {
			case 0:
				if v.Info().Malformed == 0 {
					t.Errorf("type 0 was not classified as malformed")
				}
			default:
				if v.Info().Refusals == 0 {
					t.Errorf("type %d was not classified as a refusal", typ)
				}
			}
		})
	}

	t.Run("descriptor outside the bitmap", func(t *testing.T) {
		root := tnDir("/", tnFile("victim", "x"))
		img := buildImage(t, testDefaults(versionVMFS5), root)
		// Entry 8 lies past the 2048 declared items.
		at := img.dirRecordOffset(img.root, 2)
		putU32(img.data, at+4, fdBuild(8, 0))
		v := openBuilt(t, img)
		if v.Info().Undecodable != 1 {
			t.Errorf("undecodable = %d", v.Info().Undecodable)
		}
	})
}

func TestWarningsCap(t *testing.T) {
	var children []*testNode
	for i := 0; i < 40; i++ {
		children = append(children, tnFile(fmt.Sprintf("f%02d", i), ""))
	}
	root := tnDir("/", children...)
	img := buildImage(t, testDefaults(versionVMFS5), root)
	for _, n := range img.nodes {
		if n.alias != nil || n == img.root {
			continue
		}
		putU32(img.data, n.fdOffset, 0)
	}
	v := openBuilt(t, img)
	info := v.Info()
	if len(info.Warnings) != warningCap {
		t.Errorf("warnings = %d", len(info.Warnings))
	}
	if info.WarningsDropped != 40+1-warningCap {
		t.Errorf("dropped = %d", info.WarningsDropped)
	}
	if info.Undecodable != 40 {
		t.Errorf("undecodable = %d", info.Undecodable)
	}
}

func TestFDCHeaderValidation(t *testing.T) {
	base := func() []byte {
		b := make([]byte, 28)
		putU32(b, 0, 256)
		putU32(b, 4, 8)
		putU32(b, 8, 65536)
		putU32(b, 12, 2048)
		putU32(b, 16, tFDCAreaSize)
		putU32(b, 20, 2048)
		putU32(b, 24, 1)
		return b
	}
	cases := []struct {
		name  string
		edit  func([]byte)
		parts []string
	}{
		{"zero items per entry", func(b []byte) { putU32(b, 0, 0) }, []string{"items per bitmap entry"}},
		{"huge items per entry", func(b []byte) { putU32(b, 0, 0x100001) }, []string{"items per bitmap entry"}},
		{"zero bitmap entries", func(b []byte) { putU32(b, 4, 0) }, []string{"bitmap entries per area"}},
		{"huge bitmap entries", func(b []byte) { putU32(b, 4, 0x100001) }, []string{"bitmap entries per area"}},
		{"zero header size", func(b []byte) { putU32(b, 8, 0) }, []string{"zero header size"}},
		{"wrong item size", func(b []byte) { putU32(b, 12, 4096) }, []string{"expected 2048"}},
		{"zero area size", func(b []byte) { putU32(b, 16, 0) }, []string{"zero area size"}},
		{"zero areas", func(b []byte) { putU32(b, 24, 0) }, []string{"zero areas"}},
		{"zero items", func(b []byte) { putU32(b, 20, 0) }, []string{"zero items"}},
		{"inconsistent total", func(b []byte) { putU32(b, 20, 7) }, []string{"areas of"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := base()
			tc.edit(raw)
			_, err := readBitmapHeader(source.NewMemorySource(1, raw), 0, 2048, "the FDC header")
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("error = %v", err)
			}
			wantContains(t, err, tc.parts...)
		})
	}

	t.Run("short header", func(t *testing.T) {
		_, err := readBitmapHeader(source.NewMemorySource(1, make([]byte, 27)), 0, 2048, "the FDC header")
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("offset past the source", func(t *testing.T) {
		_, err := readBitmapHeader(source.NewMemorySource(1, make([]byte, 28)), 8, 2048, "the FDC header")
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("item positions", func(t *testing.T) {
		h, err := readBitmapHeader(source.NewMemorySource(1, base()), 0, 2048, "the FDC header")
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if pos, ok := h.itemPos(0, 0); !ok || pos != 65536+8*0x400 {
			t.Errorf("item 0 = %d, %v", pos, ok)
		}
		if pos, ok := h.itemPos(7, 255); !ok || pos != 65536+8*0x400+2047*2048 {
			t.Errorf("last item = %d, %v", pos, ok)
		}
		if _, ok := h.itemPos(0, 2048); ok {
			t.Errorf("item past the total was accepted")
		}
		if _, ok := h.itemPos(8, 0); ok {
			t.Errorf("entry past the areas was accepted")
		}
	})
}

func TestOpenFatalErrors(t *testing.T) {
	good := buildImage(t, testDefaults(versionVMFS5), tnDir("/", tnFile("a", "a"))).data

	t.Run("too short for the fdc", func(t *testing.T) {
		short := append([]byte(nil), good[:25*tMiB]...)
		err := openErr(t, short)
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "block 25", "too short")
	})

	t.Run("fdc header mismatch", func(t *testing.T) {
		img := append([]byte(nil), good...)
		putU32(img, tFSInfoOff+209, 4096)
		err := openErr(t, img)
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "declares", "4096", "65536")
	})

	t.Run("fdc item size mismatch", func(t *testing.T) {
		img := append([]byte(nil), good...)
		putU32(img, tFDCBase+12, 4096)
		err := openErr(t, img)
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "expected 2048")
	})

	t.Run("fdc total mismatch", func(t *testing.T) {
		img := append([]byte(nil), good...)
		putU32(img, tFDCBase+20, 7)
		err := openErr(t, img)
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "areas of")
	})

	t.Run("root descriptor magic", func(t *testing.T) {
		img := append([]byte(nil), good...)
		putU32(img, tFDCBase+int(tFDCHeaderSize)+tBmpEntriesPerArea*0x400, 0)
		err := openErr(t, img)
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "metadata magic")
	})

	t.Run("root is not a directory", func(t *testing.T) {
		img := append([]byte(nil), good...)
		rootOff := tFDCBase + int(tFDCHeaderSize) + tBmpEntriesPerArea*0x400
		putU32(img, rootOff+512+12, 1)
		err := openErr(t, img)
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "not a directory")
	})
}

func TestInodeParseBranches(t *testing.T) {
	sb5 := &superblock{
		version:            versionVMFS5,
		blockSize:          tMiB,
		volumeBytes:        26 * tMiB,
		fdSize:             2048,
		metadataHeaderSize: 512,
		fileBlockEntries:   256,
		wideBlockAddresses: false,
	}
	sb6 := &superblock{
		version:            versionVMFS6,
		blockSize:          tMiB,
		volumeBytes:        26 * tMiB,
		fdSize:             8192,
		metadataHeaderSize: 4096,
		fileBlockEntries:   256,
		wideBlockAddresses: true,
	}

	makeFD := func(sb *superblock, id uint32) []byte {
		fd := make([]byte, sb.fdSize)
		putU32(fd, 0, inodeMagic)
		base := int(sb.metadataHeaderSize)
		putU32(fd, base+0, id)
		putU32(fd, base+4, 77)
		putU32(fd, base+8, 1)
		putU32(fd, base+12, 1)
		putU64(fd, base+20, 100)
		putU64(fd, base+28, tMiB)
		putU64(fd, base+36, 1)
		putU32(fd, base+44, 10)
		putU32(fd, base+48, 20)
		putU32(fd, base+52, 30)
		putU32(fd, base+56, 1000)
		putU32(fd, base+60, 1001)
		putU32(fd, base+64, 0o644)
		putU32(fd, base+68, blkTypeFB)
		array := int(sb.fdSize) - 256*4
		if sb.wideBlockAddresses {
			array = int(sb.fdSize) - 256*8
			putU64(fd, array, uint64(fileBlockID(3)))
		} else {
			putU32(fd, array, fileBlockID(3))
		}
		return fd
	}

	t.Run("vmfs5", func(t *testing.T) {
		fd := makeFD(sb5, fdBlockID(4))
		in, err := parseInode(fd, fdBlockID(4), 123, sb5)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if in.id != fdBlockID(4) || in.id2 != 77 || in.links != 1 || in.kind != kindFile {
			t.Errorf("inode = %+v", in)
		}
		if in.size != 100 || in.blockSize != tMiB || in.blockCount != 1 {
			t.Errorf("sizes = %+v", in)
		}
		if in.modified != 10 || in.changed != 20 || in.accessed != 30 {
			t.Errorf("times = %+v", in)
		}
		if in.uid != 1000 || in.gid != 1001 || in.mode != 0o644 {
			t.Errorf("owner = %+v", in)
		}
		if in.zla != blkTypeFB || in.blocks[0] != uint64(fileBlockID(3)) {
			t.Errorf("map = %+v", in)
		}
	})

	t.Run("vmfs6 wide address", func(t *testing.T) {
		fd := makeFD(sb6, fdBlockID(4))
		in, err := parseInode(fd, fdBlockID(4), 0, sb6)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if in.blocks[0] != uint64(fileBlockID(3)) {
			t.Errorf("wide block = %#x", in.blocks[0])
		}
	})

	t.Run("mode truncation", func(t *testing.T) {
		fd := makeFD(sb5, fdBlockID(4))
		putU32(fd, 512+64, 0x1ffff)
		in, err := parseInode(fd, fdBlockID(4), 0, sb5)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if in.mode != 0xffff {
			t.Errorf("mode = %#x", in.mode)
		}
	})

	bad := []struct {
		name  string
		edit  func([]byte)
		kind  error
		parts []string
	}{
		{"bad magic", func(fd []byte) { putU32(fd, 0, 0) }, ErrCorrupt, []string{"metadata magic"}},
		{"id mismatch", func(fd []byte) { putU32(fd, 512+0, 99) }, ErrCorrupt, []string{"names itself"}},
		{"zero links", func(fd []byte) { putU32(fd, 512+8, 0) }, ErrCorrupt, []string{"zero link count"}},
		{"type zero", func(fd []byte) { putU32(fd, 512+12, 0) }, ErrCorrupt, []string{"unused or deleted"}},
		{"rdm type four", func(fd []byte) { putU32(fd, 512+12, 4) }, ErrUnsupported, []string{"RDM"}},
		{"rdm type five", func(fd []byte) { putU32(fd, 512+12, 5) }, ErrUnsupported, []string{"RDM"}},
		{"unknown type", func(fd []byte) { putU32(fd, 512+12, 9) }, ErrUnsupported, []string{"inode type 9"}},
		{"size past volume", func(fd []byte) { putU64(fd, 512+20, 100*tMiB) }, ErrCorrupt, []string{"more than"}},
		{"zero block size", func(fd []byte) { putU64(fd, 512+28, 0) }, ErrCorrupt, []string{"zero file-block size"}},
		{"other block size", func(fd []byte) { putU64(fd, 512+28, 2*tMiB) }, ErrUnsupported, []string{"2097152-byte file blocks"}},
		{"allocation overflow", func(fd []byte) {
			putU64(fd, 512+20, 0)
			putU64(fd, 512+36, math.MaxUint64)
		}, ErrCorrupt, []string{"overflows"}},
		{"size exceeds allocation", func(fd []byte) { putU64(fd, 512+20, 2*tMiB) }, ErrCorrupt, []string{"allocates only"}},
		// The reference's "declares bytes but allocates no blocks" branch is
		// unreachable when size is nonzero: the allocation check fires first.
		{"size without blocks", func(fd []byte) {
			putU64(fd, 512+36, 0)
		}, ErrCorrupt, []string{"allocates only 0 blocks"}},
		{"blocks without zla", func(fd []byte) { putU32(fd, 512+68, 0) }, ErrCorrupt, []string{"zero-level address type 0"}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			fd := makeFD(sb5, fdBlockID(4))
			tc.edit(fd)
			_, err := parseInode(fd, fdBlockID(4), 0, sb5)
			if !errors.Is(err, tc.kind) {
				t.Fatalf("error = %v", err)
			}
			wantContains(t, err, tc.parts...)
		})
	}

	t.Run("wrong length", func(t *testing.T) {
		_, err := parseInode(make([]byte, 100), fdBlockID(4), 0, sb5)
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("metadata header leaves no room", func(t *testing.T) {
		fd := makeFD(sb5, fdBlockID(4))
		big := *sb5
		big.metadataHeaderSize = 1024
		_, err := parseInode(fd, fdBlockID(4), 0, &big)
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "no room")
	})
}

func TestExtentResolveBranches(t *testing.T) {
	sb := &superblock{blockSize: tMiB, blocks: 26, volumeBytes: 26 * tMiB}
	inodeOf := func(blocks ...uint64) *inode {
		in := &inode{
			blockID:    fdBlockID(4),
			kind:       kindFile,
			size:       uint64(len(blocks)) * tMiB,
			blockSize:  tMiB,
			blockCount: uint64(len(blocks)),
			zla:        blkTypeFB,
			at:         100,
		}
		copy(in.blocks[:], blocks)
		return in
	}

	fb := func(block uint64) uint64 { return uint64(fileBlockID(block)) }

	t.Run("empty map", func(t *testing.T) {
		in := inodeOf()
		in.size = 0
		m, err := resolveExtents(sb, in, nil)
		if err != nil || len(m.extents) != 0 {
			t.Errorf("map = %+v, %v", m, err)
		}
	})

	t.Run("too many blocks", func(t *testing.T) {
		in := inodeOf(fb(3))
		in.blockCount = maxFileBlocks + 1
		_, err := resolveExtents(sb, in, nil)
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("extended zla", func(t *testing.T) {
		in := inodeOf(fb(3))
		in.zla = zlaExtensionBase
		_, err := resolveExtents(sb, in, nil)
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "extended")
	})

	t.Run("sub-block zla", func(t *testing.T) {
		in := inodeOf(fb(3))
		in.zla = blkTypeSB
		_, err := resolveExtents(sb, in, nil)
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "sub-block")
	})

	t.Run("double indirect zla", func(t *testing.T) {
		in := inodeOf(fb(3))
		in.zla = blkTypePB2
		_, err := resolveExtents(sb, in, nil)
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "double-indirect")
	})

	t.Run("unknown zla", func(t *testing.T) {
		in := inodeOf(fb(3))
		in.zla = 9
		_, err := resolveExtents(sb, in, nil)
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("direct too many", func(t *testing.T) {
		in := inodeOf(fb(3))
		in.blockCount = 257
		_, err := resolveExtents(sb, in, nil)
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("direct zero", func(t *testing.T) {
		_, err := resolveExtents(sb, inodeOf(fb(3), 0), nil)
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
		if !strings.Contains(err.Error(), "hole") {
			t.Errorf("error lacks hole: %v", err)
		}
	})

	t.Run("direct sub-block", func(t *testing.T) {
		_, err := resolveExtents(sb, inodeOf(uint64(blkTypeSB)|8), nil)
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("direct pb2", func(t *testing.T) {
		_, err := resolveExtents(sb, inodeOf(uint64(blkTypePB2)|8), nil)
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("direct wrong type", func(t *testing.T) {
		_, err := resolveExtents(sb, inodeOf(uint64(blkTypeFD)|8), nil)
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("direct block zero physical", func(t *testing.T) {
		_, err := resolveExtents(sb, inodeOf(uint64(blkTypeFB)), nil)
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "block 0")
	})

	t.Run("direct block out of range", func(t *testing.T) {
		_, err := resolveExtents(sb, inodeOf(fb(30)), nil)
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "out of range")
	})

	t.Run("wide id does not fit", func(t *testing.T) {
		_, err := resolveExtents(sb, inodeOf(uint64(1)<<40), nil)
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "32-bit")
	})

	t.Run("direct valid", func(t *testing.T) {
		m, err := resolveExtents(sb, inodeOf(fb(3), fb(4)), nil)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if len(m.extents) != 2 {
			t.Fatalf("extents = %+v", m.extents)
		}
		if m.extents[0].logical != 0 || m.extents[0].physical != 3*tMiB || m.extents[0].len != tMiB {
			t.Errorf("extent 0 = %+v", m.extents[0])
		}
		if m.extents[1].logical != tMiB || m.extents[1].physical != 4*tMiB {
			t.Errorf("extent 1 = %+v", m.extents[1])
		}
	})

	t.Run("indirect without cache", func(t *testing.T) {
		in := inodeOf(fb(3))
		in.zla = blkTypePB
		in.blocks[0] = uint64(pointerBlockID(0))
		_, err := resolveExtents(sb, in, nil)
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, ".pbc.sf")
	})

	t.Run("indirect zero pointer", func(t *testing.T) {
		in := inodeOf(fb(3))
		in.zla = blkTypePB
		in.blocks[0] = 0
		_, err := resolveExtents(sb, in, &pbc{})
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("indirect wrong pointer types", func(t *testing.T) {
		for _, typ := range []uint32{blkTypeSB, blkTypePB2} {
			in := inodeOf(fb(3))
			in.zla = blkTypePB
			in.blocks[0] = uint64(uint32(1)<<28 | typ)
			_, err := resolveExtents(sb, in, &pbc{})
			if !errors.Is(err, ErrUnsupported) {
				t.Errorf("type %d error = %v", typ, err)
			}
		}
		for _, typ := range []uint32{blkTypeFB, blkTypeFD, 5, 7} {
			in := inodeOf(fb(3))
			in.zla = blkTypePB
			in.blocks[0] = uint64(uint32(1)<<28 | typ)
			_, err := resolveExtents(sb, in, &pbc{})
			if !errors.Is(err, ErrCorrupt) {
				t.Errorf("type %d error = %v", typ, err)
			}
		}
	})
}

func TestReadDirUnit(t *testing.T) {
	src := source.NewMemorySource(1, make([]byte, 1024))
	dummy := &superblock{blockSize: tMiB, blocks: 26, volumeBytes: 26 * tMiB}

	t.Run("not a directory", func(t *testing.T) {
		in := &inode{kind: kindFile, size: 288}
		_, err := readDir(dummy, src, in, nil)
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("zero size", func(t *testing.T) {
		in := &inode{kind: kindDirectory, blockID: 4}
		_, err := readDir(dummy, src, in, nil)
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("over the cap", func(t *testing.T) {
		in := &inode{kind: kindDirectory, blockID: 4, size: maxDirectoryBytes + 1}
		_, err := readDir(dummy, src, in, nil)
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("error = %v", err)
		}
		wantContains(t, err, "cap")
	})

	t.Run("empty stream survives parsing", func(t *testing.T) {
		// A 288-byte all-zero stream is one unused slot, not an error.
		dir := &inode{kind: kindDirectory, blockID: 4, size: 288, blockSize: tMiB, blockCount: 1, zla: blkTypeFB}
		dir.blocks[0] = uint64(fileBlockID(3))
		src := source.NewMemorySource(1, make([]byte, 26*tMiB))
		listing, err := readDir(dummy, src, dir, nil)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if listing.unusedSlots != 1 || len(listing.entries) != 0 {
			t.Errorf("listing = %+v", listing)
		}
	})
}

func TestTimesOwnersAndMode(t *testing.T) {
	file := tnFile("timed", "x")
	file.uid, file.gid = 4242, 4343
	file.mode = 0o640
	file.mtime, file.ctime, file.atime = 1_600_000_000, 1_600_000_001, 1_600_000_002
	zero := tnFile("zeroed", "y")
	zero.mtime, zero.ctime, zero.atime = 0, 0, 0
	root := tnDir("/", file, zero)
	vol := openBuilt(t, buildImage(t, testDefaults(versionVMFS5), root))

	entry, err := vol.Stat("/timed")
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if entry.UID != 4242 || entry.GID != 4343 || entry.Mode != 0o640 || entry.NLink != 1 {
		t.Errorf("owner = %+v", entry)
	}
	if !entry.Modified.Equal(time.Unix(1_600_000_000, 0).UTC()) {
		t.Errorf("mtime = %v", entry.Modified)
	}
	if !entry.Changed.Equal(time.Unix(1_600_000_001, 0).UTC()) {
		t.Errorf("ctime = %v", entry.Changed)
	}
	if !entry.Accessed.Equal(time.Unix(1_600_000_002, 0).UTC()) {
		t.Errorf("atime = %v", entry.Accessed)
	}
	if entry.Record != 1 || !entry.HasParent || entry.ParentRecord != 0 {
		t.Errorf("walk identity = %+v", entry)
	}
	if entry.InodeNumber != file.blockID || entry.RecordID != file.id2 {
		t.Errorf("descriptor identity = %+v", entry)
	}

	z, err := vol.Stat("/zeroed")
	if err != nil {
		t.Fatalf("stat zeroed: %v", err)
	}
	if !z.Modified.IsZero() || !z.Changed.IsZero() || !z.Accessed.IsZero() {
		t.Errorf("zero timestamps = %+v", z)
	}
}

func TestBlockIDGeometry(t *testing.T) {
	id := fdBuild(2, 5)
	if blockType(id) != blkTypeFD || fdEntry(id) != 2 || fdItem(id) != 5 {
		t.Errorf("fdBuild(2,5) = 0x%08x splits as %d/%d/%d", id, blockType(id), fdEntry(id), fdItem(id))
	}
	if rootBlockID != 4 || fdEntry(rootBlockID) != 0 || fdItem(rootBlockID) != 0 {
		t.Errorf("root id = 0x%08x", rootBlockID)
	}
	if got := blockNumber((26 << 3) | blkTypeFB); got != 26 {
		t.Errorf("file block = %d", got)
	}
	if got := blockNumber((32 << 3) | blkTypePB); got != 32 {
		t.Errorf("pointer block = %d", got)
	}
}

func TestByteSourceIdentityAndExtentsInto(t *testing.T) {
	root := tnDir("/", tnFile("data.bin", "0123456789"))
	vol := openBuilt(t, buildImage(t, testDefaults(versionVMFS5), root))
	stream, err := vol.OpenFile("/data.bin")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if stream.SourceID() == 0 {
		t.Errorf("source id = 0")
	}
	if stream.SectorSize() != 512 {
		t.Errorf("sector size = %d", stream.SectorSize())
	}
	if stream.ImageID() != 0 {
		t.Errorf("image id = %d", stream.ImageID())
	}

	const sentinelParent = source.ID(4242)
	out := []source.ParentRange{{Parent: sentinelParent, Len: 1, Kind: source.RangeZero}}
	ranges, err := stream.ExtentsInto(0, 10, out)
	if err != nil {
		t.Fatalf("extents into: %v", err)
	}
	if len(ranges) != 2 {
		t.Fatalf("ranges = %+v", ranges)
	}
	if ranges[0].Parent != sentinelParent || ranges[0].Len != 1 {
		t.Errorf("existing range was not preserved: %+v", ranges[0])
	}
	if ranges[1].Kind != source.RangeData || ranges[1].Len != 10 {
		t.Errorf("appended range = %+v", ranges[1])
	}

	fs, ok := stream.(*fileSource)
	if !ok {
		t.Fatalf("unexpected source type %T", stream)
	}
	block, err := fs.physicalBlockAt(5)
	if err != nil {
		t.Fatalf("physical block: %v", err)
	}
	want := root.children[0].dataBlocks[0]
	if block != want {
		t.Errorf("physical block = %d, want %d", block, want)
	}
	if fs.extentCount() != 1 {
		t.Errorf("extent count = %d", fs.extentCount())
	}
	if !strings.Contains(fs.String(), "vmfs file source") {
		t.Errorf("string = %q", fs.String())
	}
}

func TestPBCRootDotMismatch(t *testing.T) {
	node := tnFile("indirect.bin", "payload")
	node.indirect = true
	img := buildImage(t, testDefaults(versionVMFS5), tnDir("/", node))
	// The root stream's first record is ".". Claim it names a different
	// descriptor; the cache must not be loaded.
	at := img.dirRecordOffset(img.root, 0)
	putU32(img.data, at+4, fdBlockID(1))

	vol := openBuilt(t, img)
	if vol.Info().PBCLoaded {
		t.Errorf("PBC loaded despite a mismatched root dot entry")
	}
	found := false
	for _, w := range vol.Info().Warnings {
		if strings.Contains(w, "root directory's \".\" entry") {
			found = true
		}
	}
	if !found {
		t.Errorf("no root-dot warning: %q", vol.Info().Warnings)
	}
	if _, err := vol.OpenFile("/indirect.bin"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("indirect open error = %v", err)
	}
}

func TestDeletedNamesCap(t *testing.T) {
	root := tnDir("/", tnFile("live", "x"))
	for i := 0; i < 20; i++ {
		root.deleted = append(root.deleted, fmt.Sprintf("gone%02d", i))
	}
	vol := openBuilt(t, buildImage(t, testDefaults(versionVMFS5), root))
	entry, err := vol.Stat("/")
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if entry.UnusedSlots != 20 {
		t.Errorf("unused slots = %d", entry.UnusedSlots)
	}
	if len(entry.DeletedNames) != maxUnusedNames {
		t.Errorf("deleted names = %d", len(entry.DeletedNames))
	}
	if entry.DeletedNames[0] != "gone00" || entry.DeletedNames[maxUnusedNames-1] != "gone15" {
		t.Errorf("deleted names = %q", entry.DeletedNames)
	}
}

func TestLiveRecordZeroBlockID(t *testing.T) {
	root := tnDir("/", tnFile("good.txt", "ok"))
	img := buildImage(t, testDefaults(versionVMFS5), root)
	at := img.dirRecordOffset(img.root, 2)
	putU32(img.data, at+4, 0)
	vol := openBuilt(t, img)
	if vol.Info().Unreadable != 1 || vol.Info().Malformed == 0 {
		t.Errorf("info = %+v", vol.Info())
	}
}
