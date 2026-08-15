package apfs

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// LZVN decoder. Streams are hand-encoded per liblzfse opcode semantics: most
// opcodes carry literal bytes then a back-match; matches may overlap.

// buildEos appends the 8-byte end-of-stream marker to a raw opcode stream.
func buildEos(stream ...byte) []byte {
	return append(stream, 6, 0, 0, 0, 0, 0, 0, 0)
}

func TestLZVNBasicLiteralMatch(t *testing.T) {
	// sml_d opcode 192 = {L=3 literal, M=3 match}, dist byte 3, then "abc".
	// Decodes to "abcabc": literal "abc" + 3-byte match at distance 3.
	got, err := lzvnDecompress(buildEos(192, 3, 'a', 'b', 'c'), 6)
	if err != nil {
		t.Fatalf("lzvnDecompress: %v", err)
	}
	if string(got) != "abcabc" {
		t.Fatalf("got %q, want %q", got, "abcabc")
	}
}

func TestLZVNLongLiteral(t *testing.T) {
	// lrg_l opcode 224 + (L-16=36) + 52 literal bytes.
	in := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	stream := append([]byte{224, 36}, in...)
	got, err := lzvnDecompress(buildEos(stream...), uint32(len(in)))
	if err != nil {
		t.Fatalf("lzvnDecompress: %v", err)
	}
	if string(got) != in {
		t.Fatalf("long literal mismatch")
	}
}

func TestLZVNPreviousDistanceMatches(t *testing.T) {
	// sml_m (242, M=2) reuses the previous distance 3: "abcabc" + match 2 @3
	// copies out[3],out[4] = 'a','b' -> "abcabcab".
	got, err := lzvnDecompress(buildEos(192, 3, 'a', 'b', 'c', 242), 8)
	if err != nil {
		t.Fatalf("sml_m: %v", err)
	}
	if string(got) != "abcabcab" {
		t.Fatalf("sml_m got %q, want %q", got, "abcabcab")
	}
	// lrg_m (240, next=0 => M=16) reuses distance 3 over a 22-byte output.
	got, err = lzvnDecompress(buildEos(192, 3, 'a', 'b', 'c', 240, 0), 22)
	if err != nil {
		t.Fatalf("lrg_m: %v", err)
	}
	if want := strings.Repeat("abc", 7) + "a"; string(got) != want {
		t.Fatalf("lrg_m got %q, want %q", got, want)
	}
	// pre_d (70 = {L=1 literal, M=3 match}) reuses the previous distance 3:
	// "abcabc" + 'x' + match 3 @3.
	got, err = lzvnDecompress(buildEos(192, 3, 'a', 'b', 'c', 70, 'x'), 10)
	if err != nil {
		t.Fatalf("pre_d: %v", err)
	}
	if string(got) != "abcabcxbcx" {
		t.Fatalf("pre_d got %q, want %q", got, "abcabcxbcx")
	}
}

func TestLZVNErrors(t *testing.T) {
	cases := []struct {
		name    string
		src     []byte
		outLen  uint32
		wantErr string
	}{
		{"empty source", []byte{}, 4, "empty source"},
		{"sml_d truncated", []byte{192, 3, 'a', 'b'}, 6, "sml_d source truncated"},
		{"source exhausted", []byte{192, 3, 'a', 'b', 'c', 0}, 7, "sml_d source truncated"},
		{"undefined opcode", []byte{30}, 4, "undefined opcode 0x1e"},
		{"invalid distance", []byte{24, 0, 0}, 4, "invalid match distance"},
		{"literal overrun", append([]byte{224, 0}, make([]byte, 19)...), 5, "lrg_l literal overruns"},
		{"eos before full output", buildEos(), 5, "eos after 0 bytes"},
		{"eos source truncated", []byte{6, 0}, 4, "eos source truncated"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := lzvnDecompress(c.src, c.outLen)
			if err == nil {
				t.Fatalf("expected error %q, got nil", c.wantErr)
			}
			if !strings.Contains(err.Error(), strings.TrimSuffix(c.wantErr, "...")) {
				t.Fatalf("got error %q, want it to contain %q", err, c.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// decmpfs helpers.

// decmpfsEmbeddedValue builds an embedded com.apple.decmpfs xattr record value
// ({flags u16 = embedded, xdata_len u16, then the decmpfs payload}).
func decmpfsEmbeddedValue(typ uint32, size uint64, cdata []byte) []byte {
	payload := make([]byte, 16+len(cdata))
	binary.LittleEndian.PutUint32(payload[0:4], apfsDecmpfsMagic)
	binary.LittleEndian.PutUint32(payload[4:8], typ)
	binary.LittleEndian.PutUint64(payload[8:16], size)
	copy(payload[16:], cdata)
	val := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint16(val[0:2], 0x0002) // XATTR_DATA_EMBEDDED
	binary.LittleEndian.PutUint16(val[2:4], uint16(len(payload)))
	copy(val[4:], payload)
	return val
}

// fakeBlockAPFS builds an APFS whose blocks are served from a sparse map, so
// extent reads can be verified byte-for-byte without a full superblock. The
// reader is a faithful sector device: readFunc(lba, count) returns count 512-byte
// sectors, sector i of the request coming from block (lba/8 + i/8), sector i%8.
func fakeBlockAPFS(blocks map[uint64][]byte) *APFS {
	return &APFS{
		blocksize: 4096,
		startLBA:  100,
		readFunc: func(lba, count uint64) ([]byte, error) {
			out := make([]byte, count*512)
			first := (lba - 100) / 8
			for i := uint64(0); i < count; i++ {
				blk := first + i/8
				if b, ok := blocks[blk]; ok {
					sec := b[(i%8)*512 : (i%8)*512+512]
					copy(out[i*512:], sec)
				}
			}
			return out, nil
		},
	}
}

func TestAPFSDecmpfsSize(t *testing.T) {
	good := decmpfsEmbeddedValue(8, 1311, nil)
	cases := []struct {
		name string
		xas  []apfsXattr
		want uint64
	}{
		{"absent", nil, 0},
		{"only unrelated", []apfsXattr{{name: "com.apple.system.Security", value: []byte{0x02, 0x00, 0x04, 0x00}}}, 0},
		{"embedded decmpfs", []apfsXattr{{name: "com.apple.decmpfs", value: good}}, 1311},
		{"stream-stored decmpfs", []apfsXattr{{name: "com.apple.decmpfs", dataOID: 9, dataSize: 20}}, 0},
		{"bad magic", []apfsXattr{{name: "com.apple.decmpfs", value: decmpfsEmbeddedValue(8, 10, nil)[:8]}}, 0},
		{"too short", []apfsXattr{{name: "com.apple.decmpfs", value: []byte{0x02, 0x00, 0x04, 0x00, 0x66, 0x70}}}, 0},
	}
	for _, c := range cases {
		if got := apfsDecmpfsSize(c.xas); got != c.want {
			t.Errorf("%s: apfsDecmpfsSize = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestAPFSDecmpfsInline(t *testing.T) {
	lzvn := buildEos(192, 3, 'a', 'b', 'c')
	raw := append([]byte{0x06}, "rawdata"...)
	var zbytes bytes.Buffer
	zw := zlib.NewWriter(&zbytes)
	zw.Write([]byte("zlibbed"))
	zw.Close()

	cases := []struct {
		name  string
		typ   uint32
		size  uint64
		cdata []byte
		want  string
	}{
		{"type 7 lzvn", 7, 6, lzvn, "abcabc"},
		{"type 7 raw marker", 7, 7, raw, "rawdata"},
		{"type 9 uncompressed", 9, 7, append([]byte{0xCC}, "uncompd"...), "uncompd"},
		{"type 3 zlib", 3, 7, zbytes.Bytes(), "zlibbed"},
		{"type 3 raw marker", 3, 7, append([]byte{0xFF}, "zzzzzzz"...), "zzzzzzz"},
		{"type 13 raw marker", 13, 3, append([]byte{0xFF}, "abc"...), "abc"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			apfs := fakeBlockAPFS(nil)
			apfs.index = &apfsIndex{
				xattrs: map[uint64][]apfsXattr{
					5: {{name: "com.apple.decmpfs", value: decmpfsEmbeddedValue(c.typ, c.size, c.cdata)}},
				},
			}
			got, err := apfs.apfsReadDecmpfs(5)
			if err != nil {
				t.Fatalf("apfsReadDecmpfs: %v", err)
			}
			if string(got) != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}

	// Unsupported algorithms are explicit errors, never fabricated data.
	for _, typ := range []uint32{11, 13} {
		apfs := fakeBlockAPFS(nil)
		apfs.index = &apfsIndex{xattrs: map[uint64][]apfsXattr{
			5: {{name: "com.apple.decmpfs", value: decmpfsEmbeddedValue(typ, 4, []byte{0x01})}},
		}}
		if _, err := apfs.apfsReadDecmpfs(5); err == nil {
			t.Errorf("type %d: expected unsupported-algorithm error", typ)
		}
	}
}

func TestAPFSDecmpfsRsrcChunks(t *testing.T) {
	// Resource-fork layout: u32 LE offset table (chunk k spans [off[k], off[k+1]))
	// then the chunk data. The ResourceFork xattr is stored as an external stream
	// keyed by its object id, read via the xattr's dataOID.
	cases := []struct {
		name  string
		chunk []byte // raw chunk bytes (appended after the offset table)
		size  uint64
		want  string
	}{
		// A 0x06 first byte marks a whole chunk as a raw copy (the entire chunk is
		// the verbatim data, no LZVN opcode stream follows it).
		{"raw-copy marker", append([]byte{0x06}, strings.Repeat("R", 24)...), 24, strings.Repeat("R", 24)},
		// A real sml_d stream: literal "abc" + 3-byte match at distance 3.
		{"lzvn sml_d", buildEos(192, 3, 'a', 'b', 'c'), 6, "abcabc"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			offList := make([]byte, 8)
			binary.LittleEndian.PutUint32(offList[0:4], 8)
			binary.LittleEndian.PutUint32(offList[4:8], uint32(8+len(c.chunk)))
			rsrc := append(offList, c.chunk...)
			block := make([]byte, 4096)
			copy(block, rsrc)
			apfs := fakeBlockAPFS(map[uint64][]byte{700: block})
			apfs.index = &apfsIndex{
				xattrs: map[uint64][]apfsXattr{
					5: {
						{name: "com.apple.decmpfs", value: decmpfsEmbeddedValue(8, c.size, nil)},
						{name: "com.apple.ResourceFork", dataOID: 700, dataSize: uint64(len(rsrc))},
					},
				},
				extents: map[uint64][]apfsExtent{
					700: {{laddr: 0, length: 4096, paddr: 700}},
				},
			}
			got, err := apfs.apfsReadDecmpfs(5)
			if err != nil {
				t.Fatalf("apfsReadDecmpfs: %v", err)
			}
			if string(got) != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}

	// Type 10 (raw rsrc) chunks copy src[1:] of each chunk; type 12 (LZFSE rsrc)
	// is an explicit error, never fabricated data.
	rawChunk := append([]byte{0}, []byte("LITERALDATA")...) // marker + 11 bytes
	rawOff := make([]byte, 8)
	binary.LittleEndian.PutUint32(rawOff[0:4], 8)
	binary.LittleEndian.PutUint32(rawOff[4:8], uint32(8+len(rawChunk)))
	rawRsrc := append(rawOff, rawChunk...)
	rawBlock := make([]byte, 4096)
	copy(rawBlock, rawRsrc)
	apfs := fakeBlockAPFS(map[uint64][]byte{700: rawBlock})
	apfs.index = &apfsIndex{xattrs: map[uint64][]apfsXattr{
		5: {
			{name: "com.apple.decmpfs", value: decmpfsEmbeddedValue(10, 11, nil)},
			{name: "com.apple.ResourceFork", dataOID: 700, dataSize: uint64(len(rawRsrc))},
		},
	}, extents: map[uint64][]apfsExtent{700: {{laddr: 0, length: 4096, paddr: 700}}}}
	got, err := apfs.apfsReadDecmpfs(5)
	if err != nil || string(got) != "LITERALDATA" {
		t.Fatalf("type 10 rsrc: got %q err %v", got, err)
	}
	apfs.index.xattrs[5][0].value = decmpfsEmbeddedValue(12, 11, nil)
	if _, err := apfs.apfsReadDecmpfs(5); err == nil {
		t.Fatalf("type 12 rsrc: expected LZFSE-not-implemented error")
	}
}

func TestAPFSDecmpfsRsrcBadTable(t *testing.T) {
	// Chunk range runs past the resource fork -> explicit error.
	offList := make([]byte, 8)
	binary.LittleEndian.PutUint32(offList[0:4], 0)
	binary.LittleEndian.PutUint32(offList[4:8], 0xffff)
	apfs := fakeBlockAPFS(nil)
	apfs.index = &apfsIndex{xattrs: map[uint64][]apfsXattr{
		5: {
			{name: "com.apple.decmpfs", value: decmpfsEmbeddedValue(8, 24, nil)},
			{name: "com.apple.ResourceFork", dataOID: 700, dataSize: 8},
		},
	}, extents: map[uint64][]apfsExtent{700: {{laddr: 0, length: 4096, paddr: 700}}}}
	if _, err := apfs.apfsReadDecmpfs(5); err == nil {
		t.Fatalf("expected chunk-out-of-range error")
	}
}

// ---------------------------------------------------------------------------
// dstream-oid extent assembly.

func TestAPFSReadStreamAssemblesBytes(t *testing.T) {
	block10 := make([]byte, 4096)
	block11 := make([]byte, 4096)
	for i := range block10 {
		block10[i] = 0xA0
		block11[i] = 0xB0
	}
	apfs := fakeBlockAPFS(map[uint64][]byte{10: block10, 11: block11})
	apfs.index = &apfsIndex{extents: map[uint64][]apfsExtent{
		555: {{laddr: 0, length: 4096, paddr: 10}, {laddr: 4096, length: 4096, paddr: 11}},
		600: {{laddr: 0, length: 8192, paddr: 20}},
	}}

	// Two extents concatenated: 8192 bytes, all from the right physical blocks.
	got, err := apfs.apfsReadStream(555, 8192)
	if err != nil {
		t.Fatalf("apfsReadStream: %v", err)
	}
	if len(got) != 8192 || got[0] != 0xA0 || got[4095] != 0xA0 || got[4096] != 0xB0 || got[8191] != 0xB0 {
		t.Fatalf("two-extent stream did not assemble physical block data")
	}

	// Truncation to the declared size keeps only in-range extent bytes.
	got, err = apfs.apfsReadStream(555, 4096)
	if err != nil || len(got) != 4096 || got[0] != 0xA0 {
		t.Fatalf("truncated stream: len=%d err=%v", len(got), err)
	}
	got, err = apfs.apfsReadStream(555, 5000)
	if err != nil || len(got) != 5000 || got[4999] != 0xB0 {
		t.Fatalf("partial-extent stream: len=%d err=%v", len(got), err)
	}

	// A stream with no extents is a sparse hole: all zeros, no error.
	got, err = apfs.apfsReadStream(999, 100)
	if err != nil || len(got) != 100 || got[50] != 0 {
		t.Fatalf("hole stream: len=%d err=%v", len(got), err)
	}
}

func TestAPFSGetFileFollowsDstreamOID(t *testing.T) {
	// A cloned/shared stream: the DSTREAM_ID record points at a separate stream
	// object whose FILE_EXTENT records carry that oid, not the inode's. GetFile
	// must read the dstream-keyed extents (the ino-keyed ones are absent).
	block := make([]byte, 4096)
	for i := range block {
		block[i] = 0xCD
	}
	apfs := fakeBlockAPFS(map[uint64][]byte{40: block})
	apfs.index = &apfsIndex{
		dirents: map[uint64][]apfsDirent{apfsFSRootOID: {{name: "shared.bin", ino: 5}}},
		inodes:  map[uint64]*apfsInode{5: {size: 4096, mode: 0x8000}},
		dstream: map[uint64]uint64{5: 777},
		extents: map[uint64][]apfsExtent{
			777: {{laddr: 0, length: 4096, paddr: 40}},
			// ino-keyed extents deliberately absent: the stream is shared.
		},
		xattrs: map[uint64][]apfsXattr{},
	}
	got, err := apfs.GetFile("/shared.bin")
	if err != nil {
		t.Fatalf("GetFile: %v", err)
	}
	if len(got) != 4096 || got[0] != 0xCD || got[4095] != 0xCD {
		t.Fatalf("GetFile did not follow the DSTREAM_ID oid")
	}
}
