package qcow2

import (
	"bytes"
	"compress/zlib"
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func putBE32(b []byte, at int, v uint32) {
	b[at], b[at+1], b[at+2], b[at+3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
}

func putBE64(b []byte, at int, v uint64) {
	putBE32(b, at, uint32(v>>32))
	putBE32(b, at+4, uint32(v))
}

type qcow2Spec struct {
	version      uint32
	l2           [2]uint64
	clusters     map[int][]byte // cluster index -> payload at 1536 + index*512
	backingName  string
	crypt        uint32
	incompat     uint64
	autoclearBit bool
	virtual      uint64
}

func buildQCOW2(t *testing.T, spec qcow2Spec) []byte {
	t.Helper()
	if spec.version == 0 {
		spec.version = 3
	}
	if spec.virtual == 0 {
		spec.virtual = 1024
	}
	file := make([]byte, 1536+len(spec.clusters)*512)
	if len(file) < 2560 {
		file = make([]byte, 2560)
	}
	copy(file[:4], Signature)
	putBE32(file, 4, spec.version)
	putBE32(file, 20, 9) // 512-byte clusters
	putBE64(file, 24, spec.virtual)
	putBE32(file, 32, spec.crypt)
	putBE32(file, 36, 1) // one L1 entry
	putBE64(file, 40, 512)
	if spec.backingName != "" {
		putBE64(file, 8, 256)
		putBE32(file, 16, uint32(len(spec.backingName)))
		copy(file[256:], spec.backingName)
	}
	if spec.version == 3 {
		putBE64(file, 72, spec.incompat)
		if spec.autoclearBit {
			putBE64(file, 88, autoclearRawExternalData)
		}
		putBE32(file, 96, 4)
		putBE32(file, 100, 104)
	}
	putBE64(file, 512, 1024) // L1[0] -> L2 table
	putBE64(file, 1024, spec.l2[0])
	putBE64(file, 1032, spec.l2[1])
	for index, payload := range spec.clusters {
		copy(file[1536+index*512:], payload)
	}
	return file
}

func openQCOW2(t *testing.T, file []byte) *Source {
	t.Helper()
	src, err := Open(2, source.NewMemorySourceWithImage(1, 9, file))
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	return src
}

func TestQCOW2DataAndZeroClusters(t *testing.T) {
	data := bytes.Repeat([]byte{'D'}, 512)
	file := buildQCOW2(t, qcow2Spec{
		l2:       [2]uint64{1536, 1},
		clusters: map[int][]byte{0: data},
	})
	src := openQCOW2(t, file)
	if src.Len() != 1024 || src.ClusterBytes() != 512 || src.Info().Version != 3 {
		t.Fatalf("geometry = %d %d %d", src.Len(), src.ClusterBytes(), src.Info().Version)
	}

	buf := make([]byte, 1024)
	if _, err := src.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:512], data) {
		t.Fatal("data cluster did not read back")
	}
	if !bytes.Equal(buf[512:], make([]byte, 512)) {
		t.Fatal("zero cluster is not zero")
	}

	extents, err := src.Extents(0, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 2 || extents[0].Kind != source.RangeData ||
		extents[0].ParentOffset != 1536 || extents[1].Kind != source.RangeZero {
		t.Fatalf("extents = %+v", extents)
	}
}

func TestQCOW2UnallocatedCluster(t *testing.T) {
	file := buildQCOW2(t, qcow2Spec{
		l2:       [2]uint64{1536, 0},
		clusters: map[int][]byte{0: bytes.Repeat([]byte{'D'}, 512)},
	})
	src := openQCOW2(t, file)
	buf := make([]byte, 1024)
	if _, err := src.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[512:], make([]byte, 512)) {
		t.Fatal("unallocated cluster is not zero on a standalone image")
	}
}

func TestQCOW2BackingFile(t *testing.T) {
	parentFile := buildQCOW2(t, qcow2Spec{
		l2: [2]uint64{1536, 2048},
		clusters: map[int][]byte{
			0: bytes.Repeat([]byte{'P'}, 512),
			1: bytes.Repeat([]byte{'Q'}, 512),
		},
	})
	parent, err := Open(1, source.NewMemorySourceWithImage(1, 9, parentFile))
	if err != nil {
		t.Fatalf("parent Open error = %v", err)
	}

	childFile := buildQCOW2(t, qcow2Spec{
		l2:          [2]uint64{1536, 0},
		clusters:    map[int][]byte{0: bytes.Repeat([]byte{'C'}, 512)},
		backingName: "parent.qcow2",
	})
	child, err := OpenWithParent(2, source.NewMemorySourceWithImage(1, 9, childFile), parent)
	if err != nil {
		t.Fatalf("OpenWithParent error = %v", err)
	}
	if !child.Info().HasBacking || child.Info().BackingFile != "parent.qcow2" {
		t.Fatalf("info = %+v", child.Info())
	}
	buf := make([]byte, 1024)
	if _, err := child.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:512], bytes.Repeat([]byte{'C'}, 512)) {
		t.Fatal("child cluster did not read back")
	}
	if !bytes.Equal(buf[512:], bytes.Repeat([]byte{'Q'}, 512)) {
		t.Fatal("unallocated child cluster did not come from the parent")
	}
}

func TestQCOW2CompressedCluster(t *testing.T) {
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write(bytes.Repeat([]byte{'Z'}, 512)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if compressed.Len() > 512 {
		t.Fatalf("compressed payload is %d bytes", compressed.Len())
	}
	entry := compressedFlag | 1536 // one 512-byte sector
	file := buildQCOW2(t, qcow2Spec{
		l2:       [2]uint64{entry, 1},
		clusters: map[int][]byte{0: compressed.Bytes()},
	})
	src := openQCOW2(t, file)
	buf := make([]byte, 1024)
	if _, err := src.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:512], bytes.Repeat([]byte{'Z'}, 512)) {
		t.Fatal("compressed cluster did not inflate to the guest bytes")
	}
	extents, err := src.Extents(0, 512)
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 1 || extents[0].ParentOffset != 1536 || extents[0].Len != 512 {
		t.Fatalf("compressed extent = %+v", extents)
	}
}

func TestQCOW2ExtendedL2Subclusters(t *testing.T) {
	const cluster = 1 << 14
	file := make([]byte, 4*cluster)
	copy(file[:4], Signature)
	putBE32(file, 4, 3)
	putBE32(file, 20, 14)
	putBE64(file, 24, cluster)
	putBE32(file, 36, 1)
	putBE64(file, 40, cluster)
	putBE64(file, 72, incompatibleExtendedL2)
	putBE32(file, 96, 4)
	putBE32(file, 100, 104)
	putBE64(file, cluster, 2*cluster) // L1[0] -> L2 at 2 clusters
	dataOffset := uint64(3 * cluster)
	bitmap := uint64(1) | uint64(1)<<2 | uint64(1)<<(1+32)
	putBE64(file, 2*cluster, dataOffset)
	putBE64(file, 2*cluster+8, bitmap)
	for i := 0; i < cluster; i++ {
		file[dataOffset+uint64(i)] = 'X'
	}
	for i := 0; i < 512; i++ {
		file[dataOffset+uint64(i)] = 'A'
		file[dataOffset+1024+uint64(i)] = 'C'
	}

	src, err := Open(2, source.NewMemorySourceWithImage(1, 9, file))
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	if !src.Info().ExtendedL2 {
		t.Fatal("ExtendedL2 = false")
	}
	buf := make([]byte, cluster)
	if _, err := src.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:512], bytes.Repeat([]byte{'A'}, 512)) {
		t.Fatal("subcluster 0 did not read back")
	}
	if !bytes.Equal(buf[512:1024], make([]byte, 512)) {
		t.Fatal("zero subcluster 1 is not zero")
	}
	if !bytes.Equal(buf[1024:1536], bytes.Repeat([]byte{'C'}, 512)) {
		t.Fatal("subcluster 2 did not read back")
	}
	if !bytes.Equal(buf[1536:], make([]byte, cluster-1536)) {
		t.Fatal("unallocated subclusters are not zero")
	}

	extents, err := src.Extents(0, cluster)
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 32 {
		t.Fatalf("extents = %d, want 32 subcluster entries", len(extents))
	}
	kinds := []source.RangeKind{source.RangeData, source.RangeZero, source.RangeData}
	for i, kind := range kinds {
		if extents[i].Kind != kind {
			t.Fatalf("extent %d = %+v, want kind %v", i, extents[i], kind)
		}
	}
	if extents[31].Kind != source.RangeZero {
		t.Fatalf("last subcluster = %+v", extents[31])
	}
}

func TestQCOW2ExternalDataFile(t *testing.T) {
	file := buildQCOW2(t, qcow2Spec{
		l2:       [2]uint64{0, 512},
		incompat: incompatibleExternalData,
	})
	data := bytes.Repeat([]byte{'E'}, 1024)
	src, err := OpenWithOptions(2, source.NewMemorySourceWithImage(1, 9, file), Options{
		DataFile: source.NewMemorySourceWithImage(3, 9, data),
	})
	if err != nil {
		t.Fatalf("OpenWithOptions error = %v", err)
	}
	if !src.Info().ExternalDataFile || src.Info().DataFileRaw {
		t.Fatalf("info = %+v", src.Info())
	}
	buf := make([]byte, 1024)
	if _, err := src.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:512], make([]byte, 512)) {
		t.Fatal("unallocated cluster is not zero")
	}
	if !bytes.Equal(buf[512:], bytes.Repeat([]byte{'E'}, 512)) {
		t.Fatal("external data file cluster did not read back")
	}
	extents, err := src.Extents(0, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 2 || extents[1].Parent != 3 || extents[1].ParentOffset != 512 {
		t.Fatalf("extents = %+v", extents)
	}
}

func TestQCOW2RawExternalDataFile(t *testing.T) {
	file := buildQCOW2(t, qcow2Spec{
		l2:           [2]uint64{0, 0},
		incompat:     incompatibleExternalData,
		autoclearBit: true,
	})
	data := bytes.Repeat([]byte{'R'}, 1024)
	src, err := OpenWithOptions(2, source.NewMemorySourceWithImage(1, 9, file), Options{
		DataFile: source.NewMemorySourceWithImage(3, 9, data),
	})
	if err != nil {
		t.Fatalf("OpenWithOptions error = %v", err)
	}
	if !src.Info().DataFileRaw {
		t.Fatal("DataFileRaw = false")
	}
	buf := make([]byte, 1024)
	if _, err := src.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, data) {
		t.Fatal("raw external data file was not read at the guest offset")
	}
	extents, err := src.Extents(0, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 1 || extents[0].Parent != 3 || extents[0].Kind != source.RangeData {
		t.Fatalf("extents = %+v", extents)
	}
}

func TestQCOW2ExternalDataFileRefusals(t *testing.T) {
	file := buildQCOW2(t, qcow2Spec{
		l2:       [2]uint64{0, 512},
		incompat: incompatibleExternalData,
	})
	if _, err := OpenWithOptions(2, source.NewMemorySource(1, file), Options{}); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("OpenWithOptions(no data file) error = %v, want ErrUnsupported", err)
	}
	if _, err := OpenWithOptions(2, source.NewMemorySource(1, file), Options{
		DataFile: source.NewMemorySource(3, make([]byte, 512)),
	}); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("OpenWithOptions(wrong length) error = %v, want ErrUnsupported", err)
	}

	plain := buildQCOW2(t, qcow2Spec{l2: [2]uint64{0, 0}})
	if _, err := OpenWithOptions(2, source.NewMemorySource(1, plain), Options{
		DataFile: source.NewMemorySource(3, make([]byte, 1024)),
	}); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("OpenWithOptions(spurious data file) error = %v, want ErrUnsupported", err)
	}
}

func TestQCOW2Refusals(t *testing.T) {
	encrypted := buildQCOW2(t, qcow2Spec{
		l2:       [2]uint64{1536, 1},
		clusters: map[int][]byte{0: make([]byte, 512)},
		crypt:    1,
	})
	if _, err := Open(2, source.NewMemorySource(1, encrypted)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Open(encrypted) error = %v, want ErrUnsupported", err)
	}

	extended := buildQCOW2(t, qcow2Spec{
		l2:       [2]uint64{1536, 1},
		clusters: map[int][]byte{0: make([]byte, 512)},
		incompat: incompatibleExtendedL2,
	})
	if _, err := Open(2, source.NewMemorySource(1, extended)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Open(extended L2) error = %v, want ErrUnsupported", err)
	}

	backed := buildQCOW2(t, qcow2Spec{
		l2:          [2]uint64{1536, 1},
		clusters:    map[int][]byte{0: make([]byte, 512)},
		backingName: "parent.qcow2",
	})
	if _, err := Open(2, source.NewMemorySource(1, backed)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Open(backing without parent) error = %v, want ErrUnsupported", err)
	}
}
