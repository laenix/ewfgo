package lvm

import (
	"errors"
	"reflect"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	pvA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	pvB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

func memSource(id source.ID, imageID source.ImageID, data []byte) *source.MemorySource {
	return source.NewMemorySourceWithImage(id, imageID, data)
}

func linearGroup() *VolumeGroup {
	return &VolumeGroup{
		Name:       "vgtest",
		ExtentSize: 8, // 8 sectors = 4096 bytes
		PhysicalVolumes: []PhysicalVolumeEntry{{
			Name: "pv0", UUID: pvA, PEStart: 8, PECount: 16, HasPEStart: true, HasPECount: true,
		}},
		LogicalVolumes: []LogicalVolume{{
			Name: "root",
			Segments: []Segment{{
				Index: 1, StartExtent: 0, ExtentCount: 2, Kind: "linear",
				StripeCount: 1, Stripes: []Stripe{{PVUUID: pvA, StartExtent: 0}},
			}},
		}},
	}
}

func TestLogicalVolumeLinearRead(t *testing.T) {
	parentData := make([]byte, 64*1024)
	pattern := []byte("linear-volume-payload")
	for i := 0; i < 8192; i++ {
		parentData[4096+i] = pattern[i%len(pattern)]
	}
	parent := memSource(1, 7, parentData)

	l := &LVM{Label: PvLabel{PVUUID: pvA}, Group: linearGroup()}
	lv, err := Open(2, parent, l, "root")
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	if lv.Len() != 8192 {
		t.Fatalf("Len = %d, want 8192", lv.Len())
	}
	if lv.SectorSize() != 512 {
		t.Fatalf("SectorSize = %d", lv.SectorSize())
	}

	buf := make([]byte, 8192)
	n, err := lv.ReadAt(0, buf)
	if err != nil || n != 8192 {
		t.Fatalf("ReadAt = %d, %v", n, err)
	}
	for i := range buf {
		if buf[i] != pattern[i%len(pattern)] {
			t.Fatalf("byte %d = %q, want %q", i, buf[i], pattern[i%len(pattern)])
		}
	}

	extents, err := lv.Extents(0, 8192)
	if err != nil {
		t.Fatal(err)
	}
	want := []source.ParentRange{{Parent: 1, ParentOffset: 4096, Len: 8192, Kind: source.RangeData}}
	if !reflect.DeepEqual(extents, want) {
		t.Fatalf("Extents = %+v, want %+v", extents, want)
	}

	image, err := lv.MapToImage(0, 8192)
	if err != nil {
		t.Fatal(err)
	}
	wantImage := []source.ImageRange{{ImageID: 7, ImageOffset: 4096, Len: 8192, Kind: source.RangeData}}
	if !reflect.DeepEqual(image, wantImage) {
		t.Fatalf("MapToImage = %+v, want %+v", image, wantImage)
	}

	if _, err := lv.ReadAt(8192, make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("ReadAt(EOF) error = %v, want ErrOutOfRange", err)
	}
}

func TestLogicalVolumeGapReadsAsZero(t *testing.T) {
	group := &VolumeGroup{
		Name:       "vg",
		ExtentSize: 8,
		PhysicalVolumes: []PhysicalVolumeEntry{{
			Name: "pv0", UUID: pvA, PEStart: 8, PECount: 16, HasPEStart: true, HasPECount: true,
		}},
		LogicalVolumes: []LogicalVolume{{
			Name: "root",
			Segments: []Segment{
				{Index: 1, StartExtent: 0, ExtentCount: 1, Kind: "linear", StripeCount: 1,
					Stripes: []Stripe{{PVUUID: pvA, StartExtent: 0}}},
				{Index: 2, StartExtent: 2, ExtentCount: 1, Kind: "linear", StripeCount: 1,
					Stripes: []Stripe{{PVUUID: pvA, StartExtent: 2}}},
			},
		}},
	}
	data := make([]byte, 64*1024)
	for i := 0; i < 4096; i++ {
		data[4096+i] = 0x11
		data[4096+8192+i] = 0x22
	}
	parent := memSource(1, 7, data)
	l := &LVM{Label: PvLabel{PVUUID: pvA}, Group: group}
	lv, err := Open(2, parent, l, "root")
	if err != nil {
		t.Fatal(err)
	}
	if lv.Len() != 12288 {
		t.Fatalf("Len = %d, want 12288", lv.Len())
	}

	buf := make([]byte, 12288)
	if _, err := lv.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	for i := 4096; i < 8192; i++ {
		if buf[i] != 0 {
			t.Fatalf("gap byte %d = %#x, want 0", i, buf[i])
		}
	}
	if buf[0] != 0x11 || buf[8192] != 0x22 {
		t.Fatalf("data bytes = %#x %#x", buf[0], buf[8192])
	}

	extents, err := lv.Extents(0, 12288)
	if err != nil {
		t.Fatal(err)
	}
	want := []source.ParentRange{
		{Parent: 1, ParentOffset: 4096, Len: 4096, Kind: source.RangeData},
		{Parent: 1, ParentOffset: 0, Len: 4096, Kind: source.RangeZero},
		{Parent: 1, ParentOffset: 4096 + 8192, Len: 4096, Kind: source.RangeData},
	}
	if !reflect.DeepEqual(extents, want) {
		t.Fatalf("Extents = %+v, want %+v", extents, want)
	}
}

func TestLogicalVolumeStripedRead(t *testing.T) {
	group := &VolumeGroup{
		Name:       "vg",
		ExtentSize: 8, // 4096 bytes
		PhysicalVolumes: []PhysicalVolumeEntry{
			{Name: "pv0", UUID: pvA, PEStart: 8, PECount: 16, HasPEStart: true, HasPECount: true},
			{Name: "pv1", UUID: pvB, PEStart: 8, PECount: 16, HasPEStart: true, HasPECount: true},
		},
		LogicalVolumes: []LogicalVolume{{
			Name: "root",
			Segments: []Segment{{
				Index: 1, StartExtent: 0, ExtentCount: 2, Kind: "striped",
				StripeCount: 2, StripeSize: 4, HasStripeSize: true,
				Stripes: []Stripe{{PVUUID: pvA, StartExtent: 0}, {PVUUID: pvB, StartExtent: 0}},
			}},
		}},
	}

	dataA := make([]byte, 64*1024)
	dataB := make([]byte, 64*1024)
	fill := func(data []byte, at int, b byte) {
		for i := 0; i < 2048; i++ {
			data[at+i] = b
		}
	}
	fill(dataA, 4096, 'A')
	fill(dataB, 4096, 'B')
	fill(dataA, 4096+2048, 'C')
	fill(dataB, 4096+2048, 'D')

	pvs := []PhysicalVolumeSource{
		{UUID: pvA, Source: memSource(1, 7, dataA)},
		{UUID: pvB, Source: memSource(2, 7, dataB)},
	}
	lv, err := OpenInGroup(3, group, pvs, "root")
	if err != nil {
		t.Fatalf("OpenInGroup error = %v", err)
	}
	if lv.Len() != 8192 {
		t.Fatalf("Len = %d, want 8192", lv.Len())
	}

	buf := make([]byte, 8192)
	if _, err := lv.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	want := []byte("AAAABBBBCCCCDDDD")
	for chunk := 0; chunk < 4; chunk++ {
		for i := 0; i < 2048; i++ {
			if buf[chunk*2048+i] != want[chunk*4] {
				t.Fatalf("chunk %d byte %d = %q, want %q", chunk, i, buf[chunk*2048+i], want[chunk*4])
			}
		}
	}

	extents, err := lv.Extents(0, 8192)
	if err != nil {
		t.Fatal(err)
	}
	wantExtents := []source.ParentRange{
		{Parent: 1, ParentOffset: 4096, Len: 2048, Kind: source.RangeData},
		{Parent: 2, ParentOffset: 4096, Len: 2048, Kind: source.RangeData},
		{Parent: 1, ParentOffset: 6144, Len: 2048, Kind: source.RangeData},
		{Parent: 2, ParentOffset: 6144, Len: 2048, Kind: source.RangeData},
	}
	if !reflect.DeepEqual(extents, wantExtents) {
		t.Fatalf("Extents = %+v, want %+v", extents, wantExtents)
	}

	image, err := lv.MapToImage(0, 8192)
	if err != nil {
		t.Fatal(err)
	}
	wantImage := []source.ImageRange{
		{ImageID: 7, ImageOffset: 4096, Len: 2048, Kind: source.RangeData},
		{ImageID: 7, ImageOffset: 4096, Len: 2048, Kind: source.RangeData},
		{ImageID: 7, ImageOffset: 6144, Len: 2048, Kind: source.RangeData},
		{ImageID: 7, ImageOffset: 6144, Len: 2048, Kind: source.RangeData},
	}
	if !reflect.DeepEqual(image, wantImage) {
		t.Fatalf("MapToImage = %+v, want %+v", image, wantImage)
	}
}

func TestLogicalVolumeRejectsUnsupportedLayout(t *testing.T) {
	group := linearGroup()
	group.LogicalVolumes[0].Segments[0].Kind = "thin"
	l := &LVM{Label: PvLabel{PVUUID: pvA}, Group: group}
	_, err := Open(2, memSource(1, 7, make([]byte, 64*1024)), l, "root")
	if !errors.Is(err, ErrUnsupportedLayout) {
		t.Fatalf("Open error = %v, want ErrUnsupportedLayout", err)
	}
}

func TestLogicalVolumeRejectsMissingMember(t *testing.T) {
	group := linearGroup()
	group.PhysicalVolumes = append(group.PhysicalVolumes, PhysicalVolumeEntry{
		Name: "pv1", UUID: pvB, PEStart: 8, PECount: 16, HasPEStart: true, HasPECount: true,
	})
	group.LogicalVolumes[0].Segments[0].Stripes[0].PVUUID = pvB
	l := &LVM{Label: PvLabel{PVUUID: pvA}, Group: group}
	_, err := Open(2, memSource(1, 7, make([]byte, 64*1024)), l, "root")
	if !errors.Is(err, ErrMissingPhysicalVolume) {
		t.Fatalf("Open error = %v, want ErrMissingPhysicalVolume", err)
	}
}

func TestLogicalVolumeRejectsUnknownVolume(t *testing.T) {
	l := &LVM{Label: PvLabel{PVUUID: pvA}, Group: linearGroup()}
	_, err := Open(2, memSource(1, 7, make([]byte, 64*1024)), l, "missing")
	if !errors.Is(err, ErrUnknownVolume) {
		t.Fatalf("Open error = %v, want ErrUnknownVolume", err)
	}
}

func TestBytesOnStripe(t *testing.T) {
	// 5 chunks of 100 bytes across 2 stripes: 100,100,100,100,50.
	cases := []struct {
		index uint64
		want  uint64
	}{{0, 250}, {1, 200}}
	for _, tc := range cases {
		if got := bytesOnStripe(450, 100, 2, tc.index); got != tc.want {
			t.Fatalf("bytesOnStripe(450,100,2,%d) = %d, want %d", tc.index, got, tc.want)
		}
	}
}
