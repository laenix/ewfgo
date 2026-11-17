package carving

import (
	"errors"
	"testing"
)

// buildImage concatenates objects with filler between them and records where
// each one starts.
type placed struct {
	offset uint64
	length uint64
	format CarvedFormat
}

func buildImage(objects ...[]byte) ([]byte, []placed) {
	var image []byte
	var want []placed
	for _, object := range objects {
		image = append(image, filler(16)...)
		want = append(want, placed{
			offset: uint64(len(image)),
			length: uint64(len(object)),
			format: 0,
		})
		image = append(image, object...)
	}
	return image, want
}

func TestCarvesEachSupportedFormat(t *testing.T) {
	objects := [][]byte{
		makeBMP(),
		makeGIF(),
		makeTIFF(),
		makeWebP(),
		makeEVTXChunk(),
		makeSQLiteDB([]byte{1, 2, 3}),
		makePrefetchRaw(),
	}
	formats := []CarvedFormat{
		FormatBmp, FormatGif, FormatTiff, FormatWebP,
		FormatEvtxChunk, FormatSqlite, FormatPrefetch,
	}

	image, want := buildImage(objects...)
	for i := range want {
		want[i].format = formats[i]
	}

	report, err := Carve(memory(image), 0, ^uint64(0), DefaultCarveOptions())
	if err != nil {
		t.Fatalf("Carve: %v", err)
	}
	if report.Rejected != 0 {
		t.Fatalf("Rejected = %d, want 0", report.Rejected)
	}
	if len(report.Objects) != len(want) {
		t.Fatalf("got %d objects, want %d:\n%+v", len(report.Objects), len(want), report.Objects)
	}
	for i, expected := range want {
		got := report.Objects[i]
		if got.Format != expected.format || got.Offset != expected.offset || got.Len != expected.length {
			t.Errorf("object %d = (%v, %d, %d), want (%v, %d, %d)",
				i, got.Format, got.Offset, got.Len, expected.format, expected.offset, expected.length)
		}
		if !got.Terminated {
			t.Errorf("object %d (%v) is not terminated", i, got.Format)
		}
		if got.InsideOf != nil {
			t.Errorf("object %d (%v) is inside_of %d, want top level", i, got.Format, *got.InsideOf)
		}
	}
	if report.Truncated {
		t.Errorf("Truncated = true, want false")
	}
	if report.BytesScanned != uint64(len(image)) {
		t.Errorf("BytesScanned = %d, want %d", report.BytesScanned, len(image))
	}
}

func TestDecoyThatMatchesMagicButFailsValidationIsRejected(t *testing.T) {
	bmp := makeBMP()
	bmp[2] = 71 // declared size disagrees with the geometry

	gif := makeGIF()
	gif[6], gif[7] = 0, 0 // zero width

	tiff := makeTIFF()
	tiff[4], tiff[5], tiff[6], tiff[7] = 4, 0, 0, 0 // first IFD inside the header

	wave := []byte("RIFF")
	wave = append(wave, 4, 0, 0, 0)
	wave = append(wave, []byte("WAVE")...)

	chunk := makeEVTXChunk()
	chunk[testEVTXChunkHeaderLen+3] ^= 0xFF // records checksum fails

	sqlite := makeSQLiteDB([]byte{1})
	sqlite[16], sqlite[17] = 0x04, 0xD2 // 1234: not a power of two

	prefetch := make([]byte, 4096)
	prefetch[0] = 99 // unknown version
	copy(prefetch[4:8], []byte("SCCA"))
	prefetch[12] = 0x00 // declared size, still zero

	cases := []struct {
		name  string
		bytes []byte
	}{
		{"bmp", bmp},
		{"gif", gif},
		{"tiff", tiff},
		{"webp", wave},
		{"evtx-chunk", chunk},
		{"sqlite", sqlite},
		{"prefetch", prefetch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report, err := Carve(memory(tc.bytes), 0, ^uint64(0), DefaultCarveOptions())
			if err != nil {
				t.Fatalf("Carve: %v", err)
			}
			if len(report.Objects) != 0 {
				t.Fatalf("got %d objects, want none: %+v", len(report.Objects), report.Objects)
			}
			if report.Rejected != 1 {
				t.Fatalf("Rejected = %d, want 1", report.Rejected)
			}
		})
	}
}

func TestUnportedFormatsReturnErrUnsupported(t *testing.T) {
	jpeg := []byte{0xFF, 0xD8, 0xFF, 0xE0}
	png := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'}
	pdf := []byte("%PDF-1.7\n%%EOF\n")
	zip := []byte{'P', 'K', 0x03, 0x04, 0, 0, 0, 0}

	for name, bytes := range map[string][]byte{
		"jpeg": jpeg,
		"png":  png,
		"pdf":  pdf,
		"zip":  zip,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Carve(memory(bytes), 0, ^uint64(0), DefaultCarveOptions())
			if !errors.Is(err, ErrUnsupported) {
				t.Fatalf("err = %v, want ErrUnsupported", err)
			}
		})
	}
}

func TestObjectSizeLimitBoundsAnEndlessWalk(t *testing.T) {
	// A RIFF/WebP header that claims 3000 bytes; the walk may only cover 512.
	image := make([]byte, 4096)
	copy(image[0:4], []byte("RIFF"))
	image[4], image[5], image[6], image[7] = 0xB8, 0x0B, 0, 0 // 3000
	copy(image[8:12], []byte("WEBP"))

	options := CarveOptions{MaxObjectBytes: 512, MaxObjects: 16}
	report, err := Carve(memory(image), 0, ^uint64(0), options)
	if err != nil {
		t.Fatalf("Carve: %v", err)
	}
	if len(report.Objects) != 1 {
		t.Fatalf("got %d objects, want 1: %+v", len(report.Objects), report.Objects)
	}
	object := report.Objects[0]
	if object.Terminated {
		t.Fatalf("object is terminated, want a bounded walk")
	}
	if object.Len != 512 {
		t.Fatalf("Len = %d, want 512", object.Len)
	}
	if !report.Truncated {
		t.Fatalf("Truncated = false, want true")
	}
}

func TestObjectCapStopsThePass(t *testing.T) {
	var image []byte
	for i := 0; i < 4; i++ {
		image = append(image, makeBMP()...)
		image = append(image, filler(8)...)
	}
	options := CarveOptions{MaxObjectBytes: DefaultMaxObjectBytes, MaxObjects: 2}
	report, err := Carve(memory(image), 0, ^uint64(0), options)
	if err != nil {
		t.Fatalf("Carve: %v", err)
	}
	if len(report.Objects) != 2 {
		t.Fatalf("got %d objects, want 2", len(report.Objects))
	}
	if !report.Truncated {
		t.Fatalf("Truncated = false, want true")
	}
	for _, object := range report.Objects {
		if !object.Terminated {
			t.Fatalf("object %v is not terminated", object.Format)
		}
	}
}

func TestSearchStaysInsideTheRequestedRange(t *testing.T) {
	bmp := makeBMP()
	image := append(filler(100), bmp...)
	image = append(image, filler(100)...)

	// A range that ends inside the BMP reports the hit bounded by the range.
	report, err := Carve(memory(image), 100, 35, DefaultCarveOptions())
	if err != nil {
		t.Fatalf("Carve: %v", err)
	}
	if len(report.Objects) != 1 {
		t.Fatalf("got %d objects, want 1", len(report.Objects))
	}
	if report.Objects[0].Terminated {
		t.Fatalf("object is terminated, want truncated by the range")
	}
	if report.Objects[0].Len != 35 {
		t.Fatalf("Len = %d, want 35", report.Objects[0].Len)
	}
	if report.BytesScanned != 35 || report.Start != 100 {
		t.Fatalf("range = (%d, %d), want (100, 35)", report.Start, report.BytesScanned)
	}

	// A range that starts after the header reports nothing.
	report, err = Carve(memory(image), 170, 100, DefaultCarveOptions())
	if err != nil {
		t.Fatalf("Carve: %v", err)
	}
	if len(report.Objects) != 0 {
		t.Fatalf("got %d objects, want none", len(report.Objects))
	}
	if report.BytesScanned != 100 {
		t.Fatalf("BytesScanned = %d, want 100", report.BytesScanned)
	}

	// A range that starts past the source is a successful empty report.
	report, err = Carve(memory(image), 10000, 100, DefaultCarveOptions())
	if err != nil {
		t.Fatalf("Carve: %v", err)
	}
	if report.Start != uint64(len(image)) || report.BytesScanned != 0 {
		t.Fatalf("range = (%d, %d), want (%d, 0)", report.Start, report.BytesScanned, len(image))
	}
	if len(report.Objects) != 0 {
		t.Fatalf("got %d objects, want none", len(report.Objects))
	}

	// A zero-length range is empty too.
	report, err = Carve(memory(image), 0, 0, DefaultCarveOptions())
	if err != nil {
		t.Fatalf("Carve: %v", err)
	}
	if report.BytesScanned != 0 || len(report.Objects) != 0 {
		t.Fatalf("empty range scanned %d bytes and found %d objects", report.BytesScanned, len(report.Objects))
	}
}

func TestUnterminatedObjectDoesNotSwallowWhatFollows(t *testing.T) {
	// A truncated EVTX chunk (its 64 KiB extent is cut by the source bound)
	// with a complete BMP inside the bytes the walk did cover.
	chunk := makeEVTXChunk()[:2000]
	bmp := makeBMP()
	copy(chunk[1000:], bmp)

	report, err := Carve(memory(chunk), 0, ^uint64(0), DefaultCarveOptions())
	if err != nil {
		t.Fatalf("Carve: %v", err)
	}
	if len(report.Objects) != 2 {
		t.Fatalf("got %d objects, want 2: %+v", len(report.Objects), report.Objects)
	}
	if report.Objects[0].Format != FormatEvtxChunk || report.Objects[0].Terminated {
		t.Fatalf("first object = (%v, terminated=%v), want an unterminated EVTX chunk",
			report.Objects[0].Format, report.Objects[0].Terminated)
	}
	if report.Objects[1].Format != FormatBmp || !report.Objects[1].Terminated {
		t.Fatalf("second object = (%v, terminated=%v), want a terminated BMP",
			report.Objects[1].Format, report.Objects[1].Terminated)
	}
	if report.Objects[1].InsideOf != nil {
		t.Fatalf("BMP is inside_of %d; an unterminated guess must not claim an extent",
			*report.Objects[1].InsideOf)
	}
	if !report.Truncated {
		t.Fatalf("Truncated = false, want true")
	}
}

func TestObjectInsideATerminatedOneIsMarked(t *testing.T) {
	// A complete 64 KiB EVTX chunk whose unvalidated tail holds a complete BMP.
	chunk := makeEVTXChunk()
	bmp := makeBMP()
	copy(chunk[1000:], bmp)

	report, err := Carve(memory(chunk), 0, ^uint64(0), DefaultCarveOptions())
	if err != nil {
		t.Fatalf("Carve: %v", err)
	}
	if len(report.Objects) != 2 {
		t.Fatalf("got %d objects, want 2: %+v", len(report.Objects), report.Objects)
	}
	container, nested := report.Objects[0], report.Objects[1]
	if container.Format != FormatEvtxChunk || !container.Terminated {
		t.Fatalf("container = (%v, terminated=%v)", container.Format, container.Terminated)
	}
	if container.Offset != 0 || container.Len != testEVTXChunkLen {
		t.Fatalf("container extent = (%d, %d)", container.Offset, container.Len)
	}
	if nested.Format != FormatBmp || !nested.Terminated {
		t.Fatalf("nested = (%v, terminated=%v)", nested.Format, nested.Terminated)
	}
	if nested.InsideOf == nil || *nested.InsideOf != 0 {
		t.Fatalf("nested.InsideOf = %v, want 0", nested.InsideOf)
	}
	if top := report.TopLevel(); len(top) != 1 || top[0].Format != FormatEvtxChunk {
		t.Fatalf("TopLevel() = %+v, want just the EVTX chunk", top)
	}
}

func TestUnreadableBytesAreCountedAndSearchedAsZeros(t *testing.T) {
	data := append(makeBMP(), filler(4096-len(makeBMP()))...)
	src := &damagedSource{
		MemorySource: memory(data),
		badFrom:      1024,
		badTo:        2048,
	}

	report, err := Carve(src, 0, ^uint64(0), DefaultCarveOptions())
	if err != nil {
		t.Fatalf("Carve: %v", err)
	}
	if report.Unreadable != 1024 {
		t.Fatalf("Unreadable = %d, want 1024", report.Unreadable)
	}
	if len(report.Objects) != 1 || report.Objects[0].Format != FormatBmp {
		t.Fatalf("objects = %+v, want the leading BMP", report.Objects)
	}
}
