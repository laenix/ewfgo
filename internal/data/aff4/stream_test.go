package aff4

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func imageTurtle(uri, compression string, size, chunkSize, chunksPerSegment uint64) string {
	return turtleHeader + "<" + uri + "> a aff4:Image ;\n" +
		"    aff4:category aff4:imageStream ;\n" +
		"    aff4:size " + u64String(size) + " ;\n" +
		"    aff4:chunkSize " + u64String(chunkSize) + " ;\n" +
		"    aff4:chunksPerSegment " + u64String(chunksPerSegment) + " ;\n" +
		"    aff4:compressionMethod aff4:" + compression + " .\n"
}

func TestImageStoredMultiBevyAssembly(t *testing.T) {
	container := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(imageTurtle("aff4://image", "stored", 8, 4, 1))),
		store("image/00000000", []byte("ABCD")),
		store("image/00000001", []byte("EFGH")),
	), DefaultLimits())

	stream := openStream(t, container, "aff4://image")
	if stream.Kind() != KindImage || stream.StreamURI() != "aff4://image" || stream.Len() != 8 {
		t.Fatalf("stream = %s %s len=%d", stream.Kind(), stream.StreamURI(), stream.Len())
	}
	if got := string(readAll(t, stream, 0, 8)); got != "ABCDEFGH" {
		t.Fatalf("image bytes = %q", got)
	}

	chunks := stream.Chunks()
	if len(chunks) != 2 {
		t.Fatalf("chunks = %+v", chunks)
	}
	first, second := chunks[0], chunks[1]
	if first.Bevy != 0 || first.Member != "image/00000000" || first.MemberOffset != 0 ||
		first.StoredLen != 4 || first.LogicalOffset != 0 || first.LogicalLen != 4 || !first.ImageOffsetExact {
		t.Fatalf("chunk 0 = %+v", first)
	}
	if second.Bevy != 1 || second.Member != "image/00000001" || second.LogicalOffset != 4 {
		t.Fatalf("chunk 1 = %+v", second)
	}

	if chunk, ok := stream.ChunkAt(5); !ok || chunk.LogicalOffset != 4 {
		t.Fatalf("chunk at 5 = %+v, %v", chunk, ok)
	}
	if _, ok := stream.ChunkAt(8); ok {
		t.Fatal("chunk at 8 must not exist")
	}

	extents, err := stream.Extents(0, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 2 || extents[0].Kind != source.RangeData || extents[0].Len != 4 {
		t.Fatalf("extents = %+v", extents)
	}
	imageRanges, err := stream.MapToImage(0, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(imageRanges) != 2 || imageRanges[0].Kind != source.RangeData {
		t.Fatalf("image ranges = %+v", imageRanges)
	}
}

func TestImageStoredWithinOneBevy(t *testing.T) {
	container := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(imageTurtle("aff4://image", "stored", 8, 4, 2))),
		store("image/00000000", []byte("ABCDEFGH")),
	), DefaultLimits())
	stream := openStream(t, container, "aff4://image")
	if got := string(readAll(t, stream, 0, 8)); got != "ABCDEFGH" {
		t.Fatalf("image bytes = %q", got)
	}
	chunks := stream.Chunks()
	if len(chunks) != 2 || chunks[1].MemberOffset != 4 || chunks[1].Bevy != 0 {
		t.Fatalf("chunks = %+v", chunks)
	}
}

func TestImageZlibWithIndex(t *testing.T) {
	first := zlibCompress(t, []byte("ABCD"))
	second := zlibCompress(t, []byte("EFGH"))
	payload := append(append([]byte{}, first...), second...)
	container := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(imageTurtle("aff4://image", "zlib", 8, 4, 2))),
		store("image/00000000", payload),
		store("image.index", indexBytes([2]uint32{0, 0}, [2]uint32{0, uint32(len(first))})),
	), DefaultLimits())

	stream := openStream(t, container, "aff4://image")
	if got := string(readAll(t, stream, 0, 8)); got != "ABCDEFGH" {
		t.Fatalf("image bytes = %q", got)
	}
	chunks := stream.Chunks()
	if len(chunks) != 2 || chunks[0].StoredLen != uint64(len(first)) || chunks[1].StoredLen != uint64(len(second)) {
		t.Fatalf("chunks = %+v", chunks)
	}
	crcs, err := stream.MemberCRCs()
	if err != nil {
		t.Fatal(err)
	}
	if len(crcs) != 2 {
		t.Fatalf("member crcs = %+v", crcs)
	}
	for _, crc := range crcs {
		if !crc.Checked || crc.Matches == nil || !*crc.Matches {
			t.Fatalf("crc = %+v", crc)
		}
	}
}

func TestImageZeroCompression(t *testing.T) {
	container := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(imageTurtle("aff4://image", "zero", 8, 4, 2))),
		store("image/00000000", nil),
		store("image.index", indexBytes([2]uint32{0, 0}, [2]uint32{0, 0})),
	), DefaultLimits())
	stream := openStream(t, container, "aff4://image")
	if got := readAll(t, stream, 0, 8); !bytes.Equal(got, make([]byte, 8)) {
		t.Fatalf("zero image bytes = %v", got)
	}
	extents, err := stream.Extents(0, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 2 || extents[0].Kind != source.RangeZero || extents[1].Kind != source.RangeZero {
		t.Fatalf("extents = %+v", extents)
	}
}

func TestImageUnsupportedCodecsAreRefusedByName(t *testing.T) {
	for _, codec := range []string{"snappy", "lz4"} {
		t.Run(codec, func(t *testing.T) {
			container := openArchive(t, buildArchive(t,
				store(ContainerDescription, []byte("AFF4-1.0\n")),
				store(InformationTurtle, []byte(imageTurtle("aff4://image", codec, 4, 4, 1))),
			), DefaultLimits())
			_, err := container.OpenStream("aff4://image")
			if !errors.Is(err, source.ErrUnsupported) || !strings.Contains(err.Error(), codec) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestImageMissingBevyIsNamed(t *testing.T) {
	container := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(imageTurtle("aff4://image", "stored", 4, 4, 1))),
	), DefaultLimits())
	_, err := container.OpenStream("aff4://image")
	if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "image/00000000") {
		t.Fatalf("error = %v", err)
	}
}

func TestImageMissingAndShortIndex(t *testing.T) {
	compressed := imageTurtle("aff4://image", "zlib", 8, 4, 2)
	missing := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(compressed)),
		store("image/00000000", zlibCompress(t, []byte("ABCDEFGH"))),
	), DefaultLimits())
	if _, err := missing.OpenStream("aff4://image"); !errors.Is(err, source.ErrCorrupt) ||
		!strings.Contains(err.Error(), ".index") {
		t.Fatalf("missing index error = %v", err)
	}

	short := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(compressed)),
		store("image/00000000", zlibCompress(t, []byte("ABCDEFGH"))),
		store("image.index", indexBytes([2]uint32{0, 0})),
	), DefaultLimits())
	if _, err := short.OpenStream("aff4://image"); !errors.Is(err, source.ErrCorrupt) ||
		!strings.Contains(err.Error(), "needs") {
		t.Fatalf("short index error = %v", err)
	}
}

func TestImageIndexValidation(t *testing.T) {
	meta := store(InformationTurtle, []byte(imageTurtle("aff4://image", "zlib", 8, 4, 2)))
	desc := store(ContainerDescription, []byte("AFF4-1.0\n"))
	payload := store("image/00000000", zlibCompress(t, []byte("ABCDEFGH")))

	t.Run("bad bevy", func(t *testing.T) {
		container := openArchive(t, buildArchive(t, desc, meta, payload,
			store("image.index", indexBytes([2]uint32{1, 0}, [2]uint32{1, 0}))), DefaultLimits())
		_, err := container.OpenStream("aff4://image")
		if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "bevy 1") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("out of order", func(t *testing.T) {
		container := openArchive(t, buildArchive(t, desc, meta, payload,
			store("image.index", indexBytes([2]uint32{0, 4}, [2]uint32{0, 0}))), DefaultLimits())
		_, err := container.OpenStream("aff4://image")
		if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "precedes") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("out of range", func(t *testing.T) {
		container := openArchive(t, buildArchive(t, desc, meta, store("image/00000000", []byte{0x78}),
			store("image.index", indexBytes([2]uint32{0, 100}, [2]uint32{0, 100}))), DefaultLimits())
		_, err := container.OpenStream("aff4://image")
		if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "past") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestImageChunkDecodeAndLengthErrors(t *testing.T) {
	limits := DefaultLimits()

	mismatch := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(imageTurtle("aff4://image", "zlib", 4, 4, 1))),
		store("image/00000000", zlibCompress(t, []byte("ABC"))),
		store("image.index", indexBytes([2]uint32{0, 0})),
	), limits)
	mismatchStream, err := mismatch.OpenStream("aff4://image")
	if err != nil {
		t.Fatalf("OpenStream error = %v", err)
	}
	if _, err := mismatchStream.ReadAt(0, make([]byte, 4)); !errors.Is(err, source.ErrCorrupt) ||
		!strings.Contains(err.Error(), "geometry declares") {
		t.Fatalf("chunk length error = %v", err)
	}

	tooMany := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(imageTurtle("aff4://image", "stored", 8, 4, 1))),
	), limits)
	tooMany.limits.MaxChunks = 1
	if _, err := tooMany.OpenStream("aff4://image"); !errors.Is(err, ErrLimit) {
		t.Fatalf("chunk cap error = %v", err)
	}
}

func TestImageMissingProperties(t *testing.T) {
	cases := []struct {
		name  string
		text  string
		field string
	}{
		{
			name:  "no size",
			text:  turtleHeader + `<aff4://image> a aff4:Image ; aff4:chunkSize 4 ; aff4:chunksPerSegment 1 ; aff4:compressionMethod aff4:stored .`,
			field: "aff4:size",
		},
		{
			name:  "zero chunk size",
			text:  turtleHeader + `<aff4://image> a aff4:Image ; aff4:size 4 ; aff4:chunkSize 0 ; aff4:chunksPerSegment 1 ; aff4:compressionMethod aff4:stored .`,
			field: "aff4:chunkSize",
		},
		{
			name:  "zero chunks per segment",
			text:  turtleHeader + `<aff4://image> a aff4:Image ; aff4:size 4 ; aff4:chunkSize 4 ; aff4:chunksPerSegment 0 ; aff4:compressionMethod aff4:stored .`,
			field: "aff4:chunksPerSegment",
		},
		{
			name:  "no compression",
			text:  turtleHeader + `<aff4://image> a aff4:Image ; aff4:size 4 ; aff4:chunkSize 4 ; aff4:chunksPerSegment 1 .`,
			field: "aff4:compressionMethod",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			container := openArchive(t, buildArchive(t,
				store(ContainerDescription, []byte("AFF4-1.0\n")),
				store(InformationTurtle, []byte(tc.text)),
			), DefaultLimits())
			_, err := container.OpenStream("aff4://image")
			if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestImageMemberCRCMismatchIsReported(t *testing.T) {
	payload := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	archive := buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(turtleHeader+
			`<aff4://image> a aff4:Image ; aff4:size 4 ; aff4:chunkSize 4 ; aff4:chunksPerSegment 1 ; aff4:compressionMethod aff4:stored ; hash:SHA1 "abcd" .`)),
		store("image/00000000", payload),
	)
	index := bytes.Index(archive, payload)
	if index < 0 {
		t.Fatal("payload not found")
	}
	archive[index] = 0x00

	container := openArchive(t, archive, DefaultLimits())
	stream := openStream(t, container, "aff4://image")
	if got := readAll(t, stream, 0, 4); !bytes.Equal(got, []byte{0x00, 0xBB, 0xCC, 0xDD}) {
		t.Fatalf("decoded bytes = %v", got)
	}
	crcs, err := stream.MemberCRCs()
	if err != nil {
		t.Fatal(err)
	}
	if len(crcs) != 1 || !crcs[0].Checked || crcs[0].Matches == nil || *crcs[0].Matches {
		t.Fatalf("crcs = %+v", crcs)
	}
	hashes := stream.DeclaredHashes()
	if len(hashes) != 1 || hashes[0].Algorithm != "SHA1" || hashes[0].Verified {
		t.Fatalf("hashes = %+v", hashes)
	}
}

func mapTurtle(mapURI string, targets []string, dataStream string, size uint64) string {
	text := turtleHeader + "<" + mapURI + "> a aff4:Map ;\n" +
		"    aff4:category aff4:map ;\n" +
		"    aff4:size " + u64String(size) + " ;\n"
	for _, target := range targets {
		text += "    aff4:target <" + target + "> ;\n"
	}
	if dataStream != "" {
		text += "    aff4:dataStream <" + dataStream + "> .\n"
	} else {
		text = strings.TrimSuffix(text, " ;\n") + " .\n"
	}
	return text
}

func mapFixture(targets ...string) string {
	text := turtleHeader
	for _, uri := range targets {
		text += "<" + uri + "> a aff4:Image ;\n" +
			"    aff4:category aff4:imageStream ;\n" +
			"    aff4:size 4 ; aff4:chunkSize 4 ; aff4:chunksPerSegment 1 ;\n" +
			"    aff4:compressionMethod aff4:stored .\n"
	}
	return text
}

func TestMapJoinsTargetsInOrder(t *testing.T) {
	turtle := mapFixture("aff4://a", "aff4://b") +
		mapTurtle("aff4://map", []string{"aff4://a", "aff4://b"}, "", 8)
	container := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(turtle)),
		store("a/00000000", []byte("AAAA")),
		store("b/00000000", []byte("BBBB")),
		store("map.map", mapBytes([2]uint64{0, 4}, [2]uint64{4, 4})),
	), DefaultLimits())

	stream := openStream(t, container, "aff4://map")
	if stream.Kind() != KindMap || stream.Len() != 8 {
		t.Fatalf("stream = %s len=%d", stream.Kind(), stream.Len())
	}
	if got := string(readAll(t, stream, 0, 8)); got != "AAAABBBB" {
		t.Fatalf("map bytes = %q", got)
	}
	if len(stream.Chunks()) != 0 {
		t.Fatalf("map chunks = %+v", stream.Chunks())
	}
	extents, err := stream.Extents(0, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 2 || extents[0].Kind != source.RangeData {
		t.Fatalf("extents = %+v", extents)
	}
	ranges, err := stream.MapToImage(0, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 2 {
		t.Fatalf("image ranges = %+v", ranges)
	}
}

func TestMapDependentStreamsAppendAfterTargets(t *testing.T) {
	turtle := mapFixture("aff4://a", "aff4://b") +
		turtleHeader + "<aff4://map> a aff4:Map ;\n" +
		"    aff4:category aff4:map ;\n" +
		"    aff4:size 8 ;\n" +
		"    aff4:target <aff4://a> ;\n" +
		"    aff4:dependentStream <aff4://b> .\n"
	container := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(turtle)),
		store("a/00000000", []byte("AAAA")),
		store("b/00000000", []byte("BBBB")),
		store("map.map", mapBytes([2]uint64{0, 4}, [2]uint64{4, 4})),
	), DefaultLimits())
	stream := openStream(t, container, "aff4://map")
	if got := string(readAll(t, stream, 0, 8)); got != "AAAABBBB" {
		t.Fatalf("map bytes = %q", got)
	}
}

func TestMapValidationErrors(t *testing.T) {
	base := func(t *testing.T, turtle string, extra ...zipMember) *Container {
		members := []zipMember{
			store(ContainerDescription, []byte("AFF4-1.0\n")),
			store(InformationTurtle, []byte(turtle)),
			store("a/00000000", []byte("AAAA")),
		}
		members = append(members, extra...)
		return openArchive(t, buildArchive(t, members...), DefaultLimits())
	}
	targetTurtle := mapFixture("aff4://a")

	t.Run("without target", func(t *testing.T) {
		container := base(t, turtleHeader+"<aff4://map> a aff4:Map ; aff4:size 0 .\n")
		if _, err := container.OpenStream("aff4://map"); !errors.Is(err, source.ErrCorrupt) ||
			!strings.Contains(err.Error(), "no target") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("missing data stream", func(t *testing.T) {
		container := base(t, targetTurtle+mapTurtle("aff4://map", []string{"aff4://a"}, "", 4))
		if _, err := container.OpenStream("aff4://map"); !errors.Is(err, source.ErrCorrupt) ||
			!strings.Contains(err.Error(), "no readable map entry stream") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("entry out of range", func(t *testing.T) {
		container := base(t, targetTurtle+mapTurtle("aff4://map", []string{"aff4://a"}, "", 4),
			store("map.map", mapBytes([2]uint64{0, 8})))
		if _, err := container.OpenStream("aff4://map"); !errors.Is(err, source.ErrCorrupt) ||
			!strings.Contains(err.Error(), "past") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("entry crosses target", func(t *testing.T) {
		turtle := mapFixture("aff4://a", "aff4://b") +
			mapTurtle("aff4://map", []string{"aff4://a", "aff4://b"}, "", 8)
		container := base(t, turtle, store("b/00000000", []byte("BBBB")),
			store("map.map", mapBytes([2]uint64{2, 4})))
		if _, err := container.OpenStream("aff4://map"); !errors.Is(err, source.ErrCorrupt) ||
			!strings.Contains(err.Error(), "crosses") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("size mismatch", func(t *testing.T) {
		container := base(t, targetTurtle+mapTurtle("aff4://map", []string{"aff4://a"}, "", 7),
			store("map.map", mapBytes([2]uint64{0, 4})))
		if _, err := container.OpenStream("aff4://map"); !errors.Is(err, source.ErrCorrupt) ||
			!strings.Contains(err.Error(), "declares 7") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("truncated entry", func(t *testing.T) {
		container := base(t, targetTurtle+mapTurtle("aff4://map", []string{"aff4://a"}, "", 4),
			store("map.map", []byte{0, 0, 0, 0, 4, 0, 0, 0, 0}))
		if _, err := container.OpenStream("aff4://map"); !errors.Is(err, source.ErrCorrupt) ||
			!strings.Contains(err.Error(), "truncated") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestMapCycleAndDepth(t *testing.T) {
	cycle := turtleHeader +
		"<aff4://m1> a aff4:Map ; aff4:size 4 ; aff4:target <aff4://m2> .\n" +
		"<aff4://m2> a aff4:Map ; aff4:size 4 ; aff4:target <aff4://m1> .\n"
	container := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(cycle)),
	), DefaultLimits())
	if _, err := container.OpenStream("aff4://m1"); !errors.Is(err, source.ErrCorrupt) ||
		!strings.Contains(err.Error(), "cycle") {
		t.Fatalf("cycle error = %v", err)
	}

	limits := DefaultLimits()
	limits.MaxMapDepth = 0
	deep := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(cycle)),
	), limits)
	if _, err := deep.OpenStream("aff4://m1"); !errors.Is(err, ErrLimit) {
		t.Fatalf("depth error = %v", err)
	}
}

func TestMapDataStreamCanBeARecognizedStream(t *testing.T) {
	turtle := mapFixture("aff4://a") +
		turtleHeader +
		"<aff4://data> a aff4:ZipSegment ; aff4:stored <aff4://data-bytes> .\n" +
		mapTurtle("aff4://map", []string{"aff4://a"}, "aff4://data", 4)
	container := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(turtle)),
		store("a/00000000", []byte("AAAA")),
		store("data-bytes", mapBytes([2]uint64{0, 4})),
	), DefaultLimits())
	stream := openStream(t, container, "aff4://map")
	if got := string(readAll(t, stream, 0, 4)); got != "AAAA" {
		t.Fatalf("map bytes = %q", got)
	}
}

func TestZeroStream(t *testing.T) {
	container := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(turtleHeader+`<aff4://z> a aff4:Zero ; aff4:size 16 .`)),
	), DefaultLimits())
	stream := openStream(t, container, "aff4://z")
	if stream.Kind() != KindZero || stream.Len() != 16 {
		t.Fatalf("stream = %s len=%d", stream.Kind(), stream.Len())
	}
	if got := readAll(t, stream, 0, 16); !bytes.Equal(got, make([]byte, 16)) {
		t.Fatalf("zero bytes = %v", got)
	}
	extents, err := stream.Extents(0, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 1 || extents[0].Kind != source.RangeZero || extents[0].Len != 16 {
		t.Fatalf("extents = %+v", extents)
	}
}

func TestSegmentStream(t *testing.T) {
	turtle := turtleHeader + `<aff4://seg> a aff4:ZipSegment ; aff4:stored <aff4://seg-data> .`
	container := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(turtle)),
		store("seg-data", []byte("segment-bytes")),
	), DefaultLimits())
	stream := openStream(t, container, "aff4://seg")
	if stream.Kind() != KindSegment || stream.Len() != uint64(len("segment-bytes")) {
		t.Fatalf("stream = %s len=%d", stream.Kind(), stream.Len())
	}
	if got := string(readAll(t, stream, 0, stream.Len())); got != "segment-bytes" {
		t.Fatalf("segment bytes = %q", got)
	}
	extents, err := stream.Extents(2, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 1 || extents[0].Kind != source.RangeData || extents[0].Len != 4 {
		t.Fatalf("extents = %+v", extents)
	}
}

func TestFileImageIsRefused(t *testing.T) {
	container := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(turtleHeader+`<aff4://file> a aff4:FileImage ; aff4:size 4 .`)),
	), DefaultLimits())
	_, err := container.OpenStream("aff4://file")
	if !errors.Is(err, source.ErrUnsupported) || !strings.Contains(err.Error(), "FileImage") {
		t.Fatalf("error = %v", err)
	}
}

func TestReadRangeAndLossy(t *testing.T) {
	container := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(imageTurtle("aff4://image", "stored", 8, 4, 1))),
		store("image/00000000", []byte("ABCD")),
		store("image/00000001", []byte("EFGH")),
	), DefaultLimits())
	stream := openStream(t, container, "aff4://image")

	if n, err := stream.ReadAt(0, nil); n != 0 || err != nil {
		t.Fatalf("empty read = %d, %v", n, err)
	}
	if _, err := stream.ReadAt(8, make([]byte, 4)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("out of range error = %v", err)
	}
	buf := make([]byte, 4)
	if n, err := stream.ReadAt(6, buf); err != nil || n != 2 || string(buf[:n]) != "GH" {
		t.Fatalf("short read = %d, %v, %q", n, err, buf[:n])
	}

	// A corrupt zlib chunk makes the strict read fail and the lossy read
	// zero-fill while accounting for the damaged bytes.
	corrupt := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(imageTurtle("aff4://image", "zlib", 4, 4, 1))),
		store("image/00000000", []byte{0xde, 0xad, 0xbe, 0xef}),
		store("image.index", indexBytes([2]uint32{0, 0})),
	), DefaultLimits())
	bad := openStream(t, corrupt, "aff4://image")
	if _, err := bad.ReadAt(0, make([]byte, 4)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("corrupt read error = %v", err)
	}
	lossy := make([]byte, 4)
	if n, err := bad.ReadAtLossy(0, lossy); err != nil || n != 4 || !bytes.Equal(lossy, make([]byte, 4)) {
		t.Fatalf("lossy read = %d, %v, %v", n, err, lossy)
	}
	if bad.Stats().CorruptBytes == 0 {
		t.Fatal("lossy read did not count corrupt bytes")
	}
}

func TestStreamFactsAndSourceIdentity(t *testing.T) {
	root := source.NewMemorySourceWithImage(7, 42, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(storedImageTurtle("aff4://image", 4, 4, 1))),
		store("image/00000000", []byte("DATA")),
	))
	container, err := Open(root, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	stream, err := container.Image()
	if err != nil {
		t.Fatal(err)
	}
	if stream.ImageID() != 42 || stream.SectorSize() != root.SectorSize() {
		t.Fatalf("identity = image %d sector %d", stream.ImageID(), stream.SectorSize())
	}
	if stream.SourceID() == root.SourceID() {
		t.Fatal("stream source id collides with the container source")
	}
	if stream.Facts().Version != "1.0" {
		t.Fatalf("facts version = %q", stream.Facts().Version)
	}
	if stream.IsEmpty() {
		t.Fatal("non-empty stream reported empty")
	}
}
