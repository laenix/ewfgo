package aff4

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func TestImageIndexExpectedSizeMismatchIsReported(t *testing.T) {
	container := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(imageTurtle("aff4://image", "zlib", 8, 4, 2))),
		store("image.index", make([]byte, 8)),
	), DefaultLimits())
	facts := container.Facts()
	if len(facts.Images) != 1 {
		t.Fatalf("images = %+v", facts.Images)
	}
	var index MemberCheck
	for _, check := range facts.Images[0].Checks {
		if check.Role == RoleIndex {
			index = check
		}
	}
	if index.ExpectedSize == nil || *index.ExpectedSize != 16 ||
		index.Size == nil || *index.Size != 8 ||
		index.SizeMatches == nil || *index.SizeMatches {
		t.Fatalf("index check = %+v", index)
	}
}

func TestZeroAndSegmentMissingProperties(t *testing.T) {
	zero := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(turtleHeader+`<aff4://z> a aff4:Zero .`)),
	), DefaultLimits())
	if _, err := zero.OpenStream("aff4://z"); !errors.Is(err, source.ErrCorrupt) ||
		!strings.Contains(err.Error(), "aff4:size") {
		t.Fatalf("zero error = %v", err)
	}

	segment := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(turtleHeader+`<aff4://s> a aff4:ZipSegment ; aff4:stored <aff4://absent> .`)),
	), DefaultLimits())
	if _, err := segment.OpenStream("aff4://s"); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("segment error = %v", err)
	}
}

func TestMapAmbiguousAndOversizedData(t *testing.T) {
	image := mapFixture("aff4://a")

	t.Run("ambiguous data stream", func(t *testing.T) {
		turtle := image + turtleHeader +
			"<aff4://map> a aff4:Map ; aff4:size 4 ; aff4:target <aff4://a> ;\n" +
			"    aff4:stored <aff4://a> ; aff4:dataStream <aff4://b> .\n"
		container := openArchive(t, buildArchive(t,
			store(ContainerDescription, []byte("AFF4-1.0\n")),
			store(InformationTurtle, []byte(turtle)),
			store("a/00000000", []byte("AAAA")),
		), DefaultLimits())
		if _, err := container.OpenStream("aff4://map"); !errors.Is(err, source.ErrCorrupt) ||
			!strings.Contains(err.Error(), "data stream") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("map data too large", func(t *testing.T) {
		turtle := image + mapTurtle("aff4://map", []string{"aff4://a"}, "", 4)
		limits := DefaultLimits()
		limits.MaxMapBytes = 4
		container := openArchive(t, buildArchive(t,
			store(ContainerDescription, []byte("AFF4-1.0\n")),
			store(InformationTurtle, []byte(turtle)),
			store("a/00000000", []byte("AAAA")),
			store("map.map", mapBytes([2]uint64{0, 4})),
		), limits)
		if _, err := container.OpenStream("aff4://map"); !errors.Is(err, ErrLimit) {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("too many map entries", func(t *testing.T) {
		turtle := image + mapTurtle("aff4://map", []string{"aff4://a"}, "", 4)
		limits := DefaultLimits()
		limits.MaxMapEntries = 0
		container := openArchive(t, buildArchive(t,
			store(ContainerDescription, []byte("AFF4-1.0\n")),
			store(InformationTurtle, []byte(turtle)),
			store("a/00000000", []byte("AAAA")),
			store("map.map", mapBytes([2]uint64{0, 4})),
		), limits)
		if _, err := container.OpenStream("aff4://map"); !errors.Is(err, ErrLimit) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestChunkSizeAllocationLimit(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxChunkBytes = 2
	container := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(imageTurtle("aff4://image", "stored", 4, 4, 1))),
	), limits)
	if _, err := container.OpenStream("aff4://image"); !errors.Is(err, ErrLimit) {
		t.Fatalf("error = %v", err)
	}
}

func TestSampleIsBounded(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxSampleEntries = 1
	container := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(turtleHeader)),
	), limits)
	if len(container.Facts().Sample) != 1 {
		t.Fatalf("sample = %+v", container.Facts().Sample)
	}
}

func TestTurtleEscapesAndDatatypes(t *testing.T) {
	text := turtleHeader + `<aff4://x> a aff4:Image ;
    aff4:size 4 ; aff4:chunkSize 4 ; aff4:chunksPerSegment 1 ;
    aff4:compressionMethod "zlib" ;
    hash:SHA1 "a\tb" ;
    hash:SHA1 "A" .
`
	parsed := mustParseTurtle(t, text, DefaultLimits())
	if len(parsed.streams) != 1 {
		t.Fatalf("streams = %+v", parsed.streams)
	}
	stream := parsed.streams[0]
	if stream.Compression != "zlib" {
		t.Fatalf("compression = %q", stream.Compression)
	}
	if len(stream.Hashes) != 2 || stream.Hashes[0].ValueLen != 3 || stream.Hashes[1].ValueLen != 1 {
		t.Fatalf("hashes = %+v", stream.Hashes)
	}

	escaping := mustParseTurtle(t, turtleHeader+`<aff4://x/a> aff4:version "1.0" .`, DefaultLimits())
	if escaping.version != "1.0" {
		t.Fatalf("version = %q", escaping.version)
	}

	if _, err := parseTurtle("information.turtle",
		turtleHeader+`<aff4://x\q> a aff4:Image .`, DefaultLimits()); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("IRI escape error = %v", err)
	}
	if _, err := parseTurtle("information.turtle",
		turtleHeader+`<aff4://x> a aff4:Image ; aff4:compressionMethod "zlib"^^foo .`, DefaultLimits()); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("datatype error = %v", err)
	}
	if _, err := parseTurtle("information.turtle",
		turtleHeader+`<aff4://x> a aff4:Image ; aff4:compressionMethod "zlib"@ .`, DefaultLimits()); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("language tag error = %v", err)
	}
}

func TestTurtleLanguageTagAndDefaultPrefix(t *testing.T) {
	text := turtleHeader + `@prefix : <urn:default:> .
<aff4://x> a aff4:Image ; aff4:size 4 ; aff4:chunkSize 4 ; aff4:chunksPerSegment 1 ;
    aff4:compressionMethod "zlib"@en .
:v aff4:version "1.0" .
`
	parsed := mustParseTurtle(t, text, DefaultLimits())
	if parsed.version != "1.0" {
		t.Fatalf("version = %q", parsed.version)
	}
	if parsed.streams[0].Compression != "zlib" {
		t.Fatalf("compression = %q", parsed.streams[0].Compression)
	}

	if _, err := parseTurtle("information.turtle", turtleHeader+`:v aff4:version "1.0" .`,
		DefaultLimits()); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("default prefix error = %v", err)
	}
}

func TestYAMLAliasesAndValueErrors(t *testing.T) {
	text := "version: \"1.0\"\nstreams:\n" +
		"  - uri: \"aff4://m\"\n    class: Map\n    category: map\n    size: 4\n" +
		"    dependent_stream: \"aff4://img\"\n    data_stream: \"aff4://m-data\"\n" +
		"  - uri: \"aff4://img\"\n    class: ImageStream\n    category: imageStream\n" +
		"    size: 4\n    chunk_size: 4\n    chunks_per_segment: 1\n    compression_method: stored\n"
	parsed, err := parseYAML(InformationYAML, text, DefaultLimits())
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(parsed.streams) != 2 || parsed.mapStreams != 1 || parsed.imageStreams != 1 {
		t.Fatalf("streams = %+v", parsed.streams)
	}
	var image, yamlMap Stream
	for _, stream := range parsed.streams {
		if stream.IsImage() {
			image = stream
		}
		if stream.IsMap() {
			yamlMap = stream
		}
	}
	if image.Compression != "stored" || image.ChunkSize == nil || *image.ChunkSize != 4 ||
		image.ChunksPerSegment == nil || *image.ChunksPerSegment != 1 {
		t.Fatalf("image = %+v", image)
	}
	if len(yamlMap.DependentStreams) != 1 || yamlMap.DataStream != "aff4://m-data" {
		t.Fatalf("map = %+v", yamlMap)
	}

	for _, bad := range []string{
		"streams:\n  - uri: \"aff4://x\"\n    hash: no-colon\n",
		"streams:\n  - uri: \"aff4://x\"\n    size: -1\n",
		"streams:\n  - uri: \"aff4://x\"\n    type: Unknown\n",
	} {
		parsed, err := parseYAML(InformationYAML, bad, DefaultLimits())
		if bad == "streams:\n  - uri: \"aff4://x\"\n    type: Unknown\n" {
			if err != nil || parsed.ignoredPredicateCount != 1 {
				t.Fatalf("unknown type: err=%v ignored=%d", err, parsed.ignoredPredicateCount)
			}
			continue
		}
		if !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("%q: error = %v", bad, err)
		}
	}
}

func TestTurtleUnicodeEscapes(t *testing.T) {
	bs := string(rune(92))
	text := turtleHeader + `<aff4://x> a aff4:Image ;
    aff4:size 4 ; aff4:chunkSize 4 ; aff4:chunksPerSegment 1 ;
    aff4:compressionMethod "zli` + bs + `u0062" ;
    hash:SHA1 "` + bs + `U0000007A" .
`
	parsed := mustParseTurtle(t, text, DefaultLimits())
	if len(parsed.streams) != 1 {
		t.Fatalf("streams = %+v", parsed.streams)
	}
	if parsed.streams[0].Compression != "zlib" {
		t.Fatalf("compression = %q", parsed.streams[0].Compression)
	}
	if len(parsed.streams[0].Hashes) != 1 || parsed.streams[0].Hashes[0].ValueLen != 1 {
		t.Fatalf("hashes = %+v", parsed.streams[0].Hashes)
	}

	iri := turtleHeader + "<aff4://x/" + bs + "u0061> aff4:version \"1.0\" ."
	parsed = mustParseTurtle(t, iri, DefaultLimits())
	if parsed.version != "1.0" {
		t.Fatalf("version = %q", parsed.version)
	}
}

func TestLabelFallbacks(t *testing.T) {
	if (Stream{Category: "map"}).ClassLabel() != "map" {
		t.Fatal("class label did not fall back to the category")
	}
	if (Stream{}).ClassLabel() != "unknown" {
		t.Fatal("empty class label is not unknown")
	}
	for _, codec := range []compression{compressionStored, compressionZero, compressionZlib,
		compressionSnappy, compressionLz4} {
		if codec.String() == "unknown" {
			t.Fatalf("codec %d has no label", codec)
		}
	}
	if compression(200).String() != "unknown" {
		t.Fatal("unknown codec is not labelled")
	}
}

func TestCompressionLabelsAndKindStrings(t *testing.T) {
	cases := []struct {
		label string
		want  compression
		ok    bool
	}{
		{"stored", compressionStored, true},
		{"none", compressionStored, true},
		{"STORED", compressionStored, true},
		{"aff4:zero", compressionZero, true},
		{"zlib", compressionZlib, true},
		{"snappy", compressionSnappy, true},
		{"lz4", compressionLz4, true},
		{"http://aff4.org/Schema#zlib", compressionZlib, true},
		{"brotli", 0, false},
	}
	for _, tc := range cases {
		got, ok := parseCompression(tc.label)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Fatalf("parseCompression(%q) = %v, %v", tc.label, got, ok)
		}
	}
	if compressionSnappy.hasDecoder() || compressionLz4.hasDecoder() || !compressionZlib.hasDecoder() {
		t.Fatal("decoder availability is wrong")
	}
	for _, kind := range []StreamKind{KindImage, KindMap, KindZero, KindSegment} {
		if kind.String() == "unknown" {
			t.Fatalf("kind %d has no label", kind)
		}
	}
	for _, kind := range []DescriptorKind{DescriptorContainerDescription, DescriptorTurtle, DescriptorYaml} {
		if kind.String() == "unknown" {
			t.Fatalf("descriptor kind %d has no label", kind)
		}
	}
	for _, role := range []StreamRole{RoleImage, RoleMap, RoleZero, RoleIndex} {
		if role.String() == "unknown" {
			t.Fatalf("role %d has no label", role)
		}
	}
}

func TestURIBasesAndCandidateForms(t *testing.T) {
	bases := uriBases("aff4://image")
	for _, want := range []string{"aff4://image", "aff4:/image", "image"} {
		if !containsString(bases, want) {
			t.Fatalf("uriBases(aff4://image) = %v missing %q", bases, want)
		}
	}
	bases = uriBases("aff4:image")
	for _, want := range []string{"aff4:image", "image"} {
		if !containsString(bases, want) {
			t.Fatalf("uriBases(aff4:image) = %v missing %q", bases, want)
		}
	}
	if containsString(bases, "aff4:/image") {
		t.Fatalf("uriBases(aff4:image) invented a normalized form: %v", bases)
	}
	if bases := uriBases("other://x"); len(bases) != 1 || bases[0] != "other://x" {
		t.Fatalf("other bases = %v", bases)
	}
	bevies := bevyCandidates("aff4://image", 3)
	if !containsString(bevies, "image/00000003") || !containsString(bevies, "aff4://image/00000003") {
		t.Fatalf("bevy candidates = %v", bevies)
	}
	suffix := suffixMemberCandidates("aff4://image", []string{".index"})
	for _, candidate := range suffix {
		if candidate == "image" || candidate == "aff4://image" {
			t.Fatalf("suffix candidates include the bare URI: %v", suffix)
		}
	}
	if !containsString(suffix, "image.index") {
		t.Fatalf("suffix candidates = %v", suffix)
	}
	streamCandidates := streamMemberCandidates("aff4://map", []string{".map"})
	if !containsString(streamCandidates, "map") || !containsString(streamCandidates, "map.map") {
		t.Fatalf("stream candidates = %v", streamCandidates)
	}
}

func TestMemberCRCsForSegmentAndMap(t *testing.T) {
	segment := openStream(t, openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(turtleHeader+`<aff4://seg> a aff4:ZipSegment ; aff4:stored <aff4://seg-data> .`)),
		store("seg-data", []byte("segment-bytes")),
	), DefaultLimits()), "aff4://seg")
	crcs, err := segment.MemberCRCs()
	if err != nil {
		t.Fatal(err)
	}
	if len(crcs) != 1 || crcs[0].Member != "seg-data" || crcs[0].Recorded == nil {
		t.Fatalf("segment crcs = %+v", crcs)
	}

	turtle := mapFixture("aff4://a", "aff4://b") +
		mapTurtle("aff4://map", []string{"aff4://a", "aff4://b"}, "", 8)
	mapped := openStream(t, openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(turtle)),
		store("a/00000000", []byte("AAAA")),
		store("b/00000000", []byte("BBBB")),
		store("map.map", mapBytes([2]uint64{0, 4}, [2]uint64{4, 4})),
	), DefaultLimits()), "aff4://map")
	crcs, err = mapped.MemberCRCs()
	if err != nil {
		t.Fatal(err)
	}
	if len(crcs) != 3 {
		t.Fatalf("map crcs = %+v", crcs)
	}
}

func TestNestedMapResolution(t *testing.T) {
	turtle := mapFixture("aff4://a") +
		mapTurtle("aff4://inner", []string{"aff4://a"}, "", 4) +
		mapTurtle("aff4://outer", []string{"aff4://inner"}, "", 4)
	container := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(turtle)),
		store("a/00000000", []byte("AAAA")),
		store("inner.map", mapBytes([2]uint64{0, 4})),
		store("outer.map", mapBytes([2]uint64{0, 4})),
	), DefaultLimits())
	outer := openStream(t, container, "aff4://outer")
	if outer.Kind() != KindMap || outer.Len() != 4 {
		t.Fatalf("outer = %s len=%d", outer.Kind(), outer.Len())
	}
	if got := string(readAll(t, outer, 0, 4)); got != "AAAA" {
		t.Fatalf("outer bytes = %q", got)
	}
	crcs, err := outer.MemberCRCs()
	if err != nil {
		t.Fatal(err)
	}
	if len(crcs) != 3 {
		t.Fatalf("nested map crcs = %+v", crcs)
	}
}

func TestConcurrentChunkReads(t *testing.T) {
	first := zlibCompress(t, []byte("ABCD"))
	second := zlibCompress(t, []byte("EFGH"))
	payload := append(append([]byte{}, first...), second...)
	stream := openStream(t, openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(imageTurtle("aff4://image", "zlib", 8, 4, 2))),
		store("image/00000000", payload),
		store("image.index", indexBytes([2]uint32{0, 0}, [2]uint32{0, uint32(len(first))})),
	), DefaultLimits()), "aff4://image")

	var wg sync.WaitGroup
	for index := 0; index < 16; index++ {
		wg.Add(1)
		go func(offset uint64, want string) {
			defer wg.Done()
			buf := make([]byte, 4)
			if _, err := stream.ReadAt(offset, buf); err != nil {
				t.Errorf("ReadAt(%d) error = %v", offset, err)
				return
			}
			if string(buf) != want {
				t.Errorf("ReadAt(%d) = %q, want %q", offset, buf, want)
			}
			if _, err := stream.MemberCRCs(); err != nil {
				t.Errorf("MemberCRCs error = %v", err)
			}
		}(uint64(index%2)*4, []string{"ABCD", "EFGH"}[index%2])
	}
	wg.Wait()
}

func TestStreamRangeErrorsAndZeroImageRanges(t *testing.T) {
	container := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(imageTurtle("aff4://image", "stored", 8, 4, 1))),
		store("image/00000000", []byte("ABCD")),
		store("image/00000001", []byte("EFGH")),
	), DefaultLimits())
	stream := openStream(t, container, "aff4://image")
	if _, err := stream.Extents(7, 2); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("extents error = %v", err)
	}
	if _, err := stream.MapToImage(7, 2); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("map-to-image error = %v", err)
	}
	if _, err := stream.ReadAtLossy(8, make([]byte, 2)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("lossy error = %v", err)
	}

	zeroImage := openStream(t, openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(imageTurtle("aff4://image", "zero", 8, 4, 2))),
		store("image/00000000", nil),
		store("image.index", indexBytes([2]uint32{0, 0}, [2]uint32{0, 0})),
	), DefaultLimits()), "aff4://image")
	ranges, err := zeroImage.MapToImage(0, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 2 || ranges[0].Kind != source.RangeZero {
		t.Fatalf("zero image ranges = %+v", ranges)
	}
}
