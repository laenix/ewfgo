package aff4

import (
	"errors"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

const basicTurtle = turtleHeader + `
<aff4://fixture-image> a aff4:Image ;
    aff4:category aff4:imageStream ;
    aff4:size 65536 ;
    aff4:chunkSize 32768 ;
    aff4:chunksPerSegment 4 ;
    aff4:compressionMethod aff4:snappy ;
    aff4:stored <aff4://fixture-image> ;
    hash:SHA1 "0123456789abcdef0123456789abcdef01234567" .

<aff4://fixture-image.map> a aff4:Map ;
    aff4:category aff4:map ;
    aff4:chunkSize 32768 ;
    aff4:compressionMethod "zlib" .

<aff4://fixture-image.zero> aff4:category aff4:zero .
`

func mustParseTurtle(t *testing.T, text string, limits Limits) turtleParse {
	t.Helper()
	parsed, err := parseTurtle("information.turtle", text, limits)
	if err != nil {
		t.Fatalf("parseTurtle error = %v", err)
	}
	return parsed
}

func TestTurtleParsesVocabularyWithoutGuessing(t *testing.T) {
	parsed := mustParseTurtle(t, basicTurtle, DefaultLimits())
	if parsed.version != "" {
		t.Fatalf("version = %q, want none", parsed.version)
	}
	if parsed.imageStreams != 1 || parsed.mapStreams != 1 || parsed.zeroStreams != 1 {
		t.Fatalf("counts = %d/%d/%d", parsed.imageStreams, parsed.mapStreams, parsed.zeroStreams)
	}
	if len(parsed.storedLinks) != 1 {
		t.Fatalf("stored links = %d", len(parsed.storedLinks))
	}

	var image *Stream
	for index := range parsed.streams {
		if parsed.streams[index].IsImage() {
			image = &parsed.streams[index]
		}
	}
	if image == nil {
		t.Fatal("no image stream")
	}
	if image.URI != "aff4://fixture-image" {
		t.Fatalf("image uri = %q", image.URI)
	}
	if image.Size == nil || *image.Size != 65536 {
		t.Fatalf("image size = %v", image.Size)
	}
	if image.ChunkSize == nil || *image.ChunkSize != 32768 {
		t.Fatalf("image chunk size = %v", image.ChunkSize)
	}
	if image.ChunksPerSegment == nil || *image.ChunksPerSegment != 4 {
		t.Fatalf("image chunks per segment = %v", image.ChunksPerSegment)
	}
	if image.Compression != "snappy" {
		t.Fatalf("image compression = %q", image.Compression)
	}
	if len(image.Hashes) != 1 || image.Hashes[0].Algorithm != "SHA1" ||
		!image.Hashes[0].ValuePresent || image.Hashes[0].ValueLen != 40 {
		t.Fatalf("image hashes = %+v", image.Hashes)
	}
	if parsed.unknownSubjects != 0 || parsed.ignoredPredicateCount != 0 || len(parsed.warnings) != 0 {
		t.Fatalf("unknown=%d ignored=%d warnings=%v", parsed.unknownSubjects, parsed.ignoredPredicateCount, parsed.warnings)
	}
}

func TestTurtleUnknownPredicatesAreCountedNotGuessed(t *testing.T) {
	text := turtleHeader + `<aff4://x> a aff4:Image ; aff4:mystery "value" ; aff4:size 10 .`
	parsed := mustParseTurtle(t, text, DefaultLimits())
	if parsed.ignoredPredicateCount != 1 {
		t.Fatalf("ignored = %d", parsed.ignoredPredicateCount)
	}
	if len(parsed.ignoredPredicates) != 1 || parsed.ignoredPredicates[0] != Namespace+"mystery" {
		t.Fatalf("ignored predicates = %v", parsed.ignoredPredicates)
	}
	if len(parsed.streams) != 1 || parsed.streams[0].Size == nil || *parsed.streams[0].Size != 10 {
		t.Fatalf("streams = %+v", parsed.streams)
	}
}

func TestTurtleVersionOnlySubjectIsMetadataNotAStream(t *testing.T) {
	text := turtleHeader + `<aff4://container> aff4:version "1.1" .
<aff4://image> a aff4:Image ; aff4:size 8 .`
	parsed := mustParseTurtle(t, text, DefaultLimits())
	if parsed.version != "1.1" || parsed.versionLine != 3 {
		t.Fatalf("version = %q line %d", parsed.version, parsed.versionLine)
	}
	if len(parsed.streams) != 1 || parsed.streams[0].URI != "aff4://image" {
		t.Fatalf("streams = %+v", parsed.streams)
	}
	if parsed.unknownSubjects != 1 {
		t.Fatalf("unknown subjects = %d", parsed.unknownSubjects)
	}
}

func TestTurtleUnsupportedConstructsAreNamed(t *testing.T) {
	cases := []struct {
		name   string
		text   string
		errSub string
	}{
		{
			name:   "blank node property list",
			text:   turtleHeader + `<aff4://x> a [ aff4:size 1 ] .`,
			errSub: "blank node property list",
		},
		{
			name:   "collection",
			text:   turtleHeader + `<aff4://x> aff4:stored ( <aff4://a> ) .`,
			errSub: "collection",
		},
		{
			name:   "long literal",
			text:   turtleHeader + `<aff4://x> aff4:size """1""" .`,
			errSub: "long string literal",
		},
		{
			name:   "base directive",
			text:   turtleHeader + `@base <http://example/> .`,
			errSub: "@base directive",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseTurtle("information.turtle", tc.text, DefaultLimits())
			if !errors.Is(err, source.ErrUnsupported) {
				t.Fatalf("error = %v, want ErrUnsupported", err)
			}
			if !strings.Contains(err.Error(), tc.errSub) {
				t.Fatalf("error %q does not name %q", err, tc.errSub)
			}
		})
	}
}

func TestTurtleUnsupportedEscapeAndUnterminatedLiteral(t *testing.T) {
	_, err := parseTurtle("information.turtle",
		turtleHeader+`<aff4://x> a aff4:Image ; aff4:size "1\q2" .`, DefaultLimits())
	if !errors.Is(err, source.ErrUnsupported) || !strings.Contains(err.Error(), "escape") {
		t.Fatalf("escape error = %v", err)
	}

	_, err = parseTurtle("information.turtle",
		turtleHeader+`<aff4://x> a aff4:Image ; aff4:size "12 .`, DefaultLimits())
	if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "unterminated") {
		t.Fatalf("unterminated error = %v", err)
	}
}

func TestTurtleUndeclaredPrefixAndMalformedSubject(t *testing.T) {
	_, err := parseTurtle("information.turtle", `@prefix aff4: <http://aff4.org/Schema#> .
<aff4://x> a missing:Thing .`, DefaultLimits())
	if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "undeclared prefix") {
		t.Fatalf("error = %v", err)
	}

	_, err = parseTurtle("information.turtle", `@prefix aff4: <http://aff4.org/Schema#> .
bare a aff4:Image .`, DefaultLimits())
	if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "subject") {
		t.Fatalf("error = %v", err)
	}
}

func TestTurtleAcceptsPREFIXKeywordCommentsAndMetadataSubjects(t *testing.T) {
	text := "PREFIX aff4: <http://aff4.org/Schema#> .\n" +
		"# a comment\n" +
		"<aff4://meta> aff4:version \"1.0\" .\n" +
		"<aff4://x> a aff4:Image ; # trailing comment\n" +
		"    aff4:size 12 ; ;\n" +
		"    aff4:compressionMethod \"zlib\"^^<http://example/dt> .\n"
	parsed := mustParseTurtle(t, text, DefaultLimits())
	if parsed.version != "1.0" || parsed.versionLine != 3 {
		t.Fatalf("version = %q line %d", parsed.version, parsed.versionLine)
	}
	if len(parsed.streams) != 1 || parsed.streams[0].Size == nil || *parsed.streams[0].Size != 12 {
		t.Fatalf("streams = %+v", parsed.streams)
	}
}

func TestTurtleTripleAndSubjectCapsAreLimitErrors(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxTriples = 1
	if _, err := parseTurtle("information.turtle", basicTurtle, limits); !errors.Is(err, ErrLimit) {
		t.Fatalf("triple cap error = %v", err)
	}

	limits = DefaultLimits()
	limits.MaxSubjects = 1
	if _, err := parseTurtle("information.turtle", basicTurtle, limits); !errors.Is(err, ErrLimit) {
		t.Fatalf("subject cap error = %v", err)
	}

	limits = DefaultLimits()
	limits.MaxPrefixes = 1
	if _, err := parseTurtle("information.turtle", basicTurtle, limits); !errors.Is(err, ErrLimit) {
		t.Fatalf("prefix cap error = %v", err)
	}

	limits = DefaultLimits()
	limits.MaxURIBytes = 4
	if _, err := parseTurtle("information.turtle", basicTurtle, limits); !errors.Is(err, ErrLimit) {
		t.Fatalf("uri cap error = %v", err)
	}
}

func TestTurtleLineLengthIsBounded(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxLineBytes = 16
	if _, err := parseTurtle("information.turtle", basicTurtle, limits); !errors.Is(err, ErrLimit) {
		t.Fatalf("line cap error = %v", err)
	}
}

func TestParseContainerDescriptionVersions(t *testing.T) {
	cases := []struct {
		input   string
		version string
		line    uint64
	}{
		{"AFF4-1.0\n", "1.0", 1},
		{"\nAFF4/1.1\n", "1.1", 2},
		{"1.0.2", "1.0.2", 1},
		{string([]byte{0xEF, 0xBB, 0xBF}) + "AFF4-1.1.10\r\n", "1.1.10", 1},
	}
	for _, tc := range cases {
		version, line, err := parseContainerDescription(ContainerDescription, tc.input)
		if err != nil {
			t.Fatalf("%q: error = %v", tc.input, err)
		}
		if version != tc.version || line != tc.line {
			t.Fatalf("%q: version=%q line=%d", tc.input, version, line)
		}
	}
	for _, input := range []string{"hello", "", "AFF4-1", "AFF4-1.0.2.3"} {
		if _, _, err := parseContainerDescription(ContainerDescription, input); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("%q: error = %v, want corrupt", input, err)
		}
	}
}

func TestSupportedVersionIsExplicit(t *testing.T) {
	for _, version := range []string{"1.0", "1.1", "1.0.2", "1.1.10"} {
		if !supportedVersion(version) {
			t.Fatalf("supportedVersion(%q) = false", version)
		}
	}
	for _, version := range []string{"2.0", "1", "1.0.", "1.2", "1.0.2.3", "1.1.x"} {
		if supportedVersion(version) {
			t.Fatalf("supportedVersion(%q) = true", version)
		}
	}
}

func TestMemberCandidatesIncludeNormalizedURNForms(t *testing.T) {
	candidates := memberCandidates("aff4://image", RoleMap)
	want := []string{"aff4://image.map", "aff4://image/map", "image.map", "image/map"}
	for _, candidate := range want {
		if !containsString(candidates, candidate) {
			t.Fatalf("map candidates %v missing %q", candidates, candidate)
		}
	}
	image := memberCandidates("aff4://image", RoleImage)
	if len(image) != 2 || image[0] != "aff4://image" || image[1] != "image" {
		t.Fatalf("image candidates = %v", image)
	}
}

func TestExpectedIndexSizeIsDerivedFromGeometry(t *testing.T) {
	size := uint64(65536)
	chunk := uint64(32768)
	stream := Stream{URI: "aff4://x", Class: "Image", Size: &size, ChunkSize: &chunk}
	expected, ok := expectedIndexSize(stream)
	if !ok || expected != 16 {
		t.Fatalf("expected index size = %d, %v", expected, ok)
	}
	zero := uint64(0)
	stream.ChunkSize = &zero
	if _, ok := expectedIndexSize(stream); ok {
		t.Fatal("zero chunk size must not yield an expected size")
	}
}
