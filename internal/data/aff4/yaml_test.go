package aff4

import (
	"errors"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func TestYAMLVersionLines(t *testing.T) {
	parsed, err := parseYAML(InformationYAML, "aff4:version: \"1.0\"\n", DefaultLimits())
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if parsed.version != "1.0" || parsed.versionLine != 1 {
		t.Fatalf("version = %q line %d", parsed.version, parsed.versionLine)
	}

	parsed, err = parseYAML(InformationYAML, "---\nversion: 1.1 # comment\n", DefaultLimits())
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if parsed.version != "1.1" || parsed.versionLine != 2 {
		t.Fatalf("version = %q line %d", parsed.version, parsed.versionLine)
	}

	parsed, err = parseYAML(InformationYAML, "aff4:size: 10\n", DefaultLimits())
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if parsed.version != "" {
		t.Fatalf("version = %q", parsed.version)
	}

	if _, err := parseYAML(InformationYAML, "version: {a: 1}\n", DefaultLimits()); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("flow collection error = %v", err)
	}
	if _, err := parseYAML(InformationYAML, "version: \"2.0\"\nversion: \"1.0\"\n", DefaultLimits()); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("conflicting version error = %v", err)
	}
}

func TestTypedYAMLStreamsCaptureReadableVocabulary(t *testing.T) {
	text := `version: "1.0"
streams:
  - uri: "aff4://yaml-image"
    type: Image
    category: imageStream
    size: 512
    chunkSize: 256
    chunksPerSegment: 2
    compressionMethod: zlib
    stored: "aff4://yaml-image"
    hash: "SHA1:abcd"
  - uri: "aff4://yaml-map"
    type: Map
    category: map
    size: 512
    target: "aff4://yaml-image"
    dataStream: "aff4://yaml-map-data"
`
	parsed, err := parseYAML(InformationYAML, text, DefaultLimits())
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if parsed.version != "1.0" || parsed.imageStreams != 1 || parsed.mapStreams != 1 || len(parsed.streams) != 2 {
		t.Fatalf("version=%q images=%d maps=%d streams=%d",
			parsed.version, parsed.imageStreams, parsed.mapStreams, len(parsed.streams))
	}

	image := parsed.streams[0]
	if image.URI != "aff4://yaml-image" || image.Class != "Image" || image.Category != "imageStream" {
		t.Fatalf("image = %+v", image)
	}
	if image.Size == nil || *image.Size != 512 || image.ChunkSize == nil || *image.ChunkSize != 256 {
		t.Fatalf("image sizes = %+v", image)
	}
	if image.ChunksPerSegment == nil || *image.ChunksPerSegment != 2 || image.Compression != "zlib" {
		t.Fatalf("image geometry = %+v", image)
	}
	if len(image.Stored) != 1 || image.Stored[0] != "aff4://yaml-image" {
		t.Fatalf("stored = %v", image.Stored)
	}
	if len(image.Hashes) != 1 || image.Hashes[0].Algorithm != "SHA1" || image.Hashes[0].ValueLen != 4 {
		t.Fatalf("hashes = %+v", image.Hashes)
	}

	yamlMap := parsed.streams[1]
	if !yamlMap.IsMap() || len(yamlMap.Targets) != 1 || yamlMap.Targets[0] != "aff4://yaml-image" {
		t.Fatalf("map = %+v", yamlMap)
	}
	if yamlMap.DataStream != "aff4://yaml-map-data" {
		t.Fatalf("data stream = %q", yamlMap.DataStream)
	}
	if got := yamlMap.OrderedTargets(); len(got) != 1 || got[0] != "aff4://yaml-image" {
		t.Fatalf("ordered targets = %v", got)
	}
}

func TestYAMLRejectsConstructsItCannotHonour(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{"tab indentation", "\tversion: \"1.0\"\n"},
		{"anchored value", "version: &anchor 1.0\n"},
		{"bare key with no value", "version:\n"},
		{"stream without uri", "streams:\n  - size: 4\n"},
		{"property before item", "streams:\n  size: 4\n"},
		{"streams block empty", "streams:\n"},
		{"top level non-key", "streams\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseYAML(InformationYAML, tc.text, DefaultLimits()); !errors.Is(err, source.ErrCorrupt) {
				t.Fatalf("error = %v, want corrupt", err)
			}
		})
	}
}

func TestYAMLEmptyStreamSequence(t *testing.T) {
	parsed, err := parseYAML(InformationYAML, "version: \"1.0\"\nstreams: []\n", DefaultLimits())
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if parsed.version != "1.0" || len(parsed.streams) != 0 {
		t.Fatalf("parsed = %+v", parsed)
	}
}

func TestYAMLUnknownKeysAreWarned(t *testing.T) {
	text := "streams:\n  - uri: \"aff4://x\"\n    type: Image\n    mystery: 1\n"
	parsed, err := parseYAML(InformationYAML, text, DefaultLimits())
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if parsed.ignoredPredicateCount != 1 || len(parsed.ignoredPredicates) != 1 {
		t.Fatalf("ignored = %d %v", parsed.ignoredPredicateCount, parsed.ignoredPredicates)
	}
	if len(parsed.warnings) != 1 || !strings.Contains(parsed.warnings[0], "mystery") {
		t.Fatalf("warnings = %v", parsed.warnings)
	}
}

func TestYAMLDuplicateURILastWins(t *testing.T) {
	text := "streams:\n" +
		"  - uri: \"aff4://x\"\n    type: Image\n    size: 4\n" +
		"  - uri: \"aff4://x\"\n    type: Zero\n    size: 8\n"
	parsed, err := parseYAML(InformationYAML, text, DefaultLimits())
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(parsed.streams) != 1 {
		t.Fatalf("streams = %+v", parsed.streams)
	}
	if parsed.streams[0].Class != "Zero" {
		t.Fatalf("class = %q", parsed.streams[0].Class)
	}
	if parsed.streams[0].Size == nil || *parsed.streams[0].Size != 8 {
		t.Fatalf("size = %v", parsed.streams[0].Size)
	}
}
