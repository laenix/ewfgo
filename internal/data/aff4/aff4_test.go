package aff4

import (
	"errors"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func TestOpenRejectsNonZIP(t *testing.T) {
	for _, data := range [][]byte{
		{},
		[]byte("PK"),
		[]byte("NOPE and more"),
	} {
		_, err := Open(source.NewMemorySource(1, data), DefaultLimits())
		if !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("Open(%q) error = %v, want ErrCorrupt", data, err)
		}
	}
}

func TestOpenRejectsTruncatedZIP(t *testing.T) {
	full := buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(turtleHeader)),
	)
	truncated := full[:len(full)/2]
	_, err := Open(source.NewMemorySource(1, truncated), DefaultLimits())
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("truncated Open error = %v, want ErrCorrupt", err)
	}
}

func TestOpenFactsFromTurtle(t *testing.T) {
	container := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(basicTurtle)),
		store("fixture-image", []byte("placeholder")),
		store("fixture-image.map", []byte("placeholder")),
		store("fixture-image.zero", nil),
		store("fixture-image.index", make([]byte, 16)),
	), DefaultLimits())

	facts := container.Facts()
	if facts.FileSize == 0 {
		t.Fatal("file size not recorded")
	}
	if facts.Version != "1.0" {
		t.Fatalf("version = %q", facts.Version)
	}
	if len(facts.Descriptors) != 2 {
		t.Fatalf("descriptors = %+v", facts.Descriptors)
	}
	if facts.Descriptors[0].Kind != DescriptorContainerDescription ||
		facts.Descriptors[0].Version != "1.0" || facts.Descriptors[0].Line != 1 {
		t.Fatalf("container descriptor = %+v", facts.Descriptors[0])
	}
	if facts.Descriptors[1].Kind != DescriptorTurtle || facts.Descriptors[1].Version != "" {
		t.Fatalf("turtle descriptor = %+v", facts.Descriptors[1])
	}
	if facts.ImageStreams != 1 || facts.MapStreams != 1 || facts.ZeroStreams != 1 {
		t.Fatalf("counts = %d/%d/%d", facts.ImageStreams, facts.MapStreams, facts.ZeroStreams)
	}
	if facts.EntryCount != 6 || facts.FileCount != 6 || facts.DirectoryCount != 0 {
		t.Fatalf("entry counts = %d/%d/%d", facts.EntryCount, facts.FileCount, facts.DirectoryCount)
	}
	if len(facts.Streams) != 3 || facts.Streams[0].URI != "aff4://fixture-image" {
		t.Fatalf("streams = %+v", facts.Streams)
	}
	if len(facts.StoredLinks) != 1 ||
		facts.StoredLinks[0].Subject != "aff4://fixture-image" ||
		facts.StoredLinks[0].Object != "aff4://fixture-image" {
		t.Fatalf("stored links = %+v", facts.StoredLinks)
	}
	if len(facts.Hashes) != 1 || facts.Hashes[0].Algorithm != "SHA1" ||
		facts.Hashes[0].Verified || facts.Hashes[0].ValueLen != 40 {
		t.Fatalf("hashes = %+v", facts.Hashes)
	}
	if len(facts.Images) != 1 || facts.Images[0].ImageURI != "aff4://fixture-image" {
		t.Fatalf("images = %+v", facts.Images)
	}
	if len(facts.Images[0].Missing()) != 0 {
		t.Fatalf("missing members = %v", facts.Images[0].Missing())
	}
	for _, check := range facts.Images[0].Checks {
		switch check.Role {
		case RoleImage:
			if check.FoundMember != "fixture-image" {
				t.Fatalf("image check = %+v", check)
			}
		case RoleIndex:
			if check.ExpectedSize == nil || *check.ExpectedSize != 16 ||
				check.SizeMatches == nil || !*check.SizeMatches {
				t.Fatalf("index check = %+v", check)
			}
		}
	}
	if len(facts.Warnings) != 0 {
		t.Fatalf("warnings = %v", facts.Warnings)
	}
}

func TestOpenFactsFromYAML(t *testing.T) {
	yamlText := "version: \"1.0\"\nstreams:\n" +
		"  - uri: \"aff4://image\"\n    type: Image\n    category: imageStream\n" +
		"    size: 8\n    chunkSize: 4\n    chunksPerSegment: 1\n    compressionMethod: stored\n"
	container := openArchive(t, buildArchive(t,
		store(InformationYAML, []byte(yamlText)),
	), DefaultLimits())
	facts := container.Facts()
	if facts.Version != "1.0" || len(facts.Descriptors) != 1 ||
		facts.Descriptors[0].Kind != DescriptorYaml {
		t.Fatalf("facts = %+v", facts)
	}
	if facts.ImageStreams != 1 || len(facts.Streams) != 1 || !facts.Streams[0].IsImage() {
		t.Fatalf("streams = %+v", facts.Streams)
	}
}

func TestOpenVersionConflictKeepsPrimaryAndWarns(t *testing.T) {
	text := turtleHeader + "<aff4://c> aff4:version \"1.1\" .\n"
	container := openArchive(t, buildArchive(t,
		store("CONTAINER.DESCRIPTION", []byte("AFF4-1.0\n")),
		store("INFORMATION.TURTLE", []byte(text)),
	), DefaultLimits())
	facts := container.Facts()
	if facts.Version != "1.0" {
		t.Fatalf("version = %q", facts.Version)
	}
	if len(facts.Warnings) != 1 || !strings.Contains(facts.Warnings[0], "1.1") {
		t.Fatalf("warnings = %v", facts.Warnings)
	}
}

func TestOpenMissingAndUnsupportedDescriptors(t *testing.T) {
	_, err := Open(source.NewMemorySource(1, buildArchive(t,
		store("random.txt", []byte("nothing")))), DefaultLimits())
	if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "no container.description") {
		t.Fatalf("missing descriptor error = %v", err)
	}

	_, err = Open(source.NewMemorySource(1, buildArchive(t,
		store(InformationTurtle, []byte(turtleHeader+`<aff4://x> a aff4:Image .`)))), DefaultLimits())
	if !errors.Is(err, source.ErrCorrupt) || !strings.Contains(err.Error(), "no version") {
		t.Fatalf("missing version error = %v", err)
	}

	_, err = Open(source.NewMemorySource(1, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-2.0\n")))), DefaultLimits())
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("unsupported version error = %v", err)
	}
}

func TestOpenMetadataLimitsAndMalformed(t *testing.T) {
	turtle := store(InformationTurtle, []byte(basicTurtle))
	description := store(ContainerDescription, []byte("AFF4-1.0\n"))

	limits := DefaultLimits()
	limits.MaxEntries = 1
	if _, err := Open(source.NewMemorySource(1, buildArchive(t, description, turtle)), limits); !errors.Is(err, ErrLimit) {
		t.Fatalf("entry limit error = %v", err)
	}

	limits = DefaultLimits()
	limits.MaxLineBytes = 8
	if _, err := Open(source.NewMemorySource(1, buildArchive(t, description, turtle)), limits); !errors.Is(err, ErrLimit) {
		t.Fatalf("line limit error = %v", err)
	}

	limits = DefaultLimits()
	limits.MaxMetadataBytes = 4
	if _, err := Open(source.NewMemorySource(1, buildArchive(t, description)), limits); !errors.Is(err, ErrLimit) {
		t.Fatalf("metadata size limit error = %v", err)
	}

	invalid := store(InformationTurtle, []byte{0xff, 0xfe, 0x00})
	if _, err := Open(source.NewMemorySource(1, buildArchive(t, description, invalid)), DefaultLimits()); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("invalid utf-8 error = %v", err)
	}
}

func TestOpenDuplicateDescriptorFirstEntryWins(t *testing.T) {
	container := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(turtleHeader+`<aff4://x> aff4:version "1.1" .`)),
		store(InformationTurtle, []byte(turtleHeader+`<aff4://x> aff4:version "2.0" .`)),
	), DefaultLimits())
	facts := container.Facts()
	if len(facts.Descriptors) != 2 {
		t.Fatalf("descriptors = %+v", facts.Descriptors)
	}
	if facts.Descriptors[1].Version != "1.1" {
		t.Fatalf("turtle version = %q", facts.Descriptors[1].Version)
	}
}

func TestOpenTurtlePresentSuppressesYAMLStreams(t *testing.T) {
	yamlText := "streams:\n  - uri: \"aff4://image\"\n    type: Image\n    size: 4\n"
	container := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(turtleHeader)),
		store(InformationYAML, []byte(yamlText)),
	), DefaultLimits())
	facts := container.Facts()
	if len(facts.Streams) != 0 || facts.ImageStreams != 0 {
		t.Fatalf("streams = %+v", facts.Streams)
	}
	if len(facts.Descriptors) != 3 {
		t.Fatalf("descriptors = %+v", facts.Descriptors)
	}
}

func TestContainerAccessors(t *testing.T) {
	container := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(storedImageTurtle("aff4://image", 4, 4, 1))),
		store("image/00000000", []byte("DATA")),
	), DefaultLimits())

	if container.Version() != "1.0" {
		t.Fatalf("version = %q", container.Version())
	}
	if len(container.Descriptors()) != 2 {
		t.Fatalf("descriptors = %+v", container.Descriptors())
	}
	if len(container.Streams()) != 1 || !container.Streams()[0].IsImage() {
		t.Fatalf("streams = %+v", container.Streams())
	}
	if len(container.ImageStreams()) != 1 {
		t.Fatalf("image streams = %+v", container.ImageStreams())
	}
	if container.Parent() == nil || container.Parent().Len() == 0 {
		t.Fatal("parent not exposed")
	}
}

func TestContainerImageSelection(t *testing.T) {
	noImage := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(turtleHeader+`<aff4://z> a aff4:Zero ; aff4:size 4 .`)),
	), DefaultLimits())
	if _, err := noImage.Image(); !errors.Is(err, source.ErrInvalidArgument) {
		t.Fatalf("no-image error = %v", err)
	}

	two := turtleHeader +
		"<aff4://a> a aff4:Image ; aff4:size 4 ; aff4:chunkSize 4 ; aff4:chunksPerSegment 1 ; aff4:compressionMethod aff4:stored .\n" +
		"<aff4://b> a aff4:Image ; aff4:size 4 ; aff4:chunkSize 4 ; aff4:chunksPerSegment 1 ; aff4:compressionMethod aff4:stored .\n"
	ambiguous := openArchive(t, buildArchive(t,
		store(ContainerDescription, []byte("AFF4-1.0\n")),
		store(InformationTurtle, []byte(two)),
	), DefaultLimits())
	if _, err := ambiguous.Image(); !errors.Is(err, source.ErrInvalidArgument) || !strings.Contains(err.Error(), "2") {
		t.Fatalf("ambiguous error = %v", err)
	}

	if _, err := ambiguous.OpenStream("aff4://missing"); !errors.Is(err, source.ErrInvalidArgument) {
		t.Fatalf("missing stream error = %v", err)
	}
}
