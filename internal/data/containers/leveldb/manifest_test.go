package leveldb

import (
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func encodeManifest(edits ...EncodedEdit) []byte {
	var bytes []byte
	for _, edit := range edits {
		bytes = append(bytes, EncodeFullRecord(EncodeEdit(edit))...)
	}
	return bytes
}

func TestManifestEditsApplyInOrder(t *testing.T) {
	comparator := "leveldb.BytewiseComparator"
	logNumber := uint64(3)
	nextFile := uint64(7)
	lastSequence := uint64(42)
	bytes := encodeManifest(
		EncodedEdit{
			Comparator:   &comparator,
			LogNumber:    &logNumber,
			NextFile:     &nextFile,
			LastSequence: &lastSequence,
			Added: []EncodedFile{
				{Level: 0, Number: 5, Size: 100, Smallest: internalKey("a", 40, 1), Largest: internalKey("b", 41, 1)},
				{Level: 0, Number: 6, Size: 200, Smallest: internalKey("c", 42, 1), Largest: internalKey("d", 42, 1)},
			},
		},
		EncodedEdit{
			Deleted: [][2]uint32{{0, 5}},
			Added: []EncodedFile{
				{Level: 1, Number: 8, Size: 300, Smallest: internalKey("a", 42, 1), Largest: internalKey("d", 42, 1)},
			},
		},
	)
	manifest, err := OpenManifest(memorySource(bytes))
	if err != nil {
		t.Fatalf("OpenManifest: %v", err)
	}
	if !manifest.Complete || manifest.Edits != 2 || manifest.DeletedFiles != 1 {
		t.Fatalf("manifest = %+v", manifest)
	}
	if manifest.Comparator == nil || *manifest.Comparator != comparator {
		t.Fatalf("comparator = %v", manifest.Comparator)
	}
	if manifest.LogNumber == nil || *manifest.LogNumber != 3 ||
		manifest.LastSequence == nil || *manifest.LastSequence != 42 {
		t.Fatalf("numbers = %v %v", manifest.LogNumber, manifest.LastSequence)
	}
	if len(manifest.LiveTables) != 2 {
		t.Fatalf("live tables = %+v", manifest.LiveTables)
	}
	first, second := manifest.LiveTables[0], manifest.LiveTables[1]
	if first.Level != 0 || first.Number != 6 || second.Level != 1 || second.Number != 8 {
		t.Fatalf("live set = %+v", manifest.LiveTables)
	}
	if second.Smallest != "a" || second.Largest != "d" {
		t.Fatalf("keys = %q..%q", second.Smallest, second.Largest)
	}
	if got := manifest.Levels(); len(got) != 2 || got[0] != [2]int{0, 1} || got[1] != [2]int{1, 1} {
		t.Fatalf("levels = %v", got)
	}
	if manifest.LiveBytes() != 500 {
		t.Fatalf("live bytes = %d", manifest.LiveBytes())
	}
	if level, ok := manifest.MaxLevel(); !ok || level != 1 {
		t.Fatalf("max level = %d %v", level, ok)
	}
}

func TestManifestNewFileGroupIsNotLengthPrefixedAsAWhole(t *testing.T) {
	payload := []byte{7}
	payload = appendVarint(payload, 0)   // level
	payload = appendVarint(payload, 9)   // file number
	payload = appendVarint(payload, 321) // file size
	payload = appendBytes(payload, internalKey("a", 7, 1))
	payload = appendBytes(payload, internalKey("m", 7, 1))
	manifest, err := OpenManifest(memorySource(EncodeFullRecord(payload)))
	if err != nil {
		t.Fatalf("OpenManifest: %v", err)
	}
	if manifest.DecodeFailures != 0 || len(manifest.LiveTables) != 1 {
		t.Fatalf("manifest = %+v", manifest)
	}
	table := manifest.LiveTables[0]
	if table.Level != 0 || table.Number != 9 || table.Size != 321 ||
		table.Smallest != "a" || table.Largest != "m" {
		t.Fatalf("live table = %+v", table)
	}
}

func TestManifestCorruptRecordIsSkippedAndReported(t *testing.T) {
	edit := EncodedEdit{Added: []EncodedFile{
		{Level: 0, Number: 2, Size: 10, Smallest: internalKey("a", 1, 1), Largest: internalKey("b", 1, 1)},
	}}
	record := EncodeFullRecord(EncodeEdit(edit))
	record[len(record)-1] ^= 0xff
	manifest, err := OpenManifest(memorySource(record))
	if err != nil {
		t.Fatalf("OpenManifest: %v", err)
	}
	if manifest.Complete || manifest.ChecksumFailures != 1 || len(manifest.LiveTables) != 0 {
		t.Fatalf("manifest = %+v", manifest)
	}
	if len(manifest.Warnings) == 0 {
		t.Fatal("a checksum failure produced no warning")
	}
}

func TestManifestUnknownTagMakesTheEditUnusable(t *testing.T) {
	payload := []byte{42}
	payload = appendVarint(payload, 1)
	manifest, err := OpenManifest(memorySource(EncodeFullRecord(payload)))
	if err != nil {
		t.Fatalf("OpenManifest: %v", err)
	}
	if manifest.DecodeFailures != 1 || manifest.Complete || len(manifest.LiveTables) != 0 {
		t.Fatalf("manifest = %+v", manifest)
	}
}

func TestManifestTruncatedFieldIsADecodeFailure(t *testing.T) {
	payload := []byte{2} // a log number with no varint after it
	manifest, err := OpenManifest(memorySource(EncodeFullRecord(payload)))
	if err != nil {
		t.Fatalf("OpenManifest: %v", err)
	}
	if manifest.DecodeFailures != 1 || manifest.Complete {
		t.Fatalf("manifest = %+v", manifest)
	}
}

func TestParseCurrentValidatesItsPointer(t *testing.T) {
	name, err := ParseCurrent([]byte("MANIFEST-000002\n"))
	if err != nil || name != "MANIFEST-000002" {
		t.Fatalf("ParseCurrent = %q, %v", name, err)
	}
	for _, bad := range [][]byte{
		[]byte("  \n"),
		[]byte("../MANIFEST-000002\n"),
		{0xff, 0xfe},
	} {
		if _, err := ParseCurrent(bad); err == nil {
			t.Fatalf("ParseCurrent(%q) accepted", bad)
		}
	}
	current, err := OpenCurrent(memorySource([]byte("MANIFEST-000007")))
	if err != nil || current != "MANIFEST-000007" {
		t.Fatalf("OpenCurrent = %q, %v", current, err)
	}
}

func TestManifestOpenRefusesOversizedSource(t *testing.T) {
	limits := DefaultLogLimits()
	limits.MaxBytes = 1
	src := source.NewMemorySource(1, make([]byte, 8))
	if _, err := OpenManifestWithLimits(src, limits); err == nil {
		t.Fatal("an oversized manifest was read")
	}
}
