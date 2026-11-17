package leveldb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func memorySource(bytes []byte) source.ByteSource {
	return source.NewMemorySource(1, bytes)
}

func openFixture(t *testing.T, fixture *tableFixture) *Table {
	t.Helper()
	table, err := OpenTableSource(memorySource(fixture.bytes))
	if err != nil {
		t.Fatalf("OpenTableSource: %v", err)
	}
	return table
}

func TestTableEmptyIndex(t *testing.T) {
	table := openFixture(t, buildTable(nil))
	summary, err := table.Summary(DefaultTableLimits())
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if summary.Blocks != 0 || summary.Entries != 0 || !summary.ScanComplete {
		t.Fatalf("summary = %+v", summary)
	}
	if len(summary.Warnings) == 0 || !strings.Contains(summary.Warnings[0], "index is empty") {
		t.Fatalf("warnings = %v", summary.Warnings)
	}
}

func TestTableSmallSummary(t *testing.T) {
	fixture := buildTable([]tableBlockSpec{
		{entries: []testKV{
			{key: internalKey("alpha", 5, 1), value: []byte("A")},
			{key: internalKey("beta", 7, 0), value: nil},
		}},
		{entries: []testKV{
			{key: internalKey("gamma", 9, 1), value: []byte("C")},
		}, compress: true},
	})
	table := openFixture(t, fixture)
	summary, err := table.Summary(DefaultTableLimits())
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if summary.Blocks != 2 || summary.ScannedBlocks != 2 || summary.Entries != 3 {
		t.Fatalf("block/entry counts = %+v", summary)
	}
	if summary.Deleted != 1 || summary.CompressedBlocks != 1 {
		t.Fatalf("deleted/compressed = %d/%d", summary.Deleted, summary.CompressedBlocks)
	}
	if summary.FirstKey == nil || *summary.FirstKey != "alpha" {
		t.Fatalf("first key = %v", summary.FirstKey)
	}
	if summary.LastKey == nil || *summary.LastKey != "gamma" {
		t.Fatalf("last key = %v", summary.LastKey)
	}
	if summary.FirstSequence == nil || *summary.FirstSequence != 5 ||
		summary.LastSequence == nil || *summary.LastSequence != 9 {
		t.Fatalf("sequences = %v..%v", summary.FirstSequence, summary.LastSequence)
	}
	if summary.KeyBytes != uint64(len("alpha")+len("beta")+len("gamma")) {
		t.Fatalf("key bytes = %d", summary.KeyBytes)
	}
	if summary.ValueBytes != 2 {
		t.Fatalf("value bytes = %d", summary.ValueBytes)
	}
	if !summary.ScanComplete || len(summary.Warnings) != 0 {
		t.Fatalf("complete = %v, warnings = %v", summary.ScanComplete, summary.Warnings)
	}
}

func TestTableRendersNonPrintableKeysAsHex(t *testing.T) {
	user := string([]byte{0xff, 0x00})
	table := openFixture(t, buildTable([]tableBlockSpec{
		{entries: []testKV{{key: internalKey(user, 1, 1), value: []byte("v")}}},
	}))
	summary, err := table.Summary(DefaultTableLimits())
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if summary.FirstKey == nil || *summary.FirstKey != "0xff00" {
		t.Fatalf("first key = %v", summary.FirstKey)
	}
}

func TestTableMalformedInternalKeyIsCounted(t *testing.T) {
	table := openFixture(t, buildTable([]tableBlockSpec{
		{entries: []testKV{{key: []byte("short"), value: []byte("v")}}},
	}))
	summary, err := table.Summary(DefaultTableLimits())
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if summary.Malformed != 1 || summary.Entries != 0 || !summary.ScanComplete {
		t.Fatalf("summary = %+v", summary)
	}
	if len(summary.Warnings) == 0 || !strings.Contains(summary.Warnings[0], "too short") {
		t.Fatalf("warnings = %v", summary.Warnings)
	}
}

func TestTableChecksumCorruptionStopsTheScan(t *testing.T) {
	fixture := buildTable([]tableBlockSpec{
		{entries: []testKV{{key: internalKey("a", 1, 1), value: []byte("v")}}},
	})
	offset := fixture.dataOffsets[0]
	fixture.bytes[offset+len(storedBlock(buildRawBlock([]testKV{
		{key: internalKey("a", 1, 1), value: []byte("v")},
	}), 0))-1] ^= 0xff
	table := openFixture(t, fixture)
	summary, err := table.Summary(DefaultTableLimits())
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if summary.ScanComplete {
		t.Fatal("a corrupt block produced a complete scan")
	}
	if summary.Entries != 0 || summary.ScannedBlocks != 0 {
		t.Fatalf("summary = %+v", summary)
	}
	if len(summary.Warnings) == 0 || !strings.Contains(summary.Warnings[0], "checksum") {
		t.Fatalf("warnings = %v", summary.Warnings)
	}
}

func TestTableTruncatedFooterAndBadMagic(t *testing.T) {
	if _, err := OpenTableSource(memorySource(make([]byte, 20))); err == nil {
		t.Fatal("a table shorter than its footer opened")
	}
	if _, err := OpenTableSource(memorySource(make([]byte, LevelDBFooterBytes))); err == nil ||
		!strings.Contains(err.Error(), "footer magic") {
		t.Fatalf("err = %v, want a bad magic", err)
	}
	// A RocksDB magic is a recognised table format this reader does not
	// decode, not a corrupt LevelDB table.
	rocks := make([]byte, LevelDBFooterBytes)
	binary.LittleEndian.PutUint64(rocks[LevelDBFooterBytes-8:], RocksDBTableMagic)
	if _, err := OpenTableSource(memorySource(rocks)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("err = %v, want unsupported", err)
	}
}

func TestTableHandleOutsideFileIsRefused(t *testing.T) {
	var footer [LevelDBFooterBytes]byte
	handle := appendVarint(nil, 0)
	handle = appendVarint(handle, 1000)
	copy(footer[:], handle)
	second := appendVarint(nil, 0)
	second = appendVarint(second, 0)
	copy(footer[len(handle):], second)
	binary.LittleEndian.PutUint64(footer[LevelDBFooterBytes-8:], TableMagic)
	if _, err := OpenTableSource(memorySource(footer[:])); err == nil ||
		!strings.Contains(err.Error(), "runs past") {
		t.Fatalf("err = %v, want an out-of-range handle", err)
	}
}

func TestTableScanLimits(t *testing.T) {
	fixture := buildTable([]tableBlockSpec{
		{entries: []testKV{
			{key: internalKey("a", 1, 1), value: []byte("1")},
			{key: internalKey("b", 2, 1), value: []byte("2")},
		}},
		{entries: []testKV{{key: internalKey("c", 3, 1), value: []byte("3")}}},
	})
	table := openFixture(t, fixture)

	// The block-count bound is exclusive: exactly one block at bound one is
	// reported, never silently truncated.
	if _, err := table.IndexEntries(1); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("IndexEntries(1) err = %v", err)
	}

	limits := DefaultTableLimits()
	limits.MaxScanBytes = 1
	summary, err := table.Summary(limits)
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if summary.ScanComplete {
		t.Fatal("the byte bound produced a complete scan")
	}
	if summary.Entries != 2 || summary.ScannedBlocks != 1 {
		t.Fatalf("summary = %+v", summary)
	}

	limits = DefaultTableLimits()
	limits.MaxEntries = 1
	summary, err = table.Summary(limits)
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if summary.ScanComplete || summary.Entries != 1 {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestTableLargeMultiBlockScan(t *testing.T) {
	const blockCount = 50
	const perBlock = 20
	blocks := make([]tableBlockSpec, 0, blockCount)
	for block := 0; block < blockCount; block++ {
		entries := make([]testKV, 0, perBlock)
		for index := 0; index < perBlock; index++ {
			number := block*perBlock + index
			key := internalKey(fmt.Sprintf("key%04d", number), uint64(number), 1)
			entries = append(entries, testKV{key: key, value: []byte{byte(number)}})
		}
		blocks = append(blocks, tableBlockSpec{entries: entries, compress: block%2 == 0})
	}
	fixture := buildTable(blocks)
	table := openFixture(t, fixture)
	summary, err := table.Summary(DefaultTableLimits())
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if summary.Blocks != blockCount || summary.ScannedBlocks != blockCount {
		t.Fatalf("blocks = %d/%d", summary.Blocks, summary.ScannedBlocks)
	}
	if summary.Entries != blockCount*perBlock || !summary.ScanComplete {
		t.Fatalf("summary = %+v", summary)
	}
	if summary.CompressedBlocks != blockCount/2 {
		t.Fatalf("compressed blocks = %d", summary.CompressedBlocks)
	}
	if summary.FirstKey == nil || *summary.FirstKey != "key0000" {
		t.Fatalf("first key = %v", summary.FirstKey)
	}
	if summary.LastKey == nil || *summary.LastKey != "key0999" {
		t.Fatalf("last key = %v", summary.LastKey)
	}
}

func TestTableIdentifiesByMagic(t *testing.T) {
	fixture := buildTable([]tableBlockSpec{
		{entries: []testKV{{key: internalKey("a", 1, 1), value: []byte("v")}}},
	})
	identifies, err := Identifies(memorySource(fixture.bytes))
	if err != nil || !identifies {
		t.Fatalf("Identifies = %v, %v", identifies, err)
	}
	identifies, err = Identifies(memorySource([]byte("not a table at all")))
	if err != nil || identifies {
		t.Fatalf("Identifies garbage = %v, %v", identifies, err)
	}
	identifies, err = Identifies(memorySource(nil))
	if err != nil || identifies {
		t.Fatalf("Identifies empty = %v, %v", identifies, err)
	}
}
