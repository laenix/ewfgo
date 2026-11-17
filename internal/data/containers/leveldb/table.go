package leveldb

import (
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// LevelDBFooterBytes is LevelDB's fixed footer: two padded block handles
	// and the magic.
	LevelDBFooterBytes = 48
	// TableMagic is LevelDB's table magic, little-endian in the last eight
	// bytes.
	TableMagic uint64 = 0xdb4775248b80fb57
	// RocksDBTableMagic is RocksDB's block-based table magic. Tables with it
	// use a different footer and block framing and are refused explicitly.
	RocksDBTableMagic uint64 = 0x88e241b785f4cff7
	// InternalTagBytes is the size of the sequence/type tag every table key
	// ends with.
	InternalTagBytes = 8
)

// TableLimits bounds how much of a table a summary may read.
type TableLimits struct {
	// MaxScanBytes bounds the stored bytes of data blocks that may be
	// decoded.
	MaxScanBytes uint64
	// MaxEntries bounds entries the scan may visit.
	MaxEntries uint64
	// MaxBlocks bounds blocks the index may list.
	MaxBlocks int
}

// DefaultTableLimits returns the reference reader's table bounds.
func DefaultTableLimits() TableLimits {
	return TableLimits{
		MaxScanBytes: 64 * 1024 * 1024,
		MaxEntries:   4_000_000,
		MaxBlocks:    1_000_000,
	}
}

func (l TableLimits) normalized() TableLimits {
	defaults := DefaultTableLimits()
	if l.MaxScanBytes == 0 {
		l.MaxScanBytes = defaults.MaxScanBytes
	}
	if l.MaxEntries == 0 {
		l.MaxEntries = defaults.MaxEntries
	}
	if l.MaxBlocks == 0 {
		l.MaxBlocks = defaults.MaxBlocks
	}
	return l
}

// IndexEntry is one entry of the index block.
type IndexEntry struct {
	Separator []byte
	Handle    BlockHandle
}

// TableSummary is what a table says about itself.
type TableSummary struct {
	// Blocks is the number of data blocks the index lists.
	Blocks uint64
	// ScannedBlocks is the number of data blocks the scan decoded.
	ScannedBlocks uint64
	// Entries is the number of entries the scan visited.
	Entries uint64
	// Deleted is the number of entries whose value type is a deletion.
	Deleted uint64
	// Malformed is the number of entries whose internal key was too short to
	// carry a tag.
	Malformed uint64
	// ScanComplete is true when every data block was decoded.
	ScanComplete bool
	// FirstKey is the smallest user key, rendered.
	FirstKey *string
	// LastKey is the largest user key, rendered.
	LastKey *string
	// FirstSequence is the smallest sequence number the scan saw.
	FirstSequence *uint64
	// LastSequence is the largest sequence number the scan saw.
	LastSequence *uint64
	// KeyBytes is the sum of user-key bytes over the scanned entries.
	KeyBytes uint64
	// ValueBytes is the sum of value bytes over the scanned entries.
	ValueBytes uint64
	// CompressedBlocks is the number of data blocks stored compressed.
	CompressedBlocks uint64
	// Warnings are issues that do not stop the summary.
	Warnings []string
}

// Table is a LevelDB sorted table opened for random access.
type Table struct {
	src         source.ByteSource
	fileLen     uint64
	metaindex   BlockHandle
	index       BlockHandle
	indexFormat IndexValueFormat
}

// Identifies reports whether the file's last eight bytes carry a table magic.
func Identifies(src source.ByteSource) (bool, error) {
	length := src.Len()
	if length < 8 {
		return false, nil
	}
	tail, err := source.ReadVecAt(src, length-8, 8)
	if err != nil {
		return false, err
	}
	magic := le64(tail, 0)
	return magic == TableMagic || magic == RocksDBTableMagic, nil
}

// OpenTable opens a LevelDB table. It is the same operation as
// OpenTableSource.
func OpenTable(src source.ByteSource) (*Table, error) {
	return OpenTableSource(src)
}

// OpenTableSource reads and checks a table's footer. It does not read the
// index or any data block until asked.
func OpenTableSource(src source.ByteSource) (*Table, error) {
	fileLen := src.Len()
	if fileLen < LevelDBFooterBytes {
		return nil, corrupt(0, fmt.Sprintf(
			"a table of %d bytes is shorter than its %d-byte footer", fileLen, LevelDBFooterBytes))
	}
	footer, err := source.ReadVecAt(src, fileLen-LevelDBFooterBytes, LevelDBFooterBytes)
	if err != nil {
		return nil, err
	}
	magic := le64(footer, LevelDBFooterBytes-8)
	switch magic {
	case TableMagic:
		// LevelDB's footer: two handles in the first 40 bytes.
		metaindex, used, ok := DecodeBlockHandle(footer[:LevelDBFooterBytes-8])
		if !ok {
			return nil, corrupt(0, "the footer holds no metaindex handle")
		}
		index, _, ok := DecodeBlockHandle(footer[used : LevelDBFooterBytes-8])
		if !ok {
			return nil, corrupt(0, "the footer holds no index handle")
		}
		return checkedTable(src, fileLen, metaindex, index)
	case RocksDBTableMagic:
		return nil, unsupported("a RocksDB table: its footer and block framing differ from LevelDB's")
	default:
		return nil, corrupt(0, fmt.Sprintf(
			"the table footer magic is 0x%016x, not LevelDB's 0x%016x", magic, TableMagic))
	}
}

func checkedTable(src source.ByteSource, fileLen uint64, metaindex, index BlockHandle) (*Table, error) {
	if _, _, err := metaindex.Range(fileLen); err != nil {
		return nil, err
	}
	if _, _, err := index.Range(fileLen); err != nil {
		return nil, err
	}
	return &Table{
		src:       src,
		fileLen:   fileLen,
		metaindex: metaindex,
		index:     index,
	}, nil
}

// Metaindex returns the metaindex block handle.
func (t *Table) Metaindex() BlockHandle { return t.metaindex }

// IndexHandle returns the index block handle.
func (t *Table) IndexHandle() BlockHandle { return t.index }

// FileLen returns the table's length.
func (t *Table) FileLen() uint64 { return t.fileLen }

// IndexFormat returns how the index block encodes its values.
func (t *Table) IndexFormat() IndexValueFormat { return t.indexFormat }

// Block decodes one block by its handle: the named payload and its trailer.
// LevelDB block trailers are verified with CRC-32C.
func (t *Table) Block(handle BlockHandle) (*Block, error) {
	offset, size, err := handle.Range(t.fileLen)
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return nil, invalid("a block handle names zero bytes")
	}
	stored, err := source.ReadVecAt(t.src, offset, size+BlockTrailerBytes)
	if err != nil {
		return nil, err
	}
	return DecodeBlock(stored, ChecksumCRC32C, MaxBlockBytes)
}

// IndexEntries returns the index block's entries, refusing an index that lists
// at least maxBlocks entries.
func (t *Table) IndexEntries(maxBlocks int) ([]IndexEntry, error) {
	if maxBlocks <= 0 {
		return nil, limitError("the index block bound must be positive")
	}
	block, err := t.Block(t.index)
	if err != nil {
		return nil, err
	}
	entries := make([]IndexEntry, 0, min(maxBlocks, 64))
	_, err = block.ForEachIndex(t.indexFormat, func(key []byte, handle BlockHandle) bool {
		entries = append(entries, IndexEntry{
			Separator: append([]byte(nil), key...),
			Handle:    handle,
		})
		return len(entries) < maxBlocks
	})
	if err != nil {
		return nil, err
	}
	if len(entries) >= maxBlocks {
		return nil, limitError("the index lists at least %d blocks", maxBlocks)
	}
	return entries, nil
}

// Summary reads the footer and the index, then two data blocks for the key
// range, and finally scans data blocks up to a byte and entry bound. A table
// larger than the bound still reports its block count and key range with
// ScanComplete=false; it never reports a full count it did not compute.
func (t *Table) Summary(limits TableLimits) (TableSummary, error) {
	limits = limits.normalized()
	index, err := t.IndexEntries(limits.MaxBlocks)
	if err != nil {
		return TableSummary{}, err
	}
	summary := TableSummary{
		Blocks:       uint64(len(index)),
		ScanComplete: true,
	}
	if len(index) == 0 {
		summary.Warnings = append(summary.Warnings, "the table's index is empty")
		return summary, nil
	}

	// The index's first and last separators bound the table, but they are not
	// necessarily real keys. Reading the edge data blocks gives the actual
	// first and last user keys for two block reads.
	if block, err := t.Block(index[0].Handle); err == nil {
		if key, _, ok, err := block.First(); ok && err == nil {
			if user, ok := UserKey(key); ok {
				summary.FirstKey = ptr(RenderKey(user))
			}
		}
	}
	if block, err := t.Block(index[len(index)-1].Handle); err == nil {
		if key, _, ok, err := block.Last(); ok && err == nil {
			if user, ok := UserKey(key); ok {
				summary.LastKey = ptr(RenderKey(user))
			}
		}
	}

	var scannedBytes uint64
	for _, entry := range index {
		if summary.ScannedBlocks > 0 {
			overBytes := scannedBytes > limits.MaxScanBytes ||
				entry.Handle.Size > limits.MaxScanBytes-scannedBytes
			if overBytes || summary.Entries >= limits.MaxEntries {
				summary.ScanComplete = false
				break
			}
		}
		block, err := t.Block(entry.Handle)
		if err != nil {
			summary.Warnings = append(summary.Warnings, fmt.Sprintf(
				"data block %d could not be decoded: %v", summary.ScannedBlocks, err))
			summary.ScanComplete = false
			break
		}
		if block.Compression() != 0 {
			summary.CompressedBlocks++
		}
		scannedBytes += entry.Handle.Size
		summary.ScannedBlocks++
		stop := false
		_, err = block.ForEach(func(key, value []byte) bool {
			user, tag, ok := SplitInternalKey(key)
			if !ok {
				summary.Malformed++
				return true
			}
			summary.Entries++
			summary.KeyBytes += uint64(len(user))
			summary.ValueBytes += uint64(len(value))
			if tag.Kind == 0 {
				summary.Deleted++
			}
			summary.FirstSequence = ptr(minValue(summary.FirstSequence, tag.Sequence))
			summary.LastSequence = ptr(maxValue(summary.LastSequence, tag.Sequence))
			if summary.Entries >= limits.MaxEntries {
				stop = true
				return false
			}
			return true
		})
		if err != nil {
			summary.Warnings = append(summary.Warnings, fmt.Sprintf(
				"data block %d did not decode entry by entry: %v", summary.ScannedBlocks-1, err))
			summary.ScanComplete = false
			break
		}
		if stop {
			summary.ScanComplete = false
			break
		}
	}
	if summary.ScanComplete && summary.Malformed > 0 {
		summary.Warnings = append(summary.Warnings, fmt.Sprintf(
			"%d internal key(s) were too short to carry a sequence tag", summary.Malformed))
	}
	return summary, nil
}

func minValue(current *uint64, value uint64) uint64 {
	if current == nil || value < *current {
		return value
	}
	return *current
}

func maxValue(current *uint64, value uint64) uint64 {
	if current == nil || value > *current {
		return value
	}
	return *current
}
