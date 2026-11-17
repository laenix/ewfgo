package leveldb

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Limits bounds a directory-wide store read. The zero value applies the
// defaults through OpenStore.
type Limits struct {
	// MaxInMemoryBytes bounds a whole manifest or WAL copied into memory.
	MaxInMemoryBytes uint64
	// MaxFiles bounds the directory entries a store read will consider.
	MaxFiles int
	// Table bounds each table summary.
	Table TableLimits
	// Log bounds each manifest and WAL scan.
	Log LogLimits
}

// DefaultLimits returns the reference reader's store bounds.
func DefaultLimits() Limits {
	return Limits{
		MaxInMemoryBytes: MaxInMemoryBytes,
		MaxFiles:         10_000,
		Table:            DefaultTableLimits(),
		Log:              DefaultLogLimits(),
	}
}

func (l Limits) normalized() Limits {
	defaults := DefaultLimits()
	if l.MaxInMemoryBytes == 0 {
		l.MaxInMemoryBytes = defaults.MaxInMemoryBytes
	}
	if l.MaxFiles <= 0 {
		l.MaxFiles = defaults.MaxFiles
	}
	l.Table = l.Table.normalized()
	l.Log = l.Log.normalized()
	return l
}

// TableFile is one sorted table found in a store.
type TableFile struct {
	Number  uint64
	Name    string
	Live    bool
	Table   *Table
	Summary TableSummary
}

// LogFile is one write-ahead log found in a store.
type LogFile struct {
	Number uint64
	Name   string
	Log    *Log
}

// Store is a decoded LevelDB directory.
type Store struct {
	Dir string
	// CurrentManifest is the name CURRENT points at.
	CurrentManifest string
	// ManifestFiles lists every MANIFEST-* file seen in the directory.
	ManifestFiles []string
	// Manifest is the decoded CURRENT manifest.
	Manifest *Manifest
	// Tables are the sorted tables, ordered by file number.
	Tables []TableFile
	// Logs are the write-ahead logs, ordered by file number.
	Logs []LogFile
	// Warnings are per-file issues that did not stop the store read.
	Warnings []string

	closed bool
}

// Close releases the table files the store opened. It is safe to call more than
// once; after Close, the tables' random-access methods fail.
func (s *Store) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	var first error
	for index := range s.Tables {
		table := s.Tables[index].Table
		if table == nil {
			continue
		}
		src, ok := table.src.(*fileSource)
		if !ok {
			continue
		}
		if err := src.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// OpenStore reads a LevelDB store directory: CURRENT, the manifest it names,
// and every table and write-ahead log beside them.
//
// A file named like a table is only parsed when its footer carries a table
// magic; anything else is reported in Warnings and never fabricated into a
// table. Essential files (CURRENT and its manifest) are errors when they
// cannot be read.
func OpenStore(dir string, limits Limits) (*Store, error) {
	limits = limits.normalized()
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("leveldb: stat store %q: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, invalid(fmt.Sprintf("store path %q is not a directory", dir))
	}
	currentBytes, err := readFileBounded(filepath.Join(dir, "CURRENT"), limits.MaxInMemoryBytes)
	if err != nil {
		return nil, fmt.Errorf("leveldb: read CURRENT: %w", err)
	}
	manifestName, err := ParseCurrent(currentBytes)
	if err != nil {
		return nil, err
	}
	if !safeStoreName(manifestName) {
		return nil, invalid(fmt.Sprintf("CURRENT names `%s`, which is not a plain file name", manifestName))
	}
	manifestBytes, err := readFileBounded(filepath.Join(dir, manifestName), limits.MaxInMemoryBytes)
	if err != nil {
		return nil, fmt.Errorf("leveldb: read %s: %w", manifestName, err)
	}
	manifest, err := parseManifestBytes(manifestBytes, limits.Log)
	if err != nil {
		return nil, fmt.Errorf("leveldb: decode %s: %w", manifestName, err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("leveldb: list %q: %w", dir, err)
	}
	if len(entries) > limits.MaxFiles {
		return nil, limitError("the store holds %d entries, above the %d-file bound", len(entries), limits.MaxFiles)
	}

	store := &Store{Dir: dir, CurrentManifest: manifestName, Manifest: manifest}
	liveNumbers := make(map[uint64]bool, len(manifest.LiveTables))
	for _, table := range manifest.LiveTables {
		liveNumbers[table.Number] = true
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		lowered := strings.ToLower(name)
		if name == "CURRENT" {
			continue
		}
		path := filepath.Join(dir, name)
		switch {
		case strings.HasPrefix(lowered, "manifest-"):
			store.ManifestFiles = append(store.ManifestFiles, name)
		case strings.HasSuffix(lowered, ".ldb") || strings.HasSuffix(lowered, ".sst"):
			number, ok := parseFileNumber(name[:len(name)-4])
			if !ok {
				store.Warnings = append(store.Warnings, fmt.Sprintf(
					"table file %q is not numbered and was skipped", name))
				continue
			}
			table, summary, reason := openStoreTable(path, limits)
			if reason != "" {
				store.Warnings = append(store.Warnings, reason)
				continue
			}
			store.Tables = append(store.Tables, TableFile{
				Number:  number,
				Name:    name,
				Live:    liveNumbers[number],
				Table:   table,
				Summary: summary,
			})
		case strings.HasSuffix(lowered, ".log"):
			number, ok := parseFileNumber(name[:len(name)-4])
			if !ok {
				continue
			}
			logBytes, err := readFileBounded(path, limits.MaxInMemoryBytes)
			if err != nil {
				store.Warnings = append(store.Warnings, fmt.Sprintf("wal file %q could not be read: %v", name, err))
				continue
			}
			wal, err := parseWalBytes(logBytes, limits.Log)
			if err != nil {
				store.Warnings = append(store.Warnings, fmt.Sprintf("wal file %q could not be decoded: %v", name, err))
				continue
			}
			store.Logs = append(store.Logs, LogFile{Number: number, Name: name, Log: wal})
		}
	}

	sort.Strings(store.ManifestFiles)
	sort.Slice(store.Tables, func(i, j int) bool { return store.Tables[i].Number < store.Tables[j].Number })
	sort.Slice(store.Logs, func(i, j int) bool { return store.Logs[i].Number < store.Logs[j].Number })

	seen := make(map[uint64]bool, len(store.Tables))
	for _, table := range store.Tables {
		seen[table.Number] = true
	}
	for _, table := range manifest.LiveTables {
		if !seen[table.Number] {
			store.Warnings = append(store.Warnings, fmt.Sprintf(
				"the manifest names live table %d, which is not present as a readable table", table.Number))
		}
	}
	return store, nil
}

// openStoreTable opens and summarizes one candidate table file. A non-empty
// reason means the file was skipped.
func openStoreTable(path string, limits Limits) (*Table, TableSummary, string) {
	file, err := os.Open(path)
	if err != nil {
		return nil, TableSummary{}, fmt.Sprintf("table file %q could not be opened: %v", path, err)
	}
	src, err := newFileSource(file)
	if err != nil {
		file.Close()
		return nil, TableSummary{}, fmt.Sprintf("table file %q could not be sized: %v", path, err)
	}
	identifies, err := Identifies(src)
	if err != nil {
		src.Close()
		return nil, TableSummary{}, fmt.Sprintf("table file %q could not be read: %v", path, err)
	}
	if !identifies {
		src.Close()
		return nil, TableSummary{}, fmt.Sprintf(
			"%q is named like a table but carries no table footer magic; it was skipped", filepath.Base(path))
	}
	table, err := OpenTableSource(src)
	if err != nil {
		src.Close()
		return nil, TableSummary{}, fmt.Sprintf("table file %q is not a readable table: %v", path, err)
	}
	summary, err := table.Summary(limits.Table)
	if err != nil {
		src.Close()
		return nil, TableSummary{}, fmt.Sprintf("table file %q could not be summarized: %v", path, err)
	}
	return table, summary, ""
}

func parseFileNumber(stem string) (uint64, bool) {
	if !isASCIIDigits(stem) {
		return 0, false
	}
	number, err := strconv.ParseUint(stem, 10, 64)
	if err != nil {
		return 0, false
	}
	return number, true
}

func safeStoreName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	return filepath.Base(name) == name && !strings.ContainsAny(name, `/\:`)
}

// readFileBounded reads a whole file after checking its size against a bound.
func readFileBounded(path string, max uint64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	size := info.Size()
	if size < 0 || uint64(size) > max {
		return nil, limitError("a %d-byte file is above the %d-byte in-memory bound", size, max)
	}
	if size > int64(^uint(0)>>1) {
		return nil, limitError("a %d-byte file does not fit an in-memory slice", size)
	}
	data := make([]byte, int(size))
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, err
	}
	return data, nil
}

// nextFileSourceID hands out distinct source IDs for files opened by a store.
var nextFileSourceID atomic.Uint64

// fileSource adapts an os.File to source.ByteSource so a large table can be
// read block by block instead of being copied into memory.
type fileSource struct {
	file     *os.File
	size     uint64
	id       source.ID
	imageID  source.ImageID
	counters source.Counters
}

func newFileSource(file *os.File) (*fileSource, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() < 0 {
		return nil, invalid("a file reports a negative size")
	}
	return &fileSource{
		file:    file,
		size:    uint64(info.Size()),
		id:      source.ID(nextFileSourceID.Add(1)),
		imageID: source.ImageID(nextFileSourceID.Load()),
	}, nil
}

// Close releases the backing file.
func (s *fileSource) Close() error { return s.file.Close() }

// SourceID implements source.ByteSource.
func (s *fileSource) SourceID() source.ID { return s.id }

// ImageID implements source.ByteSource.
func (s *fileSource) ImageID() source.ImageID { return s.imageID }

// Len implements source.ByteSource.
func (s *fileSource) Len() uint64 { return s.size }

// SectorSize implements source.ByteSource.
func (s *fileSource) SectorSize() uint32 { return 512 }

// ReadAt implements source.ByteSource. A start at or past EOF is OutOfRange
// and a request crossing EOF is a normal short read.
func (s *fileSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= s.size {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), s.size)
	}
	n, err := s.file.ReadAt(buf, int64(offset))
	if err == io.EOF {
		s.counters.AddRead(n)
		return n, nil
	}
	if err != nil {
		return n, source.NewIOError(offset, err)
	}
	s.counters.AddRead(n)
	return n, nil
}

// ReadAtLossy implements source.ByteSource. A plain file has no damaged
// regions, so it is identical to ReadAt.
func (s *fileSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	return s.ReadAt(offset, buf)
}

// ExtentsInto implements source.ByteSource.
func (s *fileSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > s.size || length > s.size-offset {
		return out, source.NewOutOfRange(offset, length, s.size)
	}
	if length > 0 {
		out = append(out, source.ParentRange{
			Parent:       s.id,
			ParentOffset: offset,
			Len:          length,
			Kind:         source.RangeData,
		})
	}
	return out, nil
}

// Extents implements source.ByteSource.
func (s *fileSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

// MapToImage implements source.ByteSource.
func (s *fileSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	if offset > s.size || length > s.size-offset {
		return nil, source.NewOutOfRange(offset, length, s.size)
	}
	if length == 0 {
		return nil, nil
	}
	return []source.ImageRange{{
		ImageID:     s.imageID,
		ImageOffset: offset,
		Len:         length,
		Kind:        source.RangeData,
	}}, nil
}

// Stats implements source.ByteSource.
func (s *fileSource) Stats() source.Stats { return s.counters.Snapshot() }

// IsEmpty implements source.ByteSource.
func (s *fileSource) IsEmpty() bool { return s.size == 0 }
