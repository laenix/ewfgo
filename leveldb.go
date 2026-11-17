package forensic

import (
	"context"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/containers/leveldb"
)

// LevelDB is a decoded LevelDB store directory: CURRENT, the manifest it
// names, and the tables and write-ahead logs beside them. LevelDB is the
// key/value store behind Chromium local storage, IndexedDB and many Android
// application databases.
type LevelDB struct {
	dir   string
	store *leveldb.Store
}

// LevelDBInfo summarizes a store.
type LevelDBInfo struct {
	Path                 string
	CurrentManifest      string
	ManifestFiles        int
	ManifestRecords      uint64
	ManifestEdits        uint64
	ManifestComplete     bool
	ManifestCRCErrors    uint64
	ManifestDecodeErrors uint64
	LiveTables           int
	Tables               int
	Logs                 int
	TableBytes           uint64
	LogEntries           uint64
	LogDeletions         uint64
	Warnings             int
}

// LevelDBTable describes one sorted table.
type LevelDBTable struct {
	Number           uint64
	Name             string
	Live             bool
	Blocks           uint64
	ScannedBlocks    uint64
	Entries          uint64
	Deleted          uint64
	Malformed        uint64
	ScanComplete     bool
	CompressedBlocks uint64
	FirstKey         string
	LastKey          string
	FirstSequence    *uint64
	LastSequence     *uint64
	KeyBytes         uint64
	ValueBytes       uint64
}

// LevelDBLog describes one write-ahead log.
type LevelDBLog struct {
	Number           uint64
	Name             string
	Records          uint64
	Batches          uint64
	Entries          uint64
	Deletions        uint64
	ChecksumFailures uint64
	DecodeFailures   uint64
	FirstSequence    *uint64
	LastSequence     *uint64
	FirstKey         string
	LastKey          string
	StoppedAtLimit   bool
}

// OpenLevelDB reads a LevelDB store directory. Files named like tables but
// without a table footer magic are reported as warnings, never parsed as
// tables.
func OpenLevelDB(dir string, opts Options) (*LevelDB, error) {
	limits := leveldb.DefaultLimits()
	if max := opts.Limits.MaxFileBytes; max != 0 && max < limits.MaxInMemoryBytes {
		limits.MaxInMemoryBytes = max
	}
	store, err := leveldb.OpenStore(dir, limits)
	if err != nil {
		return nil, err
	}
	return &LevelDB{dir: dir, store: store}, nil
}

// Path returns the store directory.
func (l *LevelDB) Path() string { return l.dir }

// Info returns the store summary.
func (l *LevelDB) Info() LevelDBInfo {
	info := LevelDBInfo{
		Path:            l.dir,
		CurrentManifest: l.store.CurrentManifest,
		ManifestFiles:   len(l.store.ManifestFiles),
		Tables:          len(l.store.Tables),
		Logs:            len(l.store.Logs),
		Warnings:        len(l.store.Warnings),
	}
	if manifest := l.store.Manifest; manifest != nil {
		info.ManifestRecords = manifest.Records
		info.ManifestEdits = manifest.Edits
		info.ManifestComplete = manifest.Complete
		info.ManifestCRCErrors = manifest.ChecksumFailures
		info.ManifestDecodeErrors = manifest.DecodeFailures
		info.LiveTables = len(manifest.LiveTables)
	}
	for _, table := range l.store.Tables {
		info.TableBytes += table.Summary.KeyBytes + table.Summary.ValueBytes
	}
	for _, log := range l.store.Logs {
		if log.Log == nil {
			continue
		}
		info.LogEntries += log.Log.Entries
		info.LogDeletions += log.Log.Deletions
	}
	return info
}

// Tables returns the sorted tables, ordered by file number.
func (l *LevelDB) Tables(ctx context.Context) ([]LevelDBTable, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	out := make([]LevelDBTable, 0, len(l.store.Tables))
	for _, table := range l.store.Tables {
		entry := LevelDBTable{
			Number:           table.Number,
			Name:             table.Name,
			Live:             table.Live,
			Blocks:           table.Summary.Blocks,
			ScannedBlocks:    table.Summary.ScannedBlocks,
			Entries:          table.Summary.Entries,
			Deleted:          table.Summary.Deleted,
			Malformed:        table.Summary.Malformed,
			ScanComplete:     table.Summary.ScanComplete,
			CompressedBlocks: table.Summary.CompressedBlocks,
			FirstSequence:    table.Summary.FirstSequence,
			LastSequence:     table.Summary.LastSequence,
			KeyBytes:         table.Summary.KeyBytes,
			ValueBytes:       table.Summary.ValueBytes,
		}
		if table.Summary.FirstKey != nil {
			entry.FirstKey = *table.Summary.FirstKey
		}
		if table.Summary.LastKey != nil {
			entry.LastKey = *table.Summary.LastKey
		}
		out = append(out, entry)
	}
	return out, nil
}

// Logs returns the write-ahead logs, ordered by file number.
func (l *LevelDB) Logs(ctx context.Context) ([]LevelDBLog, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	out := make([]LevelDBLog, 0, len(l.store.Logs))
	for _, log := range l.store.Logs {
		if log.Log == nil {
			continue
		}
		entry := LevelDBLog{
			Number:           log.Number,
			Name:             log.Name,
			Records:          log.Log.Records,
			Batches:          log.Log.Batches,
			Entries:          log.Log.Entries,
			Deletions:        log.Log.Deletions,
			ChecksumFailures: log.Log.ChecksumFailures,
			DecodeFailures:   log.Log.DecodeFailures,
			FirstSequence:    log.Log.FirstSequence,
			LastSequence:     log.Log.LastSequence,
			StoppedAtLimit:   log.Log.StoppedAtLimit,
		}
		if log.Log.FirstKey != nil {
			entry.FirstKey = *log.Log.FirstKey
		}
		if log.Log.LastKey != nil {
			entry.LastKey = *log.Log.LastKey
		}
		out = append(out, entry)
	}
	return out, nil
}

// Warnings returns non-fatal per-file issues.
func (l *LevelDB) Warnings(ctx context.Context) ([]string, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	return append([]string(nil), l.store.Warnings...), nil
}

// Close releases the table files the store opened. It is idempotent.
func (l *LevelDB) Close() error {
	if l.store == nil {
		return nil
	}
	err := l.store.Close()
	l.store = nil
	return err
}

// String names the store for diagnostics.
func (l *LevelDB) String() string {
	return fmt.Sprintf("LevelDB(%s)", l.dir)
}
