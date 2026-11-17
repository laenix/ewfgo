package forensic

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/laenix/ewfgo/internal/data/containers/realm"
	"github.com/laenix/ewfgo/internal/data/source"
)

// RealmDatabase is a decoded Realm database: tables, columns, rows and values.
// Columns of unsupported storage kinds keep their metadata and report the
// refusal; they are never given invented cells.
type RealmDatabase struct {
	path   string
	db     *realm.Database
	closer io.Closer
}

// RealmInfo summarizes a Realm database.
type RealmInfo struct {
	FormatVersion uint8
	FileSize      uint64
	LogicalSize   uint64
	Tables        int
	Rows          int
	Columns       int
	Warnings      []string
	Refusals      []string
}

// RealmTable is one decoded object table.
type RealmTable struct {
	Name     string
	Key      uint32
	Columns  []RealmColumn
	Rows     []RealmRow
	Warnings []string
}

// RealmColumn describes one table column.
type RealmColumn struct {
	Name        string
	Type        string
	Nullable    bool
	Indexed     bool
	Unique      bool
	Collection  bool
	Unsupported string
}

// RealmRow is one object record. Cells are in column-spec order.
type RealmRow struct {
	Key   uint64
	Index int
	Cells []RealmCell
}

// RealmCell is one column value in a row.
type RealmCell struct {
	Column int
	Value  RealmValue
}

// RealmValue is a decoded Realm value.
type RealmValue struct {
	Kind  string
	Int   int64
	Bool  bool
	Float float32
	// Double is the double-precision variant.
	Double float64
	// String is the string variant.
	String string
	// Binary is the binary variant; the slice is a copy.
	Binary []byte
	// LinkKey is the target object key for a link.
	LinkKey int64
	// Timestamp is set for the timestamp variant.
	Timestamp    time.Time
	HasTimestamp bool
}

// OpenRealm opens a Realm database file.
func OpenRealm(ctx context.Context, imagePath string, opts Options) (*RealmDatabase, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw, err := source.OpenRawFileWithSectorSize(imagePath, 1, 1, opts.sectorSize(nil, 512))
	if err != nil {
		return nil, fmt.Errorf("open Realm database %s: %w", imagePath, err)
	}
	db, err := OpenRealmSource(ctx, raw, opts)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("parse Realm database %s: %w", imagePath, err)
	}
	db.path = imagePath
	db.closer = raw
	return db, nil
}

// OpenRealmSource opens a Realm database over an existing byte source. The
// source is not closed by RealmDatabase.Close.
func OpenRealmSource(ctx context.Context, src ByteSource, opts Options) (*RealmDatabase, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, fmt.Errorf("%w: nil Realm source", ErrInvalidArgument)
	}
	limits := realm.DefaultLimits()
	if opts.Limits.MaxFileBytes != 0 && opts.Limits.MaxFileBytes < limits.MaxFileBytes {
		limits.MaxFileBytes = opts.Limits.MaxFileBytes
	}
	if opts.Limits.MaxEntries != 0 && opts.Limits.MaxEntries < uint64(limits.MaxRows) {
		limits.MaxRows = opts.Limits.MaxEntries
	}
	db, err := realm.OpenWithLimits(1, src, limits)
	if err != nil {
		return nil, err
	}
	return &RealmDatabase{db: db}, nil
}

// Path returns the database path.
func (d *RealmDatabase) Path() string { return d.path }

// Info returns the database summary.
func (d *RealmDatabase) Info() RealmInfo {
	return RealmInfo{
		FormatVersion: d.db.Header.FormatVersion,
		FileSize:      d.db.Header.FileSize,
		LogicalSize:   d.db.Header.LogicalSize,
		Tables:        len(d.db.Tables),
		Rows:          d.db.RowCount(),
		Columns:       d.db.ColumnCount(),
		Warnings:      append([]string(nil), d.db.Warnings...),
		Refusals:      d.db.Refusals(),
	}
}

// Tables returns every decoded table.
func (d *RealmDatabase) Tables(ctx context.Context) ([]RealmTable, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	out := make([]RealmTable, 0, len(d.db.Tables))
	for index := range d.db.Tables {
		out = append(out, convertRealmTable(&d.db.Tables[index]))
	}
	return out, nil
}

func convertRealmTable(table *realm.Table) RealmTable {
	converted := RealmTable{
		Name: table.Name, Key: table.Key,
		Warnings: append([]string(nil), table.Warnings...),
	}
	converted.Columns = make([]RealmColumn, 0, len(table.Columns))
	for columnIndex := range table.Columns {
		column := &table.Columns[columnIndex]
		converted.Columns = append(converted.Columns, RealmColumn{
			Name: column.Name, Type: column.Type.Label(),
			Nullable: column.Nullable, Indexed: column.Indexed,
			Unique: column.Unique, Collection: column.Collection,
			Unsupported: column.Unsupported,
		})
	}
	converted.Rows = make([]RealmRow, 0, len(table.Rows))
	for rowIndex := range table.Rows {
		row := &table.Rows[rowIndex]
		convertedRow := RealmRow{Key: row.Key, Index: row.Index}
		convertedRow.Cells = make([]RealmCell, 0, len(row.Cells))
		for cellIndex := range row.Cells {
			cell := &row.Cells[cellIndex]
			convertedRow.Cells = append(convertedRow.Cells, RealmCell{
				Column: cell.Column,
				Value:  convertRealmValue(cell.Value),
			})
		}
		converted.Rows = append(converted.Rows, convertedRow)
	}
	return converted
}

// Table returns one table by name.
func (d *RealmDatabase) Table(ctx context.Context, name string) (*RealmTable, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	table, ok := d.db.FindTable(name)
	if !ok {
		return nil, fmt.Errorf("%w: Realm database has no table %q", ErrInvalidArgument, name)
	}
	converted := convertRealmTable(table)
	return &converted, nil
}

func convertRealmValue(value realm.Value) RealmValue {
	out := RealmValue{
		Kind: value.Kind.String(),
		Int:  value.Int, Bool: value.Bool,
		Float: value.Float, Double: value.Double,
		String:  value.String,
		Binary:  append([]byte(nil), value.Binary...),
		LinkKey: value.LinkKey,
	}
	if value.Kind == realm.ValueTimestamp {
		out.Timestamp = time.Unix(value.TimestampSeconds, int64(value.TimestampNanos)).UTC()
		out.HasTimestamp = true
	}
	return out
}

// Close releases the database file.
func (d *RealmDatabase) Close() error {
	if d.closer == nil {
		return nil
	}
	err := d.closer.Close()
	d.closer = nil
	return err
}
