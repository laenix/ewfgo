package leveldb

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestFile(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func storeManifest(tableNumber uint64, extra ...EncodedEdit) []byte {
	level := uint32(0)
	edits := append([]EncodedEdit{{
		Added: []EncodedFile{{
			Level:    level,
			Number:   tableNumber,
			Size:     64,
			Smallest: internalKey("a", 1, 1),
			Largest:  internalKey("m", 2, 1),
		}},
	}}, extra...)
	return encodeManifest(edits...)
}

func TestOpenStoreReadsCurrentManifestTablesAndWal(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "CURRENT", []byte("MANIFEST-000001\n"))
	writeTestFile(t, dir, "MANIFEST-000001", storeManifest(2))

	liveTable := buildTable([]tableBlockSpec{
		{entries: []testKV{{key: internalKey("a", 1, 1), value: []byte("value")}}},
	})
	writeTestFile(t, dir, "000002.ldb", liveTable.bytes)

	secondTable := buildTable([]tableBlockSpec{
		{entries: []testKV{{key: internalKey("n", 3, 1), value: []byte("other")}}},
	})
	writeTestFile(t, dir, "000005.sst", secondTable.bytes)

	// A file named like a table but without the footer magic must never be
	// reported as a table.
	writeTestFile(t, dir, "000004.ldb", []byte("this is not a table"))

	wal := EncodeFullRecord(EncodeBatch(9, []BatchEntry{
		{Key: []byte("k"), Value: []byte("v")},
	}))
	writeTestFile(t, dir, "000003.log", wal)

	store, err := OpenStore(dir, Limits{})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.Close()
	if store.CurrentManifest != "MANIFEST-000001" {
		t.Fatalf("current = %q", store.CurrentManifest)
	}
	if store.Manifest == nil || store.Manifest.Edits != 1 {
		t.Fatalf("manifest = %+v", store.Manifest)
	}
	if len(store.ManifestFiles) != 1 || store.ManifestFiles[0] != "MANIFEST-000001" {
		t.Fatalf("manifest files = %v", store.ManifestFiles)
	}
	if len(store.Tables) != 2 {
		t.Fatalf("tables = %+v, warnings = %v", store.Tables, store.Warnings)
	}
	if store.Tables[0].Number != 2 || !store.Tables[0].Live || store.Tables[0].Summary.Entries != 1 {
		t.Fatalf("live table = %+v", store.Tables[0])
	}
	if store.Tables[1].Number != 5 || store.Tables[1].Live {
		t.Fatalf("second table = %+v", store.Tables[1])
	}
	if len(store.Logs) != 1 || store.Logs[0].Number != 3 || store.Logs[0].Log.Batches != 1 {
		t.Fatalf("logs = %+v", store.Logs)
	}
	foundWarning := false
	for _, warning := range store.Warnings {
		if strings.Contains(warning, "no table footer magic") {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Fatalf("warnings = %v", store.Warnings)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestOpenStoreReportsMissingLiveTable(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "CURRENT", []byte("MANIFEST-000001\n"))
	writeTestFile(t, dir, "MANIFEST-000001", storeManifest(42))
	store, err := OpenStore(dir, Limits{})
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer store.Close()
	if len(store.Tables) != 0 {
		t.Fatalf("tables = %+v", store.Tables)
	}
	found := false
	for _, warning := range store.Warnings {
		if strings.Contains(warning, "live table 42") {
			found = true
		}
	}
	if !found {
		t.Fatalf("warnings = %v", store.Warnings)
	}
}

func TestOpenStoreRequiresAValidCurrent(t *testing.T) {
	dir := t.TempDir()
	if _, err := OpenStore(dir, Limits{}); err == nil {
		t.Fatal("a store without CURRENT opened")
	}
	writeTestFile(t, dir, "CURRENT", []byte("../MANIFEST-000001\n"))
	if _, err := OpenStore(dir, Limits{}); err == nil {
		t.Fatal("CURRENT naming a path opened")
	}
	writeTestFile(t, dir, "CURRENT", []byte("..\n"))
	if _, err := OpenStore(dir, Limits{}); err == nil {
		t.Fatal("CURRENT naming the parent directory opened")
	}
}

func TestOpenStoreFileBound(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "CURRENT", []byte("MANIFEST-000001\n"))
	writeTestFile(t, dir, "MANIFEST-000001", storeManifest(1))
	writeTestFile(t, dir, "000001.ldb", buildTable(nil).bytes)
	limits := Limits{MaxFiles: 1}
	if _, err := OpenStore(dir, limits); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err = %v, want a limit error", err)
	}
}

func TestOpenStoreRefusesAnOversizedDataFile(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "CURRENT", []byte("MANIFEST-000001\n"))
	writeTestFile(t, dir, "MANIFEST-000001", storeManifest(2))
	writeTestFile(t, dir, "000002.ldb", buildTable([]tableBlockSpec{
		{entries: []testKV{{key: internalKey("a", 1, 1), value: []byte("v")}}},
	}).bytes)
	limits := Limits{MaxInMemoryBytes: 8}
	// CURRENT itself is above the bound, so the store read stops explicitly.
	if _, err := OpenStore(dir, limits); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err = %v, want a limit error", err)
	}
}
