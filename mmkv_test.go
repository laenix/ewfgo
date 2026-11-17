package forensic_test

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	forensic "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/data/source"
)

func mmkvVarint(value uint64) []byte {
	var out []byte
	for {
		b := byte(value & 0x7F)
		value >>= 7
		if value == 0 {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

func mmkvRecord(key string, value []byte) []byte {
	out := mmkvVarint(uint64(len(key)))
	out = append(out, key...)
	out = append(out, mmkvVarint(uint64(len(value)))...)
	return append(out, value...)
}

func mmkvText(text string) []byte {
	return append(mmkvVarint(uint64(len(text))), text...)
}

func mmkvStore(records ...[]byte) []byte {
	var entries []byte
	for _, record := range records {
		entries = append(entries, record...)
	}
	payload := append(mmkvVarint(uint64(len(entries))), entries...)
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, uint32(len(payload)))
	return append(out, payload...)
}

func TestOpenMMKVStore(t *testing.T) {
	data := mmkvStore(
		mmkvRecord("a", mmkvText("hello")),
		mmkvRecord("b", []byte{}),
		mmkvRecord("a", mmkvText("new")),
	)
	path := filepath.Join(t.TempDir(), "mmkv.default")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	store, err := forensic.OpenMMKV(ctx, path, forensic.Options{})
	if err != nil {
		t.Fatalf("OpenMMKV: %v", err)
	}
	if store.Kind() != "store" || store.Path() != path {
		t.Fatalf("store = %q %q", store.Kind(), store.Path())
	}
	summary := store.Summary()
	if summary.Records != 3 || summary.Sets != 2 || summary.Deletes != 1 ||
		summary.LiveKeys != 1 || summary.DeletedKeys != 1 {
		t.Fatalf("summary = %+v", summary)
	}

	keys, err := store.Keys(ctx)
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("keys = %+v", keys)
	}
	a, ok, err := store.Lookup(ctx, "a")
	if err != nil || !ok {
		t.Fatalf("Lookup(a) = %v, %v", ok, err)
	}
	if !a.Live || a.Shape != "text" || a.Preview != "new" || a.ValueLen != 4 {
		t.Fatalf("key a = %+v", a)
	}
	b, ok, _ := store.Lookup(ctx, "b")
	if !ok || b.Live || b.HasValue || b.Deletes != 1 {
		t.Fatalf("key b = %+v", b)
	}
	if _, ok, _ := store.Lookup(ctx, "missing"); ok {
		t.Fatal("Lookup(missing) found a key")
	}
}

func TestOpenMMKVSource(t *testing.T) {
	data := mmkvStore(mmkvRecord("a", mmkvText("hello")))
	store, err := forensic.OpenMMKVSource(context.Background(), source.NewMemorySource(1, data), forensic.Options{})
	if err != nil {
		t.Fatalf("OpenMMKVSource: %v", err)
	}
	keys, err := store.Keys(context.Background())
	if err != nil || len(keys) != 1 || keys[0].Key != "a" || keys[0].Preview != "hello" {
		t.Fatalf("keys = %+v, %v", keys, err)
	}
}

func TestOpenMMKVRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mmkv.default")
	if err := os.WriteFile(path, []byte{100, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := forensic.OpenMMKV(context.Background(), path, forensic.Options{}); err == nil {
		t.Fatal("OpenMMKV accepted an undecodable store")
	}
}
