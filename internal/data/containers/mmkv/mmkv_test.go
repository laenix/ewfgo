package mmkv

import (
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func varint(value uint64) []byte {
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

func textValue(text string) []byte {
	out := varint(uint64(len(text)))
	return append(out, text...)
}

func encodeRecord(key string, value []byte) []byte {
	out := varint(uint64(len(key)))
	out = append(out, key...)
	out = append(out, varint(uint64(len(value)))...)
	return append(out, value...)
}

func store(records ...[]byte) []byte {
	var entries []byte
	for _, rec := range records {
		entries = append(entries, rec...)
	}
	payload := varint(uint64(len(entries)))
	payload = append(payload, entries...)
	out := make([]byte, 4)
	putLE32(out, 0, uint32(len(payload)))
	return append(out, payload...)
}

func putLE32(b []byte, at int, v uint32) {
	b[at], b[at+1], b[at+2], b[at+3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}

func TestRouteFile(t *testing.T) {
	if kind, ok := RouteFile("/data/user/0/com.example/files/mmkv/mmkv.default"); !ok || kind != KindStore {
		t.Fatalf("RouteFile(store) = %v, %v", kind, ok)
	}
	if kind, ok := RouteFile(`C:\app\files\mmkv\mmkv.default.crc`); !ok || kind != KindMetaCrc {
		t.Fatalf("RouteFile(meta) = %v, %v", kind, ok)
	}
	if _, ok := RouteFile("/data/app/other/mmkv.default"); ok {
		t.Fatal("RouteFile claimed a file outside a mmkv directory")
	}
}

func TestParseStoreReplay(t *testing.T) {
	file := store(
		encodeRecord("a", textValue("hello")),
		encodeRecord("b", []byte{}),
		encodeRecord("a", textValue("new")),
	)
	store, err := Parse(file)
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}
	if store.Summary.Boundary != BoundaryHeader || store.Summary.Records != 3 ||
		store.Summary.Sets != 2 || store.Summary.Deletes != 1 {
		t.Fatalf("summary = %+v", store.Summary)
	}
	if store.Summary.LiveKeys != 1 || store.Summary.DeletedKeys != 1 || store.Summary.OverwrittenKeys != 1 {
		t.Fatalf("key counts = %+v", store.Summary)
	}
	if len(store.Keys) != 2 || store.Keys[0].Key != "a" || store.Keys[1].Key != "b" {
		t.Fatalf("keys = %+v", store.Keys)
	}
	a := store.Keys[0]
	if !a.Live || a.ValueLen != 4 || a.View == nil || a.View.Shape != ShapeText || a.View.Text != "new" {
		t.Fatalf("key a = %+v view %+v", a, a.View)
	}
	if b := store.Keys[1]; b.Live || b.Deletes != 1 || b.HasValue {
		t.Fatalf("key b = %+v", b)
	}
}

func TestParseContainerValue(t *testing.T) {
	nested := encodeRecord("inner", textValue("x"))
	value := append(varint(uint64(len(nested))), nested...)
	file := store(encodeRecord("cfg", value))
	store, err := Parse(file)
	if err != nil {
		t.Fatal(err)
	}
	view := store.Keys[0].View
	if view == nil || view.Shape != ShapeContainer || view.ContainerEntries != 1 {
		t.Fatalf("view = %+v", view)
	}
}

func TestParseScanFallback(t *testing.T) {
	file := store(encodeRecord("a", textValue("x")))
	putLE32(file, 0, 0)
	store, err := Parse(file)
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}
	if store.Summary.Boundary != BoundaryScan || store.Summary.Records != 1 {
		t.Fatalf("summary = %+v", store.Summary)
	}
}

func TestParseEmptyStore(t *testing.T) {
	store, err := Parse([]byte{0, 0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	if store.Summary.Boundary != BoundaryEmpty || len(store.Keys) != 0 {
		t.Fatalf("store = %+v", store.Summary)
	}
}

func TestParseUndecodableStore(t *testing.T) {
	file := []byte{100, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff}
	if _, err := Parse(file); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Parse error = %v, want ErrUnsupported", err)
	}
}

func TestRenderKeyHex(t *testing.T) {
	got := RenderKey([]byte{0xff, 0xfe})
	if got != "0xfffe" {
		t.Fatalf("RenderKey = %q", got)
	}
}

func TestParseMeta(t *testing.T) {
	bytes := make([]byte, MetaBytes)
	putLE32(bytes, 0, 0x11223344)
	putLE32(bytes, 4, 4)
	putLE32(bytes, 8, 9)
	copy(bytes[12:28], []byte("0123456789abcdef"))
	putLE32(bytes, 28, 1024)
	putLE32(bytes, 32, 1000)
	putLE32(bytes, 36, 0xAABBCCDD)
	meta, err := ParseMeta(bytes)
	if err != nil {
		t.Fatalf("ParseMeta error = %v", err)
	}
	if meta.CRC != 0x11223344 || meta.Version != 4 || meta.Sequence != 9 ||
		meta.ActualSize != 1024 || meta.LastActualSize != 1000 || meta.LastCRC != 0xAABBCCDD || meta.Short {
		t.Fatalf("meta = %+v", meta)
	}
	if _, err := ParseMeta(make([]byte, 8)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("ParseMeta(short) error = %v", err)
	}
}
