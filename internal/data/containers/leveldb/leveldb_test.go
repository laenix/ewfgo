package leveldb

import (
	"strings"
	"testing"
)

func TestRouteFile(t *testing.T) {
	cases := []struct {
		path string
		kind Kind
		ok   bool
	}{
		{"/home/a/.config/app/leveldb/CURRENT", KindCurrent, true},
		{`C:\Users\a\AppData\Local\Google\Chrome\User Data\Default\Local Storage\leveldb\MANIFEST-000001`, KindManifest, true},
		{"/x/000123.ldb", KindTable, true},
		{"/x/000123.sst", KindTable, true},
		{"/x/Local Storage/leveldb/000003.log", KindWal, true},
		// An ordinary numeric log outside a leveldb directory is not a WAL.
		{"/var/log/000003.log", 0, false},
		{"/x/leveldb/LOG", 0, false},
		{"/x/leveldb/LOCK", 0, false},
		{"/x/current", 0, false},
	}
	for _, test := range cases {
		kind, ok := RouteFile(test.path)
		if ok != test.ok || (ok && kind != test.kind) {
			t.Fatalf("RouteFile(%q) = %v, %v; want %v, %v", test.path, kind, ok, test.kind, test.ok)
		}
	}
	if KindTable.Label() != "table" || KindManifest.Parser() != "leveldb-manifest" {
		t.Fatalf("kind labels = %q %q", KindTable.Label(), KindManifest.Parser())
	}
}

func TestSplitInternalKey(t *testing.T) {
	key := internalKey("user", 41, 1)
	user, tag, ok := SplitInternalKey(key)
	if !ok || string(user) != "user" || tag.Sequence != 41 || tag.Kind != 1 {
		t.Fatalf("split = %q %+v %v", user, tag, ok)
	}
	if _, _, ok := SplitInternalKey([]byte("short")); ok {
		t.Fatal("a short key split")
	}
	if UserKey := mustUserKey(t, key); UserKey != "user" {
		t.Fatalf("user key = %q", UserKey)
	}
}

func mustUserKey(t *testing.T, key []byte) string {
	t.Helper()
	user, ok := UserKey(key)
	if !ok {
		t.Fatal("UserKey failed")
	}
	return string(user)
}

func TestRenderKeyChoices(t *testing.T) {
	if got := RenderKey([]byte("plain")); got != "plain" {
		t.Fatalf("RenderKey plain = %q", got)
	}
	if got := RenderKey([]byte{0xff, 0x00}); got != "0xff00" {
		t.Fatalf("RenderKey binary = %q", got)
	}
	long := strings.Repeat("x", 70)
	got := RenderKey([]byte(long))
	if !strings.HasSuffix(got, "…") || len(got) != renderKeyLimit+len("…") {
		t.Fatalf("RenderKey long = %q", got)
	}
	if got := RenderInternalKey(internalKey("hello", 1, 1)); got != "hello" {
		t.Fatalf("RenderInternalKey = %q", got)
	}
}

func TestParseCurrentRejectsSeparators(t *testing.T) {
	if _, err := ParseCurrent([]byte(`MANIFEST-1/MANIFEST-2`)); err == nil {
		t.Fatal("a slash in CURRENT was accepted")
	}
}

func TestBlockIndexFormatRefusal(t *testing.T) {
	block, err := BlockFromBytes(buildRawBlock(nil))
	if err != nil {
		t.Fatalf("BlockFromBytes: %v", err)
	}
	if _, err := block.ForEachIndex(IndexValueFormat{DeltaEncoded: true}, func([]byte, BlockHandle) bool {
		return true
	}); err == nil {
		t.Fatal("a delta-encoded index was accepted")
	}
}
