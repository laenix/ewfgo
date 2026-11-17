package dmg

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func rawBinaryPlist(objects [][]byte, top uint64) []byte {
	out := append([]byte(nil), BinaryPlistSignature...)
	offsets := make([]uint16, 0, len(objects))
	for _, object := range objects {
		offsets = append(offsets, uint16(len(out)))
		out = append(out, object...)
	}
	tableOffset := len(out)
	for _, offset := range offsets {
		out = append(out, byte(offset>>8), byte(offset))
	}
	var trailer [32]byte
	trailer[6] = 2
	trailer[7] = 1
	putBE64(trailer[:], 8, uint64(len(objects)))
	putBE64(trailer[:], 16, top)
	putBE64(trailer[:], 24, uint64(tableOffset))
	return append(out, trailer[:]...)
}

func TestBinaryPlistObjectTypes(t *testing.T) {
	objects := [][]byte{
		{0x00},                         // 0 null
		{0x09},                         // 1 bool
		{0x42, 'h', 'i'},               // 2 data
		{0x53, 'a', 'b', 'c'},          // 3 ascii string
		{0x63, 0, 'a', 0, 'b', 0, 'c'}, // 4 UTF-16BE "abc"
		{0xA2, 0x02, 0x03},             // 5 array of objects 2 and 3
		{0xD2, 0x03, 0x00, 0x02, 0x04}, // 6 dict: "abc" -> data(2)
	}
	document := rawBinaryPlist(objects, 0)
	plist, err := openBinaryPlist(document)
	if err != nil {
		t.Fatalf("openBinaryPlist error = %v", err)
	}
	if _, err := plist.object(0); err != nil {
		t.Fatalf("null error = %v", err)
	}
	if _, err := plist.object(1); err != nil {
		t.Fatalf("bool error = %v", err)
	}
	data, err := plist.object(2)
	if err != nil || data.kind != plistData || string(data.data) != "hi" {
		t.Fatalf("data = %+v, %v", data, err)
	}
	text, err := plist.object(3)
	if err != nil || text.kind != plistString || text.text != "abc" {
		t.Fatalf("ascii = %+v, %v", text, err)
	}
	text, err = plist.object(4)
	if err != nil || text.kind != plistString || text.text != "abc" {
		t.Fatalf("utf16 = %+v, %v", text, err)
	}
	array, err := plist.object(5)
	if err != nil || len(array.refs) != 2 || array.refs[0] != 2 || array.refs[1] != 3 {
		t.Fatalf("array = %+v, %v", array, err)
	}
	dict, err := plist.object(6)
	if err != nil || len(dict.pairs) != 2 {
		t.Fatalf("dict = %+v, %v", dict, err)
	}
	value, err := plist.lookup(dict.pairs, "abc")
	if err != nil || value != 2 {
		t.Fatalf("lookup = %d, %v", value, err)
	}
	if _, err := plist.lookup(dict.pairs, "missing"); err != nil {
		t.Fatalf("missing lookup error = %v", err)
	}
}

func TestBinaryPlistExtendedLengths(t *testing.T) {
	longData := bytes.Repeat([]byte{'x'}, 20)
	object := append([]byte{0x4F, 0x12, 0, 0, 0, 20}, longData...)
	document := rawBinaryPlist([][]byte{object}, 0)
	plist, err := openBinaryPlist(document)
	if err != nil {
		t.Fatal(err)
	}
	data, err := plist.object(0)
	if err != nil || data.kind != plistData || len(data.data) != 20 {
		t.Fatalf("data = %+v, %v", data, err)
	}

	// An extended length whose follower is not an integer is refused.
	document = rawBinaryPlist([][]byte{{0x4F, 0x50}}, 0)
	plist, err = openBinaryPlist(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plist.object(0); err == nil {
		t.Fatal("a non-integer extended length was accepted")
	}

	// An extended reference array.
	array := append([]byte{0xAF, 0x12, 0, 0, 0, 2, 0, 0}, make([]byte, 0)...)
	array = append(array, 0x00, 0x01)
	document = rawBinaryPlist([][]byte{{0x00}, {0x00}, array}, 2)
	plist, err = openBinaryPlist(document)
	if err != nil {
		t.Fatal(err)
	}
	refs, err := plist.object(2)
	if err != nil || len(refs.refs) != 2 {
		t.Fatalf("refs = %+v, %v", refs, err)
	}
}

func TestBinaryPlistRefusals(t *testing.T) {
	valid := rawBinaryPlist([][]byte{{0x00}}, 0)

	if _, err := openBinaryPlist(valid[:20]); err == nil {
		t.Fatal("a document shorter than its trailer was accepted")
	}
	for _, patch := range []struct {
		at    int
		value byte
	}{
		{len(valid) - 32 + 6, 0},  // offset size 0
		{len(valid) - 32 + 7, 0},  // reference size 0
		{len(valid) - 32 + 15, 0}, // object count low byte -> 0
	} {
		document := append([]byte(nil), valid...)
		document[patch.at] = patch.value
		if _, err := openBinaryPlist(document); err == nil {
			t.Fatalf("malformed trailer at %d was accepted", patch.at)
		}
	}

	// Top object out of range.
	document := append([]byte(nil), valid...)
	putBE64(document, len(document)-32+16, 99)
	if _, err := openBinaryPlist(document); err == nil {
		t.Fatal("an out-of-range top object was accepted")
	}

	// Offset table past the trailer.
	document = append([]byte(nil), valid...)
	putBE64(document, len(document)-32+24, uint64(len(document)))
	if _, err := openBinaryPlist(document); err == nil {
		t.Fatal("an offset table past the trailer was accepted")
	}

	// Object offset inside the signature.
	document = append([]byte(nil), valid...)
	offsetTable := int(be64At(document, len(document)-32+24))
	document[offsetTable] = 0
	document[offsetTable+1] = 2
	if _, err := openBinaryPlist(document); err == nil {
		t.Fatal("an object offset inside the signature was accepted")
	}

	// References outside the object set.
	document = rawBinaryPlist([][]byte{{0xA1, 0x7F}}, 0)
	plist, err := openBinaryPlist(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plist.object(0); err == nil {
		t.Fatal("an out-of-range reference was accepted")
	}
}

func TestBinaryPlistUnsupportedMarkers(t *testing.T) {
	for name, object := range map[string][]byte{
		"integer": {0x13, 1, 2, 3, 4, 5, 6, 7, 8},
		"uid":     {0x80},
		"real":    {0x23, 0, 0, 0, 0, 0, 0, 0, 0},
		"unknown": {0x70},
	} {
		t.Run(name, func(t *testing.T) {
			document := rawBinaryPlist([][]byte{object}, 0)
			plist, err := openBinaryPlist(document)
			if err != nil {
				t.Fatalf("openBinaryPlist error = %v", err)
			}
			if _, err := plist.object(0); err == nil {
				t.Fatalf("%s marker was accepted", name)
			}
		})
	}
}

func TestStripDoctypePreservesLength(t *testing.T) {
	text := []byte(`<?xml version="1.0"?>` + "\n" +
		`<!DOCTYPE plist PUBLIC "a" "b">` + "\n<plist/>")
	stripped := stripDoctype(text)
	if len(stripped) != len(text) {
		t.Fatalf("length changed: %d -> %d", len(text), len(stripped))
	}
	if bytes.Contains(stripped, []byte("<!DOCTYPE")) {
		t.Fatal("DOCTYPE survived")
	}
	if !bytes.HasPrefix(stripped, []byte("<?xml")) {
		t.Fatal("prefix changed")
	}

	// An internal subset is left in place for the parser to refuse.
	subset := []byte(`<!DOCTYPE plist [ <!ENTITY x "y"> ]><plist/>`)
	if got := stripDoctype(subset); !bytes.Contains(got, []byte("<!DOCTYPE")) {
		t.Fatal("an internal subset was removed")
	}
}

func TestParseXMLPlist(t *testing.T) {
	table := encodeTable(testTable{name: "disk",
		runs: []testRun{{start: 0, sectors: 1, kind: kindRaw}}})
	for _, doctype := range []bool{false, true} {
		plist := xmlPlist([]struct {
			name string
			data []byte
		}{{"disk", table}}, doctype)
		tables, err := parsePropertyList(plist)
		if err != nil {
			t.Fatalf("parsePropertyList(doctype=%v) error = %v", doctype, err)
		}
		if len(tables) != 1 || tables[0].name == nil || *tables[0].name != "disk" {
			t.Fatalf("tables = %+v", tables)
		}
	}
}

func TestXMLPlistCFNameFallback(t *testing.T) {
	table := encodeTable(testTable{name: "unused",
		runs: []testRun{{start: 0, sectors: 1, kind: kindRaw}}})
	encoded := base64.StdEncoding.EncodeToString(table)
	xml := `<plist><dict><key>resource-fork</key><dict><key>blkx</key><array>` +
		`<dict><key>CFName</key><string>fallback</string>` +
		`<key>Data</key><data>` + encoded + `</data></dict>` +
		`</array></dict></dict></plist>`
	tables, err := parsePropertyList([]byte(xml))
	if err != nil {
		t.Fatalf("parsePropertyList error = %v", err)
	}
	if len(tables) != 1 || tables[0].name == nil || *tables[0].name != "fallback" {
		t.Fatalf("tables = %+v", tables)
	}
}

func TestParsePropertyListRejectsUnreadableXML(t *testing.T) {
	if _, err := parsePropertyList([]byte(`<plist><dict>`)); err == nil {
		t.Fatal("truncated XML was accepted")
	} else if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v", err)
	}
	if _, err := parsePropertyList([]byte(`<!DOCTYPE plist [ <!ENTITY x "y"> ]><plist/>`)); err == nil {
		t.Fatal("an internal DTD subset was accepted")
	}
}
