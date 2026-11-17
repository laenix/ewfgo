package pdf

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func testDict(entries [][2]any) *Dict {
	dict := NewDict()
	for _, entry := range entries {
		key := entry[0].(string)
		switch value := entry[1].(type) {
		case Value:
			dict.Set(key, value)
		case string:
			dict.Set(key, NameValue([]byte(value)))
		}
	}
	return dict
}

func zlibBytes(data []byte) []byte {
	var buf bytes.Buffer
	writer := zlib.NewWriter(&buf)
	_, _ = writer.Write(data)
	_ = writer.Close()
	return buf.Bytes()
}

func rawDeflateBytes(data []byte) []byte {
	var buf bytes.Buffer
	writer, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = writer.Write(data)
	_ = writer.Close()
	return buf.Bytes()
}

func TestZlibFlateDecodesAndMissingWrapperIsNoted(t *testing.T) {
	dict := testDict([][2]any{{"Filter", "FlateDecode"}})
	stream, err := DecodeStream(dict, zlibBytes([]byte("hello")), 1024)
	if err != nil {
		t.Fatalf("DecodeStream error = %v", err)
	}
	if string(stream.Bytes) != "hello" || len(stream.Filters) != 1 || stream.Filters[0] != "FlateDecode" || stream.Note != "" {
		t.Fatalf("stream = %+v", stream)
	}

	stream, err = DecodeStream(dict, rawDeflateBytes([]byte("hello")), 1024)
	if err != nil {
		t.Fatalf("headerless DecodeStream error = %v", err)
	}
	if string(stream.Bytes) != "hello" || stream.Note == "" {
		t.Fatalf("headerless stream = %+v", stream)
	}
}

func TestPNGPredictorRebuildsEachRow(t *testing.T) {
	predicted := []byte{0, 1, 2, 3, 2, 1, 1, 1}
	dict := testDict([][2]any{
		{"Filter", "FlateDecode"},
		{"DecodeParms", DictValue(testDict([][2]any{
			{"Predictor", IntValue(12)},
			{"Columns", IntValue(3)},
		}))},
	})
	stream, err := DecodeStream(dict, zlibBytes(predicted), 1024)
	if err != nil {
		t.Fatalf("DecodeStream error = %v", err)
	}
	if want := []byte{1, 2, 3, 2, 3, 4}; !bytes.Equal(stream.Bytes, want) {
		t.Fatalf("decoded = %v, want %v", stream.Bytes, want)
	}
}

func TestTiffPredictorAddsAcrossARow(t *testing.T) {
	predicted := []byte{1, 1, 1, 5, 5, 5}
	dict := testDict([][2]any{
		{"Filter", "FlateDecode"},
		{"DecodeParms", DictValue(testDict([][2]any{
			{"Predictor", IntValue(2)},
			{"Columns", IntValue(3)},
		}))},
	})
	stream, err := DecodeStream(dict, zlibBytes(predicted), 1024)
	if err != nil {
		t.Fatalf("DecodeStream error = %v", err)
	}
	if want := []byte{1, 2, 3, 5, 10, 15}; !bytes.Equal(stream.Bytes, want) {
		t.Fatalf("decoded = %v, want %v", stream.Bytes, want)
	}
}

func TestASCIIHexStopsAtMarkerAndPadsOddDigit(t *testing.T) {
	dict := testDict([][2]any{{"Filter", "ASCIIHexDecode"}})
	stream, err := DecodeStream(dict, []byte("41 42 4>"), 1024)
	if err != nil {
		t.Fatalf("DecodeStream error = %v", err)
	}
	if want := []byte{0x41, 0x42, 0x40}; !bytes.Equal(stream.Bytes, want) || stream.Note != "" {
		t.Fatalf("stream = %+v", stream)
	}
	stream, err = DecodeStream(dict, []byte("4142"), 1024)
	if err != nil {
		t.Fatalf("unterminated DecodeStream error = %v", err)
	}
	if !bytes.Equal(stream.Bytes, []byte{0x41, 0x42}) || stream.Note == "" {
		t.Fatalf("unterminated stream = %+v", stream)
	}
	if _, err := DecodeStream(dict, []byte("41zz>"), 1024); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("bad hex error = %v, want ErrCorrupt", err)
	}
}

func TestASCII85DecodesFullAndPartialGroups(t *testing.T) {
	dict := testDict([][2]any{{"Filter", "ASCII85Decode"}})
	for input, want := range map[string]string{
		"87cURD_*#TDfTZ)+T~>": "Hello, world!",
		"<~5sb~>":             "AB",
		"z6:4-~>":             "\x00\x00\x00\x00BCD",
	} {
		stream, err := DecodeStream(dict, []byte(input), 1024)
		if err != nil {
			t.Fatalf("%q error = %v", input, err)
		}
		if string(stream.Bytes) != want {
			t.Fatalf("%q = %q, want %q", input, stream.Bytes, want)
		}
	}
	if _, err := DecodeStream(dict, []byte("5~>"), 1024); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("one-character group error = %v", err)
	}
}

func TestRunLengthExpandsLiteralAndRepeatRuns(t *testing.T) {
	dict := testDict([][2]any{{"Filter", "RunLengthDecode"}})
	input := []byte{2, 'a', 'b', 'c', 254, 'x', 128}
	stream, err := DecodeStream(dict, input, 1024)
	if err != nil {
		t.Fatalf("DecodeStream error = %v", err)
	}
	if string(stream.Bytes) != "abcxxx" || stream.Note != "" {
		t.Fatalf("stream = %+v", stream)
	}
	stream, err = DecodeStream(dict, []byte{1, 'a', 'b'}, 1024)
	if err != nil {
		t.Fatalf("short DecodeStream error = %v", err)
	}
	if string(stream.Bytes) != "ab" || stream.Note == "" {
		t.Fatalf("short stream = %+v", stream)
	}
}

func TestLZWDecodesLiteralCodesAndEndCode(t *testing.T) {
	if got, err := decodeLZW([]byte{0x20, 0x90, 0x88, 0x70, 0x10}, true, 1024); err != nil || string(got) != "ABC" {
		t.Fatalf("ABC = %q, %v", got, err)
	}
	if got, err := decodeLZW([]byte{0x20, 0x90, 0xa0, 0x04, 0x38, 0x08}, true, 1024); err != nil || string(got) != "ABC" {
		t.Fatalf("AB C with clear = %q, %v", got, err)
	}
}

func TestLZWExpandsTheKwKwKCase(t *testing.T) {
	got, err := decodeLZW([]byte{0x20, 0xc0, 0xa0, 0x20}, true, 1024)
	if err != nil || string(got) != "AAA" {
		t.Fatalf("AAA = %q, %v", got, err)
	}
}

func TestLZWDecodeThroughTheFilter(t *testing.T) {
	dict := testDict([][2]any{{"Filter", "LZWDecode"}})
	stream, err := DecodeStream(dict, []byte{0x20, 0x90, 0x88, 0x70, 0x10}, 1024)
	if err != nil {
		t.Fatalf("DecodeStream error = %v", err)
	}
	if string(stream.Bytes) != "ABC" || len(stream.Filters) != 1 || stream.Filters[0] != "LZWDecode" {
		t.Fatalf("stream = %+v", stream)
	}
	dict = testDict([][2]any{
		{"Filter", "LZWDecode"},
		{"DecodeParms", DictValue(testDict([][2]any{{"EarlyChange", IntValue(0)}}))},
	})
	if _, err := DecodeStream(dict, []byte{0x20, 0x90, 0x88, 0x70, 0x10}, 1024); err != nil {
		t.Fatalf("EarlyChange=0 error = %v", err)
	}
}

func TestPNGPredictorHandlesSubUpAverageAndPaeth(t *testing.T) {
	cases := []struct {
		name      string
		predicted []byte
		want      []byte
	}{
		{"sub", []byte{1, 5, 1, 1}, []byte{5, 6, 7}},
		{"up", []byte{0, 1, 2, 3, 2, 1, 1, 1}, []byte{1, 2, 3, 2, 3, 4}},
		{"average", []byte{3, 5, 1, 1}, []byte{5, 3, 2}},
		{"paeth", []byte{0, 10, 20, 30, 4, 1, 1, 1}, []byte{10, 20, 30, 11, 21, 31}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			dict := testDict([][2]any{
				{"Filter", "FlateDecode"},
				{"DecodeParms", DictValue(testDict([][2]any{
					{"Predictor", IntValue(12)},
					{"Columns", IntValue(3)},
				}))},
			})
			stream, err := DecodeStream(dict, zlibBytes(test.predicted), 1024)
			if err != nil {
				t.Fatalf("DecodeStream error = %v", err)
			}
			if !bytes.Equal(stream.Bytes, test.want) {
				t.Fatalf("decoded = %v, want %v", stream.Bytes, test.want)
			}
		})
	}
}

func TestDecodeLimitsAreRefusalsNotPartialBytes(t *testing.T) {
	big := bytes.Repeat([]byte("abcd"), 256)
	dict := testDict([][2]any{{"Filter", "FlateDecode"}})
	if _, err := DecodeStream(dict, zlibBytes(big), 10); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("zlib limit error = %v, want ErrUnsupported", err)
	}
	if _, err := DecodeStream(dict, rawDeflateBytes(big), 10); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("deflate limit error = %v, want ErrUnsupported", err)
	}
}

func TestRefusedImageFilterIsNamed(t *testing.T) {
	dict := testDict([][2]any{{"Filter", "DCTDecode"}})
	_, err := DecodeStream(dict, []byte("jpeg"), 1024)
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("error = %v, want ErrUnsupported", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("DCTDecode")) {
		t.Fatalf("error = %v, want DCTDecode named", err)
	}
}

func TestStreamWithoutFilterIsCopiedAndStillBounded(t *testing.T) {
	stream, err := DecodeStream(NewDict(), []byte("abcd"), 1024)
	if err != nil {
		t.Fatalf("DecodeStream error = %v", err)
	}
	if string(stream.Bytes) != "abcd" || len(stream.Filters) != 0 {
		t.Fatalf("stream = %+v", stream)
	}
	if _, err := DecodeStream(NewDict(), []byte("abcd"), 3); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("limit error = %v, want ErrUnsupported", err)
	}
}

func TestFilterChainAppliesInListedOrder(t *testing.T) {
	encoded := zlibBytes([]byte("ABC"))
	var input []byte
	for _, b := range encoded {
		input = append(input, "0123456789ABCDEF"[b>>4], "0123456789ABCDEF"[b&0x0F])
	}
	input = append(input, '>')
	dict := testDict([][2]any{
		{"Filter", ArrayValue([]Value{NameValue([]byte("ASCIIHexDecode")), NameValue([]byte("FlateDecode"))})},
	})
	stream, err := DecodeStream(dict, input, 1024)
	if err != nil {
		t.Fatalf("DecodeStream error = %v", err)
	}
	if string(stream.Bytes) != "ABC" || len(stream.Filters) != 2 ||
		stream.Filters[0] != "ASCIIHexDecode" || stream.Filters[1] != "FlateDecode" {
		t.Fatalf("stream = %+v", stream)
	}
}

func TestFilterNamesReportedWithoutDecoding(t *testing.T) {
	dict := testDict([][2]any{
		{"Filter", "FlateDecode"},
		{"DecodeParms", NullValue()},
	})
	names, err := FilterNames(dict)
	if err != nil {
		t.Fatalf("FilterNames error = %v", err)
	}
	if len(names) != 1 || names[0] != "FlateDecode" {
		t.Fatalf("names = %v", names)
	}
}
