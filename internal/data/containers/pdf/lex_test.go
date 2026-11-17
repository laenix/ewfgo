package pdf

import (
	"errors"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func parseTestValue(t *testing.T, text string) Value {
	t.Helper()
	value, err := ParseFirstValue([]byte(text))
	if err != nil {
		t.Fatalf("ParseFirstValue(%q) error = %v", text, err)
	}
	return value
}

func TestNumbersKeepTheirIntegerOrRealForm(t *testing.T) {
	if value := parseTestValue(t, "42"); value.Kind() != KindInteger {
		t.Fatalf("42 kind = %v", value.Kind())
	}
	if value := parseTestValue(t, "-7"); value.integer != -7 {
		t.Fatalf("-7 = %d", value.integer)
	}
	if value := parseTestValue(t, "+3"); value.integer != 3 {
		t.Fatalf("+3 = %d", value.integer)
	}
	for text, want := range map[string]float64{"3.5": 3.5, ".5": 0.5, "12.": 12} {
		value := parseTestValue(t, text)
		if value.Kind() != KindReal || value.real != want {
			t.Fatalf("%s = %v / %v, want real %v", text, value.Kind(), value.real, want)
		}
	}
	if _, err := ParseFirstValue([]byte("--5")); err == nil {
		t.Fatal("--5 parsed, want an error")
	}
}

func TestNameDecodesHashEscapes(t *testing.T) {
	for text, want := range map[string]string{
		"/Name":   "Name",
		"/A#20B":  "A B",
		"/#41#42": "AB",
		"/":       "",
	} {
		value := parseTestValue(t, text)
		name, ok := value.AsName()
		if !ok || string(name) != want {
			t.Fatalf("%s = %q/%v, want %q", text, name, ok, want)
		}
	}
}

func TestLiteralStringUnescapesParensAndOctal(t *testing.T) {
	for text, want := range map[string]string{
		`(a\(b\)c)`:  "a(b)c",
		`(\101\102)`: "AB",
		`(a(b)c)`:    "a(b)c",
		"(a\\\nb)":   "ab",
		"(a\r\nb)":   "a\nb",
	} {
		value := parseTestValue(t, text)
		got, ok := value.AsString()
		if !ok || string(got) != want {
			t.Fatalf("%q = %q/%v, want %q", text, got, ok, want)
		}
	}
}

func TestHexStringPadsAnOddDigit(t *testing.T) {
	for text, want := range map[string][]byte{
		"<4142>":     {'A', 'B'},
		"<414>":      {0x41, 0x40},
		"< 41 4 2 >": {'A', 'B'},
		"<>":         {},
	} {
		value := parseTestValue(t, text)
		got, ok := value.AsString()
		if !ok || string(got) != string(want) {
			t.Fatalf("%q = %q/%v, want %q", text, got, ok, want)
		}
	}
}

func TestArrayAndDictionaryNest(t *testing.T) {
	value := parseTestValue(t, "[1 /Two (three) << /Key true >> null]")
	values, ok := value.AsArray()
	if !ok || len(values) != 5 {
		t.Fatalf("array = %v/%v", values, ok)
	}
	if name, _ := values[1].AsName(); string(name) != "Two" {
		t.Fatalf("values[1] = %v", values[1])
	}
	if text, _ := values[2].AsString(); string(text) != "three" {
		t.Fatalf("values[2] = %v", values[2])
	}
	dict, _ := values[3].AsDict()
	if got, ok := dict.GetBool([]byte("Key")); !ok || !got {
		t.Fatalf("/Key = %v/%v", got, ok)
	}
	if values[4].Kind() != KindNull {
		t.Fatalf("values[4] = %v", values[4])
	}
}

func TestReferenceIsReadAfterTwoIntegersAndR(t *testing.T) {
	value := parseTestValue(t, "12 0 R")
	ref, ok := value.AsReference()
	if !ok || ref.Number != 12 || ref.Generation != 0 {
		t.Fatalf("reference = %+v/%v", ref, ok)
	}
	value = parseTestValue(t, "12 0")
	if value.Kind() != KindInteger || value.integer != 12 {
		t.Fatalf("12 0 = %v", value)
	}
	value = parseTestValue(t, "[12 0]")
	values, _ := value.AsArray()
	if len(values) != 2 || values[0].Kind() != KindInteger || values[1].Kind() != KindInteger {
		t.Fatalf("[12 0] = %v", values)
	}
	value = parseTestValue(t, "12 70000 R")
	if value.Kind() != KindInteger {
		t.Fatalf("12 70000 R = %v, want integer", value)
	}
}

func TestDuplicateDictionaryKeyTakesTheLastValue(t *testing.T) {
	value := parseTestValue(t, "<< /A 1 /A 2 >>")
	dict, _ := value.AsDict()
	if got, ok := dict.GetInt([]byte("A")); !ok || got != 2 {
		t.Fatalf("/A = %d/%v", got, ok)
	}
}

func TestKeywordMustEndAtABoundary(t *testing.T) {
	if _, err := ParseFirstValue([]byte("truex")); err == nil {
		t.Fatal("truex parsed")
	}
	if _, err := ParseFirstValue([]byte("nulll")); err == nil {
		t.Fatal("nulll parsed")
	}
	if value := parseTestValue(t, "true"); value.Kind() != KindBoolean {
		t.Fatalf("true = %v", value)
	}
}

func TestNestingPastTheLimitIsRefusedByKind(t *testing.T) {
	deep := strings.Repeat("[", 80) + "0" + strings.Repeat("]", 80)
	_, err := ParseFirstValue([]byte(deep))
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("deep array error = %v, want ErrUnsupported", err)
	}
	if !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("error = %v, want a nesting refusal", err)
	}
}

func TestUnterminatedContainerNamesTheOffset(t *testing.T) {
	_, err := ParseFirstValue([]byte("<< /A [1 2"))
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("error = %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "byte") {
		t.Fatalf("error = %v, want an offset", err)
	}
}

func TestIndirectHeaderReadsNumberGenerationAndObj(t *testing.T) {
	input := []byte(" 12 0 obj << /Type /Catalog >>")
	ref, offset, err := ParseIndirectPrefix(input)
	if err != nil {
		t.Fatalf("ParseIndirectPrefix error = %v", err)
	}
	if ref.Number != 12 || ref.Generation != 0 {
		t.Fatalf("reference = %+v", ref)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(input[offset:])), "<<") {
		t.Fatalf("value starts at %q", input[offset:])
	}
}

func TestStreamStartsAfterItsEndOfLine(t *testing.T) {
	bytesValue := []byte("<< /Length 3 >>\r\nstream\r\nabc")
	parser := NewParser(bytesValue)
	value, err := parser.ParseValue()
	if err != nil {
		t.Fatalf("dictionary error = %v", err)
	}
	if _, ok := value.AsDict(); !ok {
		t.Fatal("value is not a dictionary")
	}
	start, err := parser.ParseStreamStart()
	if err != nil {
		t.Fatalf("ParseStreamStart error = %v", err)
	}
	if string(bytesValue[start:start+3]) != "abc" {
		t.Fatalf("stream starts at %q", bytesValue[start:])
	}
}

func TestCommentsAreSkippedBetweenValues(t *testing.T) {
	value := parseTestValue(t, "% leading comment\n[1 % between\n2]")
	values, _ := value.AsArray()
	if len(values) != 2 || values[0].integer != 1 || values[1].integer != 2 {
		t.Fatalf("array = %v", values)
	}
}

func TestDictionaryIterationIsSorted(t *testing.T) {
	dict := NewDict()
	dict.Set("b", IntValue(2))
	dict.Set("a", IntValue(1))
	dict.Set("c", IntValue(3))
	keys := dict.Keys()
	want := []string{"a", "b", "c"}
	for i, key := range keys {
		if string(key) != want[i] {
			t.Fatalf("keys = %q, want %q", keys, want)
		}
	}
}
