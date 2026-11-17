package officelock

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

// ownerFileWith builds an owner file the way the Office writers in the samples
// do: the first byte is the single-byte name length and the length word is the
// UTF-16 code-unit count, so an ASCII name repeats its length.
func ownerFileWith(ascii, utf16Name string, layoutB bool) []byte {
	slotLen, lengthAt, utf16Offset, total := SingleByteSlotA, UTF16LengthA, UTF16SlotA, LayoutABytes
	if layoutB {
		slotLen, lengthAt, utf16Offset, total = SingleByteSlotB, UTF16LengthB, UTF16SlotB, LayoutBBytes
	}
	bytes := make([]byte, total)
	bytes[0] = byte(len(ascii))
	copy(bytes[1:], ascii)
	for index := 1 + len(ascii); index <= slotLen; index++ {
		bytes[index] = ' '
	}
	units := encodeUTF16(utf16Name)
	bytes[lengthAt] = byte(len(units))
	bytes[lengthAt+1] = byte(len(units) >> 8)
	for index, unit := range units {
		bytes[utf16Offset+index*2] = byte(unit)
		bytes[utf16Offset+index*2+1] = byte(unit >> 8)
	}
	return bytes
}

func encodeUTF16(text string) []uint16 {
	units := make([]uint16, 0, len(text))
	for _, value := range text {
		if value < 0x10000 {
			units = append(units, uint16(value))
			continue
		}
		value -= 0x10000
		units = append(units, uint16(0xD800+(value>>10)), uint16(0xDC00+(value&0x3FF)))
	}
	return units
}

func ownerFile(ascii, utf16Name string) []byte {
	return ownerFileWith(ascii, utf16Name, false)
}

func TestBothSlotsAreReadAndAgree(t *testing.T) {
	file, err := Decode(ownerFile("Alice Test", "Alice Test"))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	owner, ok := file.Owner()
	if !ok || owner != "Alice Test" {
		t.Fatalf("owner = %q, %v", owner, ok)
	}
	if file.SingleByte == nil || *file.SingleByte != "Alice Test" {
		t.Fatalf("single byte = %v", file.SingleByte)
	}
	if file.UTF16 == nil || *file.UTF16 != "Alice Test" {
		t.Fatalf("utf16 = %v", file.UTF16)
	}
	if file.AnsiLength != 10 {
		t.Fatalf("ansi length = %d", file.AnsiLength)
	}
	if file.UTF16Length != 10 {
		t.Fatalf("utf16 length = %d", file.UTF16Length)
	}
	if file.UTF16Offset != UTF16SlotA {
		t.Fatalf("utf16 offset = %#x", file.UTF16Offset)
	}
	if !file.SlotsAgree() {
		t.Fatal("slots disagree")
	}
	if file.Layout() != "53-byte single-byte slot" {
		t.Fatalf("layout = %q", file.Layout())
	}
}

func TestElevenCharacterNameStartsWith0x0b(t *testing.T) {
	bytes := ownerFile("Tianyu Zhou", "Tianyu Zhou")
	if bytes[0] != 0x0b {
		t.Fatalf("first byte = %#x", bytes[0])
	}
	if bytes[UTF16LengthA] != 0x0b {
		t.Fatalf("length word = %#x", bytes[UTF16LengthA])
	}
	file, err := Decode(bytes)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if file.AnsiLength != 11 || file.UTF16Length != 11 {
		t.Fatalf("lengths = %d/%d", file.AnsiLength, file.UTF16Length)
	}
	if owner, _ := file.Owner(); owner != "Tianyu Zhou" {
		t.Fatalf("owner = %q", owner)
	}

	bytes[0] = 4
	for index := 1; index < 12; index++ {
		bytes[index] = ' '
	}
	copy(bytes[1:], "Alex")
	file, err = Decode(bytes)
	if err != nil {
		t.Fatalf("Decode after shorter name: %v", err)
	}
	if file.SingleByte == nil || *file.SingleByte != "Alex" {
		t.Fatalf("single byte = %v", file.SingleByte)
	}
}

func TestUnicodeNameHasNoSingleByteLength(t *testing.T) {
	file, err := Decode(ownerFile("", "刘雪松"))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if file.AnsiLength != 0 {
		t.Fatalf("ansi length = %d", file.AnsiLength)
	}
	if file.UTF16Length != 3 {
		t.Fatalf("utf16 length = %d", file.UTF16Length)
	}
	if file.SingleByte != nil {
		t.Fatalf("single byte = %v", file.SingleByte)
	}
	if file.UTF16 == nil || *file.UTF16 != "刘雪松" {
		t.Fatalf("utf16 = %v", file.UTF16)
	}
	if owner, _ := file.Owner(); owner != "刘雪松" {
		t.Fatalf("owner = %q", owner)
	}
	if !file.SlotsAgree() {
		t.Fatal("an empty slot must not count as a disagreement")
	}
}

func TestDisagreeingSlotIsKeptAndReported(t *testing.T) {
	file, err := Decode(ownerFile("Alice Test", "Bob Brown"))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if owner, _ := file.Owner(); owner != "Bob Brown" {
		t.Fatalf("owner = %q", owner)
	}
	if file.SlotsAgree() {
		t.Fatal("slots agree although they differ")
	}
}

func TestLongerValidSingleByteLengthIsNotAMarker(t *testing.T) {
	file, err := Decode(ownerFile("Reese Lu", "Reese Lu"))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if file.AnsiLength != 8 {
		t.Fatalf("ansi length = %d", file.AnsiLength)
	}
	if owner, _ := file.Owner(); owner != "Reese Lu" {
		t.Fatalf("owner = %q", owner)
	}
}

func Test54ByteSlotMovesUTF16NameTo0x39(t *testing.T) {
	file, err := Decode(ownerFileWith("Alice Test", "Alice Test", true))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if file.UTF16Offset != UTF16SlotB {
		t.Fatalf("offset = %#x", file.UTF16Offset)
	}
	if owner, _ := file.Owner(); owner != "Alice Test" {
		t.Fatalf("owner = %q", owner)
	}
	if !file.SlotsAgree() {
		t.Fatal("slots disagree")
	}
	if file.Layout() != "54-byte single-byte slot" {
		t.Fatalf("layout = %q", file.Layout())
	}
}

func TestEmptySingleByteSlotFallsBackToUTF16(t *testing.T) {
	bytes := ownerFile("", "Alice Test")
	for index := 1; index < UTF16LengthA; index++ {
		bytes[index] = ' '
	}
	file, err := Decode(bytes)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if file.SingleByte != nil {
		t.Fatalf("single byte = %v", file.SingleByte)
	}
	if owner, _ := file.Owner(); owner != "Alice Test" {
		t.Fatalf("owner = %q", owner)
	}
	if !file.SlotsAgree() {
		t.Fatal("an empty slot must not disagree")
	}
}

func TestNonTextSingleByteSlotIsNotDecodedWithAGuessedCodePage(t *testing.T) {
	bytes := ownerFile("Alice Test", "Alice Test")
	bytes[1] = 0xff
	file, err := Decode(bytes)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if file.SingleByte != nil {
		t.Fatalf("single byte = %v", file.SingleByte)
	}
	if owner, _ := file.Owner(); owner != "Alice Test" {
		t.Fatalf("owner = %q", owner)
	}
}

func TestImpossibleLengthByteIsRefusedByName(t *testing.T) {
	bytes := ownerFile("Alice Test", "Alice Test")
	bytes[0] = 'P'
	_, err := Decode(bytes)
	if !errors.Is(err, ErrNotAnOwnerFile) {
		t.Fatalf("error = %v", err)
	}
	var detail *Error
	if !errors.As(err, &detail) {
		t.Fatalf("error type = %T", err)
	}
	if detail.First != 'P' {
		t.Fatalf("first = %#x", detail.First)
	}
	if !strings.Contains(err.Error(), "cannot be the single-byte name length") {
		t.Fatalf("message = %v", err)
	}
}

func TestLengthWordsThatFitNoLayoutAreRefused(t *testing.T) {
	bytes := ownerFile("Alice Test", "Alice Test")
	bytes[UTF16LengthA] = 0xff
	bytes[UTF16LengthA+1] = 0xff
	_, err := Decode(bytes)
	if !errors.Is(err, ErrNoLayout) {
		t.Fatalf("error = %v", err)
	}
	var detail *Error
	if !errors.As(err, &detail) || detail.AnsiLength != 10 {
		t.Fatalf("detail = %+v", detail)
	}
	if !strings.Contains(err.Error(), "0x36 or 0x37") {
		t.Fatalf("message = %v", err)
	}
}

func TestFileShorterThanLayoutNamesTheSizeNeeded(t *testing.T) {
	bytes := ownerFile("Alice Test", "Alice Test")
	bytes = bytes[:100]
	_, err := Decode(bytes)
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("error = %v", err)
	}
	var detail *Error
	if !errors.As(err, &detail) {
		t.Fatalf("error type = %T", err)
	}
	if detail.Found != 100 || detail.Needed != LayoutABytes {
		t.Fatalf("found/needed = %d/%d", detail.Found, detail.Needed)
	}
}

func TestTinyFileSaysHowShortItIs(t *testing.T) {
	bytes := make([]byte, 20)
	for index := range bytes {
		bytes[index] = 0x0a
	}
	_, err := Decode(bytes)
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("error = %v", err)
	}
	var detail *Error
	if !errors.As(err, &detail) || detail.Found != 20 || detail.Needed != MinBytes {
		t.Fatalf("detail = %+v", detail)
	}
}

func TestEmptySlotsAreNotAName(t *testing.T) {
	bytes := make([]byte, LayoutABytes)
	bytes[0] = 0x0a
	for index := 1; index <= SingleByteSlotA; index++ {
		bytes[index] = ' '
	}
	bytes[UTF16LengthA] = 0x0a
	for index := UTF16SlotA; index < UTF16SlotA+20; index++ {
		bytes[index] = 0
	}
	_, err := Decode(bytes)
	if !errors.Is(err, ErrNoName) {
		t.Fatalf("error = %v", err)
	}
}

func TestNameDetection(t *testing.T) {
	for _, name := range []string{"~$port.docx", "~$Report.xlsx", `C:\docs\~$desk.pptx`, "/docs/~$x"} {
		if !IsOwnerFileName(name) {
			t.Fatalf("%q not detected as an owner file name", name)
		}
	}
	for _, name := range []string{"Report.docx", "~$", "", "~x.docx"} {
		if IsOwnerFileName(name) {
			t.Fatalf("%q wrongly detected as an owner file name", name)
		}
	}
}

func TestDetectRecognisesBothLayoutsAndRejectsNoise(t *testing.T) {
	if !Detect(ownerFile("Alice Test", "Alice Test")) {
		t.Fatal("layout A not detected")
	}
	if !Detect(ownerFileWith("Alice Test", "Alice Test", true)) {
		t.Fatal("layout B not detected")
	}
	noise := make([]byte, LayoutABytes)
	noise[0] = 'P'
	if Detect(noise) {
		t.Fatal("noise detected as an owner file")
	}
	if Detect([]byte{0x0a}) {
		t.Fatal("short input detected")
	}
}

func TestOpenReadsASourceAndMapsErrors(t *testing.T) {
	file, err := Open(source.NewMemorySource(1, ownerFile("Alice Test", "Alice Test")))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if owner, _ := file.Owner(); owner != "Alice Test" {
		t.Fatalf("owner = %q", owner)
	}

	tiny := bytes.Repeat([]byte{0x0a}, 20)
	_, err = Open(source.NewMemorySource(1, tiny))
	if !errors.Is(err, source.ErrUnexpectedEOF) {
		t.Fatalf("truncated source error = %v", err)
	}

	bad := ownerFile("Alice Test", "Alice Test")
	bad[0] = 'P'
	_, err = Open(source.NewMemorySource(1, bad))
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("unknown variant error = %v", err)
	}

	emptySlots := make([]byte, LayoutABytes)
	emptySlots[0] = 0x0a
	for index := 1; index <= SingleByteSlotA; index++ {
		emptySlots[index] = ' '
	}
	emptySlots[UTF16LengthA] = 0x0a
	_, err = Open(source.NewMemorySource(1, emptySlots))
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("no-name error = %v", err)
	}
}

func TestOpenRefusesOversizedSources(t *testing.T) {
	bytes := make([]byte, MaxBytes+1)
	_, err := Open(source.NewMemorySource(1, bytes))
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(err.Error(), "4096") {
		t.Fatalf("message = %v", err)
	}
}

func TestOpenRefusesNilSource(t *testing.T) {
	_, err := Open(nil)
	if !errors.Is(err, source.ErrInvalidArgument) {
		t.Fatalf("error = %v", err)
	}
}

func TestStoredNamesAreTrimmed(t *testing.T) {
	file, err := Decode(ownerFile("  spaced  ", "  spaced  "))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	// The reference trims surrounding whitespace in both slots.
	if owner, _ := file.Owner(); owner != "spaced" {
		t.Fatalf("owner = %q", owner)
	}
}
