package lime

import (
	stdbytes "bytes"
	"encoding/binary"
	"errors"
	"math"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func putU32(b []byte, at int, v uint32) { binary.LittleEndian.PutUint32(b[at:], v) }
func putU64(b []byte, at int, v uint64) { binary.LittleEndian.PutUint64(b[at:], v) }

func header(version uint32, start, end uint64) []byte {
	out := make([]byte, HeaderBytes)
	copy(out[0:4], Magic[:])
	putU32(out, 4, version)
	putU64(out, 8, start)
	putU64(out, 16, end)
	return out
}

func chain(ranges [][2]uint64) []byte {
	var out []byte
	for _, r := range ranges {
		out = append(out, header(Version1, r[0], r[1])...)
		for i := uint64(0); i < r[1]-r[0]; i++ {
			out = append(out, byte(r[0]+i))
		}
	}
	return out
}

func memory(bytes []byte) *source.MemorySource { return source.NewMemorySource(1, bytes) }

func TestMagicIsTheLittleEndianBytesOfTheWriterValue(t *testing.T) {
	var want [4]byte
	binary.LittleEndian.PutUint32(want[:], MagicU32)
	if Magic != want {
		t.Fatalf("Magic = % X, want % X", Magic, want)
	}
	if !LooksLike([]byte("EMiLrest")) {
		t.Fatal("LooksLike rejected the LiME magic")
	}
	if LooksLike([]byte("LiME")) {
		t.Fatal("LooksLike accepted the ASCII spelling")
	}
	if LooksLike([]byte("EMi")) {
		t.Fatal("LooksLike accepted a short prefix")
	}
}

func TestWalksTwoContiguousRanges(t *testing.T) {
	bytes := chain([][2]uint64{{0x1000, 0x1010}, {0x1010, 0x1020}})
	report, err := Read(memory(bytes), DefaultLimits())
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if report.Version != 1 || report.HeaderBytes != 32 || report.RangeCount() != 2 {
		t.Fatalf("report = %+v", report)
	}
	if report.Ranges[0].HeaderOffset != 0 || report.Ranges[0].DataOffset != 32 {
		t.Fatalf("range 0 offsets = %+v", report.Ranges[0])
	}
	if report.Ranges[1].HeaderOffset != 32+16 || report.Ranges[1].DataOffset != 32+16+32 {
		t.Fatalf("range 1 offsets = %+v", report.Ranges[1])
	}
	if report.PhysicalStart != 0x1000 || report.PhysicalEnd != 0x1020 || report.PhysicalSpan != 0x20 {
		t.Fatalf("physical span = %+v", report)
	}
	if report.DeclaredBytes != 0x20 || report.StoredBytes != 0x20 {
		t.Fatalf("byte totals = %+v", report)
	}
	if !report.Contiguous || report.Sparse || report.Gaps != 0 || report.Overlaps != 0 {
		t.Fatalf("layout = %+v", report)
	}
	if report.FinalRangeTruncated || report.TrailingBytes != 0 || report.TrailingOffset != nil {
		t.Fatalf("tail = %+v", report)
	}
	for _, r := range report.Ranges {
		if !r.ReservedZero {
			t.Fatalf("range %d reserved bytes not reported zero", r.Index)
		}
	}
	if got := report.LayoutLabel(); got != "contiguous" {
		t.Fatalf("LayoutLabel = %q", got)
	}
}

func TestReportsGapAndOverlapBetweenAdjacentRanges(t *testing.T) {
	bytes := chain([][2]uint64{{0x1000, 0x1010}, {0x1020, 0x1030}, {0x1028, 0x1038}})
	report, err := Read(memory(bytes), DefaultLimits())
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if report.Contiguous || !report.Sparse {
		t.Fatalf("layout flags = %+v", report)
	}
	if report.Gaps != 1 || report.GapBytes != 0x10 {
		t.Fatalf("gaps = %d/%d", report.Gaps, report.GapBytes)
	}
	if report.Ranges[1].GapBefore != 0x10 {
		t.Fatalf("range 1 gap = %d", report.Ranges[1].GapBefore)
	}
	if report.Overlaps != 1 || report.OverlapBytes != 8 {
		t.Fatalf("overlaps = %d/%d", report.Overlaps, report.OverlapBytes)
	}
	if report.Ranges[2].OverlapBefore != 8 {
		t.Fatalf("range 2 overlap = %d", report.Ranges[2].OverlapBefore)
	}
	if got, want := report.LayoutLabel(), "1 gap(s) of 16 byte(s), 1 overlap(s) of 8 byte(s)"; got != want {
		t.Fatalf("LayoutLabel = %q, want %q", got, want)
	}
}

func TestReportsTruncatedFinalRangeInsteadOfFailing(t *testing.T) {
	bytes := chain([][2]uint64{{0x1000, 0x1010}})
	bytes = append(bytes, header(Version1, 0x2000, 0x2100)...)
	bytes = append(bytes, stdbytes.Repeat([]byte{0xAA}, 0x20)...)

	report, err := Read(memory(bytes), DefaultLimits())
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if !report.FinalRangeTruncated || report.TruncatedBytes != 0xE0 {
		t.Fatalf("truncation = %v/%d", report.FinalRangeTruncated, report.TruncatedBytes)
	}
	if report.Ranges[1].Stored != 0x20 || report.Ranges[1].Length != 0x100 {
		t.Fatalf("range 1 = %+v", report.Ranges[1])
	}
	if report.StoredBytes != 0x10+0x20 || report.DeclaredBytes != 0x110 {
		t.Fatalf("totals = %+v", report)
	}
	if report.TrailingBytes != 0 {
		t.Fatalf("trailing bytes = %d", report.TrailingBytes)
	}
}

func TestStrictLimitsRefuseTruncatedRangeByName(t *testing.T) {
	bytes := chain([][2]uint64{{0x1000, 0x1010}})
	bytes = append(bytes, header(Version1, 0x2000, 0x2100)...)
	bytes = append(bytes, stdbytes.Repeat([]byte{0xAA}, 0x20)...)

	limits := DefaultLimits()
	limits.AllowTruncatedTail = false
	_, err := Read(memory(bytes), limits)
	if !errors.Is(err, ErrRangeExtendsPastSource) {
		t.Fatalf("error = %v, want ErrRangeExtendsPastSource", err)
	}
	var limeErr *Error
	if !errors.As(err, &limeErr) {
		t.Fatalf("error type = %T", err)
	}
	if limeErr.DataOffset != 32+16+32 || limeErr.Length != 0x100 {
		t.Fatalf("error detail = %+v", limeErr)
	}
}

func TestReportsTailThatDoesNotBeginAHeader(t *testing.T) {
	bytes := chain([][2]uint64{{0x1000, 0x1010}})
	tail := []byte("not a LiME header at all, just padding")
	bytes = append(bytes, tail...)

	report, err := Read(memory(bytes), DefaultLimits())
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if report.RangeCount() != 1 {
		t.Fatalf("range count = %d", report.RangeCount())
	}
	if report.TrailingBytes != uint64(len(tail)) {
		t.Fatalf("trailing bytes = %d, want %d", report.TrailingBytes, len(tail))
	}
	if report.TrailingOffset == nil || *report.TrailingOffset != 32+16 {
		t.Fatalf("trailing offset = %v", report.TrailingOffset)
	}
}

func TestReportsShortTailWithoutCallingItAHeader(t *testing.T) {
	bytes := chain([][2]uint64{{0x1000, 0x1010}})
	bytes = append(bytes, 0, 0, 0, 0, 0)

	report, err := Read(memory(bytes), DefaultLimits())
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if report.TrailingBytes != 5 {
		t.Fatalf("trailing bytes = %d", report.TrailingBytes)
	}
	if report.TrailingOffset == nil || *report.TrailingOffset != 32+16 {
		t.Fatalf("trailing offset = %v", report.TrailingOffset)
	}
}

func TestRefusesBadFirstMagic(t *testing.T) {
	bytes := chain([][2]uint64{{0x1000, 0x1010}})
	copy(bytes[0:4], "LiME")
	_, err := Read(memory(bytes), DefaultLimits())
	if !errors.Is(err, ErrBadMagic) {
		t.Fatalf("error = %v, want ErrBadMagic", err)
	}
	var limeErr *Error
	if !errors.As(err, &limeErr) || limeErr.Offset != 0 || limeErr.Found != [4]byte{'L', 'i', 'M', 'E'} {
		t.Fatalf("error detail = %+v", limeErr)
	}
}

func TestRefusesUnknownVersion(t *testing.T) {
	bytes := chain([][2]uint64{{0x1000, 0x1010}})
	putU32(bytes, 4, Version1+1)
	_, err := Read(memory(bytes), DefaultLimits())
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("error = %v, want ErrUnsupportedVersion", err)
	}
	var limeErr *Error
	if !errors.As(err, &limeErr) || limeErr.Version != 2 {
		t.Fatalf("error detail = %+v", limeErr)
	}
}

func TestRefusesHeaderThatDoesNotFit(t *testing.T) {
	_, err := Read(memory(make([]byte, 31)), DefaultLimits())
	if !errors.Is(err, ErrHeaderDoesNotFit) {
		t.Fatalf("error = %v, want ErrHeaderDoesNotFit", err)
	}
	var limeErr *Error
	if !errors.As(err, &limeErr) || limeErr.Offset != 0 || limeErr.Available != 31 {
		t.Fatalf("error detail = %+v", limeErr)
	}
}

func TestRefusesInvertedRange(t *testing.T) {
	_, err := Read(memory(header(Version1, 0x2000, 0x1000)), DefaultLimits())
	if !errors.Is(err, ErrBadRange) {
		t.Fatalf("error = %v, want ErrBadRange", err)
	}
	var limeErr *Error
	if !errors.As(err, &limeErr) || limeErr.Start != 0x2000 || limeErr.End != 0x1000 {
		t.Fatalf("error detail = %+v", limeErr)
	}
}

func TestRefusesMoreRangesThanTheLimit(t *testing.T) {
	bytes := chain([][2]uint64{{0x1000, 0x1010}, {0x1010, 0x1020}})
	limits := DefaultLimits()
	limits.MaxRanges = 1
	_, err := Read(memory(bytes), limits)
	if !errors.Is(err, ErrTooManyRanges) {
		t.Fatalf("error = %v, want ErrTooManyRanges", err)
	}
	var limeErr *Error
	if !errors.As(err, &limeErr) || limeErr.Limit != 1 {
		t.Fatalf("error detail = %+v", limeErr)
	}
}

func TestRefusesRangeOverThePerRangeCap(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxRangeBytes = 0x100
	_, err := Read(memory(header(Version1, 0x1000, 0x2000)), limits)
	if !errors.Is(err, ErrRangeTooLarge) {
		t.Fatalf("error = %v, want ErrRangeTooLarge", err)
	}
	var limeErr *Error
	if !errors.As(err, &limeErr) || limeErr.Length != 0x1000 || limeErr.Limit != 0x100 {
		t.Fatalf("error detail = %+v", limeErr)
	}
}

func TestAcceptsZeroLengthRange(t *testing.T) {
	bytes := header(Version1, 0x1000, 0x1000)
	bytes = append(bytes, header(Version1, 0x1000, 0x1010)...)
	bytes = append(bytes, make([]byte, 0x10)...)

	report, err := Read(memory(bytes), DefaultLimits())
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if report.RangeCount() != 2 || report.Ranges[0].Length != 0 {
		t.Fatalf("ranges = %+v", report.Ranges)
	}
	if report.Ranges[1].HeaderOffset != 32 {
		t.Fatalf("range 1 header offset = %d", report.Ranges[1].HeaderOffset)
	}
	if !report.Contiguous || report.DeclaredBytes != 0x10 {
		t.Fatalf("report = %+v", report)
	}
}

func TestRefusesDeclaredByteSumOverflow(t *testing.T) {
	bytes := header(Version1, 0x1000, 0x1004)
	bytes = append(bytes, 0, 0, 0, 0)
	bytes = append(bytes, header(Version1, 0, math.MaxUint64)...)

	limits := DefaultLimits()
	limits.MaxRangeBytes = math.MaxUint64
	_, err := Read(memory(bytes), limits)
	if !errors.Is(err, ErrSpanOverflow) {
		t.Fatalf("error = %v, want ErrSpanOverflow", err)
	}
}

func TestRangeSourceViewIsBoundedToStoredBytes(t *testing.T) {
	bytes := chain([][2]uint64{{0x1000, 0x1004}})
	parent := memory(bytes)
	report, err := Read(parent, DefaultLimits())
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}

	view, err := report.Ranges[0].OpenSource(99, parent)
	if err != nil {
		t.Fatalf("OpenSource error = %v", err)
	}
	if view.Len() != 4 {
		t.Fatalf("view len = %d", view.Len())
	}
	got := make([]byte, 4)
	if _, err := view.ReadAt(0, got); err != nil {
		t.Fatalf("ReadAt error = %v", err)
	}
	want := []byte{0x00, 0x01, 0x02, 0x03}
	if !stdbytes.Equal(got, want) {
		t.Fatalf("view bytes = % X, want % X", got, want)
	}
	extents, err := view.Extents(0, 4)
	if err != nil {
		t.Fatalf("Extents error = %v", err)
	}
	if len(extents) != 1 || extents[0].ParentOffset != 32 || extents[0].Len != 4 {
		t.Fatalf("extents = %+v", extents)
	}

	// A parent that no longer holds the declared data is refused, not zero-filled.
	short := source.NewMemorySource(1, bytes[:33])
	_, err = report.Ranges[0].OpenSource(99, short)
	if !errors.Is(err, ErrRangeExtendsPastSource) {
		t.Fatalf("short-parent error = %v, want ErrRangeExtendsPastSource", err)
	}
}

func TestRangeSourceViewOfZeroLengthRange(t *testing.T) {
	bytes := header(Version1, 0x1000, 0x1000)
	parent := memory(bytes)
	report, err := Read(parent, DefaultLimits())
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	view, err := report.Ranges[0].OpenSource(1, parent)
	if err != nil {
		t.Fatalf("OpenSource error = %v", err)
	}
	if view.Len() != 0 || !view.IsEmpty() {
		t.Fatalf("view = len %d empty %v", view.Len(), view.IsEmpty())
	}
}

func TestTrailingOffsetIsOptional(t *testing.T) {
	report, err := Read(memory(chain([][2]uint64{{0x1000, 0x1001}})), DefaultLimits())
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if report.TrailingOffset != nil {
		t.Fatalf("TrailingOffset = %v, want nil", report.TrailingOffset)
	}
}
