package dmp

import (
	"encoding/binary"
	"errors"
	"math"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func putU32(b []byte, at int, v uint32) { binary.LittleEndian.PutUint32(b[at:], v) }
func putU64(b []byte, at int, v uint64) { binary.LittleEndian.PutUint64(b[at:], v) }

func memory(bytes []byte) *source.MemorySource { return source.NewMemorySource(1, bytes) }

func kernel64() []byte {
	bytes := make([]byte, HeaderBytes64)
	copy(bytes[0:8], Magic64)
	putU32(bytes, 0x08, 15)
	putU32(bytes, 0x0c, 26002)
	putU64(bytes, Offsets64.DirectoryTableBase, 0x1a_b000)
	putU32(bytes, Offsets64.MachineImageType, 0x8664)
	putU32(bytes, Offsets64.NumberProcessors, 4)
	putU32(bytes, Offsets64.BugcheckCode, 0x9f)
	putU64(bytes, Offsets64.BugcheckParameters, 0x11)
	putU64(bytes, Offsets64.BugcheckParameters+8, 0x22)
	putU64(bytes, Offsets64.BugcheckParameters+16, 0x33)
	putU64(bytes, Offsets64.BugcheckParameters+24, 0x44)
	putU32(bytes, Offsets64.RunCount, 2)
	putU64(bytes, Offsets64.TotalPages, 5)
	putU64(bytes, Offsets64.Runs, 0x100)
	putU64(bytes, Offsets64.Runs+8, 3)
	putU64(bytes, Offsets64.Runs+16, 0x200)
	putU64(bytes, Offsets64.Runs+24, 2)
	putU32(bytes, Offsets64.DumpType, 2)
	putU32(bytes, Offsets64.WriterStatus, 1)
	return bytes
}

func TestReads64BitHeaderAndBoundsRunArray(t *testing.T) {
	report, err := Read(memory(kernel64()), DefaultLimits())
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if report.Bitness != Bit64 || report.Magic != "PAGEDU64" {
		t.Fatalf("layout = %v/%q", report.Bitness, report.Magic)
	}
	if report.Signature != [4]byte{'P', 'A', 'G', 'E'} || report.ValidDump != [4]byte{'D', 'U', '6', '4'} {
		t.Fatalf("signature = %+v", report)
	}
	if report.MajorVersion != 15 || report.MinorVersion != 26002 {
		t.Fatalf("version = %d.%d", report.MajorVersion, report.MinorVersion)
	}
	if report.DirectoryTableBase != 0x1a_b000 {
		t.Fatalf("directory table base = %#x", report.DirectoryTableBase)
	}
	if report.NumberProcessors != 4 || report.BugcheckCode != 0x9f {
		t.Fatalf("machine fields = %+v", report)
	}
	if report.BugcheckParameters != [4]uint64{0x11, 0x22, 0x33, 0x44} {
		t.Fatalf("bugcheck parameters = %v", report.BugcheckParameters)
	}
	if report.DumpTypeName == nil || *report.DumpTypeName != DumpTypeKernel {
		t.Fatalf("dump type = %v", report.DumpTypeName)
	}
	if got := report.DumpTypeLabel(); got != "kernel (2)" {
		t.Fatalf("DumpTypeLabel = %q", got)
	}
	if report.PhysicalMemoryBlockOffset != 0x88 ||
		report.ContextRecordOffset != 0x348 ||
		report.ExceptionRecordOffset != 0xf00 {
		t.Fatalf("fixed offsets = %+v", report)
	}
	pm := report.PhysicalMemory
	if pm.RunCount != 2 || pm.Capacity != 43 || pm.TotalPages != 5 {
		t.Fatalf("physical memory = %+v", pm)
	}
	if pm.PageSize != PageSize || pm.PageSizeInHeader {
		t.Fatalf("page size = %+v", pm)
	}
	if len(pm.Runs) != 2 || pm.Runs[0].BasePage != 0x100 || pm.Runs[1].PageCount != 2 {
		t.Fatalf("runs = %+v", pm.Runs)
	}
	if pm.DescriptorBytes != 16+2*16 || pm.RegionBytes != 704 {
		t.Fatalf("descriptor = %+v", pm)
	}
	if report.Directory != nil {
		t.Fatalf("non-triage dump has a directory: %+v", report.Directory)
	}
}

func TestReportsOnlyRequestedNumberOfRuns(t *testing.T) {
	limits := DefaultLimits()
	limits.ReportRuns = 1
	report, err := Read(memory(kernel64()), limits)
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if len(report.PhysicalMemory.Runs) != 1 || report.PhysicalMemory.RunCount != 2 {
		t.Fatalf("physical memory = %+v", report.PhysicalMemory)
	}
}

func TestRunCountPastHeaderIsRefused(t *testing.T) {
	bytes := kernel64()
	putU32(bytes, Offsets64.RunCount, 44)
	_, err := Read(memory(bytes), DefaultLimits())
	if !errors.Is(err, ErrRunTableOverflow) {
		t.Fatalf("error = %v, want ErrRunTableOverflow", err)
	}
	var dmpErr *Error
	if !errors.As(err, &dmpErr) || dmpErr.Count != 44 || dmpErr.Capacity != 43 {
		t.Fatalf("error detail = %+v", dmpErr)
	}
}

func TestRunCountOverReaderCapIsRefused(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxRuns = 1
	_, err := Read(memory(kernel64()), limits)
	if !errors.Is(err, ErrTooManyRuns) {
		t.Fatalf("error = %v, want ErrTooManyRuns", err)
	}
	var dmpErr *Error
	if !errors.As(err, &dmpErr) || dmpErr.Count != 2 || dmpErr.Limit != 1 {
		t.Fatalf("error detail = %+v", dmpErr)
	}
}

func TestReads32BitHeader(t *testing.T) {
	bytes := make([]byte, HeaderBytes32)
	copy(bytes[0:8], Magic32)
	putU32(bytes, 0x08, 10)
	putU32(bytes, 0x0c, 19041)
	putU32(bytes, Offsets32.DirectoryTableBase, 0x1a_b000)
	putU32(bytes, Offsets32.MachineImageType, 0x14c)
	putU32(bytes, Offsets32.NumberProcessors, 2)
	putU32(bytes, Offsets32.BugcheckCode, 0x7e)
	putU32(bytes, Offsets32.BugcheckParameters, 0x11)
	putU32(bytes, Offsets32.BugcheckParameters+4, 0x22)
	putU32(bytes, Offsets32.BugcheckParameters+8, 0x33)
	putU32(bytes, Offsets32.BugcheckParameters+12, 0x44)
	putU32(bytes, Offsets32.RunCount, 1)
	putU32(bytes, Offsets32.TotalPages, 3)
	putU32(bytes, Offsets32.Runs, 0x80)
	putU32(bytes, Offsets32.Runs+4, 3)
	putU32(bytes, Offsets32.DumpType, 1)
	putU32(bytes, Offsets32.WriterStatus, 0)

	report, err := Read(memory(bytes), DefaultLimits())
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if report.Bitness != Bit32 || report.Magic != "PAGEDU32" || report.HeaderBytes != HeaderBytes32 {
		t.Fatalf("layout = %+v", report)
	}
	if report.DumpTypeName == nil || *report.DumpTypeName != DumpTypeFull {
		t.Fatalf("dump type = %v", report.DumpTypeName)
	}
	pm := report.PhysicalMemory
	if len(pm.Runs) != 1 || pm.Runs[0].BasePage != 0x80 || pm.Capacity != 86 {
		t.Fatalf("physical memory = %+v", pm)
	}
	if pm.DescriptorBytes != 8+8 || pm.RegionBytes != 700 {
		t.Fatalf("descriptor = %+v", pm)
	}
}

func TestLegacyDumpMarkerAcceptedAs32Bit(t *testing.T) {
	bytes := make([]byte, HeaderBytes32)
	copy(bytes[0:8], Magic32Legacy)
	report, err := Read(memory(bytes), DefaultLimits())
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if report.Bitness != Bit32 || report.Magic != "PAGEDUMP" {
		t.Fatalf("layout = %+v", report)
	}
	if report.ValidDump != ValidDump32Legacy {
		t.Fatalf("valid dump = %q", report.ValidDump)
	}
}

func TestTriageDumpReadsItsDirectory(t *testing.T) {
	bytes := kernel64()
	bytes = append(bytes, make([]byte, 0x100)...)
	putU32(bytes, Offsets64.DumpType, 4)
	putU32(bytes, 0x2000+TriageDataBlocksOffset64, 0x2100)
	putU32(bytes, 0x2000+TriageDataBlocksCount64, 2)
	bytes = append(bytes, make([]byte, 0x100)...)
	putU64(bytes, 0x2100, 0xffff_f800_0000_1000)
	putU32(bytes, 0x2108, 0x2140)
	putU32(bytes, 0x210c, 0x10)
	putU64(bytes, 0x2110, 0xffff_f800_0000_2000)
	putU32(bytes, 0x2118, 0x21f0)
	putU32(bytes, 0x211c, 0x10)

	report, err := Read(memory(bytes), DefaultLimits())
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if report.DumpTypeName == nil || *report.DumpTypeName != DumpTypeTriage {
		t.Fatalf("dump type = %v", report.DumpTypeName)
	}
	directory := report.Directory
	if directory == nil {
		t.Fatal("triage dump has no directory")
	}
	if directory.TriageHeaderOffset != 0x2000 || directory.TableOffset != 0x2100 || directory.EntryCount != 2 {
		t.Fatalf("directory = %+v", directory)
	}
	if len(directory.Entries) != 2 || directory.Entries[0].Kind != "triage-data" {
		t.Fatalf("entries = %+v", directory.Entries)
	}
	if !directory.Entries[0].InBounds || directory.Entries[1].Offset != 0x21f0 || !directory.Entries[1].InBounds {
		t.Fatalf("entries = %+v", directory.Entries)
	}
	if directory.OutOfBounds != 0 {
		t.Fatalf("out of bounds = %d", directory.OutOfBounds)
	}
}

func TestTriageDirectoryPastSourceRefused(t *testing.T) {
	bytes := kernel64()
	bytes = append(bytes, make([]byte, 0x100)...)
	putU32(bytes, Offsets64.DumpType, 4)
	putU32(bytes, 0x2000+TriageDataBlocksOffset64, 0x2200)
	putU32(bytes, 0x2000+TriageDataBlocksCount64, 4)
	_, err := Read(memory(bytes), DefaultLimits())
	if !errors.Is(err, ErrDirectoryTruncated) {
		t.Fatalf("error = %v, want ErrDirectoryTruncated", err)
	}
	var dmpErr *Error
	if !errors.As(err, &dmpErr) || dmpErr.Offset != 0x2200 || dmpErr.Need != 64 {
		t.Fatalf("error detail = %+v", dmpErr)
	}
}

func TestMissingTriageHeaderRefused(t *testing.T) {
	bytes := kernel64()
	putU32(bytes, Offsets64.DumpType, 4)
	_, err := Read(memory(bytes), DefaultLimits())
	if !errors.Is(err, ErrTriageHeaderTruncated) {
		t.Fatalf("error = %v, want ErrTriageHeaderTruncated", err)
	}
	var dmpErr *Error
	if !errors.As(err, &dmpErr) || dmpErr.Offset != 0x2000 {
		t.Fatalf("error detail = %+v", dmpErr)
	}
}

func TestUnknownDumpTypePrintsNumerically(t *testing.T) {
	bytes := kernel64()
	putU32(bytes, Offsets64.DumpType, 0x77)
	report, err := Read(memory(bytes), DefaultLimits())
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if report.DumpTypeName != nil {
		t.Fatalf("dump type name = %v", report.DumpTypeName)
	}
	if got := report.DumpTypeLabel(); got != "unknown (0x77)" {
		t.Fatalf("DumpTypeLabel = %q", got)
	}
}

func TestBadSignatureNamed(t *testing.T) {
	bytes := kernel64()
	copy(bytes[0:4], "NOTA")
	_, err := Read(memory(bytes), DefaultLimits())
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("error = %v, want ErrBadSignature", err)
	}
	var dmpErr *Error
	if !errors.As(err, &dmpErr) || dmpErr.Found != [4]byte{'N', 'O', 'T', 'A'} {
		t.Fatalf("error detail = %+v", dmpErr)
	}
}

func TestUnknownValidDumpMarkerIsBitnessRefusal(t *testing.T) {
	bytes := kernel64()
	copy(bytes[4:8], "DUXX")
	_, err := Read(memory(bytes), DefaultLimits())
	if !errors.Is(err, ErrUnsupportedVariant) {
		t.Fatalf("error = %v, want ErrUnsupportedVariant", err)
	}
	var dmpErr *Error
	if !errors.As(err, &dmpErr) || dmpErr.Found != [4]byte{'D', 'U', 'X', 'X'} {
		t.Fatalf("error detail = %+v", dmpErr)
	}
}

func TestShortHeaderNamedWithLayoutOnceKnown(t *testing.T) {
	_, err := Read(memory([]byte("PAGE")), DefaultLimits())
	if !errors.Is(err, ErrHeaderTooShort) {
		t.Fatalf("error = %v, want ErrHeaderTooShort", err)
	}
	var dmpErr *Error
	if !errors.As(err, &dmpErr) || dmpErr.Bitness != nil || dmpErr.Need != 8 || dmpErr.Available != 4 {
		t.Fatalf("error detail = %+v", dmpErr)
	}

	bytes := kernel64()[:0x1000]
	_, err = Read(memory(bytes), DefaultLimits())
	if !errors.Is(err, ErrHeaderTooShort) {
		t.Fatalf("error = %v, want ErrHeaderTooShort", err)
	}
	if !errors.As(err, &dmpErr) || dmpErr.Bitness == nil || *dmpErr.Bitness != Bit64 ||
		dmpErr.Need != HeaderBytes64 || dmpErr.Available != 0x1000 {
		t.Fatalf("error detail = %+v", dmpErr)
	}
}

func TestLooksLikeAcceptsKernelAndMinidumpMagics(t *testing.T) {
	if !LooksLike([]byte(Magic64)) || !LooksLike([]byte(Magic32)) || !LooksLike([]byte(Magic32Legacy)) {
		t.Fatal("LooksLike rejected a kernel magic")
	}
	if !LooksLike([]byte("MDMP")) {
		t.Fatal("LooksLike rejected MDMP")
	}
	if LooksLike([]byte("PAGEDU6X")) || LooksLike([]byte("PAGE")) {
		t.Fatal("LooksLike accepted an unknown magic")
	}
}

func TestReadAnyDumpRoutesBySignature(t *testing.T) {
	kernel, err := ReadAnyDump(memory(kernel64()), DefaultLimits(), DefaultMiniDumpLimits())
	if err != nil {
		t.Fatalf("kernel ReadAnyDump error = %v", err)
	}
	if kernel.Kind != AnyKernel || kernel.Kernel == nil {
		t.Fatalf("kernel route = %+v", kernel)
	}

	miniBytes := make([]byte, MiniDumpHeaderBytes)
	copy(miniBytes[0:4], MiniDumpSignature[:])
	mini, err := ReadAnyDump(memory(miniBytes), DefaultLimits(), DefaultMiniDumpLimits())
	if err != nil {
		t.Fatalf("minidump ReadAnyDump error = %v", err)
	}
	if mini.Kind != AnyMiniDump || mini.MiniDump == nil || mini.MiniDump.StreamCount != 0 {
		t.Fatalf("minidump route = %+v", mini)
	}
}

func TestPhysicalViewsMapRunsToFileOffsets(t *testing.T) {
	bytes := kernel64()
	bytes = append(bytes, make([]byte, 5*PageSize)...)
	// Run 0 is three pages at file offset 0x2000, run 1 two pages at 0x5000.
	for i := uint64(0); i < 3*PageSize; i++ {
		bytes[0x2000+i] = 0xA1
	}
	for i := uint64(0); i < 2*PageSize; i++ {
		bytes[0x5000+i] = 0xB2
	}

	parent := memory(bytes)
	report, err := Read(parent, DefaultLimits())
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	views, err := report.PhysicalViews(7, parent)
	if err != nil {
		t.Fatalf("PhysicalViews error = %v", err)
	}
	if len(views) != 2 {
		t.Fatalf("views = %d", len(views))
	}
	first, second := views[0], views[1]
	if first.PhysicalStart != 0x100*PageSize || first.PhysicalEnd != 0x103*PageSize {
		t.Fatalf("run 0 physical = %#x-%#x", first.PhysicalStart, first.PhysicalEnd)
	}
	if first.FileOffset != HeaderBytes64 || first.Length != 3*PageSize {
		t.Fatalf("run 0 file = %+v", first)
	}
	if second.PhysicalStart != 0x200*PageSize || second.PhysicalEnd != 0x202*PageSize {
		t.Fatalf("run 1 physical = %#x-%#x", second.PhysicalStart, second.PhysicalEnd)
	}
	if second.FileOffset != HeaderBytes64+3*PageSize || second.Length != 2*PageSize {
		t.Fatalf("run 1 file = %+v", second)
	}

	got := make([]byte, 4)
	if _, err := first.Source.ReadAt(0, got); err != nil {
		t.Fatalf("run 0 ReadAt error = %v", err)
	}
	if got[0] != 0xA1 {
		t.Fatalf("run 0 first byte = %#x", got[0])
	}
	if _, err := second.Source.ReadAt(0, got); err != nil {
		t.Fatalf("run 1 ReadAt error = %v", err)
	}
	if got[0] != 0xB2 {
		t.Fatalf("run 1 first byte = %#x", got[0])
	}
	extents, err := first.Source.Extents(0, 4)
	if err != nil {
		t.Fatalf("Extents error = %v", err)
	}
	if len(extents) != 1 || extents[0].ParentOffset != HeaderBytes64 {
		t.Fatalf("extents = %+v", extents)
	}
}

func TestPhysicalViewsRefuseUnsubstantiatedLayouts(t *testing.T) {
	bytes := kernel64()
	bytes = append(bytes, make([]byte, 0x100)...)
	putU32(bytes, Offsets64.DumpType, 4)
	putU32(bytes, 0x2000+TriageDataBlocksOffset64, 0x2100)
	putU32(bytes, 0x2000+TriageDataBlocksCount64, 0)

	parent := memory(bytes)
	report, err := Read(parent, DefaultLimits())
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if _, err := report.PhysicalViews(1, parent); !errors.Is(err, ErrPhysicalUnavailable) {
		t.Fatalf("triage PhysicalViews error = %v, want ErrPhysicalUnavailable", err)
	}
}

func TestPhysicalViewsRefuseMissingRunData(t *testing.T) {
	parent := memory(kernel64())
	report, err := Read(parent, DefaultLimits())
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if _, err := report.PhysicalViews(1, parent); !errors.Is(err, ErrRunDataUnavailable) {
		t.Fatalf("PhysicalViews error = %v, want ErrRunDataUnavailable", err)
	}
}

func TestPhysicalViewsRefuseUnreportedRuns(t *testing.T) {
	limits := DefaultLimits()
	limits.ReportRuns = 1
	parent := memory(append(kernel64(), make([]byte, 5*PageSize)...))
	report, err := Read(parent, limits)
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if _, err := report.PhysicalViews(1, parent); !errors.Is(err, ErrPhysicalUnavailable) {
		t.Fatalf("PhysicalViews error = %v, want ErrPhysicalUnavailable", err)
	}
}

func TestPhysicalViewsRefuseAddressOverflow(t *testing.T) {
	bytes := kernel64()
	bytes = append(bytes, make([]byte, 5*PageSize)...)
	putU64(bytes, Offsets64.Runs, math.MaxUint64)

	parent := memory(bytes)
	report, err := Read(parent, DefaultLimits())
	if err != nil {
		t.Fatalf("Read error = %v", err)
	}
	if _, err := report.PhysicalViews(1, parent); !errors.Is(err, ErrOffsetOverflow) {
		t.Fatalf("PhysicalViews error = %v, want ErrOffsetOverflow", err)
	}
}
