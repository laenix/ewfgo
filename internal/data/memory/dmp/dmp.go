// Package dmp reads Windows kernel crash dumps (`PAGEDU64` / `PAGEDU32`) and
// user-mode minidumps (`MDMP`).
//
// A kernel dump starts with a fixed DUMP_HEADER32 (4 KiB) or DUMP_HEADER64
// (8 KiB) followed by the dumped data. The header names the machine, the
// crashing context, the bugcheck, the physical-memory runs the dump covers and,
// for a triage dump, a table of extra data blocks:
//
//	0x00  4 B  signature `PAGE`
//	0x04  4 B  valid-dump marker: `DU64`, `DU32` or the legacy `DUMP`
//	0x08  u32  major version          0x0c  u32  minor version
//	...        directory table base, machine, processors, bugcheck
//	...        physical-memory descriptor (run count, total pages, runs)
//	...        context record, exception record, dump type, writer status
//
// The reader reports header metadata only. It does not interpret context or
// exception bytes, page tables, kernel structures or dumped memory, and it does
// not translate addresses. Every count is capped and every table is checked
// against the source before it is read.
//
// A source whose first four bytes are `MDMP` is a user-mode minidump;
// ReadMiniDump reads its stream directory and documented stream structures
// with the same bounds discipline, and ReadAnyDump picks the layout from the
// signature.
//
// PhysicalViews is the core physical-memory view. It maps the header's
// physical runs to the file offsets where a full or kernel dump stores them.
// It refuses layouts (triage, header, bitmap) whose run-data placement is not
// substantiated and refuses missing run data rather than zero-filling it.
//
// This package is a pure-Go port of forensic-core's data/memory/dmp/mod.rs and
// dmp/minidump.rs.
package dmp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Header byte lengths.
const (
	// HeaderBytes64 is the DUMP_HEADER64 length.
	HeaderBytes64 uint64 = 0x2000
	// HeaderBytes32 is the DUMP_HEADER32 length.
	HeaderBytes32 uint64 = 0x1000
)

// The eight-byte magics that route a kernel dump.
const (
	// Magic64 is the full 64-bit dump magic.
	Magic64 = "PAGEDU64"
	// Magic32 is the 32-bit dump magic.
	Magic32 = "PAGEDU32"
	// Magic32Legacy is the legacy 32-bit kernel-dump magic.
	Magic32Legacy = "PAGEDUMP"
)

// Signature and valid-dump markers.
var (
	// Signature is the DUMP_HEADER signature dword, `PAGE`.
	Signature = [4]byte{'P', 'A', 'G', 'E'}
	// ValidDump64 is the 64-bit valid-dump dword, `DU64`.
	ValidDump64 = [4]byte{'D', 'U', '6', '4'}
	// ValidDump32 is the current 32-bit valid-dump dword, `DU32`.
	ValidDump32 = [4]byte{'D', 'U', '3', '2'}
	// ValidDump32Legacy is the legacy 32-bit valid-dump dword, `DUMP`.
	ValidDump32Legacy = [4]byte{'D', 'U', 'M', 'P'}
)

// PageSize is the implicit dump page size. Windows dump pages are 4 KiB and
// the header has no page-size field.
const PageSize uint64 = 0x1000

// Layout holds the field offsets of one DUMP_HEADER layout.
type Layout struct {
	DirectoryTableBase       int
	MachineImageType         int
	NumberProcessors         int
	BugcheckCode             int
	BugcheckParameters       int
	ImplementationVersion    int
	PhysicalMemoryBlock      int
	RunCount                 int
	TotalPages               int
	Runs                     int
	RunCapacity              int
	RunBytes                 int
	ContextRecord            int
	ExceptionRecord          int
	DumpType                 int
	WriterStatus             int
	PhysicalBlockRegionBytes uint64
}

// Offsets64 holds the DUMP_HEADER64 field offsets.
var Offsets64 = Layout{
	DirectoryTableBase:       0x10,
	MachineImageType:         0x30,
	NumberProcessors:         0x34,
	BugcheckCode:             0x38,
	BugcheckParameters:       0x40,
	ImplementationVersion:    0x104d,
	PhysicalMemoryBlock:      0x88,
	RunCount:                 0x88,
	TotalPages:               0x90,
	Runs:                     0x98,
	RunCapacity:              0x2b,
	RunBytes:                 16,
	ContextRecord:            0x348,
	ExceptionRecord:          0xf00,
	DumpType:                 0xf98,
	WriterStatus:             0x1048,
	PhysicalBlockRegionBytes: 0x2c0,
}

// Offsets32 holds the DUMP_HEADER32 field offsets.
var Offsets32 = Layout{
	DirectoryTableBase:       0x10,
	MachineImageType:         0x20,
	NumberProcessors:         0x24,
	BugcheckCode:             0x28,
	BugcheckParameters:       0x2c,
	ImplementationVersion:    0x5d,
	PhysicalMemoryBlock:      0x64,
	RunCount:                 0x64,
	TotalPages:               0x68,
	Runs:                     0x6c,
	RunCapacity:              0x56,
	RunBytes:                 8,
	ContextRecord:            0x320,
	ExceptionRecord:          0x7d0,
	DumpType:                 0xf88,
	WriterStatus:             0xf9c,
	PhysicalBlockRegionBytes: 0x2bc,
}

// Triage-header field offsets. The triage structure starts at the end of the
// dump header (0x1000 for 32-bit, 0x2000 for 64-bit).
const (
	TriageDataBlocksOffset32 = 0x60
	TriageDataBlocksCount32  = 0x64
	TriageDataBlocksOffset64 = 0x78
	TriageDataBlocksCount64  = 0x7c
	TriageMinBytes32         = 0x68
	TriageMinBytes64         = 0x80
	TriageDataBlockBytes32   = 12
	TriageDataBlockBytes64   = 16
)

// Bitness is the dump header layout a source carries.
type Bitness uint8

const (
	// Bit32 is the DUMP_HEADER32 layout.
	Bit32 Bitness = iota
	// Bit64 is the DUMP_HEADER64 layout.
	Bit64
)

// Label returns "32-bit" or "64-bit".
func (b Bitness) Label() string {
	if b == Bit64 {
		return "64-bit"
	}
	return "32-bit"
}

// HeaderBytes returns the fixed header length for this layout.
func (b Bitness) HeaderBytes() uint64 {
	if b == Bit64 {
		return HeaderBytes64
	}
	return HeaderBytes32
}

// Magic returns the eight-byte magic this layout is routed by, except that the
// legacy 32-bit marker is reported by the report's Magic field as PAGEDUMP.
func (b Bitness) Magic() string {
	if b == Bit64 {
		return Magic64
	}
	return Magic32
}

// Limits caps one dump-header read. No allocation is sized by an unvalidated
// count in the file.
type Limits struct {
	// MaxRuns is the most physical runs the descriptor may declare.
	MaxRuns int
	// ReportRuns is how many leading runs to report.
	ReportRuns int
	// MaxDirectoryEntries is the most triage directory entries allowed.
	MaxDirectoryEntries int
	// ReportDirectoryEntries is how many leading entries to report.
	ReportDirectoryEntries int
}

// DefaultLimits returns the reference limits.
func DefaultLimits() Limits {
	return Limits{
		MaxRuns:                4096,
		ReportRuns:             8,
		MaxDirectoryEntries:    4096,
		ReportDirectoryEntries: 16,
	}
}

// Error kinds. Test them with errors.Is.
var (
	ErrHeaderTooShort          = errors.New("memory/dmp: header too short")
	ErrBadSignature            = errors.New("memory/dmp: bad signature")
	ErrUnsupportedVariant      = errors.New("memory/dmp: unsupported valid-dump variant")
	ErrRunTableOverflow        = errors.New("memory/dmp: run table overflows header")
	ErrTooManyRuns             = errors.New("memory/dmp: too many runs")
	ErrTriageHeaderTruncated   = errors.New("memory/dmp: triage header truncated")
	ErrTooManyDirectoryEntries = errors.New("memory/dmp: too many triage directory entries")
	ErrDirectoryTruncated      = errors.New("memory/dmp: triage directory truncated")
	ErrOffsetOverflow          = errors.New("memory/dmp: offset overflow")
	ErrSource                  = errors.New("memory/dmp: source error")
	ErrUnsupported             = source.ErrUnsupported
	ErrPhysicalUnavailable     = fmt.Errorf("%w: this dump layout does not substantiate physical run-data placement", source.ErrUnsupported)
	ErrRunDataUnavailable      = fmt.Errorf("%w: dump physical run data is missing from the source", source.ErrUnexpectedEOF)
)

// Error is a structured kernel-dump failure.
type Error struct {
	Kind      error
	Bitness   *Bitness
	Need      uint64
	Available uint64
	Found     [4]byte
	Count     uint32
	Capacity  int
	Limit     uint64
	Offset    uint64
	Err       error
}

func (e *Error) Error() string {
	switch {
	case errors.Is(e.Kind, ErrHeaderTooShort):
		if e.Bitness != nil {
			return fmt.Sprintf("%s dump header needs %d bytes, source has %d", e.Bitness.Label(), e.Need, e.Available)
		}
		return fmt.Sprintf("too short to identify a Windows dump: need %d bytes, source has %d", e.Need, e.Available)
	case errors.Is(e.Kind, ErrBadSignature):
		return fmt.Sprintf("dump signature is % X, expected 50 41 47 45 (`PAGE`)", e.Found)
	case errors.Is(e.Kind, ErrUnsupportedVariant):
		return fmt.Sprintf("dump valid-dump field is % X; expected `DU64`, `DU32` or `DUMP`, so the bitness is not known", e.Found)
	case errors.Is(e.Kind, ErrRunTableOverflow):
		return fmt.Sprintf("dump declares %d physical runs, but its header holds at most %d", e.Count, e.Capacity)
	case errors.Is(e.Kind, ErrTooManyRuns):
		return fmt.Sprintf("dump declares %d physical runs, over the %d-run cap", e.Count, e.Limit)
	case errors.Is(e.Kind, ErrTriageHeaderTruncated):
		return fmt.Sprintf("triage dump header at %d needs %d bytes, source has %d", e.Offset, e.Need, e.Available)
	case errors.Is(e.Kind, ErrTooManyDirectoryEntries):
		return fmt.Sprintf("triage directory declares %d entries, over the %d-entry cap", e.Count, e.Limit)
	case errors.Is(e.Kind, ErrDirectoryTruncated):
		return fmt.Sprintf("triage directory table at %d needs %d bytes, source has %d", e.Offset, e.Need, e.Available)
	case errors.Is(e.Kind, ErrOffsetOverflow):
		return "dump table offset does not fit in u64"
	case errors.Is(e.Kind, ErrSource):
		if e.Err != nil {
			return e.Err.Error()
		}
		return "dump source read failed"
	default:
		if e.Err != nil {
			return e.Err.Error()
		}
		return "dump error"
	}
}

// Unwrap exposes both the kind and the underlying cause to errors.Is/As.
func (e *Error) Unwrap() []error {
	out := make([]error, 0, 2)
	if e.Kind != nil {
		out = append(out, e.Kind)
	}
	if e.Err != nil {
		out = append(out, e.Err)
	}
	return out
}

// Run is one physical-memory run named by the header.
type Run struct {
	// Index is the zero-based position in the run array.
	Index int
	// BasePage is the first page (PFN) in the run.
	BasePage uint64
	// PageCount is the number of pages the run covers.
	PageCount uint64
}

// PhysicalMemory summarises the header's embedded physical-memory descriptor.
type PhysicalMemory struct {
	// RunCount is the number of runs the descriptor declares.
	RunCount uint32
	// Capacity is the number of runs the fixed header can physically hold.
	Capacity int
	// Runs is the leading runs, at most Limits.ReportRuns.
	Runs []Run
	// TotalPages is the total pages the descriptor declares.
	TotalPages uint64
	// PageSize is the page size used to interpret run page counts.
	PageSize uint64
	// PageSizeInHeader reports whether PageSize came from a header field
	// (always false today).
	PageSizeInHeader bool
	// DescriptorBytes is the bytes the declared runs use in the descriptor.
	DescriptorBytes uint64
	// RegionBytes is the bytes reserved for the descriptor in the header.
	RegionBytes uint64
}

// DumpType names a documented dump type.
type DumpType uint32

const (
	DumpTypeUnknown DumpType = iota
	DumpTypeFull
	DumpTypeKernel
	DumpTypeHeader
	DumpTypeTriage
	DumpTypeBitmapFull
	DumpTypeBitmapKernel
)

// DumpTypeFromRaw maps a raw DumpType value, if documented.
func DumpTypeFromRaw(value uint32) (DumpType, bool) {
	if value > uint32(DumpTypeBitmapKernel) {
		return DumpTypeUnknown, false
	}
	return DumpType(value), true
}

// Label returns the documented name.
func (d DumpType) Label() string {
	switch d {
	case DumpTypeFull:
		return "full"
	case DumpTypeKernel:
		return "kernel"
	case DumpTypeHeader:
		return "header"
	case DumpTypeTriage:
		return "triage"
	case DumpTypeBitmapFull:
		return "bitmap-full"
	case DumpTypeBitmapKernel:
		return "bitmap-kernel"
	default:
		return "unknown"
	}
}

// DirectoryEntry is one entry in a triage dump's data-block directory.
type DirectoryEntry struct {
	// Index is the zero-based position in the table.
	Index int
	// Kind is the entry's fixed kind. Triage data blocks are the only
	// directory form this reader reports.
	Kind string
	// Address is the raw kernel address, as stored; never dereferenced.
	Address uint64
	// Offset is the file offset of the block.
	Offset uint32
	// Size is the declared block size.
	Size uint32
	// InBounds reports whether Offset+Size fits inside the source.
	InBounds bool
}

// Directory is a triage dump's bounded data-block directory.
type Directory struct {
	// TriageHeaderOffset is the file offset of the triage header (0x1000/0x2000).
	TriageHeaderOffset uint64
	// TableOffset is the file offset of the directory table.
	TableOffset uint64
	// EntryCount is the number of entries the table declares.
	EntryCount uint32
	// Entries is the leading entries, at most Limits.ReportDirectoryEntries.
	Entries []DirectoryEntry
	// OutOfBounds is the number of reported entries whose range leaves the source.
	OutOfBounds int
}

// Report is header metadata from a Windows kernel crash dump.
type Report struct {
	Bitness                   Bitness
	Signature                 [4]byte
	ValidDump                 [4]byte
	Magic                     string
	HeaderBytes               uint64
	MajorVersion              uint32
	MinorVersion              uint32
	ImplementationVersion     uint8
	DirectoryTableBase        uint64
	PhysicalMemoryBlockOffset uint64
	ContextRecordOffset       uint64
	ExceptionRecordOffset     uint64
	MachineImageType          uint32
	NumberProcessors          uint32
	BugcheckCode              uint32
	BugcheckParameters        [4]uint64
	DumpType                  uint32
	DumpTypeName              *DumpType
	WriterStatus              uint32
	PhysicalMemory            PhysicalMemory
	Directory                 *Directory
}

// DumpTypeLabel returns the dump type as `name (value)` or a numeric value
// when undocumented.
func (r *Report) DumpTypeLabel() string {
	if r.DumpTypeName != nil {
		return fmt.Sprintf("%s (%d)", r.DumpTypeName.Label(), r.DumpType)
	}
	return fmt.Sprintf("unknown (0x%x)", r.DumpType)
}

// RunView is one physical run mapped to its file-backed source window.
type RunView struct {
	// Run is the header's run record.
	Run Run
	// PhysicalStart is Run.BasePage * PageSize.
	PhysicalStart uint64
	// PhysicalEnd is PhysicalStart + Length.
	PhysicalEnd uint64
	// FileOffset is where the run's bytes start in the dump file.
	FileOffset uint64
	// Length is Run.PageCount * PageSize.
	Length uint64
	// Source is the bounded read-only window over the run's stored bytes.
	Source *source.SubSource
}

// PhysicalViews maps the header's physical runs to the file offsets where a
// full or kernel dump stores them.
//
// Only full and kernel dumps have a substantiated sequential run-data layout
// after the header; triage, header and bitmap dumps are refused with
// ErrPhysicalUnavailable. A run whose data leaves the source is refused with
// ErrRunDataUnavailable, and a run address that overflows uint64 is refused
// with ErrOffsetOverflow. Missing bytes are never zero-filled.
func (r *Report) PhysicalViews(id source.ID, parent source.ByteSource) ([]RunView, error) {
	if r.DumpTypeName == nil ||
		(*r.DumpTypeName != DumpTypeFull && *r.DumpTypeName != DumpTypeKernel) {
		return nil, fmt.Errorf("%w: dump type %s", ErrPhysicalUnavailable, r.DumpTypeLabel())
	}
	if int(r.PhysicalMemory.RunCount) != len(r.PhysicalMemory.Runs) {
		return nil, fmt.Errorf("%w: only %d of %d physical runs were reported; raise Limits.ReportRuns",
			ErrPhysicalUnavailable, len(r.PhysicalMemory.Runs), r.PhysicalMemory.RunCount)
	}

	views := make([]RunView, 0, len(r.PhysicalMemory.Runs))
	fileOffset := r.HeaderBytes
	for _, run := range r.PhysicalMemory.Runs {
		physicalStart, ok := mulPageSize(run.BasePage)
		if !ok {
			return nil, &Error{Kind: ErrOffsetOverflow}
		}
		length, ok := mulPageSize(run.PageCount)
		if !ok {
			return nil, &Error{Kind: ErrOffsetOverflow}
		}
		physicalEnd, ok := addU64(physicalStart, length)
		if !ok {
			return nil, &Error{Kind: ErrOffsetOverflow}
		}
		if fileOffset > parent.Len() || length > parent.Len()-fileOffset {
			return nil, fmt.Errorf("%w: run %d needs [%d, +%d) but source length is %d",
				ErrRunDataUnavailable, run.Index, fileOffset, length, parent.Len())
		}
		sub, err := source.NewSubSource(id, parent, fileOffset, length)
		if err != nil {
			return nil, fmt.Errorf("%w: run %d: %v", ErrRunDataUnavailable, run.Index, err)
		}
		views = append(views, RunView{
			Run:           run,
			PhysicalStart: physicalStart,
			PhysicalEnd:   physicalEnd,
			FileOffset:    fileOffset,
			Length:        length,
			Source:        sub,
		})
		next, ok := addU64(fileOffset, length)
		if !ok {
			return nil, &Error{Kind: ErrOffsetOverflow}
		}
		fileOffset = next
	}
	return views, nil
}

func mulPageSize(pages uint64) (uint64, bool) {
	if pages > math.MaxUint64/PageSize {
		return 0, false
	}
	return pages * PageSize, true
}

func addU64(a, b uint64) (uint64, bool) {
	if b > math.MaxUint64-a {
		return 0, false
	}
	return a + b, true
}

// LooksLike reports whether head starts with a kernel-dump or user-mode
// minidump magic.
func LooksLike(head []byte) bool {
	if len(head) >= 8 {
		magic := string(head[:8])
		if magic == Magic64 || magic == Magic32 || magic == Magic32Legacy {
			return true
		}
	}
	return MiniDumpLooksLike(head)
}

// AnyKind is the layout ReadAnyDump selected.
type AnyKind uint8

const (
	// AnyKernel is a kernel crash dump.
	AnyKernel AnyKind = iota
	// AnyMiniDump is a user-mode minidump.
	AnyMiniDump
)

// AnyDump is the layout ReadAnyDump selected. Exactly one of Kernel and
// MiniDump is non-nil.
type AnyDump struct {
	Kind     AnyKind
	Kernel   *Report
	MiniDump *MiniDumpReport
}

// ReadAnyDump reads either a kernel crash dump or a user-mode minidump. The
// four-byte signature chooses the reader. Errors are returned directly from
// the selected reader and remain errors.Is/As-friendly.
func ReadAnyDump(src source.ByteSource, kernelLimits Limits, miniDumpLimits MiniDumpLimits) (*AnyDump, error) {
	var head [4]byte
	if src.Len() >= 4 {
		if err := source.ReadExactAt(src, 0, head[:]); err != nil {
			return nil, err
		}
	}
	if head == MiniDumpSignature {
		report, err := ReadMiniDump(src, miniDumpLimits)
		if err != nil {
			return nil, err
		}
		return &AnyDump{Kind: AnyMiniDump, MiniDump: report}, nil
	}
	report, err := Read(src, kernelLimits)
	if err != nil {
		return nil, err
	}
	return &AnyDump{Kind: AnyKernel, Kernel: report}, nil
}

func u32At(bytes []byte, offset int) uint32 {
	return binary.LittleEndian.Uint32(bytes[offset : offset+4])
}

func u64At(bytes []byte, offset int) uint64 {
	return binary.LittleEndian.Uint64(bytes[offset : offset+8])
}

// Read reads a Windows kernel crash-dump header and reports its static
// metadata.
//
// Only the fixed header is read in full. The triage directory table, when
// present, is read entry by entry inside the caps; run and directory payload
// ranges are checked but never read.
func Read(src source.ByteSource, limits Limits) (*Report, error) {
	if limits.MaxRuns < 0 {
		limits.MaxRuns = 0
	}
	if limits.ReportRuns < 0 {
		limits.ReportRuns = 0
	}
	if limits.MaxDirectoryEntries < 0 {
		limits.MaxDirectoryEntries = 0
	}
	if limits.ReportDirectoryEntries < 0 {
		limits.ReportDirectoryEntries = 0
	}
	sourceLen := src.Len()
	if sourceLen < 8 {
		return nil, &Error{Kind: ErrHeaderTooShort, Need: 8, Available: sourceLen}
	}

	head, err := source.ReadVecAt(src, 0, 8)
	if err != nil {
		return nil, &Error{Kind: ErrSource, Err: err}
	}
	foundSignature := [4]byte{head[0], head[1], head[2], head[3]}
	if foundSignature != Signature {
		return nil, &Error{Kind: ErrBadSignature, Found: foundSignature}
	}

	validDump := [4]byte{head[4], head[5], head[6], head[7]}
	var bitness Bitness
	switch validDump {
	case ValidDump64:
		bitness = Bit64
	case ValidDump32, ValidDump32Legacy:
		bitness = Bit32
	default:
		return nil, &Error{Kind: ErrUnsupportedVariant, Found: validDump}
	}

	headerBytes := bitness.HeaderBytes()
	if sourceLen < headerBytes {
		return nil, &Error{
			Kind:      ErrHeaderTooShort,
			Bitness:   &bitness,
			Need:      headerBytes,
			Available: sourceLen,
		}
	}
	header, err := source.ReadVecAt(src, 0, headerBytes)
	if err != nil {
		return nil, &Error{Kind: ErrSource, Err: err}
	}

	magic := Magic64
	if bitness == Bit32 {
		if validDump == ValidDump32 {
			magic = Magic32
		} else {
			magic = Magic32Legacy
		}
	}

	layout := Offsets64
	if bitness == Bit32 {
		layout = Offsets32
	}

	var directoryTableBase uint64
	var bugcheckParameters [4]uint64
	if bitness == Bit64 {
		directoryTableBase = u64At(header, layout.DirectoryTableBase)
		bugcheckParameters = [4]uint64{
			u64At(header, layout.BugcheckParameters),
			u64At(header, layout.BugcheckParameters+8),
			u64At(header, layout.BugcheckParameters+16),
			u64At(header, layout.BugcheckParameters+24),
		}
	} else {
		directoryTableBase = uint64(u32At(header, layout.DirectoryTableBase))
		bugcheckParameters = [4]uint64{
			uint64(u32At(header, layout.BugcheckParameters)),
			uint64(u32At(header, layout.BugcheckParameters+4)),
			uint64(u32At(header, layout.BugcheckParameters+8)),
			uint64(u32At(header, layout.BugcheckParameters+12)),
		}
	}

	runCount := u32At(header, layout.RunCount)
	var totalPages uint64
	if bitness == Bit64 {
		totalPages = u64At(header, layout.TotalPages)
	} else {
		totalPages = uint64(u32At(header, layout.TotalPages))
	}
	if uint64(runCount) > uint64(layout.RunCapacity) {
		return nil, &Error{Kind: ErrRunTableOverflow, Count: runCount, Capacity: layout.RunCapacity}
	}
	if uint64(runCount) > uint64(limits.MaxRuns) {
		return nil, &Error{Kind: ErrTooManyRuns, Count: runCount, Limit: uint64(limits.MaxRuns)}
	}

	reportedRuns := int(runCount)
	if reportedRuns > limits.ReportRuns {
		reportedRuns = limits.ReportRuns
	}
	runs := make([]Run, 0, reportedRuns)
	for index := 0; index < reportedRuns; index++ {
		offset := layout.Runs + index*layout.RunBytes
		var basePage, pageCount uint64
		if bitness == Bit64 {
			basePage = u64At(header, offset)
			pageCount = u64At(header, offset+8)
		} else {
			basePage = uint64(u32At(header, offset))
			pageCount = uint64(u32At(header, offset+4))
		}
		runs = append(runs, Run{Index: index, BasePage: basePage, PageCount: pageCount})
	}
	descriptorBytes := uint64(layout.Runs-layout.RunCount) + uint64(runCount)*uint64(layout.RunBytes)

	dumpTypeRaw := u32At(header, layout.DumpType)
	dumpType, hasDumpType := DumpTypeFromRaw(dumpTypeRaw)
	var dumpTypeName *DumpType
	if hasDumpType {
		kind := dumpType
		dumpTypeName = &kind
	}

	physicalMemory := PhysicalMemory{
		RunCount:         runCount,
		Capacity:         layout.RunCapacity,
		Runs:             runs,
		TotalPages:       totalPages,
		PageSize:         PageSize,
		PageSizeInHeader: false,
		DescriptorBytes:  descriptorBytes,
		RegionBytes:      layout.PhysicalBlockRegionBytes,
	}

	var directory *Directory
	if hasDumpType && dumpType == DumpTypeTriage {
		directory, err = readDirectory(src, sourceLen, bitness, limits)
		if err != nil {
			return nil, err
		}
	}

	return &Report{
		Bitness:                   bitness,
		Signature:                 foundSignature,
		ValidDump:                 validDump,
		Magic:                     magic,
		HeaderBytes:               headerBytes,
		MajorVersion:              u32At(header, 0x08),
		MinorVersion:              u32At(header, 0x0c),
		ImplementationVersion:     header[layout.ImplementationVersion],
		DirectoryTableBase:        directoryTableBase,
		PhysicalMemoryBlockOffset: uint64(layout.PhysicalMemoryBlock),
		ContextRecordOffset:       uint64(layout.ContextRecord),
		ExceptionRecordOffset:     uint64(layout.ExceptionRecord),
		MachineImageType:          u32At(header, layout.MachineImageType),
		NumberProcessors:          u32At(header, layout.NumberProcessors),
		BugcheckCode:              u32At(header, layout.BugcheckCode),
		BugcheckParameters:        bugcheckParameters,
		DumpType:                  dumpTypeRaw,
		DumpTypeName:              dumpTypeName,
		WriterStatus:              u32At(header, layout.WriterStatus),
		PhysicalMemory:            physicalMemory,
		Directory:                 directory,
	}, nil
}

// readDirectory reads and bounds the triage data-block directory.
func readDirectory(src source.ByteSource, sourceLen uint64, bitness Bitness, limits Limits) (*Directory, error) {
	triageOffset := HeaderBytes64
	offsetField := TriageDataBlocksOffset64
	minBytes := TriageMinBytes64
	entryBytes := TriageDataBlockBytes64
	if bitness == Bit32 {
		triageOffset = HeaderBytes32
		offsetField = TriageDataBlocksOffset32
		minBytes = TriageMinBytes32
		entryBytes = TriageDataBlockBytes32
	}

	available := uint64(0)
	if triageOffset <= sourceLen {
		available = sourceLen - triageOffset
	}
	if available < uint64(minBytes) {
		return nil, &Error{
			Kind:      ErrTriageHeaderTruncated,
			Offset:    triageOffset,
			Need:      uint64(minBytes),
			Available: available,
		}
	}

	fields, err := source.ReadVecAt(src, triageOffset+uint64(offsetField), 8)
	if err != nil {
		return nil, &Error{Kind: ErrSource, Err: err}
	}
	tableOffset := uint64(binary.LittleEndian.Uint32(fields[0:4]))
	entryCount := binary.LittleEndian.Uint32(fields[4:8])

	if uint64(entryCount) > uint64(limits.MaxDirectoryEntries) {
		return nil, &Error{Kind: ErrTooManyDirectoryEntries, Count: entryCount, Limit: uint64(limits.MaxDirectoryEntries)}
	}

	tableBytes := uint64(entryCount) * uint64(entryBytes)
	tableEnd, ok := addU64(tableOffset, tableBytes)
	if !ok {
		return nil, &Error{Kind: ErrOffsetOverflow}
	}
	if tableEnd > sourceLen {
		available := uint64(0)
		if tableOffset <= sourceLen {
			available = sourceLen - tableOffset
		}
		return nil, &Error{
			Kind:      ErrDirectoryTruncated,
			Offset:    tableOffset,
			Need:      tableBytes,
			Available: available,
		}
	}

	reported := int(entryCount)
	if reported > limits.ReportDirectoryEntries {
		reported = limits.ReportDirectoryEntries
	}
	entries := make([]DirectoryEntry, 0, reported)
	outOfBounds := 0
	var row [TriageDataBlockBytes64]byte
	for index := 0; index < reported; index++ {
		offset := tableOffset + uint64(index*entryBytes)
		if err := source.ReadExactAt(src, offset, row[:entryBytes]); err != nil {
			return nil, &Error{Kind: ErrSource, Err: err}
		}
		var address uint64
		var blockOffset, blockSize uint32
		if bitness == Bit64 {
			address = binary.LittleEndian.Uint64(row[0:8])
			blockOffset = binary.LittleEndian.Uint32(row[8:12])
			blockSize = binary.LittleEndian.Uint32(row[12:16])
		} else {
			address = uint64(binary.LittleEndian.Uint32(row[0:4]))
			blockOffset = binary.LittleEndian.Uint32(row[4:8])
			blockSize = binary.LittleEndian.Uint32(row[8:12])
		}
		end, ok := addU64(uint64(blockOffset), uint64(blockSize))
		inBounds := ok && end <= sourceLen
		if !inBounds {
			outOfBounds++
		}
		entries = append(entries, DirectoryEntry{
			Index:    index,
			Kind:     "triage-data",
			Address:  address,
			Offset:   blockOffset,
			Size:     blockSize,
			InBounds: inBounds,
		})
	}

	return &Directory{
		TriageHeaderOffset: triageOffset,
		TableOffset:        tableOffset,
		EntryCount:         entryCount,
		Entries:            entries,
		OutOfBounds:        outOfBounds,
	}, nil
}
