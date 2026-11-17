package dmp

// User-mode minidump (MDMP) reading.
//
// A minidump is a flat container: a 32-byte MINIDUMP_HEADER names a directory
// of streams, and each stream is an independent structure at a file RVA. This
// reader reports the header, every bounded stream descriptor and the metadata
// inside the documented streams. It never reads pointed-to process memory,
// never maps an address and never executes any byte: addresses such as
// BaseOfImage, Teb, ExceptionAddress and memory-run starts are reported exactly
// as stored.
//
//	0x00  4 B  signature `MDMP` (0x504D444D little-endian)
//	0x04  u32  version: high 16 major, low 16 minor
//	0x08  u32  NumberOfStreams
//	0x0c  u32  StreamDirectoryRva
//	0x10  u32  CheckSum
//	0x14  u32  TimeDateStamp (Unix seconds, 0 when not supplied)
//	0x18  u64  Flags (MINIDUMP_TYPE)
//
// Streams decoded: ThreadList (3), ModuleList (4), MemoryList (5), Exception
// (6), SystemInfo (7), Memory64List (9) and MiscInfo (15). Other documented
// stream types are listed as presence-only descriptors. Every list count is
// compared with the space the stream declares and only the leading
// report_* entries are materialised.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode/utf16"

	"github.com/laenix/ewfgo/internal/data/source"
)

// MiniDumpSignature is the MINIDUMP_HEADER.Signature, the four bytes `MDMP`.
var MiniDumpSignature = [4]byte{'M', 'D', 'M', 'P'}

// MiniDumpSignatureU32 is the signature as a little-endian u32.
const MiniDumpSignatureU32 uint32 = 0x504D_444D

// Fixed structure sizes.
const (
	MiniDumpHeaderBytes         = 32
	MiniDumpDirectoryEntryBytes = 12
	MaxExceptionParameters      = 15
	SystemInfoBytes             = 56
	ModuleBytes                 = 108
	ThreadBytes                 = 48
	MemoryDescriptorBytes       = 16
	Memory64HeaderBytes         = 16
	ExceptionRecordBytes        = 152
	ExceptionStreamBytes        = 8 + ExceptionRecordBytes + 8
	MiscInfoBytes               = 24
)

// MINIDUMP_HEADER field offsets.
const (
	MiniHeaderSignature          = 0x00
	MiniHeaderVersion            = 0x04
	MiniHeaderNumberOfStreams    = 0x08
	MiniHeaderStreamDirectoryRVA = 0x0c
	MiniHeaderCheckSum           = 0x10
	MiniHeaderTimeDateStamp      = 0x14
	MiniHeaderFlags              = 0x18
)

// Documented MINIDUMP_STREAM_TYPE values.
const (
	StreamThreadList         uint32 = 3
	StreamModuleList         uint32 = 4
	StreamMemoryList         uint32 = 5
	StreamException          uint32 = 6
	StreamSystemInfo         uint32 = 7
	StreamMemory64List       uint32 = 9
	StreamHandleData         uint32 = 12
	StreamUnloadedModuleList uint32 = 14
	StreamMiscInfo           uint32 = 15
	StreamMemoryInfoList     uint32 = 16
	StreamThreadInfoList     uint32 = 17
	StreamThreadNames        uint32 = 24
)

// MINIDUMP_SYSTEM_INFO field offsets.
const (
	SysInfoProcessorArchitecture = 0x00
	SysInfoProcessorLevel        = 0x02
	SysInfoProcessorRevision     = 0x04
	SysInfoNumberOfProcessors    = 0x06
	SysInfoProductType           = 0x07
	SysInfoMajorVersion          = 0x08
	SysInfoMinorVersion          = 0x0c
	SysInfoBuildNumber           = 0x10
	SysInfoPlatformID            = 0x14
	SysInfoCSDVersionRVA         = 0x18
	SysInfoSuiteMask             = 0x1c
	SysInfoCPU                   = 0x20
)

// MINIDUMP_MODULE field offsets.
const (
	ModuleBaseOfImage   = 0x00
	ModuleSizeOfImage   = 0x08
	ModuleCheckSum      = 0x0c
	ModuleTimeDateStamp = 0x10
	ModuleNameRVA       = 0x14
	ModuleVersionInfo   = 0x18
	ModuleCVRecord      = 0x4c
	ModuleMiscRecord    = 0x54
)

// MINIDUMP_THREAD field offsets.
const (
	ThreadThreadID      = 0x00
	ThreadSuspendCount  = 0x04
	ThreadPriorityClass = 0x08
	ThreadPriority      = 0x0c
	ThreadTEB           = 0x10
	ThreadStackStart    = 0x18
	ThreadStackSize     = 0x20
	ThreadStackRVA      = 0x24
	ThreadContextSize   = 0x28
	ThreadContextRVA    = 0x2c
)

// MINIDUMP_EXCEPTION_STREAM field offsets.
const (
	ExceptionThreadID         = 0x00
	ExceptionCode             = 0x08
	ExceptionFlags            = 0x0c
	ExceptionRecord           = 0x10
	ExceptionAddress          = 0x18
	ExceptionNumberParameters = 0x20
	ExceptionParameters       = 0x28
	ExceptionContextSize      = 0xa0
	ExceptionContextRVA       = 0xa4
)

// MINIDUMP_MISC_INFO field offsets.
const (
	MiscInfoSizeOfInfo                = 0x00
	MiscInfoFlags                     = 0x04
	MiscInfoProcessID                 = 0x08
	MiscInfoProcessCreateTime         = 0x0c
	MiscInfoProcessUserTime           = 0x10
	MiscInfoProcessKernelTime         = 0x14
	MiscInfoProcessorMaxMHz           = 0x18
	MiscInfoProcessorCurrentMHz       = 0x1c
	MiscInfoProcessorMHzLimit         = 0x20
	MiscInfoProcessorMaxIdleState     = 0x24
	MiscInfoProcessorCurrentIdleState = 0x28
	MiscInfoProcessIntegrityLevel     = 0x2c
	MiscInfoProcessExecuteFlags       = 0x30
	MiscInfoProtectedProcess          = 0x34
	MiscInfoTimeZoneID                = 0x38
	MiscInfoLargePageMinimum          = 0x3c
)

// MiniDumpLimits caps one minidump read.
//
// The declared stream count must fit under MaxStreams before the directory is
// read. Every other count is reported but only min(count, report_*) entries are
// materialised.
type MiniDumpLimits struct {
	// MaxStreams is the most stream descriptors the directory may declare.
	MaxStreams int
	// ReportStreams is the most stream descriptors to retain.
	ReportStreams int
	// ReportModules is the most module entries to materialise.
	ReportModules int
	// ReportThreads is the most thread entries to materialise.
	ReportThreads int
	// ReportMemoryRuns is the most memory runs to materialise.
	ReportMemoryRuns int
	// MaxStringBytes is the most bytes decoded from one MINIDUMP_STRING.
	MaxStringBytes int
	// MaxWarnings is the most warnings retained.
	MaxWarnings int
}

// DefaultMiniDumpLimits returns the reference limits.
func DefaultMiniDumpLimits() MiniDumpLimits {
	return MiniDumpLimits{
		MaxStreams:       1024,
		ReportStreams:    256,
		ReportModules:    64,
		ReportThreads:    64,
		ReportMemoryRuns: 64,
		MaxStringBytes:   4096,
		MaxWarnings:      256,
	}
}

// Minidump error kinds. Test them with errors.Is.
var (
	ErrMiniDumpHeaderTooShort           = errors.New("memory/dmp: minidump header too short")
	ErrMiniDumpBadSignature             = errors.New("memory/dmp: minidump bad signature")
	ErrMiniDumpTooManyStreams           = errors.New("memory/dmp: minidump too many streams")
	ErrMiniDumpStreamDirectoryTruncated = errors.New("memory/dmp: minidump stream directory truncated")
	ErrMiniDumpOffsetOverflow           = errors.New("memory/dmp: minidump offset overflow")
	ErrMiniDumpSource                   = errors.New("memory/dmp: minidump source error")
)

// MiniDumpError is a structured minidump failure.
type MiniDumpError struct {
	Kind      error
	Need      uint64
	Available uint64
	Found     [4]byte
	Count     uint32
	Limit     uint64
	Offset    uint64
	Err       error
}

func (e *MiniDumpError) Error() string {
	switch {
	case errors.Is(e.Kind, ErrMiniDumpHeaderTooShort):
		return fmt.Sprintf("minidump header needs %d bytes, source has %d", e.Need, e.Available)
	case errors.Is(e.Kind, ErrMiniDumpBadSignature):
		return fmt.Sprintf("minidump signature is % X, expected 4D 44 4D 50 (`MDMP`)", e.Found)
	case errors.Is(e.Kind, ErrMiniDumpTooManyStreams):
		return fmt.Sprintf("minidump declares %d streams, over the %d-stream cap", e.Count, e.Limit)
	case errors.Is(e.Kind, ErrMiniDumpStreamDirectoryTruncated):
		return fmt.Sprintf("minidump stream directory at %d needs %d bytes, source has %d", e.Offset, e.Need, e.Available)
	case errors.Is(e.Kind, ErrMiniDumpOffsetOverflow):
		return "minidump table offset does not fit in u64"
	case errors.Is(e.Kind, ErrMiniDumpSource):
		if e.Err != nil {
			return e.Err.Error()
		}
		return "minidump source read failed"
	default:
		if e.Err != nil {
			return e.Err.Error()
		}
		return "minidump error"
	}
}

// Unwrap exposes both the kind and the underlying cause to errors.Is/As.
func (e *MiniDumpError) Unwrap() []error {
	out := make([]error, 0, 2)
	if e.Kind != nil {
		out = append(out, e.Kind)
	}
	if e.Err != nil {
		out = append(out, e.Err)
	}
	return out
}

// StreamDescriptor is one MINIDUMP_DIRECTORY entry.
type StreamDescriptor struct {
	Index      int
	StreamType uint32
	TypeName   *string
	DataSize   uint32
	RVA        uint32
	InBounds   bool
	Duplicate  bool
	Decoded    bool
}

// MiniDumpString is a bounded MINIDUMP_STRING (UTF-16LE preceded by a byte
// count).
type MiniDumpString struct {
	RVA       uint32
	ByteCount uint32
	Value     string
	Truncated bool
}

// CpuInfo is the CPU detail from the union at the end of MINIDUMP_SYSTEM_INFO.
type CpuInfo struct {
	Vendor              *string
	VersionInformation  *uint32
	FeatureInformation  *uint32
	AMDExtendedFeatures *uint32
	ProcessorFeatures   [2]uint64
	FeatureNames        []string
	UnknownFeatureBits  uint64
}

// SystemInfo is a decoded MINIDUMP_SYSTEM_INFO.
type SystemInfo struct {
	Architecture       uint16
	ArchitectureName   string
	ProcessorLevel     uint16
	ProcessorRevision  uint16
	NumberOfProcessors uint8
	ProductType        uint8
	ProductTypeName    string
	MajorVersion       uint32
	MinorVersion       uint32
	BuildNumber        uint32
	PlatformID         uint32
	PlatformName       string
	CSDVersion         *MiniDumpString
	SuiteMask          uint16
	SuiteNames         []string
	CPU                CpuInfo
}

// FixedFileInfo is VS_FIXEDFILEINFO from a module record.
type FixedFileInfo struct {
	Signature        uint32
	StructVersion    uint32
	FileVersionMS    uint32
	FileVersionLS    uint32
	ProductVersionMS uint32
	ProductVersionLS uint32
	FileFlagsMask    uint32
	FileFlags        uint32
	FileOS           uint32
	FileType         uint32
	FileSubtype      uint32
	FileDateMS       uint32
	FileDateLS       uint32
}

// FileVersionLabel returns a major.minor.build.revision label.
func (f FixedFileInfo) FileVersionLabel() string {
	return versionLabel(f.FileVersionMS, f.FileVersionLS)
}

// ProductVersionLabel returns a major.minor.build.revision label.
func (f FixedFileInfo) ProductVersionLabel() string {
	return versionLabel(f.ProductVersionMS, f.ProductVersionLS)
}

func versionLabel(ms, ls uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", ms>>16, ms&0xffff, ls>>16, ls&0xffff)
}

// MiniDumpModule is one sampled MINIDUMP_MODULE.
type MiniDumpModule struct {
	Index       int
	BaseOfImage uint64
	SizeOfImage uint32
	Checksum    uint32
	Timestamp   uint32
	NameRVA     uint32
	Name        *MiniDumpString
	Version     FixedFileInfo
}

// ModuleList is a bounded MINIDUMP_MODULE_LIST.
type ModuleList struct {
	DeclaredCount uint32
	Modules       []MiniDumpModule
}

// MiniDumpThread is one sampled MINIDUMP_THREAD.
type MiniDumpThread struct {
	Index           int
	ThreadID        uint32
	SuspendCount    uint32
	PriorityClass   uint32
	Priority        uint32
	TEB             uint64
	StackStart      uint64
	StackSize       uint32
	StackRVA        uint32
	StackInBounds   bool
	ContextSize     uint32
	ContextRVA      uint32
	ContextInBounds bool
}

// ThreadList is a bounded MINIDUMP_THREAD_LIST.
type ThreadList struct {
	DeclaredCount uint32
	Threads       []MiniDumpThread
}

// MemoryRun is one sampled MINIDUMP_MEMORY_DESCRIPTOR.
type MemoryRun struct {
	Index    int
	Start    uint64
	Size     uint64
	RVA      uint64
	InBounds bool
}

// MemoryList is a bounded MINIDUMP_MEMORY_LIST.
type MemoryList struct {
	DeclaredCount uint32
	TotalBytes    uint64
	Runs          []MemoryRun
	OutOfBounds   int
}

// Memory64List is a bounded MINIDUMP_MEMORY64_LIST.
type Memory64List struct {
	DeclaredCount uint64
	BaseRVA       uint64
	TotalBytes    uint64
	Runs          []MemoryRun
	OutOfBounds   int
}

// ExceptionStream is a decoded MINIDUMP_EXCEPTION_STREAM.
type ExceptionStream struct {
	ThreadID         uint32
	ExceptionCode    uint32
	ExceptionFlags   uint32
	FlagNames        []string
	ExceptionRecord  uint64
	ExceptionAddress uint64
	NumberParameters uint32
	Parameters       []uint64
	ContextSize      uint32
	ContextRVA       uint32
	ContextInBounds  bool
	Noncontinuable   bool
	Unwinding        bool
	// FirstChance is always nil: minidumps store no first-chance marker.
	FirstChance *bool
}

// MiscInfo is the stable fields of MINIDUMP_MISC_INFO.
type MiscInfo struct {
	SizeOfInfo                uint32
	Flags                     uint32
	ProcessID                 uint32
	ProcessCreateTime         uint32
	ProcessUserTime           uint32
	ProcessKernelTime         uint32
	ProcessorMaxMHz           *uint32
	ProcessorCurrentMHz       *uint32
	ProcessorMHzLimit         *uint32
	ProcessorMaxIdleState     *uint32
	ProcessorCurrentIdleState *uint32
	ProcessIntegrityLevel     *uint32
	ProcessExecuteFlags       *uint32
	ProtectedProcess          *uint32
	TimeZoneID                *uint32
	LargePageMinimum          *uint32
}

// MiniDumpReport is header and stream metadata from a user-mode minidump.
type MiniDumpReport struct {
	Signature          [4]byte
	VersionMajor       uint16
	VersionMinor       uint16
	StreamCount        uint32
	StreamDirectoryRVA uint32
	Checksum           uint32
	Timestamp          uint32
	Flags              uint64
	FlagNames          []string
	Streams            []StreamDescriptor
	DuplicateStreams   []uint32
	SystemInfo         *SystemInfo
	Modules            *ModuleList
	Threads            *ThreadList
	Memory             *MemoryList
	Memory64           *Memory64List
	Exception          *ExceptionStream
	MiscInfo           *MiscInfo
	Warnings           []string
	SourceLen          uint64
}

// MemoryBytesReported is the total bytes the header declares through the
// memory streams, saturating. It sums the runs this reader materialised; each
// list's DeclaredCount carries the full count.
func (r *MiniDumpReport) MemoryBytesReported() uint64 {
	var total uint64
	if r.Memory != nil {
		total = r.Memory.TotalBytes
	}
	if r.Memory64 != nil {
		if math.MaxUint64-total < r.Memory64.TotalBytes {
			return math.MaxUint64
		}
		total += r.Memory64.TotalBytes
	}
	return total
}

// MiniDumpLooksLike reports whether head starts with the minidump magic.
func MiniDumpLooksLike(head []byte) bool {
	return len(head) >= 4 && [4]byte{head[0], head[1], head[2], head[3]} == MiniDumpSignature
}

// StreamTypeName returns the documented name for a MINIDUMP_STREAM_TYPE.
func StreamTypeName(streamType uint32) (string, bool) {
	names := map[uint32]string{
		0:  "UnusedStream",
		1:  "ReservedStream0",
		2:  "ReservedStream1",
		3:  "ThreadListStream",
		4:  "ModuleListStream",
		5:  "MemoryListStream",
		6:  "ExceptionStream",
		7:  "SystemInfoStream",
		8:  "ThreadExListStream",
		9:  "Memory64ListStream",
		10: "CommentStreamA",
		11: "CommentStreamW",
		12: "HandleDataStream",
		13: "FunctionTableStream",
		14: "UnloadedModuleListStream",
		15: "MiscInfoStream",
		16: "MemoryInfoListStream",
		17: "ThreadInfoListStream",
		18: "HandleOperationListStream",
		19: "TokenStream",
		20: "JavaScriptDataStream",
		21: "SystemMemoryInfoStream",
		22: "ProcessVmCountersStream",
		23: "IptTraceStream",
		24: "ThreadNamesStream",
	}
	name, ok := names[streamType]
	return name, ok
}

// MiniDumpFlagNames returns the names of the set bits in MINIDUMP_HEADER.Flags.
func MiniDumpFlagNames(flags uint64) []string {
	known := []struct {
		bit  uint64
		name string
	}{
		{0x0000_0001, "WithDataSegs"},
		{0x0000_0002, "WithFullMemory"},
		{0x0000_0004, "WithHandleData"},
		{0x0000_0008, "FilterMemory"},
		{0x0000_0010, "ScanMemory"},
		{0x0000_0020, "WithUnloadedModules"},
		{0x0000_0040, "WithIndirectlyReferencedMemory"},
		{0x0000_0080, "FilterModulePaths"},
		{0x0000_0100, "WithProcessThreadData"},
		{0x0000_0200, "WithPrivateReadWriteMemory"},
		{0x0000_0400, "WithoutOptionalData"},
		{0x0000_0800, "WithFullMemoryInfo"},
		{0x0000_1000, "WithThreadInfo"},
		{0x0000_2000, "WithCodeSegs"},
		{0x0000_4000, "WithoutAuxilliaryState"},
		{0x0000_8000, "WithPrivateWriteCopyMemory"},
		{0x0001_0000, "IgnoreInaccessibleMemory"},
		{0x0002_0000, "WithTokenInformation"},
		{0x0004_0000, "WithModuleHeaders"},
		{0x0008_0000, "FilterTriage"},
		{0x0010_0000, "WithAvxXStateContext"},
	}
	var out []string
	for _, flag := range known {
		if flags&flag.bit != 0 {
			out = append(out, flag.name)
		}
	}
	return out
}

// ExceptionFlagNames returns the names of the set bits in
// MINIDUMP_EXCEPTION.ExceptionFlags.
func ExceptionFlagNames(flags uint32) []string {
	known := []struct {
		bit  uint32
		name string
	}{
		{0x01, "EXCEPTION_NONCONTINUABLE"},
		{0x02, "EXCEPTION_UNWINDING"},
		{0x04, "EXCEPTION_EXIT_UNWIND"},
		{0x08, "EXCEPTION_STACK_INVALID"},
		{0x10, "EXCEPTION_NESTED_CALL"},
		{0x20, "EXCEPTION_TARGET_UNWIND"},
		{0x40, "EXCEPTION_COLLIDED_UNWIND"},
		{0x80, "EXCEPTION_SOFTWARE_ORIGIN"},
	}
	var out []string
	for _, flag := range known {
		if flags&flag.bit != 0 {
			out = append(out, flag.name)
		}
	}
	return out
}

func architectureName(architecture uint16) string {
	switch architecture {
	case 0:
		return "x86"
	case 1:
		return "mips"
	case 2:
		return "alpha"
	case 3:
		return "ppc"
	case 5:
		return "arm"
	case 6:
		return "ia64"
	case 9:
		return "amd64"
	case 12:
		return "arm64"
	default:
		return fmt.Sprintf("unknown (0x%x)", architecture)
	}
}

func productTypeName(productType uint8) string {
	switch productType {
	case 1:
		return "workstation"
	case 2:
		return "domain controller"
	case 3:
		return "server"
	default:
		return fmt.Sprintf("unknown (%d)", productType)
	}
}

func platformName(platformID uint32) string {
	switch platformID {
	case 0:
		return "win32s"
	case 1:
		return "windows 9x"
	case 2:
		return "windows nt"
	case 3:
		return "windows ce"
	default:
		return fmt.Sprintf("unknown (0x%x)", platformID)
	}
}

func suiteNames(mask uint16) []string {
	known := []struct {
		bit  uint16
		name string
	}{
		{0x0001, "small business"},
		{0x0002, "enterprise"},
		{0x0004, "backoffice"},
		{0x0008, "communications"},
		{0x0010, "terminal services"},
		{0x0020, "small business restricted"},
		{0x0040, "embedded nt"},
		{0x0080, "datacenter"},
		{0x0100, "single-user terminal services"},
		{0x0200, "personal"},
		{0x0400, "server app"},
	}
	var out []string
	for _, suite := range known {
		if mask&suite.bit != 0 {
			out = append(out, suite.name)
		}
	}
	return out
}

func x86FeatureNames(features uint32) ([]string, uint64) {
	known := []struct {
		bit  uint32
		name string
	}{
		{1 << 0, "floating-point precision errata"},
		{1 << 1, "floating-point emulated"},
		{1 << 2, "compare-exchange double"},
		{1 << 3, "mmx"},
		{1 << 4, "ppc movemem 64-bit ok"},
		{1 << 5, "alpha byte instructions"},
		{1 << 6, "sse"},
		{1 << 7, "3dnow"},
		{1 << 8, "rdtsc"},
		{1 << 9, "pae"},
		{1 << 10, "sse2"},
		{1 << 11, "sse daz mode"},
		{1 << 12, "nx"},
		{1 << 13, "sse3"},
		{1 << 14, "compare-exchange 128"},
		{1 << 15, "compare64-exchange 128"},
		{1 << 16, "channels"},
		{1 << 17, "xsave"},
		{1 << 18, "arm vfp 32 registers"},
		{1 << 19, "arm neon"},
		{1 << 20, "second-level address translation"},
		{1 << 21, "virtual firmware"},
		{1 << 22, "rdwrfsgsbase"},
		{1 << 23, "fastfail"},
		{1 << 24, "arm divide"},
		{1 << 25, "arm 64-bit load/store atomic"},
		{1 << 26, "arm external cache"},
		{1 << 27, "arm fmac"},
		{1 << 28, "rdrand"},
		{1 << 29, "arm v8"},
		{1 << 30, "arm v8 crypto"},
		{1 << 31, "arm v8 crc32"},
	}
	var names []string
	var knownMask uint32
	for _, feature := range known {
		knownMask |= feature.bit
		if features&feature.bit != 0 {
			names = append(names, feature.name)
		}
	}
	return names, uint64(features &^ knownMask)
}

// ReadMiniDump reads a minidump and reports its bounded static metadata.
func ReadMiniDump(src source.ByteSource, limits MiniDumpLimits) (*MiniDumpReport, error) {
	if limits.MaxStreams < 0 {
		limits.MaxStreams = 0
	}
	if limits.ReportStreams < 0 {
		limits.ReportStreams = 0
	}
	if limits.ReportModules < 0 {
		limits.ReportModules = 0
	}
	if limits.ReportThreads < 0 {
		limits.ReportThreads = 0
	}
	if limits.ReportMemoryRuns < 0 {
		limits.ReportMemoryRuns = 0
	}
	sourceLen := src.Len()
	if sourceLen < MiniDumpHeaderBytes {
		return nil, &MiniDumpError{Kind: ErrMiniDumpHeaderTooShort, Need: MiniDumpHeaderBytes, Available: sourceLen}
	}

	header, err := source.ReadVecAt(src, 0, MiniDumpHeaderBytes)
	if err != nil {
		return nil, &MiniDumpError{Kind: ErrMiniDumpSource, Err: err}
	}
	if [4]byte{header[0], header[1], header[2], header[3]} != MiniDumpSignature {
		return nil, &MiniDumpError{
			Kind:  ErrMiniDumpBadSignature,
			Found: [4]byte{header[0], header[1], header[2], header[3]},
		}
	}

	version := u32At(header, MiniHeaderVersion)
	streamCount := u32At(header, MiniHeaderNumberOfStreams)
	streamDirectoryRVA := u32At(header, MiniHeaderStreamDirectoryRVA)
	checksum := u32At(header, MiniHeaderCheckSum)
	timestamp := u32At(header, MiniHeaderTimeDateStamp)
	flags := binary.LittleEndian.Uint64(header[MiniHeaderFlags:])

	if uint64(streamCount) > uint64(limits.MaxStreams) {
		return nil, &MiniDumpError{Kind: ErrMiniDumpTooManyStreams, Count: streamCount, Limit: uint64(limits.MaxStreams)}
	}

	directoryBytes := uint64(streamCount) * uint64(MiniDumpDirectoryEntryBytes)
	directoryOffset := uint64(streamDirectoryRVA)
	directoryEnd, ok := addU64(directoryOffset, directoryBytes)
	if !ok {
		return nil, &MiniDumpError{Kind: ErrMiniDumpOffsetOverflow}
	}
	if directoryEnd > sourceLen {
		available := uint64(0)
		if directoryOffset <= sourceLen {
			available = sourceLen - directoryOffset
		}
		return nil, &MiniDumpError{
			Kind:      ErrMiniDumpStreamDirectoryTruncated,
			Offset:    directoryOffset,
			Need:      directoryBytes,
			Available: available,
		}
	}

	ctx := &miniContext{src: src, sourceLen: sourceLen, limits: limits}
	streams := make([]StreamDescriptor, 0, int(streamCount))
	duplicates := make([]uint32, 0)
	seen := make(map[uint32]bool)
	var row [MiniDumpDirectoryEntryBytes]byte
	for index := 0; index < int(streamCount); index++ {
		offset := directoryOffset + uint64(index*MiniDumpDirectoryEntryBytes)
		if err := source.ReadExactAt(src, offset, row[:]); err != nil {
			return nil, &MiniDumpError{Kind: ErrMiniDumpSource, Err: err}
		}
		streamType := binary.LittleEndian.Uint32(row[0:4])
		dataSize := binary.LittleEndian.Uint32(row[4:8])
		rva := binary.LittleEndian.Uint32(row[8:12])
		end, ok := addU64(uint64(rva), uint64(dataSize))
		inBounds := ok && end <= sourceLen
		first := !seen[streamType]
		seen[streamType] = true
		if !first {
			duplicates = append(duplicates, streamType)
		}
		if !inBounds {
			name := "unknown"
			if known, ok := StreamTypeName(streamType); ok {
				name = known
			}
			ctx.warn(fmt.Sprintf("stream %d (%s) declares RVA 0x%x and %d byte(s), past the source", index, name, rva, dataSize))
		}
		var typeName *string
		if name, ok := StreamTypeName(streamType); ok {
			typeName = &name
		}
		streams = append(streams, StreamDescriptor{
			Index:      index,
			StreamType: streamType,
			TypeName:   typeName,
			DataSize:   dataSize,
			RVA:        rva,
			InBounds:   inBounds,
			Duplicate:  !first,
			Decoded:    false,
		})
	}

	var systemInfo *SystemInfo
	var modules *ModuleList
	var threads *ThreadList
	var memoryList *MemoryList
	var memory64 *Memory64List
	var exception *ExceptionStream
	var miscInfo *MiscInfo

	for index := range streams {
		descriptor := &streams[index]
		if descriptor.Duplicate || !descriptor.InBounds {
			continue
		}
		switch descriptor.StreamType {
		case StreamSystemInfo:
			systemInfo = decodeSystemInfo(ctx, descriptor)
		case StreamModuleList:
			modules = decodeModules(ctx, descriptor)
		case StreamThreadList:
			threads = decodeThreads(ctx, descriptor)
		case StreamMemoryList:
			memoryList = decodeMemoryList(ctx, descriptor)
		case StreamMemory64List:
			memory64 = decodeMemory64List(ctx, descriptor)
		case StreamException:
			exception = decodeException(ctx, descriptor)
		case StreamMiscInfo:
			miscInfo = decodeMiscInfo(ctx, descriptor)
		}
	}

	for index := range streams {
		descriptor := &streams[index]
		var decoded bool
		switch descriptor.StreamType {
		case StreamSystemInfo:
			decoded = systemInfo != nil
		case StreamModuleList:
			decoded = modules != nil
		case StreamThreadList:
			decoded = threads != nil
		case StreamMemoryList:
			decoded = memoryList != nil
		case StreamMemory64List:
			decoded = memory64 != nil
		case StreamException:
			decoded = exception != nil
		case StreamMiscInfo:
			decoded = miscInfo != nil
		}
		descriptor.Decoded = decoded && !descriptor.Duplicate && descriptor.InBounds
	}

	if len(streams) > limits.ReportStreams {
		hidden := len(streams) - limits.ReportStreams
		streams = streams[:limits.ReportStreams]
		ctx.warn(fmt.Sprintf("%d stream descriptor(s) beyond the %d-descriptor report cap were not listed", hidden, limits.ReportStreams))
	}

	return &MiniDumpReport{
		Signature:          MiniDumpSignature,
		VersionMajor:       uint16(version >> 16),
		VersionMinor:       uint16(version & 0xffff),
		StreamCount:        streamCount,
		StreamDirectoryRVA: streamDirectoryRVA,
		Checksum:           checksum,
		Timestamp:          timestamp,
		Flags:              flags,
		FlagNames:          MiniDumpFlagNames(flags),
		Streams:            streams,
		DuplicateStreams:   duplicates,
		SystemInfo:         systemInfo,
		Modules:            modules,
		Threads:            threads,
		Memory:             memoryList,
		Memory64:           memory64,
		Exception:          exception,
		MiscInfo:           miscInfo,
		Warnings:           ctx.warnings,
		SourceLen:          sourceLen,
	}, nil
}

type miniContext struct {
	src       source.ByteSource
	sourceLen uint64
	limits    MiniDumpLimits
	warnings  []string
}

func (c *miniContext) warn(message string) {
	if len(c.warnings) < c.limits.MaxWarnings {
		c.warnings = append(c.warnings, message)
	}
}

// read reads a pre-validated range; false when the source refuses it.
func (c *miniContext) read(offset uint64, buffer []byte) bool {
	if offset > c.sourceLen || uint64(len(buffer)) > c.sourceLen-offset {
		return false
	}
	return source.ReadExactAt(c.src, offset, buffer) == nil
}

func (c *miniContext) str(rva uint32) *MiniDumpString {
	if rva == 0 {
		return nil
	}
	offset := uint64(rva)
	if offset > c.sourceLen || c.sourceLen-offset < 4 {
		c.warn(fmt.Sprintf("MINIDUMP_STRING at RVA 0x%x has no length prefix inside the source", rva))
		return nil
	}
	body := offset + 4
	var length [4]byte
	if !c.read(offset, length[:]) {
		c.warn(fmt.Sprintf("MINIDUMP_STRING length at RVA 0x%x could not be read", rva))
		return nil
	}
	byteCount := binary.LittleEndian.Uint32(length[:])
	remaining := c.sourceLen - body
	var capBytes uint64
	if c.limits.MaxStringBytes > 0 {
		capBytes = uint64(c.limits.MaxStringBytes)
	}
	available := uint64(byteCount)
	if available > capBytes {
		available = capBytes
	}
	if available > remaining {
		available = remaining
	}
	buf := make([]byte, int(available))
	if available > 0 && !c.read(body, buf) {
		c.warn(fmt.Sprintf("MINIDUMP_STRING body at RVA 0x%x could not be read", rva))
		return nil
	}
	units := make([]uint16, 0, len(buf)/2)
	for i := 0; i+1 < len(buf); i += 2 {
		unit := binary.LittleEndian.Uint16(buf[i : i+2])
		if unit == 0 {
			break
		}
		units = append(units, unit)
	}
	truncated := uint64(byteCount) > available
	if truncated {
		c.warn(fmt.Sprintf("MINIDUMP_STRING at RVA 0x%x declares %d byte(s), only %d are available within the cap", rva, byteCount, available))
	}
	return &MiniDumpString{
		RVA:       rva,
		ByteCount: byteCount,
		Value:     string(utf16.Decode(units)),
		Truncated: truncated,
	}
}

func decodeSystemInfo(ctx *miniContext, descriptor *StreamDescriptor) *SystemInfo {
	if int(descriptor.DataSize) < SystemInfoBytes {
		ctx.warn(fmt.Sprintf("SystemInfoStream declares %d byte(s), too short for the %d-byte structure", descriptor.DataSize, SystemInfoBytes))
		return nil
	}
	var bytes [SystemInfoBytes]byte
	if !ctx.read(uint64(descriptor.RVA), bytes[:]) {
		ctx.warn("SystemInfoStream could not be read")
		return nil
	}

	architecture := binary.LittleEndian.Uint16(bytes[SysInfoProcessorArchitecture:])
	csdRVA := u32At(bytes[:], SysInfoCSDVersionRVA)
	csdVersion := ctx.str(csdRVA)

	var vendor *string
	var versionInformation, featureInformation, amdExtendedFeatures *uint32
	var featureNames []string
	var unknownFeatureBits uint64
	if architecture == 0 {
		var builder strings.Builder
		for _, b := range bytes[SysInfoCPU : SysInfoCPU+12] {
			if b == 0 {
				break
			}
			builder.WriteRune(rune(b))
		}
		value := builder.String()
		vendor = &value
		version := u32At(bytes[:], SysInfoCPU+12)
		features := u32At(bytes[:], SysInfoCPU+16)
		amd := u32At(bytes[:], SysInfoCPU+20)
		versionInformation = &version
		featureInformation = &features
		amdExtendedFeatures = &amd
		featureNames, unknownFeatureBits = x86FeatureNames(features)
	}

	suiteMask := binary.LittleEndian.Uint16(bytes[SysInfoSuiteMask:])
	return &SystemInfo{
		Architecture:       architecture,
		ArchitectureName:   architectureName(architecture),
		ProcessorLevel:     binary.LittleEndian.Uint16(bytes[SysInfoProcessorLevel:]),
		ProcessorRevision:  binary.LittleEndian.Uint16(bytes[SysInfoProcessorRevision:]),
		NumberOfProcessors: bytes[SysInfoNumberOfProcessors],
		ProductType:        bytes[SysInfoProductType],
		ProductTypeName:    productTypeName(bytes[SysInfoProductType]),
		MajorVersion:       u32At(bytes[:], SysInfoMajorVersion),
		MinorVersion:       u32At(bytes[:], SysInfoMinorVersion),
		BuildNumber:        u32At(bytes[:], SysInfoBuildNumber),
		PlatformID:         u32At(bytes[:], SysInfoPlatformID),
		PlatformName:       platformName(u32At(bytes[:], SysInfoPlatformID)),
		CSDVersion:         csdVersion,
		SuiteMask:          suiteMask,
		SuiteNames:         suiteNames(suiteMask),
		CPU: CpuInfo{
			Vendor:              vendor,
			VersionInformation:  versionInformation,
			FeatureInformation:  featureInformation,
			AMDExtendedFeatures: amdExtendedFeatures,
			ProcessorFeatures: [2]uint64{
				binary.LittleEndian.Uint64(bytes[SysInfoCPU:]),
				binary.LittleEndian.Uint64(bytes[SysInfoCPU+8:]),
			},
			FeatureNames:       featureNames,
			UnknownFeatureBits: unknownFeatureBits,
		},
	}
}

func decodeModules(ctx *miniContext, descriptor *StreamDescriptor) *ModuleList {
	if descriptor.DataSize < 4 {
		ctx.warn("ModuleListStream is shorter than its count")
		return nil
	}
	var countBytes [4]byte
	if !ctx.read(uint64(descriptor.RVA), countBytes[:]) {
		ctx.warn("ModuleListStream count could not be read")
		return nil
	}
	declaredCount := binary.LittleEndian.Uint32(countBytes[:])
	body := uint64(descriptor.DataSize) - 4
	capacity := body / ModuleBytes
	if uint64(declaredCount) > capacity {
		ctx.warn(fmt.Sprintf("ModuleListStream declares %d module(s) but its %d byte(s) hold at most %d", declaredCount, descriptor.DataSize, capacity))
	}
	sampled := int(declaredCount)
	if sampled > ctx.limits.ReportModules {
		sampled = ctx.limits.ReportModules
	}
	if uint64(sampled) > capacity {
		sampled = int(capacity)
	}
	if sampled < int(declaredCount) {
		ctx.warn(fmt.Sprintf("ModuleListStream reports the first %d of %d module(s)", sampled, declaredCount))
	}
	need := 4 + sampled*ModuleBytes
	bytes := make([]byte, need)
	if !ctx.read(uint64(descriptor.RVA), bytes) {
		ctx.warn("ModuleListStream could not be read")
		return nil
	}

	modules := make([]MiniDumpModule, 0, sampled)
	for index := 0; index < sampled; index++ {
		base := 4 + index*ModuleBytes
		nameRVA := u32At(bytes, base+ModuleNameRVA)
		name := ctx.str(nameRVA)
		version := FixedFileInfo{
			Signature:        u32At(bytes, base+ModuleVersionInfo),
			StructVersion:    u32At(bytes, base+ModuleVersionInfo+4),
			FileVersionMS:    u32At(bytes, base+ModuleVersionInfo+8),
			FileVersionLS:    u32At(bytes, base+ModuleVersionInfo+12),
			ProductVersionMS: u32At(bytes, base+ModuleVersionInfo+16),
			ProductVersionLS: u32At(bytes, base+ModuleVersionInfo+20),
			FileFlagsMask:    u32At(bytes, base+ModuleVersionInfo+24),
			FileFlags:        u32At(bytes, base+ModuleVersionInfo+28),
			FileOS:           u32At(bytes, base+ModuleVersionInfo+32),
			FileType:         u32At(bytes, base+ModuleVersionInfo+36),
			FileSubtype:      u32At(bytes, base+ModuleVersionInfo+40),
			FileDateMS:       u32At(bytes, base+ModuleVersionInfo+44),
			FileDateLS:       u32At(bytes, base+ModuleVersionInfo+48),
		}
		modules = append(modules, MiniDumpModule{
			Index:       index,
			BaseOfImage: u64At(bytes, base+ModuleBaseOfImage),
			SizeOfImage: u32At(bytes, base+ModuleSizeOfImage),
			Checksum:    u32At(bytes, base+ModuleCheckSum),
			Timestamp:   u32At(bytes, base+ModuleTimeDateStamp),
			NameRVA:     nameRVA,
			Name:        name,
			Version:     version,
		})
	}
	return &ModuleList{DeclaredCount: declaredCount, Modules: modules}
}

func decodeThreads(ctx *miniContext, descriptor *StreamDescriptor) *ThreadList {
	if descriptor.DataSize < 4 {
		ctx.warn("ThreadListStream is shorter than its count")
		return nil
	}
	var countBytes [4]byte
	if !ctx.read(uint64(descriptor.RVA), countBytes[:]) {
		ctx.warn("ThreadListStream count could not be read")
		return nil
	}
	declaredCount := binary.LittleEndian.Uint32(countBytes[:])
	body := uint64(descriptor.DataSize) - 4
	capacity := body / ThreadBytes
	if uint64(declaredCount) > capacity {
		ctx.warn(fmt.Sprintf("ThreadListStream declares %d thread(s) but its %d byte(s) hold at most %d", declaredCount, descriptor.DataSize, capacity))
	}
	sampled := int(declaredCount)
	if sampled > ctx.limits.ReportThreads {
		sampled = ctx.limits.ReportThreads
	}
	if uint64(sampled) > capacity {
		sampled = int(capacity)
	}
	if sampled < int(declaredCount) {
		ctx.warn(fmt.Sprintf("ThreadListStream reports the first %d of %d thread(s)", sampled, declaredCount))
	}
	need := 4 + sampled*ThreadBytes
	bytes := make([]byte, need)
	if !ctx.read(uint64(descriptor.RVA), bytes) {
		ctx.warn("ThreadListStream could not be read")
		return nil
	}

	threads := make([]MiniDumpThread, 0, sampled)
	for index := 0; index < sampled; index++ {
		base := 4 + index*ThreadBytes
		contextSize := u32At(bytes, base+ThreadContextSize)
		contextRVA := u32At(bytes, base+ThreadContextRVA)
		stackSize := u32At(bytes, base+ThreadStackSize)
		stackRVA := u32At(bytes, base+ThreadStackRVA)
		threads = append(threads, MiniDumpThread{
			Index:           index,
			ThreadID:        u32At(bytes, base+ThreadThreadID),
			SuspendCount:    u32At(bytes, base+ThreadSuspendCount),
			PriorityClass:   u32At(bytes, base+ThreadPriorityClass),
			Priority:        u32At(bytes, base+ThreadPriority),
			TEB:             u64At(bytes, base+ThreadTEB),
			StackStart:      u64At(bytes, base+ThreadStackStart),
			StackSize:       stackSize,
			StackRVA:        stackRVA,
			StackInBounds:   rangeInBounds(uint64(stackRVA), uint64(stackSize), ctx.sourceLen),
			ContextSize:     contextSize,
			ContextRVA:      contextRVA,
			ContextInBounds: rangeInBounds(uint64(contextRVA), uint64(contextSize), ctx.sourceLen),
		})
	}
	return &ThreadList{DeclaredCount: declaredCount, Threads: threads}
}

func rangeInBounds(rva, size, sourceLen uint64) bool {
	end, ok := addU64(rva, size)
	return ok && end <= sourceLen
}

func decodeMemoryList(ctx *miniContext, descriptor *StreamDescriptor) *MemoryList {
	if descriptor.DataSize < 4 {
		ctx.warn("MemoryListStream is shorter than its count")
		return nil
	}
	var countBytes [4]byte
	if !ctx.read(uint64(descriptor.RVA), countBytes[:]) {
		ctx.warn("MemoryListStream count could not be read")
		return nil
	}
	declaredCount := binary.LittleEndian.Uint32(countBytes[:])
	body := uint64(descriptor.DataSize) - 4
	capacity := body / MemoryDescriptorBytes
	if uint64(declaredCount) > capacity {
		ctx.warn(fmt.Sprintf("MemoryListStream declares %d run(s) but its %d byte(s) hold at most %d", declaredCount, descriptor.DataSize, capacity))
	}
	sampled := int(declaredCount)
	if sampled > ctx.limits.ReportMemoryRuns {
		sampled = ctx.limits.ReportMemoryRuns
	}
	if uint64(sampled) > capacity {
		sampled = int(capacity)
	}
	if sampled < int(declaredCount) {
		ctx.warn(fmt.Sprintf("MemoryListStream reports the first %d of %d run(s)", sampled, declaredCount))
	}
	need := 4 + sampled*MemoryDescriptorBytes
	bytes := make([]byte, need)
	if !ctx.read(uint64(descriptor.RVA), bytes) {
		ctx.warn("MemoryListStream could not be read")
		return nil
	}

	var totalBytes uint64
	outOfBounds := 0
	runs := make([]MemoryRun, 0, sampled)
	for index := 0; index < sampled; index++ {
		base := 4 + index*MemoryDescriptorBytes
		start := u64At(bytes, base)
		size := uint64(u32At(bytes, base+8))
		rva := uint64(u32At(bytes, base+12))
		inBounds := rangeInBounds(rva, size, ctx.sourceLen)
		if !inBounds {
			outOfBounds++
		}
		if math.MaxUint64-totalBytes < size {
			totalBytes = math.MaxUint64
		} else {
			totalBytes += size
		}
		runs = append(runs, MemoryRun{Index: index, Start: start, Size: size, RVA: rva, InBounds: inBounds})
	}
	if outOfBounds > 0 {
		ctx.warn(fmt.Sprintf("%d memory-list run(s) point past the source", outOfBounds))
	}
	return &MemoryList{DeclaredCount: declaredCount, TotalBytes: totalBytes, Runs: runs, OutOfBounds: outOfBounds}
}

func decodeMemory64List(ctx *miniContext, descriptor *StreamDescriptor) *Memory64List {
	if int(descriptor.DataSize) < Memory64HeaderBytes {
		ctx.warn(fmt.Sprintf("Memory64ListStream declares %d byte(s), too short for its %d-byte header", descriptor.DataSize, Memory64HeaderBytes))
		return nil
	}
	var header [Memory64HeaderBytes]byte
	if !ctx.read(uint64(descriptor.RVA), header[:]) {
		ctx.warn("Memory64ListStream header could not be read")
		return nil
	}
	declaredCount := binary.LittleEndian.Uint64(header[0:8])
	baseRVA := binary.LittleEndian.Uint64(header[8:16])
	body := uint64(descriptor.DataSize) - Memory64HeaderBytes
	capacity := body / MemoryDescriptorBytes
	if declaredCount > capacity {
		ctx.warn(fmt.Sprintf("Memory64ListStream declares %d run(s) but its %d byte(s) hold at most %d", declaredCount, descriptor.DataSize, capacity))
	}
	sampled := declaredCount
	if sampled > capacity {
		sampled = capacity
	}
	if sampled > uint64(ctx.limits.ReportMemoryRuns) {
		sampled = uint64(ctx.limits.ReportMemoryRuns)
	}
	if sampled < declaredCount {
		ctx.warn(fmt.Sprintf("Memory64ListStream reports the first %d of %d run(s)", sampled, declaredCount))
	}
	need := Memory64HeaderBytes + int(sampled)*MemoryDescriptorBytes
	bytes := make([]byte, need)
	if !ctx.read(uint64(descriptor.RVA), bytes) {
		ctx.warn("Memory64ListStream could not be read")
		return nil
	}

	var totalBytes uint64
	cursor := baseRVA
	outOfBounds := 0
	runs := make([]MemoryRun, 0, int(sampled))
	for index := 0; index < int(sampled); index++ {
		base := Memory64HeaderBytes + index*MemoryDescriptorBytes
		start := u64At(bytes, base)
		size := u64At(bytes, base+8)
		inBounds := rangeInBounds(cursor, size, ctx.sourceLen)
		if !inBounds {
			outOfBounds++
		}
		if math.MaxUint64-totalBytes < size {
			totalBytes = math.MaxUint64
		} else {
			totalBytes += size
		}
		runs = append(runs, MemoryRun{Index: index, Start: start, Size: size, RVA: cursor, InBounds: inBounds})
		if math.MaxUint64-cursor < size {
			cursor = math.MaxUint64
		} else {
			cursor += size
		}
	}
	if outOfBounds > 0 {
		ctx.warn(fmt.Sprintf("%d memory64 run(s) point past the source", outOfBounds))
	}
	return &Memory64List{DeclaredCount: declaredCount, BaseRVA: baseRVA, TotalBytes: totalBytes, Runs: runs, OutOfBounds: outOfBounds}
}

func decodeException(ctx *miniContext, descriptor *StreamDescriptor) *ExceptionStream {
	if int(descriptor.DataSize) < ExceptionStreamBytes {
		ctx.warn(fmt.Sprintf("ExceptionStream declares %d byte(s), too short for the %d-byte structure", descriptor.DataSize, ExceptionStreamBytes))
		return nil
	}
	var bytes [ExceptionStreamBytes]byte
	if !ctx.read(uint64(descriptor.RVA), bytes[:]) {
		ctx.warn("ExceptionStream could not be read")
		return nil
	}

	exceptionFlags := u32At(bytes[:], ExceptionFlags)
	numberParameters := u32At(bytes[:], ExceptionNumberParameters)
	parameterCount := int(numberParameters)
	if parameterCount > MaxExceptionParameters {
		parameterCount = MaxExceptionParameters
	}
	if int(numberParameters) > MaxExceptionParameters {
		ctx.warn(fmt.Sprintf("ExceptionStream declares %d parameter(s); only %d fit the record", numberParameters, MaxExceptionParameters))
	}
	parameters := make([]uint64, 0, parameterCount)
	for index := 0; index < parameterCount; index++ {
		parameters = append(parameters, u64At(bytes[:], ExceptionParameters+index*8))
	}

	contextSize := u32At(bytes[:], ExceptionContextSize)
	contextRVA := u32At(bytes[:], ExceptionContextRVA)
	return &ExceptionStream{
		ThreadID:         u32At(bytes[:], ExceptionThreadID),
		ExceptionCode:    u32At(bytes[:], ExceptionCode),
		ExceptionFlags:   exceptionFlags,
		FlagNames:        ExceptionFlagNames(exceptionFlags),
		ExceptionRecord:  u64At(bytes[:], ExceptionRecord),
		ExceptionAddress: u64At(bytes[:], ExceptionAddress),
		NumberParameters: numberParameters,
		Parameters:       parameters,
		ContextSize:      contextSize,
		ContextRVA:       contextRVA,
		ContextInBounds:  rangeInBounds(uint64(contextRVA), uint64(contextSize), ctx.sourceLen),
		Noncontinuable:   exceptionFlags&0x01 != 0,
		Unwinding:        exceptionFlags&0x66 != 0,
		FirstChance:      nil,
	}
}

func decodeMiscInfo(ctx *miniContext, descriptor *StreamDescriptor) *MiscInfo {
	if int(descriptor.DataSize) < MiscInfoBytes {
		ctx.warn(fmt.Sprintf("MiscInfoStream declares %d byte(s), too short for its %d-byte prefix", descriptor.DataSize, MiscInfoBytes))
		return nil
	}
	available := descriptor.DataSize
	var prefix [4]byte
	if !ctx.read(uint64(descriptor.RVA), prefix[:]) {
		ctx.warn("MiscInfoStream size could not be read")
		return nil
	}
	sizeOfInfo := binary.LittleEndian.Uint32(prefix[:])
	declared := sizeOfInfo
	if declared > available {
		ctx.warn(fmt.Sprintf("MiscInfoStream SizeOfInfo %d exceeds the %d declared stream byte(s)", sizeOfInfo, descriptor.DataSize))
	}
	readLen := declared
	if readLen < MiscInfoBytes {
		readLen = MiscInfoBytes
	}
	if readLen > available {
		readLen = available
	}
	// The largest field this reader decodes ends at 0x40; do not allocate
	// beyond it even when SizeOfInfo claims more.
	const maxRead = MiscInfoLargePageMinimum + 4
	if readLen > maxRead {
		readLen = maxRead
	}
	bytes := make([]byte, int(readLen))
	if !ctx.read(uint64(descriptor.RVA), bytes) {
		ctx.warn("MiscInfoStream could not be read")
		return nil
	}
	at := func(offset int) (uint32, bool) {
		if offset < 0 || offset+4 > len(bytes) {
			return 0, false
		}
		return binary.LittleEndian.Uint32(bytes[offset : offset+4]), true
	}
	flags, ok := at(MiscInfoFlags)
	if !ok {
		return nil
	}
	processID, ok := at(MiscInfoProcessID)
	if !ok {
		return nil
	}
	processCreateTime, ok := at(MiscInfoProcessCreateTime)
	if !ok {
		return nil
	}
	processUserTime, ok := at(MiscInfoProcessUserTime)
	if !ok {
		return nil
	}
	processKernelTime, ok := at(MiscInfoProcessKernelTime)
	if !ok {
		return nil
	}
	misc := &MiscInfo{
		SizeOfInfo:        sizeOfInfo,
		Flags:             flags,
		ProcessID:         processID,
		ProcessCreateTime: processCreateTime,
		ProcessUserTime:   processUserTime,
		ProcessKernelTime: processKernelTime,
	}
	optional := []struct {
		offset int
		field  **uint32
	}{
		{MiscInfoProcessorMaxMHz, &misc.ProcessorMaxMHz},
		{MiscInfoProcessorCurrentMHz, &misc.ProcessorCurrentMHz},
		{MiscInfoProcessorMHzLimit, &misc.ProcessorMHzLimit},
		{MiscInfoProcessorMaxIdleState, &misc.ProcessorMaxIdleState},
		{MiscInfoProcessorCurrentIdleState, &misc.ProcessorCurrentIdleState},
		{MiscInfoProcessIntegrityLevel, &misc.ProcessIntegrityLevel},
		{MiscInfoProcessExecuteFlags, &misc.ProcessExecuteFlags},
		{MiscInfoProtectedProcess, &misc.ProtectedProcess},
		{MiscInfoTimeZoneID, &misc.TimeZoneID},
		{MiscInfoLargePageMinimum, &misc.LargePageMinimum},
	}
	for _, item := range optional {
		if value, ok := at(item.offset); ok {
			copied := value
			*item.field = &copied
		}
	}
	return misc
}
