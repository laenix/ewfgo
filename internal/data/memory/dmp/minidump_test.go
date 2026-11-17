package dmp

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"
)

func putU16(b []byte, at int, v uint16) { binary.LittleEndian.PutUint16(b[at:], v) }

func putString(b []byte, rva int, text string) {
	units := append(utf16.Encode([]rune(text)), 0)
	putU32(b, rva, uint32(len(units)*2))
	for index, unit := range units {
		putU16(b, rva+4+index*2, unit)
	}
}

// minidump builds a valid user-mode minidump with SystemInfo, ModuleList,
// ThreadList, Exception, MemoryList, Memory64List and MiscInfo streams.
func minidump() []byte {
	// Header 32 B; directory 7 * 12 = 84 B at 0x20; payloads from 0x100.
	bytes := make([]byte, 0x440)
	copy(bytes[0:4], MiniDumpSignature[:])
	putU32(bytes, MiniHeaderVersion, 0x0000_a793)
	putU32(bytes, MiniHeaderNumberOfStreams, 7)
	putU32(bytes, MiniHeaderStreamDirectoryRVA, 0x20)
	putU32(bytes, MiniHeaderCheckSum, 0)
	putU32(bytes, MiniHeaderTimeDateStamp, 1_700_000_000)
	putU64(bytes, MiniHeaderFlags, 0x2|0x4)

	directory := 0x20
	entries := []struct {
		kind uint32
		size uint32
		rva  int
	}{
		{StreamSystemInfo, SystemInfoBytes, 0x100},
		{StreamModuleList, 4 + ModuleBytes, 0x140},
		{StreamThreadList, 4 + ThreadBytes, 0x1c0},
		{StreamException, ExceptionStreamBytes, 0x200},
		{StreamMemoryList, 4 + MemoryDescriptorBytes, 0x2c0},
		{StreamMemory64List, Memory64HeaderBytes + 2*MemoryDescriptorBytes, 0x300},
		{StreamMiscInfo, 0x40, 0x340},
	}
	for index, entry := range entries {
		row := directory + index*MiniDumpDirectoryEntryBytes
		putU32(bytes, row, entry.kind)
		putU32(bytes, row+4, entry.size)
		putU32(bytes, row+8, uint32(entry.rva))
	}

	// SystemInfo at 0x100.
	info := 0x100
	putU16(bytes, info+SysInfoProcessorArchitecture, 9)
	putU16(bytes, info+SysInfoProcessorLevel, 6)
	putU16(bytes, info+SysInfoProcessorRevision, 0x3f01)
	bytes[info+SysInfoNumberOfProcessors] = 8
	bytes[info+SysInfoProductType] = 1
	putU32(bytes, info+SysInfoMajorVersion, 10)
	putU32(bytes, info+SysInfoMinorVersion, 0)
	putU32(bytes, info+SysInfoBuildNumber, 19045)
	putU32(bytes, info+SysInfoPlatformID, 2)
	putU32(bytes, info+SysInfoCSDVersionRVA, 0x3e0)
	putU16(bytes, info+SysInfoSuiteMask, 0x0100|0x0002)
	putString(bytes, 0x3e0, "Service Pack 1")

	// Module list at 0x140: one module named at 0x3a0.
	modules := 0x140
	putU32(bytes, modules, 1)
	module := modules + 4
	putU64(bytes, module+ModuleBaseOfImage, 0x0000_7ff6_0000_0000)
	putU32(bytes, module+ModuleSizeOfImage, 0x12_0000)
	putU32(bytes, module+ModuleCheckSum, 0xabcd)
	putU32(bytes, module+ModuleTimeDateStamp, 0x6500_0000)
	putU32(bytes, module+ModuleNameRVA, 0x3a0)
	putU32(bytes, module+ModuleVersionInfo+8, 0x0001_0002)
	putU32(bytes, module+ModuleVersionInfo+12, 0x0003_0004)
	putU32(bytes, module+ModuleVersionInfo+16, 0x0005_0006)
	putU32(bytes, module+ModuleVersionInfo+20, 0x0007_0008)
	putU32(bytes, module+ModuleVersionInfo+28, 0x1)
	putString(bytes, 0x3a0, "sample.exe")

	// Thread list at 0x1c0.
	threads := 0x1c0
	putU32(bytes, threads, 1)
	thread := threads + 4
	putU32(bytes, thread+ThreadThreadID, 0x1234)
	putU32(bytes, thread+ThreadSuspendCount, 0)
	putU32(bytes, thread+ThreadPriorityClass, 0x20)
	putU32(bytes, thread+ThreadPriority, 8)
	putU64(bytes, thread+ThreadTEB, 0x0000_0000_7ffd_0000)
	putU64(bytes, thread+ThreadStackStart, 0x0000_0000_0010_0000)
	putU32(bytes, thread+ThreadStackSize, 0x40)
	putU32(bytes, thread+ThreadStackRVA, 0x3c0)
	putU32(bytes, thread+ThreadContextSize, 0x40)
	putU32(bytes, thread+ThreadContextRVA, 0x3c0)

	// Exception at 0x200.
	exc := 0x200
	putU32(bytes, exc+ExceptionThreadID, 0x1234)
	putU32(bytes, exc+ExceptionCode, 0xc000_0005)
	putU32(bytes, exc+ExceptionFlags, 0x1)
	putU64(bytes, exc+ExceptionRecord, 0)
	putU64(bytes, exc+ExceptionAddress, 0x0000_7ff6_0000_1000)
	putU32(bytes, exc+ExceptionNumberParameters, 2)
	putU64(bytes, exc+ExceptionParameters, 0x10)
	putU64(bytes, exc+ExceptionParameters+8, 0x20)
	putU32(bytes, exc+ExceptionContextSize, 0x40)
	putU32(bytes, exc+ExceptionContextRVA, 0x3c0)

	// Memory list at 0x2c0: one run.
	memoryList := 0x2c0
	putU32(bytes, memoryList, 1)
	putU64(bytes, memoryList+4, 0x0000_0000_0010_0000)
	putU32(bytes, memoryList+12, 0x40)
	putU32(bytes, memoryList+16, 0x3c0)

	// Memory64 list at 0x300: two runs; data starts at BaseRva 0x3f0.
	memory64 := 0x300
	putU64(bytes, memory64, 2)
	putU64(bytes, memory64+8, 0x3f0)
	putU64(bytes, memory64+16, 0x0000_0000_0020_0000)
	putU64(bytes, memory64+24, 0x10)
	putU64(bytes, memory64+32, 0x0000_0000_0030_0000)
	putU64(bytes, memory64+40, 0x10)

	// MiscInfo at 0x340.
	misc := 0x340
	putU32(bytes, misc+MiscInfoSizeOfInfo, 0x40)
	putU32(bytes, misc+MiscInfoFlags, 0x3)
	putU32(bytes, misc+MiscInfoProcessID, 0x1a2b)
	putU32(bytes, misc+MiscInfoProcessCreateTime, 0x6500_0001)
	putU32(bytes, misc+MiscInfoProcessUserTime, 0x10)
	putU32(bytes, misc+MiscInfoProcessKernelTime, 0x20)
	putU32(bytes, misc+MiscInfoProcessorMaxMHz, 3600)
	putU32(bytes, misc+MiscInfoProcessIntegrityLevel, 0x2000)

	return bytes
}

func TestReadsMinimalMinidump(t *testing.T) {
	report, err := ReadMiniDump(memory(minidump()), DefaultMiniDumpLimits())
	if err != nil {
		t.Fatalf("ReadMiniDump error = %v", err)
	}
	if report.Signature != MiniDumpSignature {
		t.Fatalf("signature = %q", report.Signature)
	}
	if report.VersionMajor != 0 || report.VersionMinor != 0xa793 {
		t.Fatalf("version = %d.%d", report.VersionMajor, report.VersionMinor)
	}
	if report.StreamCount != 7 || report.StreamDirectoryRVA != 0x20 {
		t.Fatalf("directory = %+v", report)
	}
	if report.Timestamp != 1_700_000_000 {
		t.Fatalf("timestamp = %d", report.Timestamp)
	}
	if !contains(report.FlagNames, "WithFullMemory") || !contains(report.FlagNames, "WithHandleData") {
		t.Fatalf("flags = %v", report.FlagNames)
	}
	if len(report.Streams) != 7 {
		t.Fatalf("streams = %d", len(report.Streams))
	}
	for _, stream := range report.Streams {
		if !stream.Decoded {
			t.Fatalf("stream %d not decoded: %+v", stream.Index, stream)
		}
	}

	info := report.SystemInfo
	if info == nil {
		t.Fatal("system info is nil")
	}
	if info.Architecture != 9 || info.ArchitectureName != "amd64" || info.NumberOfProcessors != 8 {
		t.Fatalf("system info = %+v", info)
	}
	if info.BuildNumber != 19045 {
		t.Fatalf("build = %d", info.BuildNumber)
	}
	if info.CSDVersion == nil || info.CSDVersion.Value != "Service Pack 1" {
		t.Fatalf("csd = %+v", info.CSDVersion)
	}
	if !contains(info.SuiteNames, "enterprise") || !contains(info.SuiteNames, "single-user terminal services") {
		t.Fatalf("suites = %v", info.SuiteNames)
	}

	modules := report.Modules
	if modules == nil || modules.DeclaredCount != 1 || len(modules.Modules) != 1 {
		t.Fatalf("modules = %+v", modules)
	}
	if modules.Modules[0].Name == nil || modules.Modules[0].Name.Value != "sample.exe" {
		t.Fatalf("module name = %+v", modules.Modules[0].Name)
	}
	if got := modules.Modules[0].Version.FileVersionLabel(); got != "1.2.3.4" {
		t.Fatalf("file version = %q", got)
	}
	if got := modules.Modules[0].Version.ProductVersionLabel(); got != "5.6.7.8" {
		t.Fatalf("product version = %q", got)
	}
	if modules.Modules[0].Version.FileFlags != 0x1 {
		t.Fatalf("file flags = %#x", modules.Modules[0].Version.FileFlags)
	}

	threads := report.Threads
	if threads == nil || len(threads.Threads) != 1 || threads.Threads[0].ThreadID != 0x1234 {
		t.Fatalf("threads = %+v", threads)
	}
	if threads.Threads[0].TEB != 0x7ffd_0000 || !threads.Threads[0].StackInBounds || !threads.Threads[0].ContextInBounds {
		t.Fatalf("thread = %+v", threads.Threads[0])
	}

	exception := report.Exception
	if exception == nil || exception.ExceptionCode != 0xc000_0005 {
		t.Fatalf("exception = %+v", exception)
	}
	if len(exception.Parameters) != 2 || exception.Parameters[0] != 0x10 || exception.Parameters[1] != 0x20 {
		t.Fatalf("parameters = %v", exception.Parameters)
	}
	if !exception.Noncontinuable || exception.FirstChance != nil {
		t.Fatalf("exception flags = %+v", exception)
	}

	memoryList := report.Memory
	if memoryList == nil || memoryList.DeclaredCount != 1 || memoryList.Runs[0].RVA != 0x3c0 || memoryList.TotalBytes != 0x40 {
		t.Fatalf("memory list = %+v", memoryList)
	}

	memory64 := report.Memory64
	if memory64 == nil || memory64.DeclaredCount != 2 || memory64.BaseRVA != 0x3f0 {
		t.Fatalf("memory64 = %+v", memory64)
	}
	if memory64.Runs[0].RVA != 0x3f0 || memory64.Runs[1].RVA != 0x400 {
		t.Fatalf("memory64 runs = %+v", memory64.Runs)
	}
	if !memory64.Runs[0].InBounds || !memory64.Runs[1].InBounds || memory64.TotalBytes != 0x20 {
		t.Fatalf("memory64 = %+v", memory64)
	}
	if got := report.MemoryBytesReported(); got != 0x60 {
		t.Fatalf("memory bytes reported = %#x", got)
	}

	misc := report.MiscInfo
	if misc == nil || misc.ProcessID != 0x1a2b {
		t.Fatalf("misc info = %+v", misc)
	}
	if misc.ProcessorMaxMHz == nil || *misc.ProcessorMaxMHz != 3600 {
		t.Fatalf("max mhz = %v", misc.ProcessorMaxMHz)
	}
	if misc.ProcessIntegrityLevel == nil || *misc.ProcessIntegrityLevel != 0x2000 {
		t.Fatalf("integrity = %v", misc.ProcessIntegrityLevel)
	}
}

func TestOutOfRangeDescriptorReportedAndSkipped(t *testing.T) {
	bytes := minidump()
	row := 0x20 + 2*MiniDumpDirectoryEntryBytes
	putU32(bytes, row+8, 0xffff_fff0)

	report, err := ReadMiniDump(memory(bytes), DefaultMiniDumpLimits())
	if err != nil {
		t.Fatalf("ReadMiniDump error = %v", err)
	}
	descriptor := report.Streams[2]
	if descriptor.StreamType != StreamThreadList || descriptor.InBounds || descriptor.Decoded {
		t.Fatalf("descriptor = %+v", descriptor)
	}
	if report.Threads != nil {
		t.Fatalf("threads = %+v", report.Threads)
	}
	if !anyContains(report.Warnings, "past the source") {
		t.Fatalf("warnings = %v", report.Warnings)
	}
}

func TestDuplicateStreamTypesReportedFirstDecoded(t *testing.T) {
	bytes := minidump()
	row := 0x20 + 7*MiniDumpDirectoryEntryBytes
	putU32(bytes, row, StreamSystemInfo)
	putU32(bytes, row+4, SystemInfoBytes)
	putU32(bytes, row+8, 0x100)
	putU32(bytes, MiniHeaderNumberOfStreams, 8)

	report, err := ReadMiniDump(memory(bytes), DefaultMiniDumpLimits())
	if err != nil {
		t.Fatalf("ReadMiniDump error = %v", err)
	}
	if report.StreamCount != 8 {
		t.Fatalf("stream count = %d", report.StreamCount)
	}
	if len(report.DuplicateStreams) != 1 || report.DuplicateStreams[0] != StreamSystemInfo {
		t.Fatalf("duplicates = %v", report.DuplicateStreams)
	}
	if !report.Streams[7].Duplicate || report.SystemInfo == nil {
		t.Fatalf("report = %+v", report)
	}
}

func TestTruncatedModuleNameReportedNotInvented(t *testing.T) {
	bytes := minidump()
	putU32(bytes, 0x3a0, 0x100)
	bytes = bytes[:0x3a6]

	report, err := ReadMiniDump(memory(bytes), DefaultMiniDumpLimits())
	if err != nil {
		t.Fatalf("ReadMiniDump error = %v", err)
	}
	modules := report.Modules
	if modules == nil || len(modules.Modules) != 1 || modules.Modules[0].Name == nil {
		t.Fatalf("modules = %+v", modules)
	}
	name := modules.Modules[0].Name
	if !name.Truncated || name.ByteCount != 0x100 {
		t.Fatalf("name = %+v", name)
	}
	if !anyContains(report.Warnings, "declares 256") {
		t.Fatalf("warnings = %v", report.Warnings)
	}
}

func TestMemory64RunPastSourceMarked(t *testing.T) {
	bytes := minidump()
	putU64(bytes, 0x300+32+8, 0x1000)

	report, err := ReadMiniDump(memory(bytes), DefaultMiniDumpLimits())
	if err != nil {
		t.Fatalf("ReadMiniDump error = %v", err)
	}
	memory64 := report.Memory64
	if memory64 == nil || !memory64.Runs[0].InBounds || memory64.Runs[1].InBounds {
		t.Fatalf("memory64 = %+v", memory64)
	}
	if memory64.OutOfBounds != 1 {
		t.Fatalf("out of bounds = %d", memory64.OutOfBounds)
	}
	if !anyContains(report.Warnings, "memory64") {
		t.Fatalf("warnings = %v", report.Warnings)
	}
}

func TestMinidumpBadSignatureRefused(t *testing.T) {
	bytes := minidump()
	copy(bytes[0:4], "NOPE")
	_, err := ReadMiniDump(memory(bytes), DefaultMiniDumpLimits())
	if !errors.Is(err, ErrMiniDumpBadSignature) {
		t.Fatalf("error = %v, want ErrMiniDumpBadSignature", err)
	}
	var miniErr *MiniDumpError
	if !errors.As(err, &miniErr) || miniErr.Found != [4]byte{'N', 'O', 'P', 'E'} {
		t.Fatalf("error detail = %+v", miniErr)
	}
}

func TestMinidumpStreamCountOverCapRefused(t *testing.T) {
	bytes := minidump()
	putU32(bytes, MiniHeaderNumberOfStreams, 5000)
	limits := DefaultMiniDumpLimits()
	_, err := ReadMiniDump(memory(bytes), limits)
	if !errors.Is(err, ErrMiniDumpTooManyStreams) {
		t.Fatalf("error = %v, want ErrMiniDumpTooManyStreams", err)
	}
	var miniErr *MiniDumpError
	if !errors.As(err, &miniErr) || miniErr.Count != 5000 || miniErr.Limit != uint64(limits.MaxStreams) {
		t.Fatalf("error detail = %+v", miniErr)
	}
}

func TestMinidumpDirectoryPastSourceRefused(t *testing.T) {
	bytes := minidump()
	putU32(bytes, MiniHeaderStreamDirectoryRVA, 0xffff_fff0)
	_, err := ReadMiniDump(memory(bytes), DefaultMiniDumpLimits())
	if !errors.Is(err, ErrMiniDumpStreamDirectoryTruncated) {
		t.Fatalf("error = %v, want ErrMiniDumpStreamDirectoryTruncated", err)
	}
	var miniErr *MiniDumpError
	if !errors.As(err, &miniErr) || miniErr.Offset != 0xffff_fff0 {
		t.Fatalf("error detail = %+v", miniErr)
	}
}

func TestMinidumpShortHeaderNamed(t *testing.T) {
	_, err := ReadMiniDump(memory([]byte("MDMP")), DefaultMiniDumpLimits())
	if !errors.Is(err, ErrMiniDumpHeaderTooShort) {
		t.Fatalf("error = %v, want ErrMiniDumpHeaderTooShort", err)
	}
	var miniErr *MiniDumpError
	if !errors.As(err, &miniErr) || miniErr.Need != MiniDumpHeaderBytes || miniErr.Available != 4 {
		t.Fatalf("error detail = %+v", miniErr)
	}
}

func TestMinidumpMagicProbeAcceptsOnlyMDMP(t *testing.T) {
	if !MiniDumpLooksLike([]byte("MDMP")) || !MiniDumpLooksLike([]byte("MDMPrest")) {
		t.Fatal("MiniDumpLooksLike rejected MDMP")
	}
	if MiniDumpLooksLike([]byte("PAGE")) || MiniDumpLooksLike([]byte("MDM")) {
		t.Fatal("MiniDumpLooksLike accepted a non-MDMP prefix")
	}
	if MiniDumpSignatureU32 != 0x504d_444d {
		t.Fatalf("signature u32 = %#x", MiniDumpSignatureU32)
	}
}

func TestMinidumpOverCapacityCountsAreWarned(t *testing.T) {
	bytes := minidump()
	// The module stream declares one module but has room for one; claim 5.
	putU32(bytes, 0x140, 5)
	report, err := ReadMiniDump(memory(bytes), DefaultMiniDumpLimits())
	if err != nil {
		t.Fatalf("ReadMiniDump error = %v", err)
	}
	modules := report.Modules
	if modules == nil || modules.DeclaredCount != 5 || len(modules.Modules) != 1 {
		t.Fatalf("modules = %+v", modules)
	}
	if !anyContains(report.Warnings, "hold at most") {
		t.Fatalf("warnings = %v", report.Warnings)
	}
}

func TestStreamTypeNamesAndFlags(t *testing.T) {
	if name, ok := StreamTypeName(StreamMemory64List); !ok || name != "Memory64ListStream" {
		t.Fatalf("StreamTypeName = %q/%v", name, ok)
	}
	if _, ok := StreamTypeName(9999); ok {
		t.Fatal("StreamTypeName accepted an unknown type")
	}
	names := MiniDumpFlagNames(0x1 | 0x2 | 0x10000)
	if !contains(names, "WithDataSegs") || !contains(names, "WithFullMemory") || !contains(names, "IgnoreInaccessibleMemory") {
		t.Fatalf("flag names = %v", names)
	}
	excNames := ExceptionFlagNames(0x1 | 0x2)
	if !contains(excNames, "EXCEPTION_NONCONTINUABLE") || !contains(excNames, "EXCEPTION_UNWINDING") {
		t.Fatalf("exception flag names = %v", excNames)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func anyContains(values []string, substr string) bool {
	for _, value := range values {
		if strings.Contains(value, substr) {
			return true
		}
	}
	return false
}
