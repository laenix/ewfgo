// Package memory holds read-only Windows/Linux memory-dump readers.
//
// It is the Go counterpart of forensic-core's data/memory.rs, which re-exports
// the LiME, hibernation and crash-dump readers:
//
//   - lime reads LiME chain headers and exposes per-range source windows.
//   - hiber validates hiberfil.sys page-zero signatures and stable fields,
//     refusing unsubstantiated fields and XPRESS decompression explicitly.
//   - dmp reads Windows kernel crash dump headers, triage directories, the
//     physical-memory descriptor and user-mode minidump streams.
//
// Every reader consumes the shared internal/data/source ByteSource contract and
// returns errors.Is-friendly failures; no reader fabricates bytes or offsets.
package memory

import (
	"github.com/laenix/ewfgo/internal/data/memory/dmp"
	"github.com/laenix/ewfgo/internal/data/memory/hiber"
	"github.com/laenix/ewfgo/internal/data/memory/lime"
	"github.com/laenix/ewfgo/internal/data/source"
)

// LiME re-exports.
type (
	// LimeError is lime.Error.
	LimeError = lime.Error
	// LimeLimits is lime.Limits.
	LimeLimits = lime.Limits
	// LimeRange is lime.Range.
	LimeRange = lime.Range
	// LimeReport is lime.Report.
	LimeReport = lime.Report
)

// Hibernation re-exports.
type (
	// HiberError is hiber.Error.
	HiberError = hiber.Error
	// HiberReport is hiber.Report.
	HiberReport = hiber.Report
	// HiberSignature is hiber.Signature.
	HiberSignature = hiber.Signature
)

// Crash-dump re-exports.
type (
	// DmpBitness is dmp.Bitness.
	DmpBitness = dmp.Bitness
	// DmpDirectory is dmp.Directory.
	DmpDirectory = dmp.Directory
	// DmpDirectoryEntry is dmp.DirectoryEntry.
	DmpDirectoryEntry = dmp.DirectoryEntry
	// DmpError is dmp.Error.
	DmpError = dmp.Error
	// DmpLimits is dmp.Limits.
	DmpLimits = dmp.Limits
	// DmpPhysicalMemory is dmp.PhysicalMemory.
	DmpPhysicalMemory = dmp.PhysicalMemory
	// DmpReport is dmp.Report.
	DmpReport = dmp.Report
	// DmpRun is dmp.Run.
	DmpRun = dmp.Run
	// DmpRunView is dmp.RunView.
	DmpRunView = dmp.RunView
	// DumpType is dmp.DumpType.
	DumpType = dmp.DumpType
	// MiniDumpError is dmp.MiniDumpError.
	MiniDumpError = dmp.MiniDumpError
	// MiniDumpLimits is dmp.MiniDumpLimits.
	MiniDumpLimits = dmp.MiniDumpLimits
	// MiniDumpReport is dmp.MiniDumpReport.
	MiniDumpReport = dmp.MiniDumpReport
)

// ReadLime walks a LiME chain. It is lime.Read.
func ReadLime(src source.ByteSource, limits lime.Limits) (*lime.Report, error) {
	return lime.Read(src, limits)
}

// ReadHiber reads a hibernation file's page-zero header. It is hiber.Read.
func ReadHiber(src source.ByteSource) (*hiber.Report, error) {
	return hiber.Read(src)
}

// ReadDMP reads a Windows kernel crash-dump header. It is dmp.Read.
func ReadDMP(src source.ByteSource, limits dmp.Limits) (*dmp.Report, error) {
	return dmp.Read(src, limits)
}

// ReadMiniDump reads a user-mode minidump. It is dmp.ReadMiniDump.
func ReadMiniDump(src source.ByteSource, limits dmp.MiniDumpLimits) (*dmp.MiniDumpReport, error) {
	return dmp.ReadMiniDump(src, limits)
}

// ReadAnyDump routes by signature. It is dmp.ReadAnyDump.
func ReadAnyDump(src source.ByteSource, kernelLimits dmp.Limits, miniDumpLimits dmp.MiniDumpLimits) (*dmp.AnyDump, error) {
	return dmp.ReadAnyDump(src, kernelLimits, miniDumpLimits)
}
