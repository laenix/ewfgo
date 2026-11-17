package forensic

import (
	"context"
	"fmt"
	"io"
	"sort"

	"github.com/laenix/ewfgo/internal/data/memory/dmp"
	"github.com/laenix/ewfgo/internal/data/memory/hiber"
	"github.com/laenix/ewfgo/internal/data/memory/lime"
	"github.com/laenix/ewfgo/internal/data/source"
)

// MemoryImage is an opened memory-dump container: LiME, a Windows hibernation
// file, a kernel crash dump or a user-mode minidump. Addresses in Runs and
// ReadAt are physical addresses for LiME/kernel dumps and virtual addresses for
// a minidump (the stream's address space).
type MemoryImage struct {
	path  string
	kind  string
	src   ByteSource
	info  MemoryInfo
	runs  []memoryRun
	rErr  error
	close io.Closer
}

type memoryRun struct {
	address uint64
	length  uint64
	// fileOffset is the run's offset in the dump file (for reporting).
	fileOffset uint64
	// base is the source-local offset of the run's first byte.
	base uint64
	src  ByteSource
}

// MemoryRun is one address range present in the dump.
type MemoryRun struct {
	Address    uint64
	Length     uint64
	FileOffset uint64
}

// MemoryInfo summarizes a memory dump.
type MemoryInfo struct {
	Kind         string
	Bitness      string
	DumpType     string
	Architecture string

	PageSize      uint64
	Processors    uint32
	Ranges        int
	Streams       int
	Modules       int
	Threads       int
	PhysicalStart uint64
	PhysicalEnd   uint64
	StoredBytes   uint64
	BytesReported uint64
	Warnings      []string
}

// OpenMemory opens a memory dump from a path.
func OpenMemory(ctx context.Context, imagePath string, opts Options) (*MemoryImage, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw, err := source.OpenRawFileWithSectorSize(imagePath, 1, 1, opts.sectorSize(nil, 512))
	if err != nil {
		return nil, fmt.Errorf("open memory dump %s: %w", imagePath, err)
	}
	image, err := OpenMemorySource(ctx, raw, opts)
	if err != nil {
		raw.Close()
		return nil, err
	}
	image.path = imagePath
	image.close = raw
	return image, nil
}

// OpenMemorySource opens a memory dump over an existing byte source (for
// example an archive entry or nested node). The source is not closed by
// MemoryImage.Close.
func OpenMemorySource(ctx context.Context, src ByteSource, opts Options) (*MemoryImage, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, fmt.Errorf("%w: nil memory source", ErrInvalidArgument)
	}
	headLen := src.Len()
	if headLen > 8 {
		headLen = 8
	}
	head, err := source.ReadVecAt(src, 0, headLen)
	if err != nil {
		return nil, err
	}

	image := &MemoryImage{src: src}
	switch {
	case len(head) >= 4 && lime.LooksLike(head[:4]):
		report, err := lime.Read(src, lime.DefaultLimits())
		if err != nil {
			return nil, fmt.Errorf("parse LiME dump: %w", err)
		}
		image.kind = "LiME"
		image.info = MemoryInfo{
			Kind:          "LiME",
			PhysicalStart: report.PhysicalStart, PhysicalEnd: report.PhysicalEnd,
			StoredBytes: report.StoredBytes,
		}
		for _, r := range report.Ranges {
			image.runs = append(image.runs, memoryRun{
				address: r.Start, length: r.Stored,
				fileOffset: r.DataOffset, base: r.DataOffset, src: src,
			})
		}

	case len(head) >= 4 && (string(head[:4]) == "hibr" || string(head[:4]) == "HIBR"):
		report, err := hiber.Read(src)
		if err != nil {
			return nil, fmt.Errorf("parse hibernation file: %w", err)
		}
		image.kind = "Windows hiberfil"
		image.info = MemoryInfo{Kind: image.kind}
		for _, field := range report.RefusedFields {
			image.info.Warnings = append(image.info.Warnings, "refused: "+field)
		}

	case len(head) >= 4 && dmp.MiniDumpLooksLike(head[:4]):
		report, err := dmp.ReadMiniDump(src, dmp.DefaultMiniDumpLimits())
		if err != nil {
			return nil, fmt.Errorf("parse minidump: %w", err)
		}
		image.kind = "Windows minidump"
		image.info = MemoryInfo{
			Kind: "Windows minidump", Streams: len(report.Streams),
			BytesReported: report.MemoryBytesReported(),
			Warnings:      append([]string(nil), report.Warnings...),
		}
		if report.SystemInfo != nil {
			image.info.Architecture = report.SystemInfo.ArchitectureName
			image.info.Processors = uint32(report.SystemInfo.NumberOfProcessors)
		}
		if report.Modules != nil {
			image.info.Modules = len(report.Modules.Modules)
		}
		if report.Threads != nil {
			image.info.Threads = int(report.Threads.DeclaredCount)
		}
		addMiniRuns(image, report, src)

	case dmp.LooksLike(head):
		report, err := dmp.Read(src, dmp.DefaultLimits())
		if err != nil {
			return nil, fmt.Errorf("parse kernel dump: %w", err)
		}
		image.kind = "Windows kernel dump"
		image.info = MemoryInfo{
			Kind: image.kind, Bitness: report.Bitness.Label(),
			DumpType:   report.DumpTypeLabel(),
			PageSize:   report.PhysicalMemory.PageSize,
			Processors: report.NumberProcessors,
		}
		views, viewErr := report.PhysicalViews(1, src)
		if viewErr != nil {
			image.rErr = viewErr
		}
		for _, view := range views {
			if view.Source == nil {
				image.rErr = fmt.Errorf("run at %#x has no source window", view.PhysicalStart)
				continue
			}
			image.runs = append(image.runs, memoryRun{
				address: view.PhysicalStart, length: view.Length,
				fileOffset: view.FileOffset, src: view.Source,
			})
		}

	default:
		return nil, fmt.Errorf("%w: source is not a recognised memory dump", ErrUnsupported)
	}

	sort.Slice(image.runs, func(i, j int) bool { return image.runs[i].address < image.runs[j].address })
	image.info.Ranges = len(image.runs)
	return image, nil
}

func addMiniRuns(image *MemoryImage, report *dmp.MiniDumpReport, raw ByteSource) {
	if report.Memory != nil {
		for _, run := range report.Memory.Runs {
			if !run.InBounds {
				continue
			}
			image.runs = append(image.runs, memoryRun{
				address: run.Start, length: run.Size,
				fileOffset: run.RVA, base: run.RVA, src: raw,
			})
		}
	}
	if report.Memory64 != nil {
		for _, run := range report.Memory64.Runs {
			if !run.InBounds {
				continue
			}
			image.runs = append(image.runs, memoryRun{
				address: run.Start, length: run.Size,
				fileOffset: run.RVA, base: run.RVA, src: raw,
			})
		}
	}
}

// Path returns the dump path.
func (m *MemoryImage) Path() string { return m.path }

// Kind returns the dump kind.
func (m *MemoryImage) Kind() string { return m.kind }

// Info returns the parsed metadata.
func (m *MemoryImage) Info() MemoryInfo {
	info := m.info
	info.Warnings = append([]string(nil), m.info.Warnings...)
	return info
}

// Runs returns the address ranges present in the dump.
func (m *MemoryImage) Runs() []MemoryRun {
	out := make([]MemoryRun, 0, len(m.runs))
	for _, run := range m.runs {
		out = append(out, MemoryRun{Address: run.address, Length: run.length, FileOffset: run.fileOffset})
	}
	return out
}

// RawSource returns the dump container's byte source.
func (m *MemoryImage) RawSource() ByteSource { return m.src }

// ReadAt reads memory at addr. The whole requested range must be covered by
// contiguous runs: a range crossing a gap or the end of the dump returns an
// explicit error rather than zero-filled or partial evidence.
func (m *MemoryImage) ReadAt(ctx context.Context, addr uint64, buf []byte) (int, error) {
	if err := checkContext(ctx); err != nil {
		return 0, err
	}
	if len(buf) == 0 {
		return 0, nil
	}
	if len(m.runs) == 0 {
		if m.rErr != nil {
			return 0, fmt.Errorf("%w: dump has no readable physical layout: %v", ErrUnsupported, m.rErr)
		}
		return 0, fmt.Errorf("%w: dump has no memory runs", ErrUnsupported)
	}
	end := addr + uint64(len(buf))
	if end < addr {
		return 0, fmt.Errorf("%w: address range overflows u64", ErrInvalidArgument)
	}

	// Walk the sorted runs, requiring exact contiguity for the whole request.
	cursor := addr
	done := 0
	for cursor < end {
		index := sort.Search(len(m.runs), func(i int) bool {
			return m.runs[i].address+m.runs[i].length > cursor
		})
		if index >= len(m.runs) || m.runs[index].address > cursor {
			return 0, fmt.Errorf("%w: memory at address %#x is not present in the dump", ErrOutOfRange, cursor)
		}
		run := &m.runs[index]
		within := cursor - run.address
		avail := run.length - within
		want := end - cursor
		if avail > want {
			avail = want
		}
		local := run.base + within
		n, err := run.src.ReadAt(local, buf[done:done+int(avail)])
		if err != nil {
			return 0, fmt.Errorf("read memory at %#x: %w", cursor, err)
		}
		if uint64(n) != avail {
			return 0, fmt.Errorf("read memory at %#x: %w", cursor, io.ErrUnexpectedEOF)
		}
		cursor += avail
		done += int(avail)
	}
	return done, nil
}

// Close releases the dump file. It is idempotent.
func (m *MemoryImage) Close() error {
	if m.close == nil {
		return nil
	}
	err := m.close.Close()
	m.close = nil
	return err
}

// MemoryReader is the unified read surface; it exists so a caller can store a
// MemoryImage behind a small interface.
type MemoryReader interface {
	Kind() string
	Info() MemoryInfo
	Runs() []MemoryRun
	ReadAt(ctx context.Context, addr uint64, buf []byte) (int, error)
}

var _ MemoryReader = (*MemoryImage)(nil)
