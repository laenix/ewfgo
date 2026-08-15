# ewfgo - Pure Go EWF Forensic Image Parser

A pure Go implementation for parsing Expert Witness Format (EWF) forensic disk images (EnCase .E01 files).

## Features

- ✅ Pure Go implementation, no external C dependencies (no CGO, no external processes)
- ✅ Validate EWF file format (E01)
- ✅ Parse EWF sections (header, disk, table, volume)
- ✅ Parse MBR and GPT partition tables
- ✅ Read sector data (single or multiple sectors) through exact-decompression
- ✅ Decompress zlib (method 1) and raw DEFLATE (method 2) chunks; EWF-LZ (method 3) is an explicit unsupported error — never fabricated
- ✅ Parallel chunk decompression (GOMAXPROCS workers, 256-chunk batches) with a 64 MiB decompressed-chunk LRU cache
- ✅ MD5/SHA1 acquisition-hash verification (`StoredHashes`, `VerifyImageHash`)
- ✅ Filesystem parsing (FAT12/16/32, exFAT, NTFS, ext4, XFS, Btrfs, APFS): list directories and read files
- ✅ Filesystem detection for many more (HFS+, ReFS, F2FS, SquashFS, BitLocker, LUKS, ZFS, RAID, ...)
- ✅ Multi-partition support (MBR + GPT)
- ✅ Multi-volume file support (E01, E02... auto-discovered)
- ✅ Read-only NBD server (`cmd/nbdserve`) to mount an image as a block device

## Installation

```bash
go get github.com/laenix/ewfgo
```

## Quick Start

### CLI Usage

```bash
# Build
go build -o ewftool ./cmd/main.go

# Show disk/partition info
./ewftool evidence.E01 info

# List MBR partitions
./ewftool evidence.E01 parts

# Show filesystem detection per partition
./ewftool evidence.E01 fs

# List root directory
./ewftool evidence.E01 ls

# List a specific directory (optionally select the partition: ls <partition#> <path>)
./ewftool evidence.E01 ls 0 /home
```

### Programmatic Usage

```go
package main

import (
	"fmt"
	"log"

	"github.com/laenix/ewfgo"
)

func main() {
	// Open EWF image
	img, err := ewf.Open("evidence.E01")
	if err != nil {
		log.Fatal(err)
	}
	defer img.Close()

	// Print metadata
	fmt.Printf("Case: %s\n", img.CaseNumber())
	fmt.Printf("Evidence: %s\n", img.EvidenceNumber())
	fmt.Printf("Examiner: %s\n", img.Examiner())

	// Print disk info
	disk := img.GetDiskInfo()
	fmt.Printf("Total Sectors: %d\n", disk.TotalSectors)
	fmt.Printf("Sector Size: %d bytes\n", disk.SectorBytes)

	// Read MBR
	mbr, err := img.MBR()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Disk Signature: %d\n", mbr.DiskSignature)

	// Scan filesystems
	parts, err := img.ScanFileSystems()
	if err != nil {
		log.Fatal(err)
	}
	for _, p := range parts {
		fmt.Printf("Partition %d: %s (%s)\n", p.Index, p.TypeName, p.FileSystem)
	}

	// Read partition data
	if len(parts) > 0 {
		data, err := img.ReadSectors(parts[0].StartSector, 16)
		if err == nil {
			fmt.Printf("Read %d bytes from partition\n", len(data))
		}
	}
}
```

### Reading a partition's filesystem

`OpenFileSystem(index)` opens one partition's filesystem as an `*ewf.ImageFS`
with `ListDir`/`ReadFile` (index `<= 0` selects the first partition):

```go
fs, err := img.OpenFileSystem(0) // first partition
if err != nil {
	log.Fatal(err)
}
defer fs.Close()

entries, err := fs.ListDir("/")
if err != nil {
	log.Fatal(err)
}
for _, e := range entries {
	fmt.Printf("%s (%d bytes, dir=%v)\n", e.Name, e.Size, e.IsDir)
}

data, err := fs.ReadFile("path/to/file.txt")
if err != nil {
	log.Fatal(err) // explicit error, never fabricated content
}
```

### Verifying the acquisition hashes

`VerifyImageHash` streams the whole media data through the exact-decompression
read path and compares against the MD5/SHA1 stored in the E01:

```go
res, err := img.VerifyImageHash()
if err != nil {
	log.Fatal(err)
}
fmt.Printf("MD5 match: %v, SHA1 match: %v (%d bytes hashed)\n",
	res.MD5Match, res.SHA1Match, res.BytesHashed)

md5Hash, sha1Hash := img.StoredHashes() // acquisition hashes, nil if absent
```

## Examples

A runnable walkthrough of the forensic API lives in
[examples/forensic](examples/forensic/main.go): it opens an image, prints its
case number and sector count, enumerates partitions, lists the first
partition's root directory and, if present, prints the content of a named file
(default `fixture.txt`):

```bash
go run ./examples/forensic evidence.E01          # reads fixture.txt if present
go run ./examples/forensic evidence.E01 /etc/hostname   # read a named file
```

`go run ./...` also builds every example, so `go build ./...` and
`go vet ./...` cover them.

## Supported Filesystems

| Filesystem | Detection | Notes |
|------------|-----------|-------|
| NTFS | ✅ | Windows |
| FAT12/16/32 | ✅ | Windows/MS-DOS |
| exFAT | ✅ | Windows/SD cards |
| ext2/3/4 | ✅ | Linux |
| XFS | ✅ | Linux |
| Btrfs | ✅ | Linux |
| F2FS | ✅ | Linux/Mobile |
| SquashFS | ✅ | Live CD |
| HFS+ | ✅ | macOS (legacy) |
| APFS | ✅ | macOS (modern) |
| ReFS | ✅ | Windows Server |
| BitLocker | ✅ | Detection only |
| LUKS | ✅ | Detection only |
| ZFS | ✅ | Detection only |
| RAID | ✅ | Linux MD detection |

**Fully parsed (list directories + read files)** via `OpenFileSystem` →
`ImageFS.ListDir` / `ImageFS.ReadFile`: **FAT12/16/32, exFAT, NTFS, ext4, XFS,
Btrfs, APFS**. Every other row in the table is detection-only — recognized by
its on-disk signature but with no file parser; requesting its filesystem
returns an explicit error, never fabricated data.

## API Reference

### Core Functions

| Function | Description |
|----------|-------------|
| `ewf.Open(filepath)` | Open and parse EWF image |
| `ewf.IsEWF(filepath)` | Check if valid EWF file |
| `ewf.DetectFileSystem(sectorData)` | Detect filesystem from raw sector bytes |
| `ewf.GuessFileSystemFromPartitionType(t)` | Guess filesystem label from an MBR partition-type byte |

### EWFImage Methods

| Method | Description |
|--------|-------------|
| `Close()` | Close file |
| `CaseNumber()` | Get case number |
| `EvidenceNumber()` | Get evidence number |
| `Examiner()` | Get examiner name |
| `TotalSectors()` | Get total sector count |
| `SectorSize()` | Get sector size in bytes |
| `GetDiskInfo()` | Get disk metadata |
| `ReadSector(lba)` | Read single sector |
| `ReadSectors(lba, count)` | Read multiple sectors |
| `MBR()` | Parse MBR |
| `GPT()` | Parse GPT |
| `APM()` | Parse Apple Partition Map (error if absent) |
| `BSD()` | Parse BSD disklabel (error if absent) |
| `LVM2()` | Parse LVM2 physical-volume header (error if absent) |
| `DetectPartitionType()` | Human-readable type of the first MBR partition |
| `ScanFileSystems()` | Scan partitions and detect filesystems (GPT/MBR) |
| `OpenFileSystem(index)` | Open a partition's filesystem as `*ImageFS` |
| `StoredHashes()` | Return stored acquisition MD5/SHA1 (nil if absent) |
| `VerifyImageHash()` | Stream whole media data, compare computed vs stored MD5/SHA1 |

### ImageFS Methods

`OpenFileSystem` returns an `*ewf.ImageFS` (one partition's filesystem; all
calls are mutex-guarded):

| Method | Description |
|--------|-------------|
| `Size()` | Logical partition size in bytes |
| `ReadBlock(off, p)` | Read partition-relative raw bytes (may cross sectors; `io.EOF` past the end) |
| `ListDir(path)` | List directory at `path` (`""`/`"/"` = root); each entry's `Path` is absolute |
| `ReadFile(path)` | Return full content of the file at `path` |
| `Close()` | Release the parser; further calls error |
| `FSType()` | Resolved filesystem type |

## Project Structure

```
ewfgo/
├── ewf.go          # Public API: Open / IsEWF / EWFImage / Close
├── metadata.go     # CaseNumber / EvidenceNumber / Examiner / TotalSectors / SectorSize / GetDiskInfo
├── read.go         # ReadSector(s) / StoredHashes / VerifyImageHash
├── partition.go    # MBR / GPT / APM / BSD / LVM2 / ScanFileSystems / DetectPartitionType
├── filesystem.go   # ImageFS: OpenFileSystem / ListDir / ReadFile (the one filesystem entry point)
├── nbd/            # Read-only NBD exporter (NewImageExporter, NewPartitionExporter)
├── cmd/
│   ├── main.go     # ewftool CLI (info / parts / fs / ls)
│   ├── nbdserve/   # NBD server (TCP, or Unix socket with -unix)
│   ├── sweepverify/ # forensic sweep toolkit (fswalker / metadump / verifyhash)
│   ├── benchparse/ benchread/  # parse / read benchmarks
│   └── ewffixture/ exfat-inject/  # fixture generators (tests)
├── examples/
│   └── forensic/   # Runnable forensic-API demo (Open → ScanFileSystems → ListDir → ReadFile)
└── internal/
    ├── open.go     # Open / segment discovery / Close
    ├── read.go     # sector reads + chunk decompression (parallel, 64 MiB LRU cache)
    ├── sections.go # EWF section walk + header/table/volume parsing
    ├── types.go    # data model (EWFImage, SegmentFile, Section, ...)
    ├── format.go   # format constants (EVF signature, section layout)
    ├── chunkcache.go  # 64 MiB decompressed-chunk LRU cache
    ├── mbr.go / gpt.go / partitions.go  # Partition-table parsing
    ├── ewffixture/ # Hermetic in-memory E01 fixtures for tests
    └── filesystem/ # Parser hub + one subpackage per filesystem
        ├── fs.go      # types, FileSystem/Reader interfaces, DetectFileSystem, registries
        ├── fsutil.go  # JoinPath (shared path helper)
        ├── fat/       # FAT12/16/32 handler + boot-sector validation
        ├── exfat/     # exFAT handler
        ├── ntfs/      # NTFS handler
        ├── ext4/      # ext2/3/4 handler
        ├── xfs/       # XFS handler (sparse-aware)
        ├── btrfs/     # Btrfs handler
        ├── apfs/      # APFS handler (+ decmpfs / LZVN resource decompression)
        └── detect/    # detection-only stubs (HFS+, ReFS, F2FS, SquashFS, BitLocker, LUKS, ZFS, RAID)
```

## Supported EWF Versions

- EnCase 1-7 format (EWF-E01)
- Single file E01
- Multi-volume files (E01, E02...)

## Platform support

ewfgo is pure Go with no CGO and no runtime external processes, so it compiles
and behaves identically on Windows, Linux and macOS. The supported build matrix
is the 7 toolchain-feasible `(GOOS, GOARCH)` pairs:

| GOOS    | GOARCH  |
|---------|---------|
| windows | amd64   |
| windows | arm64   |
| linux   | amd64   |
| linux   | arm64   |
| linux   | riscv64 |
| darwin  | amd64   |
| darwin  | arm64   |

RISC-V (`riscv64`) is linux-only: Go's `go tool dist list` omits
`windows/riscv64` and `darwin/riscv64`, so those two pairs are deliberately not
in the matrix. All targets build with `CGO_ENABLED=0`.

Enforcement lives in two bash scripts (run under WSL, Git Bash or macOS):

```bash
scripts/build-matrix.sh   # builds + vets all 7 pairs with CGO_ENABLED=0, then runs the native build/vet/test gate
scripts/check-hermetic.sh # greps for accidental platform dependence (cgo, os/exec, syscall, unsafe,
                          # absolute paths, endianness misuse, Windows path separators) and fails on any
                          # hit that is not explicitly whitelisted
```

`internal/crossplatform/` holds runtime assertions that run on every OS the test
suite runs on: golden SHA-256 hashes of the first sector of every committed
fat32 fixture (proving byte-exact decompression across endianness), and a test
that `\`- and `/`-separated forensic paths resolve identically.

## Correctness (the red line)

Reads return **real on-disk data or an explicit error** — never fabricated,
zeroed, or partial bytes for real content. Every sector read goes through the
exact-decompression path (chunks are validated, then inflated; a chunk that is
not a valid zlib or raw-DEFLATE stream — including EWF method 3 LZ — is an
explicit error). Unsupported filesystems, unimplemented parser paths, and
out-of-range reads all error rather than invent bytes. The test suite is
hermetic: it builds in-memory synthetic E01 fixtures with
`internal/ewffixture` (no external tools), and `go test ./...` passes on a
plain Windows box.

## Read performance

Chunk decompression runs in parallel (256-chunk batches across `GOMAXPROCS`
workers) with a 64 MiB decompressed-chunk LRU cache for repeated random access.
Measured on a real image (`mac.E01`): the parallel path reaches **569.5 → 1115
MiB/s (1.93× faster than the sequential baseline)**.

## Reference

- [EWF Format Specification](./Expert%20Witness%20Compression%20Format%20(EWF).asciidoc)

## License

MIT