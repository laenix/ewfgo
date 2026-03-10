# ewfgo - Pure Go EWF Forensic Image Parser

A pure Go implementation for parsing Expert Witness Format (EWF) forensic disk images (EnCase .E01 files).

## Features

- ✅ Pure Go implementation, no external C dependencies
- ✅ Validate EWF file format (E01)
- ✅ Parse EWF sections (header, disk, table, volume)
- ✅ Parse MBR partition table
- ✅ Parse GPT partition table  
- ✅ Read sector data (single or multiple sectors)
- ✅ Decompress zlib/deflate compressed data
- ✅ MD5/SHA1 hash verification
- ✅ Filesystem detection (NTFS, FAT, ext4, XFS, Btrfs, HFS+, APFS, etc.)
- ✅ Multi-partition support
- 🚧 Multi-volume file support (E01, E02...)

## Installation

```bash
go get github.com/laenix/ewfgo
```

## Quick Start

### CLI Usage

```bash
# Build
go build -o ewftool ./cmd/main.go

# Show disk info
./ewftool evidence.E01 info

# Show filesystem detection
./ewftool evidence.E01 fs

# Test file reading
./ewftool evidence.E01 ls
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
	parts, _ := img.ScanFileSystems()
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

## API Reference

### Core Functions

| Function | Description |
|----------|-------------|
| `ewf.Open(filepath)` | Open and parse EWF image |
| `ewf.IsEWF(filepath)` | Check if valid EWF file |

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
| `ScanFileSystems()` | Scan partitions and detect filesystems |
| `ListFiles(partitionIndex)` | List root directory |

## Project Structure

```
ewfgo/
├── ewfgo.go          # Main entry point
├── open.go           # Public API
├── open_files.go     # File reading functions
├── cmd/main.go       # CLI tool
├── open.go          # Exported API
├── open_files.go     # File reading functions
├── internal/
│   ├── constants.go  # Constants
│   ├── ewf.go        # Core EWF parsing
│   ├── mbr.go        # MBR parsing
│   ├── gpt.go        # GPT parsing
│   ├── partitions.go # APM/BSD/LVM detection
│   └── filesystem/   # Filesystem implementations
│       ├── fs.go     # Interface & detection
│       ├── ntfs.go   # NTFS parser
│       ├── fat.go    # FAT parser
│       ├── ext4.go   # ext2/3/4 parser
│       └── ...       # More filesystems
└── cmd/
    └── main.go       # CLI entry
```

## Supported EWF Versions

- EnCase 1-7 format (EWF-E01)
- Single file E01
- Multi-volume files (E01, E02...)

## Reference

- [EWF Format Specification](./Expert%20Witness%20Compression%20Format%20(EWF).asciidoc)

## License

MIT