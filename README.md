# ewfgo

**A pure-Go, read-only forensic data engine.**

[English](README.md) | [简体中文](README.zh-CN.md)

ewfgo opens evidence containers and the filesystems inside them. It is a single
CGO-free Go module for EWF/E01 images, raw disks, virtual disks, partition
tables, volume managers, filesystems, logical evidence, archives, memory dumps
and file carving.

Every read is either the exact evidence bytes or an explicit error. The engine
never substitutes raw container bytes for media bytes, never fabricates a
directory entry, and never silently zero-fills a failed decode.

---

## Why ewfgo

- **Pure Go.** `CGO_ENABLED=0`, no external processes, no platform-specific
  syscalls in the read path. Windows, Linux and macOS on amd64, arm64 and
  Linux/riscv64.
- **Evidence-first.** Strict reads fail loudly. Unsupported or encrypted data
  is named, not guessed.
- **Provenance built in.** Every byte source carries IDs and extent maps back to
  the image container.
- **One API, many formats.** Disk images, logical evidence, archives, databases,
  memory dumps and memory carving all expose the same `ByteSource` contract.

---

## Integrity guarantees

| Rule | Behaviour |
|---|---|
| Exact decoding | A damaged chunk, page, block or record is an error, never a zero-filled substitute. |
| No container leakage | Sector and file reads come from the decoded guest medium, never from EWF/QCOW2/VHD container bytes. |
| No invented entries | A directory listing that cannot be parsed returns an error; names are never synthesized. |
| Bounded reads | Reads past EOF return the readable prefix plus `io.EOF`; the tail is never made up. |
| Explicit unsupported | Known-but-unimplemented features return `ErrUnsupported` naming the feature. |
| Read-only | No write, modify or repair path exists. |

---

## Supported formats

### Containers and evidence files

| Family | Formats |
|---|---|
| Disk images | EWF/E01 (multi-segment E01/E02/...), raw disks, VHD, VHDX, VMDK (sparse, stream-optimized, split/flat descriptors), QCOW2 (v2/v3), VDI, DMG, Android sparse |
| Logical evidence | EnCase L01/Lx01 v1 (with L02/L03 segments), AFF4 |
| Windows images | WIM (XPRESS Huffman, LZX), Android `super.img` dynamic partitions |
| Archives | ZIP/Zip64, TAR, CPIO (newc/crc/odc/binary), ar, CAB (stored/MSZIP), XAR (stored/zlib/bzip2/xz/lzma), RAR 5 (stored members), 7-Zip (Copy/LZMA/LZMA2/Deflate/Bzip2/PPMd/Delta/BCJ), Android/MIUI backup |
| Documents | OLE2/CFB, OOXML (docx/xlsx/pptx and macro/template variants), PDF (xref/incremental updates, object streams, metadata, actions, embedded files, Standard-handler decryption), Office owner (`~$`) files, serialized certificate stores |
| Databases | SQLCipher 1–4, Realm, MMKV, LevelDB stores (tables, manifest, WAL) |
| Mail stores | Outlook PST/OST (ANSI 14/15, Unicode 23/36; folders, messages, recipients, attachments, embedded messages, deleted-item recovery, compressed RTF) |
| Logs and patches | Windows CLFS (metadata), MSDelta PA19/PA30/PA31 |
| Streams | gzip, bzip2, LZ4 (standard frames, linked/independent blocks), XZ (LZMA2, concatenated streams) |
| Memory | LiME, Windows hiberfil, Windows kernel dump, user-mode minidump |

### Partition tables and volumes

- MBR (with EBR chains), GPT (primary, backup, CRC-verified), Apple Partition
  Map, BSD disklabel.
- Linux mdraid RAID0/10/4/5/6 with P/Q parity rebuild.
- LVM linear and striped logical volumes.
- Intel IMSM RAID0/1/10 (RAID5 is refused explicitly).
- Windows LDM dynamic disks: concatenated, spanned, striped, mirrored, RAID-5.
- Apple CoreStorage metadata.
- Partition/filesystem signature scanning for damaged tables.

### Filesystems

| Read directories and files | Detection / metadata |
|---|---|
| FAT12/16/32, exFAT, NTFS, ext2/3/4, XFS, Btrfs, APFS, ZFS | ReFS and other recognised formats without a reader |
| HFS+/HFSX (including decmpfs zlib/LZVN/LZFSE), HFS classic, F2FS, SquashFS, ISO 9660, UDF | |
| CramFS, EROFS, JFS, ReiserFS, VMFS5/6, UFS1/UFS2 | |
| Minix v1/v2/v3, System V/Xenix/Coherent, HPFS, GFS2, NILFS2, OCFS2, UBIFS, YAFFS, BeFS, JFFS2, HAMMER2, QNX6 | |

BitLocker volumes can be unlocked with a 48-digit recovery password, a user
password or a 256-bit startup key; AES-XTS, AES-CBC and Elephant-diffuser
sectors are decrypted after the volume's AES-CCM tags accept the key. LUKS1 and
LUKS2 volumes can be unlocked with a passphrase (PBKDF2 or Argon2i/id key
slots, anti-forensic merge, AES-XTS or AES-CBC-ESSIV/plain64); the key is
accepted only after the volume digest verifies it. Detached headers and
non-AES ciphers are refused explicitly.

### Memory and carving

- LiME, hiberfil, kernel crash dump, minidump.
- BMP, GIF, TIFF, WEBP, EVTX, SQLite and Prefetch carving, with LZXPRESS.

---

## Install

```bash
go get github.com/laenix/ewfgo
```

Requires Go 1.24 or newer.

---

## Quick start

### CLI

```bash
go build -o ewftool ./cmd

./ewftool evidence.E01 info
./ewftool evidence.E01 parts
./ewftool evidence.E01 fs
./ewftool evidence.E01 vols
./ewftool evidence.E01 enc
./ewftool evidence.E01 nested
./ewftool evidence.E01 ls 0 /home
./ewftool -version
```

`nbdserve` exports an image or one partition as a read-only Network Block
Device:

```bash
go build -o nbdserve ./cmd/nbdserve
./nbdserve -addr 127.0.0.1:10809 evidence.E01
```

### Library

```go
package main

import (
	"context"
	"fmt"
	"log"

	forensic "github.com/laenix/ewfgo"
)

func main() {
	ctx := context.Background()

	img, err := forensic.Open(ctx, "evidence.E01", forensic.Options{})
	if err != nil {
		log.Fatal(err)
	}
	defer img.Close()

	info := img.Info()
	fmt.Printf("%s case=%q size=%d sector=%d\n",
		info.Format, info.CaseNumber, img.Size(), img.SectorSize())

	parts, err := img.Partitions(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, p := range parts {
		fmt.Printf("partition %d: type=%q fs=%q offset=%d size=%d\n",
			p.Index(), p.TypeName(), p.Format(), p.Offset(), p.Length())
	}

	fsys, err := parts[0].OpenFilesystem(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer fsys.Close()

	entries, err := fsys.ListDir(ctx, "/")
	if err != nil {
		log.Fatal(err)
	}
	for _, e := range entries {
		fmt.Println(e.Path, e.Size, e.IsDir)
	}

	file, err := fsys.Open(ctx, "/fixture.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	data, err := file.ReadAll()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(data))
}
```

---

## Guides

### Images and partitions

`Open` recognises EWF/E01 (including sibling segments), raw disks and the
virtual-disk containers listed above. `OpenSource` wraps an already-decoded
`ByteSource` and performs no container sniffing.

```go
parts, err := img.Partitions(ctx)
p := parts[0]
fmt.Println(p.Offset(), p.Length(), p.Source().Len())
```

An image with no partition table but a recognised filesystem returns one
whole-volume entry:

```go
p.WholeVolume() // true; p.Source() covers the entire image
```

or open it directly:

```go
fsys, err := img.OpenFilesystem(ctx)
```

### Filesystem access

`FileSystem` exposes directories, metadata and streaming file handles:

```go
entries, err := fsys.ListDir(ctx, "/etc")
entry, err := fsys.Stat(ctx, "/etc/hosts")

file, err := fsys.Open(ctx, "/etc/hosts")
n, err := file.ReadAt(buf, 0) // io.ReaderAt
_, err = file.Seek(0, io.SeekStart)
data, err := file.ReadAll()   // bounded by Limits.MaxFileBytes

err = fsys.Walk(ctx, "/", func(e forensic.Entry) error {
	fmt.Println(e.Path)
	return nil
})
```

Paths are `/`-separated and absolute; a leading `\` is accepted and normalized.

### `io/fs` adapter

```go
vfs := forensic.AsFS(ctx, fsys)

data, err := fs.ReadFile(vfs, "etc/hosts")
err = fs.WalkDir(vfs, ".", func(name string, d fs.DirEntry, err error) error {
	if err != nil {
		return err
	}
	fmt.Println(name)
	return nil
})
```

The adapter is read-only and rejects `..` traversal.

### Provenance

```go
graph, err := img.Graph(ctx)       // validated image/partition/FS DAG
src := parts[0].Source()
ranges, err := src.MapToImage(0, 4096)
```

`SourceID`, `ImageID`, `Extents` and `MapToImage` let any parser byte be traced
back to the container that stores it.

### Verification

`Verify` streams the whole decoded medium through the strict read path and
compares the computed hashes with the acquisition hashes stored in the image.

```go
res, err := img.Verify(ctx)
fmt.Printf("MD5=%v SHA1=%v bytes=%d\n",
	res.MD5Match, res.SHA1Match, res.BytesHashed)
```

### Assembled volumes

```go
volumes, err := img.Volumes(ctx)
for _, v := range volumes {
	fmt.Println(v.Name(), v.Kind(), v.Format(), v.Readable(), v.Problem())
	fsys, err := v.OpenFilesystem(ctx)
	_ = fsys
	_ = err
}
```

`Volumes` assembles mdraid and LVM volumes from the image's partitions.
Incomplete arrays are reported with `Readable() == false` and a `Problem()`
naming the missing member; they are never served with zero-filled members.

Standalone volume-manager APIs:

```go
ldm, err := forensic.OpenLDM(ctx, "dynamic-disk.img", forensic.Options{})
imsm, err := forensic.OpenIMSM(ctx, "disk0.img", forensic.Options{})
super, err := forensic.OpenSuper(ctx, "super.img", forensic.Options{})
```

### Nested containers

`OpenNested` recursively inspects an evidence file: an archive entry can be an
E01, the E01 can hold partitions and filesystems, a file in a filesystem can be
a TAR, and an entry in that TAR can be a memory dump or a document.

```go
tree, err := forensic.OpenNested(ctx, "outer.zip", forensic.DefaultNestedOptions())
if err != nil {
	log.Fatal(err)
}
defer tree.Close()

fmt.Println(tree.Nodes, tree.Truncated)
walk(tree.Root, 0)

func walk(node *forensic.NestedNode, depth int) {
	fmt.Printf("%*s%s [%s] %s\n", depth*2, "", node.Name, node.Kind, node.Detail)
	if node.Err != "" {
		fmt.Println("  error:", node.Err)
	}
	for _, child := range node.Children {
		walk(child, depth+1)
	}
}
```

Each node carries `Kind`, `Detail`, `Size`, `Source` (when byte-addressable)
and a display `Path`. A nested artifact that fails to parse records `Err` on
its node without aborting its siblings. Use `OpenNestedSource` for an
already-opened `ByteSource`, and the `*Source` constructors (`OpenDocumentSource`,
`OpenMemorySource`, `OpenWIMSource`, `OpenLogicalSource`, `OpenAFF4Source`) to
open a nested node's `Source` with typed APIs.

Bounds are explicit:

```go
opts := forensic.DefaultNestedOptions()
opts.MaxDepth = 8
opts.MaxNodes = 5000
opts.MaxEntries = 2000
opts.InspectFiles = false // containers/partitions/filesystems only
```

Recognised nested layers include E01, L01, WIM, AFF4, ZIP/TAR/CPIO/ar/CAB/
XAR/RAR/7z, Android backup, OLE/CFB, gzip/bzip2/LZ4/XZ, disk containers, partition tables,
filesystems, memory dumps, OOXML documents and PDFs (including PDF embedded
files). SQLCipher/Realm/MMKV are not
auto-unlocked in a tree; open them explicitly with their normal API. A nested
split VMDK descriptor needs `NestedOptions.Resolver`. A multi-segment E01
inside an archive is opened from the named entry as segment 1; if later segments
are required, the missing data is reported as an explicit read error rather
than zero-filled.

### Logical evidence (L01)

```go
logical, err := forensic.OpenLogical(ctx, "evidence.L01", forensic.Options{})
entries, err := logical.Entries(ctx)
file, err := logical.Open(ctx, "/CASE/big.txt")
```

L02/L03 siblings are discovered automatically.

### Archives and WIM

```go
archive, err := forensic.OpenArchive(ctx, "backup.zip", forensic.Options{})
entries, err := archive.Entries(ctx)
file, err := archive.Open(ctx, "dir/report.txt")

wim, err := forensic.OpenWIM(ctx, "install.wim", forensic.Options{})
images, err := wim.Images(ctx)
entries, err = wim.Entries(ctx, images[0].Index)
file, err = wim.Open(ctx, images[0].Index, "Windows/System32/drivers/etc/hosts")
```

Archive names are sanitized: absolute paths, drive prefixes and `..` components
are rejected before any export step can run.

### AFF4

```go
aff4, err := forensic.OpenAFF4(ctx, "evidence.aff4", forensic.Options{})
streams, err := aff4.Streams(ctx)
src, err := aff4.ImageSource(ctx) // logical image stream as a ByteSource
```

### Databases and documents

```go
db, err := forensic.OpenSQLCipher(ctx, "browser.db", "passphrase", forensic.Options{})
src := db.Source() // decrypted SQLite pages, HMAC-checked per page

realmDB, err := forensic.OpenRealm(ctx, "default.realm", forensic.Options{})
tables, err := realmDB.Tables(ctx)

doc, err := forensic.OpenDocument(ctx, "report.docx", forensic.Options{})
info := doc.Info()
rels, err := doc.ExternalRelationships(ctx)

owner, err := forensic.OpenOfficeOwner(ctx, "~$report.docx", forensic.Options{})
name, ok := owner.Owner()

store, err := forensic.OpenCertificateStore(ctx, "certstore.sst", forensic.Options{})
certs, err := store.Certificates(ctx)
```

SQLCipher 1–4 profiles are tried in order. A wrong passphrase is
`ErrWrongPassphrase` (also `ErrDecrypt`); every page is re-authenticated before
AES-CBC decryption. OOXML relationship and template targets are reported
verbatim and never fetched.

### Memory dumps

```go
mem, err := forensic.OpenMemory(ctx, "memory.lime", forensic.Options{})
info := mem.Info()
runs := mem.Runs()
n, err := mem.ReadAt(ctx, 0x1000, buf) // physical or minidump virtual address
```

A request crossing a gap between runs is `ErrOutOfRange`; missing ranges are
never zero-filled.

### Carving and signature scanning

```go
report, err := img.Carve(ctx, 0, img.Size(), forensic.DefaultCarveOptions())
for _, object := range report.TopLevel() {
	fmt.Println(object.Format.Label(), object.Offset, object.Len)
}

scan, err := img.Scan(ctx, forensic.DefaultScanOptions())
for _, candidate := range scan.TopLevel() {
	fmt.Println(candidate.Offset, candidate.Label, candidate.Status)
}
```

Scanning is the recovery path for damaged or overwritten partition tables;
every candidate must confirm its own metadata (and checksum where present).

### NBD export

```bash
go build -o nbdserve ./cmd/nbdserve
./nbdserve -addr 127.0.0.1:10809 -export evidence evidence.E01
```

```go
exp := nbd.NewExporter(img.Source())     // whole image
exp = nbd.NewExporter(parts[0].Source()) // one partition
```

The export is read-only and cross-platform; Linux can attach it with
`nbd-client` and mount the block device. Platform notes, mount/cleanup commands
and QEMU verification are in [docs/nbd-mount.md](docs/nbd-mount.md). A runnable
API example is [examples/nbd](examples/nbd).

---

## Options and limits

```go
type Options struct {
	Limits     Limits
	SectorSize uint32
	Resolver   func(name string) (ByteSource, error)
}

type Limits struct {
	MaxEntries   uint64 // directory/archive entry cap
	MaxDepth     int    // Walk depth cap
	MaxFileBytes uint64 // ReadAll cap (1 GiB when unset)
}
```

`SectorSize` is a hint for raw files and `OpenSource` inputs; a container's
declared geometry takes precedence. `Resolver` opens side files such as split
VMDK extents.

---

## Error contract

Match with `errors.Is`, never by message:

```go
forensic.ErrOutOfRange
forensic.ErrUnexpectedEOF
forensic.ErrCorrupt
forensic.ErrIO
forensic.ErrUnsupported
forensic.ErrDecrypt
forensic.ErrCancelled
forensic.ErrInvalidArgument
```

An unsupported filesystem, an encrypted volume without a key, a damaged chunk
or a read past EOF returns one of these — never invented bytes.

---

## Examples

Runnable programs live in [`examples/`](examples/). Each takes its input path
on the command line.

| Example | What it demonstrates |
|---|---|
| [`examples/forensic`](examples/forensic) | open an image, list partitions, list directories, read a file |
| [`examples/verify`](examples/verify) | acquisition-hash verification |
| [`examples/scan`](examples/scan) | signature scan after partition-table damage |
| [`examples/carve`](examples/carve) | carving known file signatures from an image |
| [`examples/logical`](examples/logical) | L01 catalog listing and file read |
| [`examples/archive`](examples/archive) | ZIP/TAR/CPIO/ar/CAB/XAR/RAR entry listing and read |
| [`examples/wim`](examples/wim) | WIM image/entry listing and file read |
| [`examples/memory`](examples/memory) | memory-dump metadata, runs and a hex dump |
| [`examples/document`](examples/document) | OOXML attribution metadata |
| [`examples/pdf`](examples/pdf) | PDF metadata, pages and embedded-file export |
| [`examples/nested`](examples/nested) | recursive ZIP → E01 → TAR → memory/document tree |
| [`examples/leveldb`](examples/leveldb) | LevelDB manifest/table/WAL summary |
| [`examples/nbd`](examples/nbd) | read-only NBD export with mount instructions |

```bash
go run ./examples/forensic evidence.E01
go run ./examples/verify evidence.E01
go run ./examples/archive backup.zip
go run ./examples/nested  outer.zip
```

See [`examples/README.md`](examples/README.md) for details.

---

## Building the tools

```bash
go build -o ewftool  ./cmd
go build -o nbdserve ./cmd/nbdserve
go build ./cmd/...     # includes benchmarks and fixture generators
```

Release builds stamp the version with
`-ldflags "-X main.version=<tag>"`.

---

## Testing

The suite is hermetic: it needs only the Go toolchain and the committed
fixtures. It is expected to pass on Windows, Linux and macOS.

```bash
go test ./...
go test -race ./...
go vet ./...
gofmt -l .
```

Additional project checks:

```bash
scripts/check-hermetic.sh   # platform-dependence audit
scripts/build-matrix.sh     # 7-target CGO-free cross-build
```

CI runs the suite on Ubuntu, Windows and macOS; the release workflow runs vet,
the full test suite and the hermetic audit before it builds the seven target
pairs.

### Validation status

The reader has been exercised against real evidence and against an independent
reference fixture corpus. Real-evidence runs covered an E01 → VHDX → GPT →
FAT32/NTFS chain, PDF, 7-Zip, gzip and OOXML files, and a truncated PST/OST
that was refused explicitly. Case identifiers, paths, user names and exact
per-case measurements are deliberately not recorded in this repository.

Reference fixtures covered XZ, 7-Zip (Copy/LZMA/LZMA2/Deflate/Bzip2/PPMd/
Delta/BCJ/BCJ2), RAR 5, PDF (xref/object-stream/incremental/encrypted),
HFS+/HFSX including decmpfs, HFS classic, APFS (including decmpfs), SquashFS
(xz/lzo/lzma/lz4), WIM (stored/LZX), XAR, DMG, ZFS, HAMMER2, QNX6, LevelDB
tables, LUKS1/LUKS2, BitLocker (XTS/CBC/Elephant, recovery/password/startup
key) and PST. Formats with no sample in either corpus — notably Zstandard
streams and SquashFS zstd blocks — remain refused explicitly.

---

## Status and limitations

- The library is read-only by design.
- Some format branches are explicitly unsupported and say so: EWF-LZ chunks,
  solid/ESD WIM (LZMS), SquashFS zstd blocks, Zstandard streams, APFS LZBitmap
  compression, RAR 4 and RAR compressed members, IMSM RAID5, CLFS record
  payloads, MSDelta reconstruction, CoreStorage decryption, and BitLocker
  volumes whose protectors are TPM/PIN-only.
- Zstandard streams are recognised but refused; LZ4 legacy frames
  (`0x184C2102`) are refused while standard frames (`0x184D2204`) decode.
  XZ uses the LZMA2 filter only; Delta/BCJ filter chains and CRC64/SHA-256
  check types are refused explicitly.
- Thin LVM volume assembly is not exposed yet; thin-pool metadata is parsed.
- Formats without a reader are detected but return `ErrUnsupported` when
  opened.

## License

See [LICENSE](LICENSE).
