# Public forensic API

The public package is `forensic` at the module root
(`import forensic "github.com/laenix/ewfgo"`). It exposes the evidence data
plane: byte sources, images, partitions, filesystems, files and logical
evidence catalogs.

## Correctness contract

A read is either the exact evidence byte range or an explicit error. The API
never returns raw container bytes as media bytes, never zero-fills a failed
decode in strict mode, and never fabricates directory entries.

- Strict reads (`ReadAt`, `File.ReadAt`, `File.ReadAll`) fail on a damaged or
  undecodable range.
- Bounded reads return the readable prefix plus `io.EOF`; the tail is never
  synthesized.
- Unsupported or encrypted volumes return errors wrapping
  `ErrUnsupported`/`ErrDecrypt`.

## Sources and provenance

```go
type ByteSource = source.ByteSource

type ByteSource interface {
    SourceID() ID
    ImageID() ImageID
    Len() uint64
    SectorSize() uint32
    ReadAt(offset uint64, buf []byte) (int, error)
    ReadAtLossy(offset uint64, buf []byte) (int, error)
    Extents(offset, length uint64) ([]ParentRange, error)
    ExtentsInto(offset, length uint64, out []ParentRange) ([]ParentRange, error)
    MapToImage(offset, length uint64) ([]ImageRange, error)
    Stats() Stats
    IsEmpty() bool
}
```

`ReaderAt(src)` adapts a ByteSource to `io.ReaderAt` for standard-library
decoders. `Extents` translates a logical range into the immediate parent;
`MapToImage` walks the chain to the image container. `RangeData`, `RangeZero`, `RangeHole`,
`RangeError` and `RangeDerived` distinguish stored bytes, explicit zeros,
unallocated space, damaged regions and computed (RAID-rebuilt) ranges.

## Opening

```go
func Open(ctx context.Context, path string, opts Options) (*Image, error)
func OpenSource(ctx context.Context, src ByteSource, opts Options) (*Image, error)
func OpenLogical(ctx context.Context, path string, opts Options) (*LogicalImage, error)
```

`Open` recognises EWF/E01 disk images (including sibling E02/E03 segments),
raw disks, VHD, VHDX, VMDK (sparse and descriptor assemblies), QCOW2, VDI, DMG
and Android sparse images. WIM images use `OpenWIM`; L01 uses `OpenLogical`;
AFF4 uses `OpenAFF4`; CLFS logs use `OpenCLFS`; archive-shaped containers use
`OpenArchive`. Passing one of those files to `Open` returns an explicit error
naming the right opener. L01 logical evidence is opened with `OpenLogical`; passing
it to `Open` returns an explicit error naming `OpenLogical`.

```go
type Options struct {
    Limits     Limits
    SectorSize uint32
    Resolver   func(name string) (ByteSource, error)
}
```

`SectorSize` overrides the sector-size hint for raw files and `OpenSource`
inputs; a container's declared geometry takes precedence. `Resolver` opens a
side file such as a split VMDK extent by name; nil resolves names relative to
the image's directory. `OpenSource` does not take ownership of `src`; the
caller keeps it open.

## Image

```go
func (i *Image) Info() ImageInfo
func (i *Image) Format() string
func (i *Image) Path() string
func (i *Image) Size() uint64
func (i *Image) SectorSize() uint32
func (i *Image) Source() ByteSource
func (i *Image) Graph(ctx context.Context) (*source.SourceGraph, error)
func (i *Image) Partitions(ctx context.Context) ([]*Partition, error)
func (i *Image) PartitionTable(ctx context.Context) (string, error)
func (i *Image) OpenFilesystem(ctx context.Context) (FileSystem, error)
func (i *Image) Verify(ctx context.Context) (*HashVerification, error)
func (i *Image) Close() error
```

`Image.Source()` is the decoded guest medium for EWF, never the container file
bytes. `Graph` returns image, partition and filesystem nodes in a validated
provenance DAG. `OpenFilesystem` works only on an image without a partition
table. `Verify` streams the whole medium through the strict path and compares
MD5/SHA1 with the container's stored acquisition hashes.

## Partitions

```go
func (p *Partition) Index() int
func (p *Partition) TypeName() string
func (p *Partition) TableKind() string
func (p *Partition) Offset() uint64
func (p *Partition) Length() uint64
func (p *Partition) NodeID() ID
func (p *Partition) Source() ByteSource
func (p *Partition) Format() string
func (p *Partition) Encrypted() bool
func (p *Partition) WholeVolume() bool
func (p *Partition) OpenFilesystem(ctx context.Context) (FileSystem, error)
```

`TypeName` is the partition table's label (for example "Linux swap"); `Format`
is the signature-based detection (for example "ext4" or "unknown").
`WholeVolume` marks the single entry returned for an image with no partition
table but a recognised filesystem.

### io/fs adapter

`AsFS(ctx, fsys)` returns an `fs.FS`/`fs.ReadDirFS`/`fs.StatFS`/`fs.ReadFileFS`.
Names are relative to the volume root; `".."` components are rejected. The
root stat is synthesized as a directory ("" / "." / "/"), because most
filesystem formats do not store a root directory entry.

## Nested evidence

```go
func OpenNested(ctx context.Context, path string, opts NestedOptions) (*NestedTree, error)
func OpenNestedSource(ctx context.Context, src ByteSource, opts NestedOptions) (*NestedTree, error)

type NestedOptions struct {
    Options      Options
    MaxDepth     int
    MaxNodes     int
    MaxEntries   uint64
    InspectFiles bool
    Resolver     func(name string) (ByteSource, error)
}

type NestedTree struct { Root *NestedNode; Nodes int; Truncated bool }
func (t *NestedTree) Close() error

type NestedNode struct {
    Name, Path, Kind, Detail string
    Size                     uint64
    Source                   ByteSource
    Err                      string
    Children                 []*NestedNode
}
```

`OpenNested` recursively identifies containers inside containers: a ZIP entry
can be an E01, the E01 can contain partitions/filesystems, a file in a
filesystem can be a TAR, and a TAR entry can be a memory dump or an OOXML
document. `NestedNode.Source` is present for byte-addressable nodes; use
`File.Source`/`Archive.OpenSource` for programmatic access to nested file
bytes.

Per-node failures are recorded in `NestedNode.Err`; the walk continues.
Limits mark `NestedTree.Truncated`. Split VMDK descriptors need
`NestedOptions.Resolver`. SQLCipher/Realm/MMKV are not auto-unlocked in a tree.

## Assembled volumes

```go
func (i *Image) Volumes(ctx context.Context) ([]*Volume, error)

func (v *Volume) Name() string
func (v *Volume) Kind() string        // "mdraid RAID5", "LVM2 logical volume", ...
func (v *Volume) Format() string      // detected filesystem label
func (v *Volume) Source() ByteSource  // nil when unreadable
func (v *Volume) Readable() bool
func (v *Volume) Problem() string     // why members are missing
func (v *Volume) Length() uint64
func (v *Volume) Encrypted() bool
func (v *Volume) Encryption(ctx context.Context) (*EncryptionInfo, error)
func (v *Volume) Members() []VolumeMember
func (v *Volume) OpenFilesystem(ctx context.Context) (FileSystem, error)
```

`Volumes` assembles Linux mdraid arrays (RAID0/10/4/5/6, including parity
rebuild for missing members when possible) and LVM logical volumes from the
image's partitions. Incomplete arrays or logical volumes are still reported,
with `Readable` false and a `Problem` naming the missing member; they are never
silently omitted or served with zero-filled members. LVM thin-pool metadata is
parsed, but thin-volume assembly is not exposed yet and reports an explicit
`Problem`.

## Encryption

```go
type BitLockerCredentials struct {
    RecoveryPassword string // 48 digits, dashes/whitespace accepted
    Password         string // user password
    StartupKey       []byte // 256-bit external key
}

func (p *Partition) UnlockBitLocker(ctx context.Context, creds BitLockerCredentials) (*BitLockerVolume, error)
func (i *Image) UnlockBitLocker(ctx context.Context, creds BitLockerCredentials) (*BitLockerVolume, error)
func OpenBitLockerSource(ctx context.Context, src ByteSource, creds BitLockerCredentials) (*BitLockerVolume, error)

func (v *BitLockerVolume) Info() BitLockerUnlockInfo
func (v *BitLockerVolume) Source() ByteSource // decrypted plaintext
```

BitLocker unlock follows the on-disk chain: recovery/password/startup key into
the stretched AES-CCM key, the protector's wrapped key into the VMK, the FVEK,
then AES-XTS or AES-CBC/Elephant sector decryption. The VMK and FVEK are never
returned by the public API. A wrong key returns an error wrapping `ErrDecrypt`;
TPM/PIN-only protectors and unsupported methods are refused explicitly.

```go
func (p *Partition) UnlockLUKS(ctx context.Context, passphrase string) (*LUKSVolume, error)
func (i *Image) UnlockLUKS(ctx context.Context, passphrase string) (*LUKSVolume, error)
func OpenLUKSSource(ctx context.Context, src ByteSource, passphrase string) (*LUKSVolume, error)
func (v *LUKSVolume) Info() LUKSUnlockInfo
func (v *LUKSVolume) Source() ByteSource
```

LUKS1/LUKS2 unlock tries PBKDF2 and Argon2i/id key slots, verifies the
anti-forensic merge and the volume digest, then decrypts AES-XTS,
AES-CBC-ESSIV-SHA256 or CBC-plain64 segments. The master key is never exposed.
A wrong passphrase wraps `ErrDecrypt`; detached headers, non-AES ciphers,
unsupported KDF/hash/IV modes and malformed segment layouts are refused.
CoreStorage exposes metadata only and refuses decryption.

## Filesystems

```go
type FileSystem interface {
    Type() string
    Info() FSInfo
    ListDir(ctx context.Context, dir string) ([]Entry, error)
    Stat(ctx context.Context, path string) (*Entry, error)
    Open(ctx context.Context, path string) (*File, error)
    Walk(ctx context.Context, root string, fn WalkFunc) error
    Close() error
}
```

Paths are `/`-separated; a leading `\` is accepted and normalized. Returned
`Entry.Path` is absolute. `Walk` is depth-first and does not follow symbolic
links; return `ErrSkipDir` from the callback to skip a directory's children.

Routing by detected format:

| Detected | Reader |
|---|---|
| NTFS, exFAT, FAT12/16/32, ext2/3/4, XFS, Btrfs, APFS | legacy sector handlers via the byte-source sector adapter |
| HFS+/HFSX | `hfsplus` |
| F2FS | `f2fs` |
| SquashFS | `squashfs` |
| ISO 9660 | `iso9660` |
| UDF | `udf` |
| CramFS | `cramfs` |
| EROFS | `erofs` |
| JFS | `jfs` |
| ReiserFS | `reiserfs` |
| VMFS5/VMFS6 | `vmfs` |
| Minix v1/v2/v3 | `minix` |
| System V / Xenix / Coherent | `sysv` |
| UFS1/UFS2 | `ufs` |
| HFS classic | `hfs` |
| HPFS | `hpfs` |
| GFS2 | `gfs2` |
| NILFS2 | `nilfs2` |
| OCFS2 | `ocfs2` |
| UBIFS | `ubifs` |
| YAFFS2 | `yaffs` |
| JFFS2 | `jffs2` |
| HAMMER2 | `hammer2` |
| ZFS | `zfs` |
| QNX6 (QNX6/MMI, either byte order) | `qnx6` |
| BeFS | `befs` |

Encrypted volumes (BitLocker, LUKS, CoreStorage) and formats without a reader
return explicit errors.

### io/fs adapter

`AsFS(ctx, fsys)` returns an `fs.FS`/`fs.ReadDirFS`/`fs.StatFS`/`fs.ReadFileFS`.
Names are relative to the volume root; `".."` components are rejected. The
root stat is synthesized as a directory ("" / "." / "/"), because most
filesystem formats do not store a root directory entry.

## Files

`File.Source()` returns the backing ByteSource for source-backed readers;
`File.OpenSource()` materializes a legacy stream-only handle when necessary.
`File` implements `io.Reader`, `io.ReaderAt` and `io.Seeker`, and is safe for
concurrent `ReadAt` calls. `ReadAll` respects `Limits.MaxFileBytes` and, when
the limit is unset, refuses files above 1 GiB rather than making an unbounded
allocation; raise the limit explicitly to read larger files in one call. All
read methods remain available for large files.

```go
type File struct{ /* ... */ }

func (f *File) Entry() Entry
func (f *File) Size() uint64
func (f *File) ReadAt(p []byte, off int64) (int, error)
func (f *File) ReadAll() ([]byte, error)
func (f *File) Close() error
```

## Archives

```go
func OpenArchive(ctx context.Context, path string, opts Options) (*Archive, error)
func OpenArchiveSource(ctx context.Context, src ByteSource, opts Options) (*Archive, error)

type Archive struct{ /* ... */ }
func (a *Archive) Format() string
func (a *Archive) Entries(ctx context.Context) ([]ArchiveEntry, error)
func (a *Archive) Open(ctx context.Context, path string) (*File, error)
func (a *Archive) OpenSource(ctx context.Context, path string) (ByteSource, error)
func (a *Archive) Close() error
```

Supported formats: ZIP/Zip64, TAR, CPIO (newc/crc/odc/binary), ar, CAB
(stored/MSZIP), XAR (stored/zlib/bzip2/xz/lzma), 7-Zip (Copy/LZMA/LZMA2/
Deflate/Bzip2/PPMd/Delta/BCJ/BCJ2), RAR 5 (stored members; compressed, encrypted and split members are
listed but refused on read; RAR 4 is refused at open) and Android/MIUI backup
(the inner tar).
`ArchiveEntry.Path` is relative to the archive root. Names are sanitized at
open time: absolute paths, drive prefixes and `..` components are rejected.
Nested archives are opened explicitly by opening an entry as a new archive
source.

## Delta patches

```go
func OpenDelta(ctx context.Context, path string, opts Options) (*DeltaPatch, error)
func OpenDeltaSource(ctx context.Context, src ByteSource, opts Options) (*DeltaPatch, error)

func (d *DeltaPatch) Info() DeltaInfo
func (d *DeltaPatch) PrefixCRCMatches(ctx context.Context) (bool, error)
```

Identifies PA19/PA30/PA31 Microsoft Delta patches and verifies the optional
prefix CRC. Reconstructing the target is not implemented (it requires the base
file and a delta applier) and is never attempted.

## Compressed streams

```go
func OpenCompressed(ctx context.Context, path string, opts Options) (*DecodedStream, error)
func OpenCompressedSource(ctx context.Context, src ByteSource, opts Options) (*DecodedStream, error)

type DecodedStream struct {
    *File
    // Format() returns "gzip", "bzip2", "lz4" or "xz".
}
```

The decoder verifies the stream checksum and enforces `Limits.MaxFileBytes`
(default 512 MiB) before exposing the decoded bytes. LZ4 uses the standard
frame format (`0x184D2204`) with stored or compressed blocks and independent or
linked block histories; frame/block/content checksums are verified. Legacy LZ4
frames (`0x184C2102`) and frames with a dictionary ID are refused. XZ supports
LZMA2 blocks, concatenated streams and stream padding with header/block/index/
footer CRC verification; non-LZMA2 filters and CRC64/SHA-256 checks are
refused. Zstandard streams are recognised and refused explicitly.

## Windows LDM dynamic disks

```go
func OpenLDM(ctx context.Context, path string, opts Options) (*LDM, error)
func OpenLDMSource(ctx context.Context, src ByteSource, opts Options) (*LDM, error)

func (l *LDM) Info() LDMInfo
func (l *LDM) Disks(ctx context.Context) ([]LDMDisk, error)
func (l *LDM) Volumes(ctx context.Context) ([]LDMVolume, error)
func (l *LDM) OpenVolume(ctx context.Context, volumeID uint64) (ByteSource, error)
func (l *LDM) Assemble(ctx context.Context, volumeID uint64, members []LDMMember) (ByteSource, error)
```

The database is replicated on every dynamic disk. `OpenVolume` reads a
concatenated volume whose extents are on the opened disk; `Assemble` combines
member disks for spanned/striped/mirrored/RAID-5 volumes. Missing members are
explicit errors; RAID-5 rebuilds at most one missing column.

## Intel IMSM arrays

```go
func OpenIMSM(ctx context.Context, path string, opts Options) (*IMSMContainer, error)
func OpenIMSMSource(ctx context.Context, src ByteSource, opts Options) (*IMSMContainer, error)

func (c *IMSMContainer) Info() IMSMInfo
func (c *IMSMContainer) Disks(ctx context.Context) ([]IMSMDiskInfo, error)
func (c *IMSMContainer) Volumes(ctx context.Context) ([]IMSMVolumeInfo, error)
func (c *IMSMContainer) Assemble(ctx context.Context, volumeIndex int, members []IMSMMember) (ByteSource, error)
```

IMSM metadata is replicated on each member disk. `Assemble` accepts the member
images with their disk-table indexes and builds RAID0/1/10 sources. RAID5 is
recognised but refused with `ErrUnsupported` (parity rotation/rebuild is not
implemented); missing members are never zero-filled.

## Signature scanning

```go
func Scan(src ByteSource, options ScanOptions) (*ScanReport, error)
func (i *Image) Scan(ctx context.Context, options ScanOptions) (*ScanReport, error)
func (p *Partition) Scan(...)
func (v *Volume) Scan(...)
```

Candidates carry offset, signature offset, format id/label, declared volume
length with its size basis, and a status (`ScanVerified`, `ScanUnverified`,
`ScanRejected`) plus the check that produced it. `InsideOf` marks mirrors,
backup boot sectors and nested volumes so only top-level volumes start a
recovered layout.

## Android super images

```go
func OpenSuper(ctx context.Context, path string, opts Options) (*SuperImage, error)
func OpenSuperSource(ctx context.Context, src ByteSource, opts Options) (*SuperImage, error)

func (s *SuperImage) Info() SuperInfo
func (s *SuperImage) Partitions(ctx context.Context) ([]SuperPartition, error)
func (s *SuperImage) OpenPartition(ctx context.Context, name string) (ByteSource, error)
```

Geometry and metadata slots are SHA-256 verified (primary and backup geometry),
and each logical partition is assembled from linear and zero extents as a
`ByteSource`. To read a filesystem inside a super partition, wrap that source
with `OpenSource` and use the normal `Partitions`/`OpenFilesystem` flow.

## SQLCipher and Realm databases

```go
func OpenSQLCipher(ctx context.Context, path, passphrase string, opts Options) (*SQLCipherDatabase, error)
func OpenSQLCipherSource(ctx context.Context, src ByteSource, passphrase string, opts Options) (*SQLCipherDatabase, error)
func (d *SQLCipherDatabase) Info() SQLCipherInfo
func (d *SQLCipherDatabase) Source() ByteSource

func OpenRealm(ctx context.Context, path string, opts Options) (*RealmDatabase, error)
func OpenRealmSource(ctx context.Context, src ByteSource, opts Options) (*RealmDatabase, error)
func (d *RealmDatabase) Info() RealmInfo
func (d *RealmDatabase) Tables(ctx context.Context) ([]RealmTable, error)
func (d *RealmDatabase) Table(ctx context.Context, name string) (*RealmTable, error)
```

SQLCipher profiles 4/3/2/1 are tried in order; a wrong passphrase returns
`ErrWrongPassphrase` (also `ErrDecrypt`). Every page is HMAC-verified before
AES-CBC decryption; a failed page is `ErrCorrupt`, never plaintext zeros.
Realm exposes tables, columns, rows and typed values; unsupported storage kinds
keep metadata and are refused explicitly rather than fabricated.

## LevelDB stores

```go
func OpenLevelDB(dir string, opts Options) (*LevelDB, error)
func (s *LevelDB) Info() LevelDBInfo
func (s *LevelDB) Tables(ctx context.Context) ([]LevelDBTable, error)
func (s *LevelDB) Logs(ctx context.Context) ([]LevelDBLog, error)
func (s *LevelDB) Warnings(ctx context.Context) ([]string, error)
func (s *LevelDB) Close() error
```

`OpenLevelDB` reads a LevelDB store directory: `CURRENT`, the manifest it
names, every `.ldb`/`.sst` table and every `.log` WAL. A file named like a
table is parsed only when its footer carries the table magic; otherwise it is
reported in `Warnings` and never turned into entries. Table summaries expose
block/entry/tombstone counts and rendered first/last keys (non-printable keys
as hex), manifest summaries expose the live set and sequence numbers, and WAL
summaries expose decoded batches. CRC failures and truncated records are
explicit. RocksDB table framing and unsupported compression types are refused.

## Office documents and certificate stores

```go
func OpenDocument(ctx context.Context, path string, opts Options) (*Document, error)
func OpenDocumentSource(ctx context.Context, src ByteSource, opts Options) (*Document, error)
func (d *Document) Info() DocumentInfo
func (d *Document) ExternalRelationships(ctx context.Context) ([]DocumentRelationship, error)
func (d *Document) Embedded(ctx context.Context) ([]DocumentObject, error)

func OpenOfficeOwner(ctx context.Context, path string, opts Options) (*OfficeOwner, error)
func OpenOfficeOwnerSource(ctx context.Context, src ByteSource, opts Options) (*OfficeOwner, error)
func (o *OfficeOwner) Owner() (string, bool)
func (o *OfficeOwner) Layout() string
func (o *OfficeOwner) SlotsAgree() bool

func OpenCertificateStore(ctx context.Context, path string, opts Options) (*CertificateStore, error)
func OpenCertificateStoreSource(ctx context.Context, src ByteSource, opts Options) (*CertificateStore, error)
func (s *CertificateStore) Certificates(ctx context.Context) ([]CertificateInfo, error)
func (s *CertificateStore) OpenCertificate(ctx context.Context, index int) (ByteSource, error)
```

OOXML exposes docProps core/app/custom facts, workbook sheets and defined
names, slide counts, external relationships, embedded objects, macro parts and
signatures. Relationship/template targets are reported verbatim and never
resolved. Certificate stores expose DER metadata, hashes and source-backed
blobs; X.509 subject/issuer parsing is not performed.

## Outlook PST/OST stores

```go
func OpenPST(ctx context.Context, path string, opts Options) (*PSTFile, error)
func OpenPSTSource(ctx context.Context, src ByteSource, opts Options) (*PSTFile, error)
func (p *PSTFile) Info() PSTInfo
func (p *PSTFile) Folders(ctx context.Context) ([]PSTFolder, error)
func (p *PSTFile) Messages(ctx context.Context) ([]PSTMessage, error)
func (p *PSTFile) Message(ctx context.Context, nid uint64) (*PSTMessage, error)
func (p *PSTFile) Close() error
```

The reader handles ANSI 14/15 and Unicode 512/4 KiB stores, NBT/BBT trees,
AMap/PMap allocation, XBLOCK streams, heaps, BTH tables, property contexts,
recipients/attachments/embedded messages, search folders and deleted-item
recovery. Compressible and no-encryption stores are decoded; strong or
password-based encryption is refused (`ErrDecrypt`), never returned as
ciphertext. Bodies are reported absent when not stored, and attachment hashes
are computed only from decoded bytes.

## PDF documents

```go
func OpenPDF(ctx context.Context, path string, opts Options) (*PDFDocument, error)
func OpenPDFWithPassword(ctx context.Context, path, password string, opts Options) (*PDFDocument, error)
func OpenPDFSource(ctx context.Context, src ByteSource, opts Options) (*PDFDocument, error)
func OpenPDFSourceWithPassword(ctx context.Context, src ByteSource, password string, opts Options) (*PDFDocument, error)

func (d *PDFDocument) Info() PDFInfo
func (d *PDFDocument) Attachments(ctx context.Context) ([]PDFAttachment, error)
func (d *PDFDocument) OpenAttachment(ctx context.Context, name string) (ByteSource, error)
func (d *PDFDocument) Close() error
```

The reader handles classic xref tables, xref streams, incremental updates and
object streams, and decodes Flate/LZW/ASCIIHex/ASCII85/RunLength filters with
predictors. `PDFInfo` reports the version, metadata dictionary, page counts,
outlines, actions, AcroForm fields, JavaScript presence, embedded files,
encryption facts and repair notes. Standard security handler revisions 2–6 are
decrypted when a password is accepted; without one, strings/streams stay opaque
and attachment reads are refused, never served as ciphertext. Image filters
(DCT/JPX/JBIG2/CCITT), `/Crypt` and unknown handlers are refused explicitly.

## CLFS logs

```go
func OpenCLFS(ctx context.Context, path string, opts Options) (*CLFS, error)
func OpenCLFSSource(ctx context.Context, src ByteSource, opts Options) (*CLFS, error)

func (c *CLFS) Info() CLFSInfo
func (c *CLFS) ClientNames(ctx context.Context) ([]string, error)
func (c *CLFS) ContainerNames(ctx context.Context) ([]string, error)
func (c *CLFS) OpenStream(ctx context.Context, name string) (ByteSource, error)
func (c *CLFS) OpenRecord(ctx context.Context, lsn uint64) (ByteSource, error)
```

Base logs (`.blf`) and containers (`*.regtrans-ms`) are parsed for control/base
records, metadata blocks, symbols, client and container contexts, and physical
LSNs. Record payloads are not reconstructed; those calls return
`ErrUnsupported`.

## Memory dumps

```go
func OpenMemory(ctx context.Context, path string, opts Options) (*MemoryImage, error)
func OpenMemorySource(ctx context.Context, src ByteSource, opts Options) (*MemoryImage, error)

func (m *MemoryImage) Kind() string
func (m *MemoryImage) Info() MemoryInfo
func (m *MemoryImage) Runs() []MemoryRun
func (m *MemoryImage) ReadAt(ctx context.Context, addr uint64, buf []byte) (int, error)
```

LiME ranges and full/kernel Windows dump runs are address-mapped; minidumps use
their virtual-memory streams. Hibernation files expose metadata only (no
substantiated run layout). A request crossing a gap is `ErrOutOfRange`; missing
runs are never zero-filled. Triage/bitmap dumps report that no physical layout
is available.

## Carving

```go
func Carve(src ByteSource, start, length uint64, options CarveOptions) (*CarveReport, error)
func (i *Image) Carve(ctx context.Context, start, length uint64, options CarveOptions) (*CarveReport, error)
func (p *Partition) Carve(...)
func (v *Volume) Carve(...)
```

`CarveReport.Objects` carries validated objects with absolute offsets, lengths,
termination status and format; `Unreadable` counts bytes the source could not
deliver. A header hit that does not walk to a valid structure is counted in
`Rejected`, never reported as an object.

## AFF4 evidence containers

```go
func OpenAFF4(ctx context.Context, path string, opts Options) (*AFF4Evidence, error)
func OpenAFF4Source(ctx context.Context, src ByteSource, opts Options) (*AFF4Evidence, error)

func (a *AFF4Evidence) Info() AFF4Info
func (a *AFF4Evidence) Streams(ctx context.Context) ([]AFF4StreamInfo, error)
func (a *AFF4Evidence) ImageSource(ctx context.Context) (ByteSource, error)
func (a *AFF4Evidence) OpenStream(ctx context.Context, uri string) (ByteSource, error)
```

AFF4 declares streams in Turtle/YAML; image and map streams are exposed as
`ByteSource` with chunk-level provenance. Snappy/LZ4 chunks and AFF4-L
FileImage streams are enumerated and refused explicitly.

## Free-space maps

Filesystems that can read their allocation metadata implement
`FreeSpaceProvider`:

```go
if provider, ok := fsys.(forensic.FreeSpaceProvider); ok {
	space, err := provider.FreeSpace(ctx)
	for _, run := range space.Runs {
		fmt.Println(run.Offset, run.Length)
	}
}
```

`FreeSpaceMap` carries sorted, non-overlapping runs at volume-relative
offsets, the covered range, the allocation-area start, the on-disk basis and
caveat notes. JFS, ReiserFS, System V, UFS and HPFS implement it today; other filesystems
return `ErrUnsupported`.

## WIM images

```go
func OpenWIM(ctx context.Context, path string, opts Options) (*WIM, error)
func OpenWIMSource(ctx context.Context, src ByteSource, opts Options) (*WIM, error)

func (w *WIM) Info() WIMInfo
func (w *WIM) Images(ctx context.Context) ([]WIMImage, error)
func (w *WIM) Entries(ctx context.Context, imageIndex uint32) ([]WIMEntry, error)
func (w *WIM) Open(ctx context.Context, imageIndex uint32, path string) (*File, error)
func (w *WIM) OpenStream(ctx context.Context, imageIndex uint32, path, streamName string) (*File, error)
```

XPRESS Huffman and LZX resources are decoded; solid/ESD (LZMS) and split WIMs
are refused at open with an explicit error naming the limitation.

## OLE documents and MMKV stores

```go
func OpenOLE(ctx context.Context, path string, opts Options) (*OLEFile, error)
func OpenOLESource(ctx context.Context, src ByteSource, opts Options) (*OLEFile, error)

func (o *OLEFile) Entries(ctx context.Context) ([]OLEEntry, error)
func (o *OLEFile) ListStorage(ctx context.Context, path string) ([]OLEEntry, error)
func (o *OLEFile) Open(ctx context.Context, path string) (*File, error)
```

OLE2/CFB paths are absolute and start at the root storage. The directory tree
is walked as a red-black sibling tree; cycles and out-of-range links are errors.

```go
func OpenMMKV(ctx context.Context, path string, opts Options) (*MMKVStore, error)
func OpenMMKVSource(ctx context.Context, src ByteSource, opts Options) (*MMKVStore, error)
func (m *MMKVStore) Keys(ctx context.Context) ([]MMKVKey, error)
func (m *MMKVStore) Lookup(ctx context.Context, key string) (*MMKVKey, bool, error)
func (m *MMKVStore) Summary() MMKVSummary
func (m *MMKVStore) Meta() *MMKVMeta
```

MMKV is append-only: `Keys` reports each key's final replayed state (live or
deleted), set/delete counts, value length, SHA-256 and a bounded preview.

## Logical evidence

`LogicalImage` exposes an L01 catalog:

```go
func (l *LogicalImage) Info() ImageInfo
func (l *LogicalImage) Entries(ctx context.Context) ([]LogicalEntry, error)
func (l *LogicalImage) Open(ctx context.Context, path string) (*File, error)
func (l *LogicalImage) ReadAt(offset uint64, buf []byte) (int, error)
func (l *LogicalImage) Close() error
```

Entry metadata not recorded by the catalog stays zero (`HasSize` false, zero
times, empty hashes); nothing is synthesized.

## Errors

All failures wrap one of:

```go
ErrOutOfRange
ErrUnexpectedEOF
ErrCorrupt
ErrIO
ErrUnsupported
ErrDecrypt
ErrCancelled
ErrInvalidArgument
```

Match with `errors.Is`.
