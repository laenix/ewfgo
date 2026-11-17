# Examples

Runnable programs that use only the public `forensic` package. Every program
accepts its input path with a flag (`-image`, except where noted) and exits
non-zero with an explicit error when the data cannot be served.

Run them from the repository root:

```bash
go run ./examples/<name> -image <path>
```

| Program | Input | What it does |
|---|---|---|
| `forensic` | any disk image | Opens the image, lists partitions, selects one, lists a directory, optionally reads a file. |
| `verify` | E01/raw image | Streams the whole medium and compares computed MD5/SHA1 with stored acquisition hashes. |
| `scan` | any image | Signature-scans for partition tables, boot sectors and filesystem superblocks after table damage. |
| `carve` | any image | Carves known file signatures; `-out DIR` exports terminated top-level objects. |
| `logical` | L01/Lx01 | Lists the logical evidence catalog and optionally reads one acquired file. |
| `archive` | ZIP/TAR/CPIO/ar/CAB/XAR/RAR/7z/Android backup | Lists entries and optionally reads one. |
| `wim` | WIM | Lists images and entries, optionally reads a file from one image. |
| `memory` | LiME/hiberfil/dmp/minidump | Prints metadata and address runs; optionally hex-dumps bytes at an address. |
| `document` | docx/xlsx/pptx | Prints attribution metadata, external relationships and embedded objects. |
| `pdf` | PDF | Prints metadata, page/form facts and embedded files; optionally exports an attachment. |
| `nested` | any evidence file | Recursively prints containers inside containers (ZIP → E01 → filesystem → TAR → memory/document). |
| `nbd` | any disk image | Exports the image or one partition as a read-only NBD device and prints Linux mount/QEMU commands. |
| `leveldb` | LevelDB store directory | Summarizes CURRENT, the manifest live set, table key ranges/counts and WAL batches. |

## Typical commands

```bash
# Disk image walk-through
go run ./examples/forensic -image evidence.E01
go run ./examples/forensic -image evidence.E01 -partition 1 -dir /etc -read /etc/hosts

# Integrity and recovery
go run ./examples/verify -image evidence.E01
go run ./examples/scan   -image evidence.E01 -limit 67108864
go run ./examples/carve  -image evidence.E01 -out ./carved

# Logical evidence and archives
go run ./examples/logical -image evidence.L01 -read /CASE/big.txt
go run ./examples/archive -image backup.zip -read dir/report.txt

# Windows and memory artefacts
go run ./examples/wim      -image install.wim -image-index 1
go run ./examples/memory   -image memory.lime -addr 0x1000 -length 256
go run ./examples/document -image report.docx

# Recursive nesting
go run ./examples/nested -image outer.zip
go run ./examples/nested -image outer.zip -depth 6 -nodes 5000 -files=false
```

## Notes

- Examples never fabricate data: a failed read or unsupported format is printed
  as an error.
- `carve -out` writes only complete (`Terminated`) top-level objects and uses
  offset-based file names; verify exported files against your case notes.
- Read [`../README.md`](../README.md) for the full API and format list, or
  [`../README.zh-CN.md`](../README.zh-CN.md) for Chinese documentation.
- On Windows Git Bash, paths beginning with `/` are rewritten by MSYS. Prefix
  the command with `MSYS_NO_PATHCONV=1`, for example
  `MSYS_NO_PATHCONV=1 go run ./examples/forensic -image evidence.E01 -read /etc/hosts`.
