# ewfgo

**纯 Go、只读的取证数据引擎。**

[English](README.md) | [简体中文](README.zh-CN.md)

ewfgo 用来打开证据容器以及容器内的文件系统。它是单一、无 CGO 的 Go 模块，
覆盖 EWF/E01 镜像、原始磁盘、虚拟磁盘、分区表、卷管理器、文件系统、逻辑证据、
压缩/归档容器、内存转储和文件雕刻。

每一次读取要么返回证据的真实字节，要么返回明确错误。引擎不会把容器原始字节
当作磁盘数据、不会虚构目录项、也不会在解码失败时静默补零。

---

## 设计目标

- **纯 Go**：`CGO_ENABLED=0`，读取路径不依赖外部进程和平台特定 syscall。
  支持 Windows / Linux / macOS，amd64 / arm64，以及 Linux/riscv64。
- **证据优先**：严格读取失败即报错；不支持或加密的数据明确说明，不猜测。
- **内置溯源**：每个字节源都带 ID 和 extent 映射，可回溯到镜像容器。
- **统一 API**：磁盘镜像、逻辑证据、归档、数据库、内存转储和雕刻共用
  `ByteSource` 契约。

---

## 完整性规则

| 规则 | 行为 |
|---|---|
| 精确解码 | 损坏的 chunk / page / block / record 返回错误，绝不补零冒充数据。 |
| 不漏容器字节 | 扇区和文件读取只来自解码后的客体介质，绝不返回 EWF/QCOW2/VHD 容器字节。 |
| 不虚构目录项 | 无法解析的目录返回错误；名称不会被合成。 |
| 有界读取 | 读取越过 EOF 时返回可读前缀 + `io.EOF`，尾部不会补造。 |
| 明确不支持 | 已知但未实现的特性返回 `ErrUnsupported`，并在错误中说明具体特性。 |
| 只读 | 没有写入、修改或修复路径。 |

---

## 支持的格式

### 容器与证据文件

| 类别 | 格式 |
|---|---|
| 磁盘镜像 | EWF/E01（自动发现 E01/E02/...）、原始磁盘、VHD、VHDX、VMDK（稀疏、streamOptimized、split/flat 描述符）、QCOW2（v2/v3）、VDI、DMG、Android sparse |
| 逻辑证据 | EnCase L01/Lx01 v1（含 L02/L03 分段）、AFF4 |
| Windows 镜像 | WIM（XPRESS Huffman、LZX）、Android `super.img` 动态分区 |
| 归档 | ZIP/Zip64、TAR、CPIO（newc/crc/odc/binary）、ar、CAB（stored/MSZIP）、XAR（stored/zlib/bzip2/xz/lzma）、RAR 5（stored 成员）、7-Zip（Copy/LZMA/LZMA2/Deflate/Bzip2/PPMd/Delta/BCJ）、Android/MIUI backup |
| 文档 | OLE2/CFB、OOXML（docx/xlsx/pptx 及宏/模板变体）、PDF（xref/增量更新、对象流、元数据、动作、嵌入文件、Standard 安全处理器解密）、Office 所有者文件（`~$`）、序列化证书库 |
| 数据库 | SQLCipher 1–4、Realm、MMKV、LevelDB 存储（表、manifest、WAL） |
| 邮件库 | Outlook PST/OST（ANSI 14/15、Unicode 23/36；文件夹、邮件、收件人、附件、嵌入邮件、已删除项恢复、压缩 RTF） |
| 日志与补丁 | Windows CLFS（元数据）、MSDelta PA19/PA30/PA31 |
| 压缩流 | gzip、bzip2、LZ4（标准帧，独立/链接块）、XZ（LZMA2、串联流） |
| 内存 | LiME、Windows hiberfil、Windows 内核转储、用户态 minidump |

### 分区表与卷

- MBR（含 EBR 链）、GPT（主/备份、CRC 校验）、Apple Partition Map、BSD disklabel。
- Linux mdraid RAID0/10/4/5/6，含 P/Q 奇偶校验重建。
- LVM 线性与条带逻辑卷。
- Intel IMSM RAID0/1/10（RAID5 明确拒绝）。
- Windows LDM 动态磁盘：拼接、跨盘、条带、镜像、RAID-5。
- Apple CoreStorage 元数据。
- 分区表损坏时的文件系统签名扫描。

### 文件系统

| 可列目录、读文件 | 仅检测/元数据 |
|---|---|
| FAT12/16/32、exFAT、NTFS、ext2/3/4、XFS、Btrfs、APFS、ZFS | ReFS 及其他已识别但尚无读取器的格式 |
| HFS+/HFSX（含 decmpfs zlib/LZVN/LZFSE）、HFS classic、F2FS、SquashFS、ISO 9660、UDF | |
| CramFS、EROFS、JFS、ReiserFS、VMFS5/6、UFS1/UFS2 | |
| Minix v1/v2/v3、System V/Xenix/Coherent、HPFS、GFS2、NILFS2、OCFS2、UBIFS、YAFFS、BeFS、JFFS2、HAMMER2、QNX6 | |

BitLocker 可用 48 位恢复密码、用户密码或 256 位启动密钥解锁；卷的 AES-CCM
标签验证通过后，按 AES-XTS、AES-CBC 或 Elephant diffuser 解密扇区。LUKS1
与 LUKS2 可用口令解锁（PBKDF2 或 Argon2i/id key slot、anti-forensic merge、
AES-XTS 或 AES-CBC-ESSIV/plain64），只有卷 digest 验证通过后才接受密钥；
detached header 与非 AES 加密算法会明确拒绝。

### 内存与雕刻

- LiME、hiberfil、内核崩溃转储、minidump。
- BMP、GIF、TIFF、WEBP、EVTX、SQLite、Prefetch 雕刻，含 LZXPRESS。

---

## 安装

```bash
go get github.com/laenix/ewfgo
```

需要 Go 1.24 或更高版本。

---

## 快速开始

### 命令行

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

`nbdserve` 可以把整个镜像或单个分区导出为只读 NBD：

```bash
go build -o nbdserve ./cmd/nbdserve
./nbdserve -addr 127.0.0.1:10809 evidence.E01
```

### 库

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

## 使用指南

### 镜像与分区

`Open` 支持 EWF/E01（含多段）、原始磁盘和上文列出的虚拟磁盘容器。
`OpenSource` 用于包装已经解码好的 `ByteSource`，不会做容器探测。

```go
parts, err := img.Partitions(ctx)
p := parts[0]
fmt.Println(p.Offset(), p.Length(), p.Source().Len())
```

没有分区表但能识别文件系统的镜像会返回一个“整卷”条目：

```go
p.WholeVolume() // true，p.Source() 覆盖整个镜像
```

也可以直接打开：

```go
fsys, err := img.OpenFilesystem(ctx)
```

### 文件系统

```go
entries, err := fsys.ListDir(ctx, "/etc")
entry, err := fsys.Stat(ctx, "/etc/hosts")

file, err := fsys.Open(ctx, "/etc/hosts")
n, err := file.ReadAt(buf, 0) // io.ReaderAt
_, err = file.Seek(0, io.SeekStart)
data, err := file.ReadAll()   // 受 Limits.MaxFileBytes 限制

err = fsys.Walk(ctx, "/", func(e forensic.Entry) error {
	fmt.Println(e.Path)
	return nil
})
```

路径统一使用 `/`，调用方传入 `\` 也会被规范化。

### `io/fs` 适配器

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

适配器只读，并拒绝 `..` 路径穿越。

### 溯源

```go
graph, err := img.Graph(ctx) // 已验证的镜像/分区/文件系统 DAG
src := parts[0].Source()
ranges, err := src.MapToImage(0, 4096)
```

`SourceID`、`ImageID`、`Extents` 和 `MapToImage` 可以把解析器读到的任意字节
追溯到容器中的实际位置。

### 校验采集哈希

```go
res, err := img.Verify(ctx)
fmt.Printf("MD5=%v SHA1=%v bytes=%d\n",
	res.MD5Match, res.SHA1Match, res.BytesHashed)
```

### 组装卷

```go
volumes, err := img.Volumes(ctx)
for _, v := range volumes {
	fmt.Println(v.Name(), v.Kind(), v.Format(), v.Readable(), v.Problem())
	fsys, err := v.OpenFilesystem(ctx)
	_ = fsys
	_ = err
}
```

`Volumes` 会从镜像分区中组装 mdraid 和 LVM 卷。成员不全的卷会以
`Readable() == false` 和 `Problem()` 报告，不会用零填充成员。

独立的卷管理器接口：

```go
ldm, err := forensic.OpenLDM(ctx, "dynamic-disk.img", forensic.Options{})
imsm, err := forensic.OpenIMSM(ctx, "disk0.img", forensic.Options{})
super, err := forensic.OpenSuper(ctx, "super.img", forensic.Options{})
```

### 嵌套容器

`OpenNested` 会递归检查证据文件：ZIP 条目里可以是 E01，E01 里可以有分区和文件系统，
文件系统里的某个文件可以是 TAR，TAR 里的条目又可以是内存转储或文档。

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

每个节点带有 `Kind`、`Detail`、`Size`、`Source`（可字节访问时）以及用于显示的
`Path`。某个嵌套层解析失败只会记录在该节点的 `Err` 上，不会中止兄弟节点。
已有 `ByteSource` 时可使用 `OpenNestedSource`；对嵌套节点的 `Source` 可用
`OpenDocumentSource`、`OpenMemorySource`、`OpenWIMSource`、`OpenLogicalSource`、
`OpenAFF4Source` 等源版本继续做类型化解析。

限制是显式的：

```go
opts := forensic.DefaultNestedOptions()
opts.MaxDepth = 8
opts.MaxNodes = 5000
opts.MaxEntries = 2000
opts.InspectFiles = false // 只检查容器/分区/文件系统
```

可自动识别的嵌套层包括 E01、L01、WIM、AFF4、ZIP/TAR/CPIO/ar/CAB/XAR/RAR/7z、
Android backup、OLE/CFB、gzip/bzip2/LZ4/XZ、虚拟磁盘容器、分区表、文件系统、内存转储、
OOXML 文档和 PDF（含 PDF 嵌入文件）。SQLCipher/Realm/MMKV 不会在树中自动解锁，请用各自的 API 显式打开。
嵌套的 split VMDK 描述符需要 `NestedOptions.Resolver`。归档内的多段 E01
只把被打开的条目作为第 1 段；若需要后续分段，缺失数据会明确报错，不会补零。

### 逻辑证据（L01）

```go
logical, err := forensic.OpenLogical(ctx, "evidence.L01", forensic.Options{})
entries, err := logical.Entries(ctx)
file, err := logical.Open(ctx, "/CASE/big.txt")
```

L02/L03 分段会自动发现。

### 归档与 WIM

```go
archive, err := forensic.OpenArchive(ctx, "backup.zip", forensic.Options{})
entries, err := archive.Entries(ctx)
file, err := archive.Open(ctx, "dir/report.txt")

wim, err := forensic.OpenWIM(ctx, "install.wim", forensic.Options{})
images, err := wim.Images(ctx)
entries, err = wim.Entries(ctx, images[0].Index)
file, err = wim.Open(ctx, images[0].Index, "Windows/System32/drivers/etc/hosts")
```

归档条目名称会做安全校验：绝对路径、盘符和 `..` 组件在导出前就会被拒绝。

### AFF4

```go
aff4, err := forensic.OpenAFF4(ctx, "evidence.aff4", forensic.Options{})
streams, err := aff4.Streams(ctx)
src, err := aff4.ImageSource(ctx) // 逻辑镜像流，可直接当作 ByteSource
```

### 数据库与文档

```go
db, err := forensic.OpenSQLCipher(ctx, "browser.db", "passphrase", forensic.Options{})
src := db.Source() // 解密后的 SQLite 页，每页都重新校验 HMAC

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

SQLCipher 会按 4、3、2、1 的顺序尝试配置。错误口令返回
`ErrWrongPassphrase`（同时匹配 `ErrDecrypt`）；每页解密前都会重新校验 HMAC。
OOXML 的外部关系和模板路径按原样报告，绝不自动访问或解析。

### 内存转储

```go
mem, err := forensic.OpenMemory(ctx, "memory.lime", forensic.Options{})
info := mem.Info()
runs := mem.Runs()
n, err := mem.ReadAt(ctx, 0x1000, buf) // 物理地址或 minidump 虚拟地址
```

跨内存段空洞的读取会返回 `ErrOutOfRange`，不会补零。

### 雕刻与签名扫描

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

签名扫描用于分区表损坏或覆盖后的恢复；每个候选都必须通过自身元数据
（以及格式提供的校验和）确认。

### NBD 导出

```bash
go build -o nbdserve ./cmd/nbdserve
./nbdserve -addr 127.0.0.1:10809 -export evidence evidence.E01
```

```go
exp := nbd.NewExporter(img.Source())     // 整个镜像
exp = nbd.NewExporter(parts[0].Source()) // 单个分区
```

导出是只读的，且跨平台；Linux 可用 `nbd-client` 挂载为块设备。
平台说明、挂载/清理命令和 QEMU 验证方式见
[docs/nbd-mount.md](docs/nbd-mount.md)，可运行的 API 示例见
[examples/nbd](examples/nbd)。

---

## 选项与限制

```go
type Options struct {
	Limits     Limits
	SectorSize uint32
	Resolver   func(name string) (ByteSource, error)
}

type Limits struct {
	MaxEntries   uint64 // 目录/归档条目上限
	MaxDepth     int    // Walk 深度上限
	MaxFileBytes uint64 // ReadAll 上限（未设置时 1 GiB）
}
```

`SectorSize` 只对原始文件和 `OpenSource` 输入生效；容器声明的几何优先。
`Resolver` 用于打开 VMDK split 等旁路文件。

---

## 错误契约

用 `errors.Is` 判断，不要匹配错误字符串：

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

不支持的文件系统、无密钥的加密卷、损坏的 chunk 或越过 EOF 的读取都会返回这些
错误之一，绝不返回虚构字节。

---

## 示例程序

可运行示例位于 [`examples/`](examples/)，每个程序都从命令行接收输入路径。

| 示例 | 内容 |
|---|---|
| [`examples/forensic`](examples/forensic) | 打开镜像、列分区、列目录、读取文件 |
| [`examples/verify`](examples/verify) | 采集哈希校验 |
| [`examples/scan`](examples/scan) | 分区表损坏后的签名扫描 |
| [`examples/carve`](examples/carve) | 从镜像中雕刻已知文件签名 |
| [`examples/logical`](examples/logical) | L01 目录列举与文件读取 |
| [`examples/archive`](examples/archive) | ZIP/TAR/CPIO/ar/CAB/XAR/RAR 条目列举与读取 |
| [`examples/wim`](examples/wim) | WIM 镜像/条目列举与读取 |
| [`examples/memory`](examples/memory) | 内存转储元数据、内存段与十六进制输出 |
| [`examples/document`](examples/document) | OOXML 归属元数据 |
| [`examples/pdf`](examples/pdf) | PDF 元数据、页面与嵌入文件导出 |
| [`examples/nested`](examples/nested) | 递归 ZIP → E01 → TAR → 内存/文档树 |
| [`examples/nbd`](examples/nbd) | 只读 NBD 导出及挂载说明 |
| [`examples/leveldb`](examples/leveldb) | LevelDB manifest/表/WAL 摘要 |

```bash
go run ./examples/forensic evidence.E01
go run ./examples/verify evidence.E01
go run ./examples/archive backup.zip
go run ./examples/nested  outer.zip
```

更多说明见 [`examples/README.md`](examples/README.md)。

---

## 构建命令行工具

```bash
go build -o ewftool  ./cmd
go build -o nbdserve ./cmd/nbdserve
go build ./cmd/...     # 包含基准测试和夹具生成工具
```

发布构建可用 `-ldflags "-X main.version=<tag>"` 写入版本号。

---

## 测试

测试套件是封闭的（hermetic）：只需要 Go 工具链和仓库内夹具，预期在
Windows、Linux、macOS 上全部通过。

```bash
go test ./...
go test -race ./...
go vet ./...
gofmt -l .
```

额外检查：

```bash
scripts/check-hermetic.sh   # 平台依赖审计
scripts/build-matrix.sh     # 7 个目标的无 CGO 交叉构建
```

CI 在 Ubuntu、Windows、macOS 上运行测试；release 工作流在构建 7 个目标
之前会先运行 vet、完整测试套件和 hermetic 审计。

### 验证状态

读取器已在真实检材和独立的参考夹具语料上验证。真实检材覆盖
E01 → VHDX → GPT → FAT32/NTFS 链，以及 PDF、7-Zip、gzip、OOXML 文件和
一个被正确拒绝的截断 PST/OST。仓库中不记录案件编号、路径、用户名和逐检材
的精确测量值。

Rust 参考实现的独立夹具语料还覆盖了：XZ、7-Zip（Copy/LZMA/LZMA2/Deflate/
Bzip2/PPMd/Delta/BCJ/BCJ2）、RAR 5、PDF（xref/对象流/增量更新/加密）、
HFS+/HFSX（含 decmpfs）、HFS classic、APFS（含 decmpfs）、SquashFS
（xz/lzo/lzma/lz4）、WIM（stored/LZX）、XAR、DMG、ZFS、HAMMER2、QNX6、
LevelDB 表、LUKS1/LUKS2、BitLocker（XTS/CBC/Elephant，恢复密码/用户密码/
启动密钥）以及 PST。两套语料都没有样本的格式——尤其是 Zstandard 流和
SquashFS zstd 块——仍然明确拒绝。

---

## 状态与限制

- 库按设计只读。
- 以下分支会明确返回不支持：EWF-LZ、solid/ESD WIM（LZMS）、DMG 的
  SquashFS zstd 块、Zstandard 流、APFS LZBitmap 压缩、RAR 4 与 RAR 压缩成员、IMSM RAID5、
  CLFS 记录载荷、MSDelta 重建、CoreStorage 解密，以及仅提供 TPM/PIN
  保护器的 BitLocker 卷。
- Zstandard 流可以识别但会拒绝解码；LZ4 旧式帧（`0x184C2102`）拒绝，
  标准帧（`0x184D2204`）可解码。XZ 仅支持 LZMA2 过滤器；Delta/BCJ 过滤器链
  以及 CRC64/SHA-256 校验类型会明确拒绝。
- LVM thin 卷组装尚未暴露；thin-pool 元数据可以解析。
- 没有读取器的格式可以被检测，但打开时返回 `ErrUnsupported`。

## 许可证

见 [LICENSE](LICENSE)。
