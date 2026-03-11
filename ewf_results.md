# EWF Parser 测试结果

## 测试日期
2026-03-11

## 代码结构
```
/mnt/d/code/ewfgo/
├── cmd/main.go              # CLI入口
├── open.go                  # 外层API（分区扫描等）
├── open_files.go            # 文件列表API（简化版）
└── internal/
    ├── ewf.go               # EWF核心解析
    ├── mbr.go, gpt.go       # 分区表解析
    └── filesystem/
        ├── fs.go            # 文件系统接口定义
        ├── fat32.go         # ✅ FAT32实现
        ├── ntfs.go          # ✅ NTFS实现(已修复)
        ├── ext4.go          # ⚠️ ext4实现(待完善)
        └── ...其他文件系统
```

---

## 1. video.E01 - FAT32 ✅

### 分区信息
- 文件系统: FAT32
- 起始LBA: 63
- 大小: 58.04 GB

### 目录浏览测试
```bash
# 根目录
$ ewftool video.E01 ls
Found 2 entries:
  [DIR ] VIDEO
  [DIR ] SYSTEM~1

# VIDEO 目录
$ ewftool video.E01 ls VIDEO
Found 3 entries:
  [DIR ] .
  [DIR ] ..
  [DIR ] 00

# VIDEO/00/20250416/0000-0~1 目录
$ ewftool video.E01 ls VIDEO/00/20250416/0000-0~1
Found 17 entries:
  [FILE] 004745~1.TS    8266924 bytes
  [FILE] 003530~2.TS    8961020 bytes
  [FILE] 003659~2.TS   10058940 bytes
  ...
```

**结论**: ✅ FAT32 子目录浏览完全工作，支持多级目录遍历，文件大小正确

---

## 2. 1.计算机检材.E01 - NTFS ✅

### 分区信息
```
Partition 1: NTFS/HPFS | NTFS | LBA 2048 | 549.00 MB
Partition 2: NTFS/HPFS | NTFS | LBA 1126400 | 34.58 GB
Partition 3: NTFS/HPFS | NTFS | LBA 73646080 | 4.88 GB
```

### NTFS 解析
- MFT cluster: 46848
- MFT sector: 376832
- 找到 12 个系统文件

### 根目录列表
```
Found 12 entries:
  [FILE] $MFT
  [FILE] $MFTMirr
  [FILE] $LogFile
  [FILE] $Volume
  [FILE] $AttrDef
  [FILE] $TXF_DATA
  [FILE] $Bitmap
  [FILE] $Boot
  [FILE] $BadClus
  [FILE] $Secure
  [FILE] $UpCase
  [FILE] $Extend
```

**结论**: ✅ NTFS MFT 解析工作，显示系统元数据文件

---

## 3. server.E01 - Linux LVM ⚠️

### 分区信息
```
Partition 1: Linux | ext4 | LBA 2048 | 300.00 MB
Partition 2: Linux Swap | Swap | LBA 616448 | 2.00 GB
Partition 3: Linux | ext4 | LBA 4810752 | 117.71 GB
```

### 状态
- 错误: ext4 superblock not found

**原因**: 实际上使用的是 LVM (LVM2_member)，不是直接的 ext4 文件系统

---

## 4. pc-disk.E01 - GPT ❌

### 分区信息
```
Partition 1: GPT Protective | GPT | LBA 1 | 2.00 TB
```

### 状态
- GPT 分区解析未实现

---

## 完成的功能

| 功能 | 状态 |
|------|------|
| FAT32 根目录列表 | ✅ |
| FAT32 子目录浏览 | ✅ (2026-03-11) |
| FAT32 文件大小 | ✅ |
| NTFS 系统文件 | ✅ |
| MBR 分区解析 | ✅ |
| GPT 分区解析 | ❌ |
| LVM 支持 | ❌ |
| NTFS 真实目录 | ❌ |

---

## 待实现功能

1. ✅ ~~FAT32 子目录浏览~~ - 已完成
2. **NTFS 真实目录列表** - 实现 $INDEX_ROOT 解析
3. **ext4 目录列表** - 针对不同 block size 调整
4. **GPT 分区解析** - 解析实际 GPT 分区表
5. **LVM 支持** - 解析 LVM PV 和 LV
