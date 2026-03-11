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
    ├── mbr.go, gpt.go      # 分区表解析
    └── filesystem/
        ├── fs.go            # 文件系统接口定义
        ├── fat32.go         # ✅ FAT32实现
        ├── ntfs.go          # ⚠️ NTFS实现(待完善)
        ├── ext4.go          # ⚠️ ext4实现(待完善)
        └── ...其他文件系统
```

---

## 1. video.E01 - FAT32 ✅

### 分区信息
- 文件系统: FAT32
- 起始LBA: 63
- 大小: 58.04 GB

### FAT32 参数
- BytesPerSector: 512
- SectorsPerCluster: 64
- Reserved: 38
- NumFATs: 2
- SectorsPerFAT32: 14905
- RootCluster: 2
- TotalSectors: 121728961
- 计算得到: fatStart=101, dataAreaStart=29911, rootDirLBA=29911

### 根目录列表
```
Found 2 entries:
  [DIR ] VIDEO                                   0 bytes
  [DIR ] SYSTEM~1                                0 bytes
```

### 对比 ewflib
```
d/d 4:	video
d/d 3518469:	video/00
d/d 3519493:	video/00/20250416
d/d 1827846:	video/00/20250416/0000-0100
r/r 1828871:	video/00/20250416/0000-0100/004745-00000-T.TS
...
```

**结论**: FAT32 根目录工作正常，UTF-16LE中文文件名解码正确。子目录浏览待实现。

---

## 2. 1.计算机检材.E01 - NTFS ⚠️

### 分区信息
```
Partition 1: NTFS/HPFS | NTFS | LBA 2048 | 549.00 MB
Partition 2: NTFS/HPFS | NTFS | LBA 1126400 | 34.58 GB
Partition 3: NTFS/HPFS | NTFS | LBA 73646080 | 4.88 GB
```

### NTFS 解析状态
- MFT cluster: 46848
- MFT sector: 376832
- 错误: no entries found in MFT

**问题**: MFT 解析需要完善

### 对比 ewflib
(需要测试)

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

## 待实现功能

1. **NTFS 目录列表** - MFT 解析完善
2. **ext4 目录列表** - 针对不同 block size 调整
3. **子目录浏览** - 实现目录遍历
4. **GPT 分区解析** - 解析实际 GPT 分区表
5. **LVM 支持** - 解析 LVM PV 和 LV
