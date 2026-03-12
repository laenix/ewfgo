# EWF 工具测试结果

## 测试时间
2026-03-12 (更新)

## 2026-03-12 修复内容

### 1. FAT32 根目录 LBA 计算 Bug
- **问题**: `sectorsPerFAT < 1000` 条件太严格，导致使用错误的 fallback 计算
- **修复**: 将阈值从 1000 改为 100
- **结果**: pc-disk.E01 分区2 现在正确显示 EFI 目录 (与 ewflib 完全匹配)

### 2. XFS 检测 Bug - 大端序解析
- **问题**: XFS 使用大端序 (big-endian)，但代码使用小端序解析
- **修复**: 
  - 修改 DetectFileSystem() 使用大端序解析 XFS 超级块字段
  - 添加 fallback: 如果 blocksize 有效就返回 XFS
- **结果**: server.E01, 服务器检材01-04 等文件的 XFS 现在能正确检测

### 3. XFS 根 inode Fallback
- **问题**: 部分 XFS 镜像的根 inode 字段为 0
- **修复**: 添加 inode 128 作为 fallback (标准 XFS 根目录)
- **结果**: 服务器检材01 等文件可以列出目录

### 4. XFS inode 读取调试 (未完成)
- **问题**: server.E01 分区1 的 inode 读取返回垃圾数据
- **分析**: 
  - 使用 xfs_db 从导出的原始分区镜像可以正确读取 inode 64
  - 但 EWF 读取器返回的数据不正确
  - 可能是 chunk 表解析问题
- **状态**: 需要进一步调试

---

## 测试结果概览

| # | 文件名 | 分区 | 文件系统 | 目录列表 | 状态 |
|---|--------|------|----------|----------|------|
| 1 | pc-disk.E01 | 1 (NTFS) | NTFS | 26 | ✅ |
| 2 | pc-disk.E01 | 2 (FAT32) | FAT32 | 1 (EFI) | ✅ 已修复 |
| 3 | pc-disk.E01 | 4 (NTFS) | NTFS | 244 | ✅ |
| 4 | video.E01 | 1 (FAT32) | FAT32 | 2 | ✅ |
| 5 | 1.计算机检材.E01 | 1 (NTFS) | NTFS | 160 | ✅ |
| 6 | 1.计算机检材.E01 | 2 (NTFS) | NTFS | 244 | ✅ |
| 7 | 服务器检材01.E01 | 1 (XFS) | XFS | 5 | ⚠️ |
| 8 | server.E01 | 1 (XFS) | XFS | - | ❌ inode读取问题 |
| 9 | server.E01 | 3 (XFS) | XFS | - | ❌ inode读取问题 |

---

## 调试记录 - server.E01 XFS 问题

### 发现
1. 使用 `xfs_db` 从导出的原始分区镜像 (`/tmp/server_part1.img`) 可以正确读取 XFS inode
2. 但 EWF 读取器读取相同位置返回垃圾数据

### 验证步骤
```bash
# 导出分区
sudo dd if=/mnt/server/ewf1 of=/tmp/server_part1.img bs=512 skip=2048 count=614400

# 使用 xfs_db 读取 - 成功
sudo xfs_db -r /tmp/server_part1.img -c "inode 64" -c "p"
# 输出: core.magic = 0x494e, mode = 040555 (目录)

# 直接读取原始 EWF 镜像 - 失败
sudo dd if=/mnt/d/e01/server.E01 bs=512 skip=2175 count=1 | xxd
# 输出: 垃圾数据

# 通过 EWF 读取器 - 失败
./ewftool_test /mnt/d/e01/server.E01 ls 0
# inode 数据全部为零
```

### 根目录 extent 信息 (从 xfs_db 获取)
- inode 64: `u3.bmx[0] = [0,17,1,0]`
- 目录数据在 block 17
- block 17 相对 LBA = 17 * 8 = 136
- 绝对 LBA = 2048 + 136 = 2184
- 目录 magic = "XDB3" (0x58444233)

### 结论
- EWF 读取器在读取特定位置时返回垃圾数据
- 可能与 chunk 表解析或压缩相关
- 需要进一步调试 EWF 内部读取逻辑

---

## 代码修改记录

### fat32.go
- 修改 sectorsPerFAT 阈值: 1000 → 100 (第92行)

### open.go
- 修改 XFS 检测使用大端序解析 (第566-590行)

### xfs.go
- 添加 inode 128 作为根目录 fallback (第213行)
- 扩展 extent 偏移尝试范围 (第438行)
- 修复 inode 读取扇区计算 (第399-401行)
