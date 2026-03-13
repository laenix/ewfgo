# EWF 工具测试结果

## 测试时间
2026-03-13 13:25

---

## 测试对比总结

### 与 ewflib (ewfinfo) 和 Sleuth Kit 对比

| 检材 | ewfinfo | sleuthkit (fls) | ewfgo | 状态 |
|------|---------|-----------------|-------|------|
| 服务器检材04.E01 | ✅ | ⚠️ 无法识别XFS | ✅ 14条 | ✅ 可工作 |
| 服务器检材一.E01 | ✅ | ❌ 无法识别XFS | ❌ 根目录失败 | ❌ 失败 |

### 关键发现

1. **服务器检材一.E01 无法被标准工具读取**
   - sleuthkit 的 fls 无法识别文件系统
   - ewfgo 也不能读取根目录
   - ewfinfo 可以读取元数据（说明E01格式正确）

2. **可能原因**
   - XFS 超级块数据损坏或不标准
   - inode table 位置异常
   - 可能使用了非标准 XFS 参数

---

## 详细分析

### 服务器检材04.E01 - XFS (工作正常)
```
分区: Linux (0x83) 1GB + Linux LVM 39GB
文件系统检测: XFS
目录列表: vmlinuz*, initramfs*, System.map, config, symvers 等
总计: 14 条目
```

### 服务器检材一.E01 - XFS (无法读取)
```
分区: Linux (0x83) 1GB + Linux LVM 49GB  
文件系统检测: XFS (仅检测到magic)
目录列表: 错误 "XFS: could not find root directory"
sleuthkit: "Cannot determine file system type"
```

---

## 代码分析

### XFS 超级块解析问题
两者的超级块都有解析问题，使用 fallback 默认值:
- blocksize=4096 (检测到)
- agblocks=65536 (fallback)
- agcount=1 (fallback)
- inodeSize=512 (fallback)

### 根目录定位
- 尝试 inode 64, 128, 8 → 失败 (magic 无效)
- 回退到 brute force 遍历 inode 1-500
- 服务器检材04.E01: 在 inode 1 找到 5 条目
- 服务器检材一.E01: 未找到任何条目

### 数据偏移分析
- parseInlineDirectory 在 offset 0x80 查找
- 服务器检材04.E01 找到 vmlinuz, initramfs 等 boot 文件
- 服务器检材一.E01 数据中无匹配模式

---

## 已确认的问题

1. ❌ XFS 超级块字段解析错误 - 使用 fallback
2. ❌ 服务器检材一.E01 无法读取根目录
3. ⚠️ inode table 起始位置使用硬编码 fallback

---

## 待解决问题

### 高优先级
1. XFS 超级块正确解析 agblocks/agcount
2. 服务器检材一.E01 根目录读取

### 中优先级
3. XFS inode table 起始位置动态计算
4. 非标准 XFS 格式支持

---

## 测试命令

```bash
# 重建工具
cd /mnt/d/code/ewfgo/cmd && /snap/bin/go build -o /tmp/ewftool .

# 查看分区
/tmp/ewftool /mnt/d/e01/服务器检材04.E01 fs
/tmp/ewftool /mnt/d/e01/服务器检材一.E01 fs

# 列出目录
/tmp/ewftool /mnt/d/e01/服务器检材04.E01 ls 0 ""
/tmp/ewftool /mnt/d/e01/服务器检材一.E01 ls 0 ""

# 对比 sleuthkit
mmls -t dos /mnt/d/e01/服务器检材一.E01
fls -o 2048 /mnt/d/e01/服务器检材一.E01

# 对比 ewfinfo
ewfinfo /mnt/d/e01/服务器检材一.E01
```

---

## 参考工具

- `ewfinfo` - libewf 自带信息查看
- `mmls` - The Sleuth Kit 分区查看  
- `fls` - The Sleuth Kit 文件列表
- `xfs_db` - XFS 文件系统调试

