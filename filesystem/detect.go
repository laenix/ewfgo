package filesystem

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// DetectFileSystem 从Reader中检测文件系统类型
func DetectFileSystem(reader Reader) (FileSystemType, error) {
	// 读取第一个扇区（MBR或引导扇区）
	sector, err := reader.ReadSector(0)
	if err != nil {
		return FileSystemTypeUnknown, fmt.Errorf("读取引导扇区失败: %w", err)
	}

	// 检查是否为MBR分区表
	if len(sector) >= 512 && sector[510] == 0x55 && sector[511] == 0xAA {
		// 检查分区表
		partitionOffset := 446 // MBR分区表起始偏移
		for i := 0; i < 4; i++ {
			partitionEntry := sector[partitionOffset+i*16 : partitionOffset+(i+1)*16]
			partitionType := partitionEntry[4]

			// 检查分区是否活动
			if partitionEntry[0] == 0x80 || partitionEntry[0] == 0x00 {
				// 获取分区起始扇区
				startSector := binary.LittleEndian.Uint32(partitionEntry[8:12])

				if startSector > 0 {
					// 读取分区的引导扇区
					partitionSector, err := reader.ReadSector(uint64(startSector))
					if err != nil {
						continue
					}

					// 检查分区的文件系统类型
					fsType := detectPartitionFileSystem(partitionSector, partitionType)
					if fsType != FileSystemTypeUnknown {
						return fsType, nil
					}
				}
			}
		}
	}

	// 直接检查扇区是否为文件系统引导扇区
	fsType := detectPartitionFileSystem(sector, 0)
	if fsType != FileSystemTypeUnknown {
		return fsType, nil
	}

	// 检查EXT文件系统
	// EXT超级块位于1024字节偏移处
	superBlock, err := reader.ReadBytes(1024, 1024)
	if err == nil && len(superBlock) >= 1024 {
		// 检查EXT魔数（0xEF53）
		magic := binary.LittleEndian.Uint16(superBlock[56:58])
		if magic == 0xEF53 {
			// 检查特征位以区分EXT2/3/4
			featureCompat := binary.LittleEndian.Uint32(superBlock[92:96])
			featureIncompat := binary.LittleEndian.Uint32(superBlock[96:100])

			hasJournal := (featureCompat & 0x4) != 0
			hasExtent := (featureIncompat & 0x40) != 0

			if hasExtent {
				return FileSystemTypeEXT4, nil
			} else if hasJournal {
				return FileSystemTypeEXT3, nil
			} else {
				return FileSystemTypeEXT2, nil
			}
		}
	}

	// 尝试读取更多扇区进行检测
	for i := uint64(1); i < 10; i++ {
		additionalSector, err := reader.ReadSector(i)
		if err != nil {
			break
		}

		// 检查是否包含文件系统特征
		fsType := detectPartitionFileSystem(additionalSector, 0)
		if fsType != FileSystemTypeUnknown {
			return fsType, nil
		}
	}

	// 如果所有检测都失败，返回RAW类型
	return FileSystemTypeRaw, nil
}

// detectPartitionFileSystem 检测分区的文件系统类型
func detectPartitionFileSystem(sector []byte, partitionType byte) FileSystemType {
	if len(sector) < 512 {
		return FileSystemTypeUnknown
	}

	// 检查FAT文件系统
	if sector[510] == 0x55 && sector[511] == 0xAA {
		// 根据分区类型判断
		switch partitionType {
		case 0x01, 0x04, 0x06, 0x0E:
			return FileSystemTypeFAT16
		case 0x0B, 0x0C:
			return FileSystemTypeFAT32
		}

		// FAT文件系统的特征检测
		bytesPerSector := binary.LittleEndian.Uint16(sector[11:13])
		if bytesPerSector == 0 {
			bytesPerSector = 512 // 默认值
		}

		sectorsPerCluster := sector[13]
		if sectorsPerCluster == 0 {
			sectorsPerCluster = 1 // 默认值
		}

		reservedSectors := binary.LittleEndian.Uint16(sector[14:16])
		numFATs := sector[16]
		if numFATs == 0 {
			numFATs = 2 // 默认值
		}

		rootEntries := binary.LittleEndian.Uint16(sector[17:19])
		totalSectors16 := binary.LittleEndian.Uint16(sector[19:21])
		sectorsPerFAT16 := binary.LittleEndian.Uint16(sector[22:24])
		totalSectors32 := binary.LittleEndian.Uint32(sector[32:36])

		// 检查FAT32特有字段
		if sectorsPerFAT16 == 0 {
			sectorsPerFAT32 := binary.LittleEndian.Uint32(sector[36:40])
			if sectorsPerFAT32 > 0 {
				// 检查FAT32文件系统标识
				if bytes.Equal(sector[82:90], []byte("FAT32   ")) {
					return FileSystemTypeFAT32
				}
				return FileSystemTypeFAT32
			}
		}

		// 检查FAT12/FAT16文件系统标识
		if bytes.Equal(sector[54:62], []byte("FAT16   ")) {
			return FileSystemTypeFAT16
		}
		if bytes.Equal(sector[54:62], []byte("FAT12   ")) {
			return FileSystemTypeFAT12
		}

		// 计算集群总数来区分FAT12和FAT16
		totalSectors := totalSectors16
		if totalSectors16 == 0 {
			totalSectors = uint16(totalSectors32)
		}

		// 防止除零错误
		if bytesPerSector == 0 || sectorsPerCluster == 0 {
			// 根据经验判断
			if rootEntries > 512 {
				return FileSystemTypeFAT16
			}
			return FileSystemTypeFAT12
		}

		dataSectors := uint32(totalSectors) - uint32(reservedSectors) - (uint32(numFATs) * uint32(sectorsPerFAT16)) - (uint32(rootEntries) * 32 / uint32(bytesPerSector))
		clusterCount := dataSectors / uint32(sectorsPerCluster)

		if clusterCount < 4085 {
			return FileSystemTypeFAT12
		} else {
			return FileSystemTypeFAT16
		}
	}

	// 检查NTFS文件系统
	if bytes.Equal(sector[3:11], []byte("NTFS    ")) {
		return FileSystemTypeNTFS
	}

	// 检查EXT文件系统特征
	if len(sector) >= 1024 && binary.LittleEndian.Uint16(sector[1024+56:1024+58]) == 0xEF53 {
		return FileSystemTypeEXT2 // 默认返回EXT2，后续会进一步区分
	}

	// 检查HFS/HFS+文件系统
	if len(sector) >= 1024 {
		if bytes.Equal(sector[1024:1028], []byte("H+")) || bytes.Equal(sector[1024:1028], []byte("HX")) {
			return FileSystemTypeHFSPlus
		} else if bytes.Equal(sector[1024:1028], []byte("BD")) {
			return FileSystemTypeHFS
		}
	}

	return FileSystemTypeUnknown
}

// min 返回两个数中的较小者
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
