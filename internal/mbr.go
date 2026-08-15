package internal

// MBR is a Master Boot Record parsed from sector 0.
type MBR struct {
	BootCode       [440]byte         // 引导代码（GRUB/Windows Boot Manager）
	DiskSignature  uint32            // 磁盘签名（Windows NTFS 等使用）
	Reserved       uint16            // 保留字段（通常 0x0000）
	PartitionTable [4]PartitionEntry // 4个分区表项（每项16字节）
	BootSignature  uint16            // 结束标志（0x55AA）
}

type PartitionEntry struct {
	BootFlag      uint8   // 0x80=可启动，0x00=非启动
	StartCHS      [3]byte // CHS 起始地址（传统BIOS）
	PartitionType uint8   // 分区类型标识（0x07=NTFS，0x83=Linux…）
	EndCHS        [3]byte // CHS 结束地址
	StartLBA      uint32  // 分区起始扇区（LBA逻辑寻址）
	PartitionSize uint32  // 分区大小（扇区数）
}
