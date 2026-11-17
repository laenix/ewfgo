package f2fs

// Node and inode layout constants.
const (
	NodeFooterSize = 24
	SizeOfINid     = 20
	NIDsPerInode   = 5
	AddrsOffset    = 360
)

// Inline flags, in the order f2fs_fs.h declares them.
const (
	InlineXattr     uint8 = 0x01
	InlineData      uint8 = 0x02
	InlineDentry    uint8 = 0x04
	InlineDataExist uint8 = 0x08
	InlineDots      uint8 = 0x10
	ExtraAttr       uint8 = 0x20
)

// File-type bits of i_mode.
const (
	SIFMT  uint16 = 0xF000
	SIFDIR uint16 = 0x4000
	SIFREG uint16 = 0x8000
	SIFLNK uint16 = 0xA000
)

// F2fsTime is an F2FS timestamp: whole seconds since the Unix epoch and a
// nanosecond remainder.
type F2fsTime struct {
	Seconds uint64
	Nanos   uint32
}

// UnixNanos returns the timestamp in nanoseconds since the Unix epoch.
func (t F2fsTime) UnixNanos() int64 {
	if t.Seconds > uint64(1<<63-1)/1_000_000_000 {
		return int64(^uint64(0) >> 1)
	}
	return int64(t.Seconds)*1_000_000_000 + int64(t.Nanos)
}

// IsZero reports whether the timestamp records nothing.
func (t F2fsTime) IsZero() bool { return t.Seconds == 0 && t.Nanos == 0 }

// NodeFooter is the 24-byte footer that closes every node block.
type NodeFooter struct {
	NID         uint32
	Ino         uint32
	Flag        uint32
	CPVer       uint64
	NextBlkaddr uint32
}

// ParseNodeFooter reads the footer that closes bytes.
func ParseNodeFooter(bytes []byte, blockSize int) (NodeFooter, error) {
	if len(bytes) < blockSize || blockSize <= NodeFooterSize {
		return NodeFooter{}, invalidf("a node block of %d bytes cannot hold its footer", blockSize)
	}
	at := blockSize - NodeFooterSize
	nid, err := u32At(bytes, at)
	if err != nil {
		return NodeFooter{}, err
	}
	ino, err := u32At(bytes, at+4)
	if err != nil {
		return NodeFooter{}, err
	}
	flag, err := u32At(bytes, at+8)
	if err != nil {
		return NodeFooter{}, err
	}
	cpVer, err := u64At(bytes, at+12)
	if err != nil {
		return NodeFooter{}, err
	}
	next, err := u32At(bytes, at+20)
	if err != nil {
		return NodeFooter{}, err
	}
	return NodeFooter{NID: nid, Ino: ino, Flag: flag, CPVer: cpVer, NextBlkaddr: next}, nil
}

// Inode is a parsed F2FS inode.
type Inode struct {
	NID         uint32
	Ino         uint32
	Mode        uint16
	Advise      uint8
	InlineFlags uint8
	UID         uint32
	GID         uint32
	Links       uint32
	Size        uint64
	Blocks      uint64
	Atime       F2fsTime
	Ctime       F2fsTime
	Mtime       F2fsTime
	Crtime      *F2fsTime
	Generation  uint32
	Depth       uint32
	XattrNID    uint32
	Flags       uint32
	Pino        uint32
	ProjectID   *uint32
	// CompressedBlocks is i_compr_blocks: physical blocks stored compressed.
	CompressedBlocks uint64
	// CompressAlgorithm is i_compress_algorithm.
	CompressAlgorithm uint8
	// LogClusterSize is i_log_cluster_size; zero with no compression.
	LogClusterSize uint8
	DirLevel       uint8
	// Addresses are the block addresses stored in the inode.
	Addresses []uint32
	// NIDs are the indirect node ids.
	NIDs [NIDsPerInode]uint32
	// Inline holds the bytes of an inline file or fast symlink.
	Inline []byte
	// AddressesOffset is where the address array (and inline bytes) starts.
	AddressesOffset int
	// AddressBytes is how many bytes the address area holds.
	AddressBytes int
	BlockSize    uint32
}

// ParseInode parses the inode at the start of a node block.
func ParseInode(bytes []byte, blockSize uint32, nid uint32) (*Inode, error) {
	size := int(blockSize)
	if len(bytes) < size || size < AddrsOffset+NodeFooterSize {
		return nil, invalidf("the block of %d bytes cannot hold an inode", size)
	}
	bytes = bytes[:size]
	footer, err := ParseNodeFooter(bytes, size)
	if err != nil {
		return nil, err
	}
	if footer.NID != nid {
		return nil, invalidf("the node block read for id %d carries id %d", nid, footer.NID)
	}
	inlineFlags, err := u8At(bytes, 3)
	if err != nil {
		return nil, err
	}
	addressesOffset := AddrsOffset
	var projectID *uint32
	var crtime *F2fsTime
	var compressedBlocks uint64
	var compressAlgorithm uint8
	var logClusterSize uint8
	if inlineFlags&ExtraAttr != 0 {
		extra, err := u16At(bytes, AddrsOffset)
		if err != nil {
			return nil, err
		}
		offset := AddrsOffset + int(extra)
		if int(extra) < 40 || offset > size-NodeFooterSize-SizeOfINid {
			return nil, invalidf("the inode's extra attributes claim %d bytes, which do not fit", extra)
		}
		addressesOffset = offset
		project, err := u32At(bytes, AddrsOffset+4)
		if err != nil {
			return nil, err
		}
		projectID = &project
		seconds, err := u64At(bytes, AddrsOffset+12)
		if err != nil {
			return nil, err
		}
		nanos, err := u32At(bytes, AddrsOffset+20)
		if err != nil {
			return nil, err
		}
		crtime = &F2fsTime{Seconds: seconds, Nanos: nanos}
		compressedBlocks, err = u64At(bytes, AddrsOffset+24)
		if err != nil {
			return nil, err
		}
		compressAlgorithm, err = u8At(bytes, AddrsOffset+32)
		if err != nil {
			return nil, err
		}
		logClusterSize, err = u8At(bytes, AddrsOffset+33)
		if err != nil {
			return nil, err
		}
	}
	addressBytes := size - NodeFooterSize - SizeOfINid - addressesOffset
	count := addressBytes / 4
	addresses := make([]uint32, 0, count)
	for index := 0; index < count; index++ {
		address, err := u32At(bytes, addressesOffset+index*4)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, address)
	}
	var nids [NIDsPerInode]uint32
	nidsAt := size - NodeFooterSize - SizeOfINid
	for index := range nids {
		nids[index], err = u32At(bytes, nidsAt+index*4)
		if err != nil {
			return nil, err
		}
	}
	fileSize, err := u64At(bytes, 16)
	if err != nil {
		return nil, err
	}
	mode, err := u16At(bytes, 0)
	if err != nil {
		return nil, err
	}
	advise, err := u8At(bytes, 2)
	if err != nil {
		return nil, err
	}
	uid, err := u32At(bytes, 4)
	if err != nil {
		return nil, err
	}
	gid, err := u32At(bytes, 8)
	if err != nil {
		return nil, err
	}
	links, err := u32At(bytes, 12)
	if err != nil {
		return nil, err
	}
	blocks, err := u64At(bytes, 24)
	if err != nil {
		return nil, err
	}
	atimeSeconds, err := u64At(bytes, 32)
	if err != nil {
		return nil, err
	}
	// A short symbolic link keeps its target where the addresses would be, with
	// or without the inline-data flag; an inline file only when the flag says so.
	inlineContents := inlineFlags&InlineData != 0 || mode&SIFMT == SIFLNK
	var inline []byte
	if inlineContents && fileSize <= uint64(addressBytes) {
		inline = make([]byte, int(fileSize))
		copy(inline, bytes[addressesOffset:addressesOffset+int(fileSize)])
	}
	ctimeSeconds, err := u64At(bytes, 40)
	if err != nil {
		return nil, err
	}
	mtimeSeconds, err := u64At(bytes, 48)
	if err != nil {
		return nil, err
	}
	atimeNanos, err := u32At(bytes, 56)
	if err != nil {
		return nil, err
	}
	ctimeNanos, err := u32At(bytes, 60)
	if err != nil {
		return nil, err
	}
	mtimeNanos, err := u32At(bytes, 64)
	if err != nil {
		return nil, err
	}
	generation, err := u32At(bytes, 68)
	if err != nil {
		return nil, err
	}
	depth, err := u32At(bytes, 72)
	if err != nil {
		return nil, err
	}
	xattrNID, err := u32At(bytes, 76)
	if err != nil {
		return nil, err
	}
	flags, err := u32At(bytes, 80)
	if err != nil {
		return nil, err
	}
	pino, err := u32At(bytes, 84)
	if err != nil {
		return nil, err
	}
	dirLevel, err := u8At(bytes, 347)
	if err != nil {
		return nil, err
	}
	return &Inode{
		NID:               nid,
		Ino:               footer.Ino,
		Mode:              mode,
		Advise:            advise,
		InlineFlags:       inlineFlags,
		UID:               uid,
		GID:               gid,
		Links:             links,
		Size:              fileSize,
		Blocks:            blocks,
		Atime:             F2fsTime{Seconds: atimeSeconds, Nanos: atimeNanos},
		Ctime:             F2fsTime{Seconds: ctimeSeconds, Nanos: ctimeNanos},
		Mtime:             F2fsTime{Seconds: mtimeSeconds, Nanos: mtimeNanos},
		Crtime:            crtime,
		Generation:        generation,
		Depth:             depth,
		XattrNID:          xattrNID,
		Flags:             flags,
		Pino:              pino,
		ProjectID:         projectID,
		CompressedBlocks:  compressedBlocks,
		CompressAlgorithm: compressAlgorithm,
		LogClusterSize:    logClusterSize,
		DirLevel:          dirLevel,
		Addresses:         addresses,
		NIDs:              nids,
		Inline:            inline,
		AddressesOffset:   addressesOffset,
		AddressBytes:      addressBytes,
		BlockSize:         blockSize,
	}, nil
}

// CheckReadable refuses inodes whose contents this reader cannot follow.
func (i *Inode) CheckReadable() error {
	if i.CompressedBlocks > 0 || i.LogClusterSize > 0 {
		if i.LogClusterSize == 0 {
			return invalidf("inode %#x has %d compressed blocks but a cluster log size of zero",
				i.Ino, i.CompressedBlocks)
		}
		if i.LogClusterSize > MaxClusterLog {
			return unsupportedf("inode %#x with a compressed cluster of 2^%d blocks, above the 2^%d this reader bounds",
				i.Ino, i.LogClusterSize, MaxClusterLog)
		}
		clusterBytes := uint64(i.BlockSize) << i.LogClusterSize
		if clusterBytes > MaxDecompressed {
			return unsupportedf("inode %#x with a %d-byte compressed cluster, above the %d-byte limit",
				i.Ino, clusterBytes, MaxDecompressed)
		}
	}
	if i.InlineFlags&InlineDentry != 0 {
		return unsupportedf("the inline directory %#x (node id %d)", i.Ino, i.NID)
	}
	if i.InlineFlags&InlineData != 0 && i.InlineFlags&InlineXattr != 0 && i.Size > uint64(i.AddressBytes) {
		return unsupportedf("the inline data of inode %#x, which shares its bytes with an inline extended attribute", i.Ino)
	}
	if i.InlineFlags&InlineData != 0 && i.Size > uint64(i.AddressBytes) && i.Inline == nil {
		return unsupportedf("inode %#x is marked as holding inline data but is %d bytes, larger than the %d bytes the inode holds",
			i.Ino, i.Size, i.AddressBytes)
	}
	return nil
}

// FileType returns the S_IFMT bits of the inode's mode.
func (i *Inode) FileType() uint16 { return i.Mode & SIFMT }

// IsDir reports whether the inode is a directory.
func (i *Inode) IsDir() bool { return i.FileType() == SIFDIR }

// IsRegular reports whether the inode is a regular file.
func (i *Inode) IsRegular() bool { return i.FileType() == SIFREG }

// IsSymlink reports whether the inode is a symbolic link.
func (i *Inode) IsSymlink() bool { return i.FileType() == SIFLNK }

// IsCompressed reports whether the inode records compressed blocks or a
// compression cluster size.
func (i *Inode) IsCompressed() bool {
	return i.CompressedBlocks > 0 || i.LogClusterSize > 0
}

// CompressAlgorithmName returns the algorithm's name.
func (i *Inode) CompressAlgorithmName() string {
	return AlgorithmName(i.CompressAlgorithm)
}

// ClusterBytes returns the plaintext bytes one cluster produces, when the inode
// records a compression cluster size.
func (i *Inode) ClusterBytes() (uint64, bool) {
	if i.LogClusterSize == 0 {
		return 0, false
	}
	return uint64(i.BlockSize) << i.LogClusterSize, true
}

// DirectCapacity returns how many data block addresses the inode stores.
func (i *Inode) DirectCapacity() int { return len(i.Addresses) }

// SymlinkTarget returns the target bytes of a short symbolic link.
func (i *Inode) SymlinkTarget() []byte {
	if !i.IsSymlink() {
		return nil
	}
	return i.Inline
}
