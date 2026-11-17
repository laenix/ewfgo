package ocfs2

import (
	"github.com/laenix/ewfgo/internal/data/source"
)

// Every OCFS2 inode is one filesystem block beginning with INODE01. The id2
// union at 0xc0 is an extent list, an inline-data header, or a fast symbolic
// link's target.

// InodeSignature is the signature every inode block carries.
var InodeSignature = []byte("INODE01")

// Offsets inside a dinode.
const (
	InlineHeaderOffset = 0xc0
	InlineDataOffset   = 0xc8
	FastSymlinkOffset  = 0xc0
	InodeListOffset    = 0xc0
)

// Kind is what an inode's mode bits say it is.
type Kind uint8

// Inode kinds.
const (
	KindFile Kind = iota
	KindDirectory
	KindSymlink
	KindFifo
	KindSocket
	KindBlockDevice
	KindCharDevice
	KindUnknown
)

// KindFromMode classifies a mode word.
func KindFromMode(mode uint16) Kind {
	switch mode & 0xf000 {
	case 0x8000:
		return KindFile
	case 0x4000:
		return KindDirectory
	case 0xa000:
		return KindSymlink
	case 0x1000:
		return KindFifo
	case 0xc000:
		return KindSocket
	case 0x6000:
		return KindBlockDevice
	case 0x2000:
		return KindCharDevice
	default:
		return KindUnknown
	}
}

// Label names a kind.
func (k Kind) Label() string {
	switch k {
	case KindFile:
		return "file"
	case KindDirectory:
		return "directory"
	case KindSymlink:
		return "symlink"
	case KindFifo:
		return "fifo"
	case KindSocket:
		return "socket"
	case KindBlockDevice:
		return "block device"
	case KindCharDevice:
		return "character device"
	default:
		return "unknown"
	}
}

// IsDirectory reports whether the kind is a directory.
func (k Kind) IsDirectory() bool { return k == KindDirectory }

// IsSymlink reports whether the kind is a symbolic link.
func (k Kind) IsSymlink() bool { return k == KindSymlink }

// IsFile reports whether the kind is a regular file.
func (k Kind) IsFile() bool { return k == KindFile }

// HasData reports whether the kind carries file data or a directory stream.
func (k Kind) HasData() bool {
	return k == KindFile || k == KindDirectory || k == KindSymlink
}

// Inode is one parsed OCFS2 dinode.
type Inode struct {
	Block       uint64
	Mode        uint16
	Flags       uint32
	DynFeatures uint16
	UID         uint32
	GID         uint32
	Links       uint32
	Size        uint64
	Clusters    uint32
	Accessed    *int64
	Modified    *int64
	Changed     *int64
	Kind        Kind
	// FastSymlink is a fast symbolic link's target, without the NUL.
	FastSymlink []byte
	// Inline is an inline file's or directory's bytes.
	Inline []byte
	// List is the extent list for an ordinary file or directory.
	List *ExtentList
}

// FastSymlinkText is the fast symbolic link's target as text.
func (i *Inode) FastSymlinkText() string { return string(i.FastSymlink) }

// IsIndexedDirectory reports whether the inode uses the indexed directory
// format.
func (i *Inode) IsIndexedDirectory() bool {
	return i.Kind.IsDirectory() && i.DynFeatures&IndexedDirFl != 0
}

// timestamp converts a stored second/nanosecond pair to Unix seconds. A zero
// pair is "unset", not 1970. The nanosecond remainder is checked but not
// reported.
func timestamp(seconds uint64, nanoseconds uint32) (*int64, error) {
	if nanoseconds >= 1_000_000_000 {
		return nil, corruptf("a timestamp has %d nanoseconds, outside 0..1,000,000,000", nanoseconds)
	}
	if seconds == 0 && nanoseconds == 0 {
		return nil, nil
	}
	if seconds > uint64(^uint64(0)>>1) {
		return nil, corruptf("timestamp %d does not fit a signed 64-bit second count", seconds)
	}
	value := int64(seconds)
	return &value, nil
}

func parseInode(bytes []byte, block uint64, superblock *Superblock) (*Inode, error) {
	blockSize := int(superblock.BlockSize)
	if len(bytes) < blockSize {
		return nil, corruptf("inode block %d is %d bytes, shorter than the %d-byte block", block, len(bytes), blockSize)
	}
	if !hasSignature(bytes, InodeSignature) {
		return nil, corruptf("inode block %d has no INODE01 signature", block)
	}
	inodeBlock := le64(bytes, 0x50)
	if inodeBlock != block {
		return nil, corruptf("inode read from block %d names itself as block %d", block, inodeBlock)
	}
	generation := le32(bytes, 0x60)
	if generation != superblock.FsGeneration {
		return nil, corruptf("inode block %d belongs to filesystem generation 0x%08x, but the superblock declares 0x%08x",
			block, generation, superblock.FsGeneration)
	}

	flags := le32(bytes, 0x2c)
	if flags&ValidFl == 0 {
		return nil, corruptf("inode block %d is not in use", block)
	}
	if flags&OrphanedFl != 0 {
		return nil, corruptf("inode block %d is orphaned; its name is not in a directory and deleted-name recovery is not read", block)
	}
	if flags&SuperBlockFl != 0 {
		return nil, corruptf("inode block %d carries the superblock flag but is not block 2", block)
	}

	mode := le16(bytes, 0x28)
	kind := KindFromMode(mode)
	if kind == KindUnknown {
		return nil, corruptf("inode block %d has mode 0x%04x, which names no supported file type", block, mode)
	}
	dynFeatures := le16(bytes, 0x74)
	if unknown := dynFeatures &^ KnownDynFeatures; unknown != 0 {
		return nil, unsupportedf("inode block %d has dynamic-feature bits 0x%04x; this reader decodes only 0x%04x",
			block, unknown, KnownDynFeatures)
	}

	links := uint32(le16(bytes, 0x2a)) | uint32(le16(bytes, 0x10))<<16
	if links == 0 {
		return nil, corruptf("inode block %d has a zero link count", block)
	}
	size := le64(bytes, 0x20)
	if size > superblock.VolumeBytes {
		return nil, corruptf("inode block %d declares %d bytes, more than the %d-byte volume",
			block, size, superblock.VolumeBytes)
	}
	clusters := le32(bytes, 0x14)
	inlineFlag := dynFeatures&InlineDataFl != 0
	clusterBytes := uint64(clusters) * uint64(superblock.ClusterSize)
	if uint64(superblock.ClusterSize) != 0 && clusterBytes/uint64(superblock.ClusterSize) != uint64(clusters) {
		return nil, corruptf("inode block %d's allocation overflows", block)
	}
	fastSymlinkLayout := kind == KindSymlink && clusters == 0 && !inlineFlag
	if !inlineFlag && !fastSymlinkLayout && size > clusterBytes {
		return nil, corruptf("inode block %d declares %d bytes but allocates only %d clusters (%d bytes)",
			block, size, clusters, clusterBytes)
	}

	accessed, err := timestamp(le64(bytes, 0x30), le32(bytes, 0x64))
	if err != nil {
		return nil, err
	}
	changed, err := timestamp(le64(bytes, 0x38), le32(bytes, 0x68))
	if err != nil {
		return nil, err
	}
	modified, err := timestamp(le64(bytes, 0x40), le32(bytes, 0x6c))
	if err != nil {
		return nil, err
	}

	var fastSymlink []byte
	var inline []byte
	var list *ExtentList

	switch {
	case inlineFlag:
		if kind == KindSymlink {
			return nil, unsupportedf("inode block %d is an inline symbolic link; only fast and extent-mapped targets are decoded", block)
		}
		if clusters != 0 {
			return nil, corruptf("inode block %d is inline but allocates %d clusters", block, clusters)
		}
		if blockSize < InlineDataOffset {
			return nil, corruptf("block size %d is too small for the inline-data area at %d", blockSize, InlineDataOffset)
		}
		idCount := int(le16(bytes, InlineHeaderOffset))
		capacity := blockSize - InlineDataOffset
		if idCount > capacity {
			return nil, corruptf("inode block %d declares %d inline bytes, more than the %d that fit",
				block, idCount, capacity)
		}
		if size > uint64(idCount) {
			return nil, corruptf("inode block %d declares %d bytes but its inline area holds %d", block, size, idCount)
		}
		end := InlineDataOffset + int(size)
		inline = make([]byte, int(size))
		copy(inline, bytes[InlineDataOffset:end])
	case kind == KindSymlink && clusters == 0:
		if blockSize < FastSymlinkOffset {
			return nil, corruptf("block size %d is too small for the fast-symlink area at %d", blockSize, FastSymlinkOffset)
		}
		capacity := uint64(blockSize - FastSymlinkOffset)
		if size >= capacity {
			return nil, corruptf("inode block %d declares a %d-byte fast symbolic link, too long for the %d-byte inline area",
				block, size, capacity)
		}
		at := FastSymlinkOffset + int(size)
		if bytes[at] != 0 {
			return nil, corruptf("inode block %d's fast symbolic link is not NUL-terminated at byte %d", block, size)
		}
		fastSymlink = make([]byte, int(size))
		copy(fastSymlink, bytes[FastSymlinkOffset:at])
	case kind.HasData():
		if clusters == 0 && size != 0 {
			return nil, corruptf("inode block %d declares %d bytes but allocates no clusters and carries no inline data", block, size)
		}
		list, err = ParseExtentList(bytes, InodeListOffset, blockSize, "the inode's extent list")
		if err != nil {
			return nil, err
		}
		if clusters == 0 && list.NextFree != 0 {
			return nil, corruptf("inode block %d allocates no clusters but its extent list has %d records",
				block, list.NextFree)
		}
	case clusters != 0:
		return nil, corruptf("inode block %d is a %s but allocates %d clusters", block, kind.Label(), clusters)
	}

	return &Inode{
		Block:       block,
		Mode:        mode,
		Flags:       flags,
		DynFeatures: dynFeatures,
		UID:         le32(bytes, 0x18),
		GID:         le32(bytes, 0x1c),
		Links:       links,
		Size:        size,
		Clusters:    clusters,
		Accessed:    accessed,
		Modified:    modified,
		Changed:     changed,
		Kind:        kind,
		FastSymlink: fastSymlink,
		Inline:      inline,
		List:        list,
	}, nil
}

// ReadInode reads one inode block.
func ReadInode(src source.ByteSource, superblock *Superblock, block uint64) (*Inode, error) {
	if _, err := superblock.ValidateBlock(block, "an inode"); err != nil {
		return nil, err
	}
	offset, ok := superblock.BlockOffset(block)
	if !ok {
		return nil, corruptf("inode block %d overflows the byte address space", block)
	}
	bytes := make([]byte, int(superblock.BlockSize))
	if err := source.ReadExactAt(src, offset, bytes); err != nil {
		return nil, err
	}
	return parseInode(bytes, block, superblock)
}
