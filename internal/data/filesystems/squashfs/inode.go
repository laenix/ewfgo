package squashfs

import (
	"encoding/binary"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// uncompressedBlockBit marks a data block stored without compression.
	uncompressedBlockBit = 1 << 24
	// blockSizeMask is the stored-length mask of a data block entry.
	blockSizeMask = 0x00FF_FFFF
	// maxBlocks bounds one inode's block list.
	maxBlocks = 4_000_000
	// maxSymlinkBytes is the longest symbolic-link target accepted.
	maxSymlinkBytes = 4096
)

type inodeKind uint8

const (
	kindDirectory inodeKind = iota
	kindFile
	kindSymlink
	kindBlockDevice
	kindCharDevice
	kindFifo
	kindSocket
)

func (k inodeKind) label() string {
	switch k {
	case kindDirectory:
		return "directory"
	case kindFile:
		return "regular"
	case kindSymlink:
		return "symlink"
	case kindBlockDevice:
		return "block device"
	case kindCharDevice:
		return "character device"
	case kindFifo:
		return "fifo"
	default:
		return "socket"
	}
}

type inode struct {
	inodeType      uint16
	kind           inodeKind
	extended       bool
	mode           uint16
	uidIndex       uint16
	gidIndex       uint16
	modified       uint32
	inodeNumber    uint32
	nlink          uint32
	size           uint64
	startBlock     uint64
	dirOffset      uint16
	fragment       uint32
	fragmentOffset uint32
	blocks         []uint32
	symlinkTarget  string
	hasSymlink     bool
	rdev           uint32
	xattr          uint32
}

// headerBytes returns the fixed header size for an on-disk inode type.
func headerBytes(inodeType uint16) (int, bool) {
	switch inodeType {
	case 1:
		return 32, true // basic directory
	case 2:
		return 32, true // basic regular file
	case 3:
		return 24, true // symbolic link
	case 4, 5:
		return 24, true // block and character device
	case 6, 7:
		return 20, true // fifo and socket
	case 8:
		return 40, true // extended directory
	case 9:
		return 56, true // extended regular file
	case 10:
		return 24, true // extended symbolic link
	case 11, 12:
		return 28, true // extended block and character device
	case 13, 14:
		return 24, true // extended fifo and socket
	default:
		return 0, false
	}
}

func kindOf(inodeType uint16) (inodeKind, error) {
	switch inodeType {
	case 1, 8:
		return kindDirectory, nil
	case 2, 9:
		return kindFile, nil
	case 3, 10:
		return kindSymlink, nil
	case 4, 11:
		return kindBlockDevice, nil
	case 5, 12:
		return kindCharDevice, nil
	case 6, 13:
		return kindFifo, nil
	case 7, 14:
		return kindSocket, nil
	default:
		return 0, corruptf("inode type %d does not exist", inodeType)
	}
}

func isExtended(inodeType uint16) bool { return inodeType >= 8 }

func le16At(b []byte, at int) uint16 { return binary.LittleEndian.Uint16(b[at:]) }
func le32At(b []byte, at int) uint32 { return binary.LittleEndian.Uint32(b[at:]) }
func le64At(b []byte, at int) uint64 { return binary.LittleEndian.Uint64(b[at:]) }

// parseInodeHeader parses the fixed part of an inode. It does not consume a
// symbolic link's target bytes or a file's block list.
func parseInodeHeader(header []byte) (*inode, error) {
	if len(header) < 4 {
		return nil, corruptf("a truncated inode header")
	}
	inodeType := le16At(header, 0)
	fixed, ok := headerBytes(inodeType)
	if !ok {
		return nil, corruptf("inode type %d does not exist", inodeType)
	}
	if len(header) < fixed {
		return nil, corruptf("a truncated inode header")
	}
	kind, err := kindOf(inodeType)
	if err != nil {
		return nil, err
	}
	in := &inode{
		inodeType:   inodeType,
		kind:        kind,
		extended:    isExtended(inodeType),
		mode:        le16At(header, 2),
		uidIndex:    le16At(header, 4),
		gidIndex:    le16At(header, 6),
		modified:    le32At(header, 8),
		inodeNumber: le32At(header, 12),
		nlink:       1,
		fragment:    invalidFragment,
	}
	switch inodeType {
	case 1:
		in.startBlock = uint64(le32At(header, 16))
		in.nlink = le32At(header, 20)
		in.size = uint64(le16At(header, 24))
		in.dirOffset = le16At(header, 26)
	case 8:
		in.nlink = le32At(header, 16)
		in.size = uint64(le32At(header, 20))
		in.startBlock = uint64(le32At(header, 24))
		in.dirOffset = le16At(header, 34)
		in.xattr = le32At(header, 36)
	case 2:
		in.startBlock = uint64(le32At(header, 16))
		in.fragment = le32At(header, 20)
		in.fragmentOffset = le32At(header, 24)
		in.size = uint64(le32At(header, 28))
	case 9:
		in.startBlock = le64At(header, 16)
		in.size = le64At(header, 24)
		in.nlink = le32At(header, 40)
		in.fragment = le32At(header, 44)
		in.fragmentOffset = le32At(header, 48)
		in.xattr = le32At(header, 52)
	case 3, 10:
		in.nlink = le32At(header, 16)
		targetLen := le32At(header, 20)
		if targetLen > maxSymlinkBytes {
			return nil, corruptf("a symbolic link of %d bytes is longer than %d", targetLen, maxSymlinkBytes)
		}
		in.size = uint64(targetLen)
	case 4, 5:
		in.nlink = le32At(header, 16)
		in.rdev = le32At(header, 20)
	case 11, 12:
		in.nlink = le32At(header, 16)
		in.rdev = le32At(header, 20)
		in.xattr = le32At(header, 24)
	case 6, 7:
		in.nlink = le32At(header, 16)
	case 13, 14:
		in.nlink = le32At(header, 16)
		in.xattr = le32At(header, 20)
	}
	return in, nil
}

// blockCount returns how many data block entries a file of this size has.
func blockCount(size uint64, fragment uint32, blockSize uint32) (int, error) {
	bs := uint64(blockSize)
	var count uint64
	if fragment != invalidFragment {
		if size%bs == 0 {
			return 0, corruptf("a %d-byte file names both a fragment and a whole number of blocks", size)
		}
		count = size / bs
	} else {
		count = (size + bs - 1) / bs
	}
	if count > maxBlocks {
		return 0, corruptf("a file needs %d block entries, more than the %d bound", count, maxBlocks)
	}
	return int(count), nil
}

// blockLen returns the logical bytes block index covers.
func blockLen(size uint64, fragment uint32, blockSize uint32, index int) uint64 {
	bs := uint64(blockSize)
	if fragment != invalidFragment {
		return bs
	}
	whole := (size + bs - 1) / bs
	if uint64(index)+1 < whole {
		return bs
	}
	remainder := size % bs
	if remainder == 0 {
		return bs
	}
	return remainder
}

func parseBlockList(list []byte) ([]uint32, error) {
	blocks := make([]uint32, len(list)/4)
	for i := range blocks {
		entry := binary.LittleEndian.Uint32(list[i*4:])
		if entry>>25 != 0 {
			return nil, corruptf("block entry %#x sets a bit that is not part of its size or type", entry)
		}
		blocks[i] = entry
	}
	return blocks, nil
}

// parseInode parses a complete inode from contiguous bytes. It exists for
// callers that already hold the header and block list together; the volume
// reads them through the metadata cache instead.
func parseInode(data []byte, blockSize uint32) (*inode, error) {
	if len(data) < 2 {
		return nil, corruptf("a truncated inode header")
	}
	inodeType := le16At(data, 0)
	fixed, ok := headerBytes(inodeType)
	if !ok {
		return nil, corruptf("inode type %d does not exist", inodeType)
	}
	if len(data) < fixed {
		return nil, corruptf("a truncated inode header")
	}
	in, err := parseInodeHeader(data[:fixed])
	if err != nil {
		return nil, err
	}
	return finishInode(in, data, fixed, blockSize)
}

// finishInode reads the variable part that follows an inode's fixed header.
func finishInode(in *inode, data []byte, at int, blockSize uint32) (*inode, error) {
	switch in.kind {
	case kindSymlink:
		if at+int(in.size) > len(data) {
			return nil, corruptf("a symbolic link target runs past the inode")
		}
		in.symlinkTarget = string(data[at : at+int(in.size)])
		in.hasSymlink = true
		at += int(in.size)
		if in.inodeType == 10 {
			if at+4 > len(data) {
				return nil, corruptf("a symbolic link xattr index runs past the inode")
			}
			in.xattr = le32At(data, at)
		}
	case kindFile:
		count, err := blockCount(in.size, in.fragment, blockSize)
		if err != nil {
			return nil, err
		}
		if at+count*4 > len(data) {
			return nil, corruptf("a block list of %d entries runs past the inode", count)
		}
		blocks, err := parseBlockList(data[at : at+count*4])
		if err != nil {
			return nil, err
		}
		in.blocks = blocks
	}
	return in, nil
}

// readInode reads and parses the inode at ref, whose high half is a metadata
// block relative to the inode table.
func readInode(cache *metadataCache, src source.ByteSource, blockSize uint32, inodeTableStart uint64, ref uint64) (*inode, error) {
	block := inodeTableStart + (ref >> 16)
	if block < inodeTableStart {
		return nil, corruptf("an inode block address overflows")
	}
	offset := int(ref & 0xFFFF)
	if offset >= metadataBytes {
		return nil, corruptf("inode %#x names offset %d, past a metadata block", ref, offset)
	}
	head, _, _, err := cache.spanCursor(src, block, offset, 2)
	if err != nil {
		return nil, err
	}
	inodeType := le16At(head, 0)
	fixed, ok := headerBytes(inodeType)
	if !ok {
		return nil, corruptf("inode type %d does not exist", inodeType)
	}
	header, block, offset, err := cache.spanCursor(src, block, offset, fixed)
	if err != nil {
		return nil, err
	}
	if len(header) != fixed {
		return nil, corruptf("a truncated inode header")
	}
	in, err := parseInodeHeader(header)
	if err != nil {
		return nil, err
	}
	if in.kind == kindSymlink {
		target, block, offset, err := cache.spanCursor(src, block, offset, int(in.size))
		if err != nil {
			return nil, err
		}
		in.symlinkTarget = string(target)
		in.hasSymlink = true
		if in.inodeType == 10 {
			xattr, _, _, err := cache.spanCursor(src, block, offset, 4)
			if err != nil {
				return nil, err
			}
			in.xattr = le32At(xattr, 0)
		}
		return in, nil
	}
	if in.kind == kindFile {
		count, err := blockCount(in.size, in.fragment, blockSize)
		if err != nil {
			return nil, err
		}
		list, _, _, err := cache.spanCursor(src, block, offset, count*4)
		if err != nil {
			return nil, err
		}
		blocks, err := parseBlockList(list)
		if err != nil {
			return nil, err
		}
		in.blocks = blocks
	}
	return in, nil
}

// allocatedBytes is the sum of the logical bytes a file actually stores.
func allocatedBytes(in *inode, blockSize uint32) uint64 {
	var total uint64
	for index, entry := range in.blocks {
		if entry != 0 {
			total += blockLen(in.size, in.fragment, blockSize, index)
		}
	}
	if in.fragment != invalidFragment {
		total += in.size % uint64(blockSize)
	}
	return total
}
