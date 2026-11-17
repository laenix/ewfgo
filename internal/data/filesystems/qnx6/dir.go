package qnx6

import (
	"fmt"
	"strings"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Bytes in a directory slot.
const DirEntrySize = 32

// ShortNameMax is the most bytes of a name stored in a slot.
const ShortNameMax = 27

// LongMarker is the de_size value that marks a long-name entry.
const LongMarker = 0xff

// LongRecordSize is the bytes in a long-name record.
const LongRecordSize uint64 = 512

// LongNameMax is the most bytes of a long name the record can hold.
const LongNameMax = 510

// MaxDirectoryBytes is the largest directory stream accepted.
const MaxDirectoryBytes uint64 = 64 * 1024 * 1024

// DirEntry is one name inside a directory.
type DirEntry struct {
	Name string
	// Inode is the 1-based inode number.
	Inode uint64
}

// Directory is one directory's decoded data.
type Directory struct {
	Entries []DirEntry
	// Blocks counts directory data blocks read.
	Blocks uint64
	// ExtentBlocks counts pointer blocks read while resolving the directory
	// and Longfile streams.
	ExtentBlocks uint64
	// ExtentRecords counts pointer slots examined while resolving those
	// streams.
	ExtentRecords uint64
}

// NameChecksum is the rotate-add checksum QNX6 uses for long names.
func NameChecksum(bytes []byte) uint32 {
	var crc uint32
	for _, value := range bytes {
		add := (crc >> 1) + uint32(value)
		var flip uint32
		if crc&1 != 0 {
			flip = 0x8000_0000
		}
		crc = add ^ flip
	}
	return crc
}

func lossyUTF8(bytes []byte) string {
	return strings.ToValidUTF8(string(bytes), "�")
}

// longfile reads long names from the superblock's Longfile stream.
type longfile struct {
	superblock *Superblock
	source     source.ByteSource
	mapper     *Mapper
}

func newLongfile(superblock *Superblock, src source.ByteSource) *longfile {
	return &longfile{
		superblock: superblock,
		source:     src,
		mapper:     NewMapper(superblock, src),
	}
}

func (l *longfile) name(block uint64, expectedChecksum uint32) (string, error) {
	if l.superblock.Longfile.Size == 0 {
		return "", corruptf("a directory entry names a long filename but the Longfile root node is empty")
	}
	blockSize := uint64(l.superblock.BlockSize)
	start := block * blockSize
	end := start + LongRecordSize
	if end < start {
		return "", corruptf("a long-name record offset overflows")
	}
	if end > l.superblock.Longfile.Size {
		return "", corruptf("a directory entry names Longfile block %d, whose record ends at byte %d, past the %d-byte Longfile stream",
			block, end, l.superblock.Longfile.Size)
	}
	mapped, err := l.mapper.Map(l.superblock.Longfile.Ptr, l.superblock.Longfile.Levels,
		block, "the Longfile stream")
	if err != nil {
		return "", err
	}
	physical, ok := l.superblock.BlockOffset(mapped)
	if !ok {
		return "", corruptf("Longfile block %d maps to block %d, which overflows", block, mapped)
	}
	bytes := make([]byte, int(l.superblock.BlockSize))
	if err := source.ReadExactAt(l.source, physical, bytes); err != nil {
		return "", err
	}

	length := int(l.superblock.Order.u16(bytes, 0))
	if length == 0 || length > LongNameMax {
		return "", corruptf("the long-name record in block %d declares %d bytes, outside 1..=%d",
			block, length, LongNameMax)
	}
	if length+2 > len(bytes) {
		return "", corruptf("the long-name record in block %d declares %d bytes, past its %d-byte block",
			block, length, len(bytes))
	}
	nameBytes := bytes[2 : 2+length]
	checksum := NameChecksum(nameBytes)
	if checksum != expectedChecksum {
		return "", corruptf("the long-name record in block %d has checksum 0x%08x but the directory slot stores 0x%08x",
			block, checksum, expectedChecksum)
	}
	if err := validateName(nameBytes, "a long-name record"); err != nil {
		return "", err
	}
	return lossyUTF8(nameBytes), nil
}

func validateName(bytes []byte, what string) error {
	if len(bytes) == 0 {
		return corruptf("%s has an empty name", what)
	}
	for _, value := range bytes {
		if value == 0 {
			return corruptf("%s has a NUL in its name", what)
		}
		if value == '/' {
			return corruptf("%s has a slash in its name", what)
		}
	}
	return nil
}

// readDirectory parses a directory inode's data stream.
func readDirectory(superblock *Superblock, src source.ByteSource, inode *Inode) (*Directory, error) {
	if !inode.Kind.IsDirectory() {
		return nil, corruptf("inode %d is a %s, not a directory", inode.Number, inode.Kind.Label())
	}
	if inode.Size > MaxDirectoryBytes {
		return nil, corruptf("directory inode %d declares %d bytes, more than the %d-byte cap",
			inode.Number, inode.Size, MaxDirectoryBytes)
	}
	if inode.Size == 0 {
		return nil, corruptf("directory inode %d has no data", inode.Number)
	}
	if inode.Size%DirEntrySize != 0 {
		return nil, corruptf("directory inode %d declares %d bytes, not a multiple of the %d-byte entry size",
			inode.Number, inode.Size, DirEntrySize)
	}

	blockSize := uint64(superblock.BlockSize)
	needed := (inode.Size + blockSize - 1) / blockSize
	mapResult, err := Resolve(superblock, src, inode.Ptrs, inode.Levels, needed,
		fmt.Sprintf("directory inode %d", inode.Number))
	if err != nil {
		return nil, err
	}

	directory := &Directory{
		ExtentBlocks:  mapResult.MetadataBlocks,
		ExtentRecords: mapResult.Pointers,
	}
	long := newLongfile(superblock, src)
	blockBytes := make([]byte, int(superblock.BlockSize))

	for index, block := range mapResult.Blocks {
		physical, ok := superblock.BlockOffset(block)
		if !ok {
			return nil, corruptf("directory inode %d data block %d overflows the byte address space",
				inode.Number, index)
		}
		if err := source.ReadExactAt(src, physical, blockBytes); err != nil {
			return nil, err
		}
		blockStart := uint64(index) * blockSize
		available := inode.Size - blockStart
		if available > blockSize {
			available = blockSize
		}
		if err := parseSlots(blockBytes[:available], &directory.Entries, long,
			fmt.Sprintf("directory inode %d data block %d (filesystem block %d)",
				inode.Number, index, block)); err != nil {
			return nil, err
		}
		directory.Blocks++
	}
	directory.ExtentBlocks += long.mapper.MetadataBlocks
	directory.ExtentRecords += long.mapper.Pointers
	return directory, nil
}

func parseSlots(bytes []byte, entries *[]DirEntry, long *longfile, what string) error {
	if len(bytes)%DirEntrySize != 0 {
		return corruptf("%s: %d trailing bytes are not a whole %d-byte slot",
			what, len(bytes), DirEntrySize)
	}
	order := long.superblock.Order
	for offset := 0; offset < len(bytes); offset += DirEntrySize {
		inode := order.u32(bytes, offset)
		length := bytes[offset+4]
		if inode == 0 || length == 0 {
			continue
		}
		if length == LongMarker {
			block := order.u32(bytes, offset+8)
			checksum := order.u32(bytes, offset+0x0c)
			name, err := long.name(uint64(block), checksum)
			if err != nil {
				return err
			}
			*entries = append(*entries, DirEntry{Name: name, Inode: uint64(inode)})
			continue
		}
		if int(length) > ShortNameMax {
			return corruptf("%s: slot at offset %d has name length %d, outside 1..=%d and not the 0x%02x long marker",
				what, offset, length, ShortNameMax, LongMarker)
		}
		nameBytes := bytes[offset+5 : offset+5+int(length)]
		if err := validateName(nameBytes, fmt.Sprintf("%s: slot at offset %d", what, offset)); err != nil {
			return err
		}
		*entries = append(*entries, DirEntry{Name: lossyUTF8(nameBytes), Inode: uint64(inode)})
	}
	return nil
}
