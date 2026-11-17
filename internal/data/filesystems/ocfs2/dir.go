package ocfs2

import (
	"github.com/laenix/ewfgo/internal/data/source"
)

// A linear OCFS2 directory is a stream of 12-byte-header records. rec_len tiles
// each block exactly; an inode number of zero is a free or deleted slot and is
// skipped, so deleted-name recovery is not read. When the volume carries
// META_ECC, every directory block ends with a 64-byte DIRTRL1 trailer.

const (
	// MaxDirectoryBytes is the largest directory stream accepted.
	MaxDirectoryBytes uint64 = 64 * 1024 * 1024
	// DirMemberLen is the fixed part of one directory entry.
	DirMemberLen = 12
	// DirMinRecLen is the smallest rec_len OCFS2 writes.
	DirMinRecLen = 16
	// DirTrailerSize is the metadata-ECC directory trailer size.
	DirTrailerSize = 64
)

// DirTrailerSignature is the trailer's signature.
var DirTrailerSignature = []byte("DIRTRL1")

// DirEntry is one name inside a directory.
type DirEntry struct {
	Name     string
	Inode    uint64
	FileType uint8
}

// Directory is one directory's decoded data.
type Directory struct {
	Entries       []DirEntry
	Blocks        uint64
	ExtentBlocks  uint64
	ExtentRecords uint64
}

// ReadDirectory parses a directory inode's records.
func ReadDirectory(superblock *Superblock, src source.ByteSource, inode *Inode, id source.ID) (*Directory, error) {
	if !inode.Kind.IsDirectory() {
		return nil, corruptf("inode block %d is a %s, not a directory", inode.Block, inode.Kind.Label())
	}
	if inode.Size > MaxDirectoryBytes {
		return nil, corruptf("directory inode %d declares %d bytes, more than the %d-byte cap",
			inode.Block, inode.Size, MaxDirectoryBytes)
	}

	if inode.Inline != nil {
		directory := &Directory{}
		entries, err := parseDirEntries(inode.Inline, 0, len(inode.Inline),
			"inline directory inode "+u64Text(inode.Block))
		if err != nil {
			return nil, err
		}
		directory.Entries = entries
		return directory, nil
	}

	if inode.Size == 0 {
		return nil, corruptf("directory inode %d has no data", inode.Block)
	}
	blockSize := int(superblock.BlockSize)
	if inode.Size%uint64(superblock.BlockSize) != 0 {
		return nil, corruptf("directory inode %d declares %d bytes, not a whole number of %d-byte blocks",
			inode.Block, inode.Size, superblock.BlockSize)
	}
	file, err := newOcfs2FileSource(id, src, superblock, inode)
	if err != nil {
		return nil, err
	}
	directory := &Directory{
		ExtentBlocks:  file.ExtentBlocksRead(),
		ExtentRecords: file.ExtentRecords(),
	}
	blocks := inode.Size / uint64(superblock.BlockSize)
	buf := make([]byte, blockSize)
	for index := uint64(0); index < blocks; index++ {
		offset := index * uint64(superblock.BlockSize)
		got, err := file.readAt(offset, buf)
		if err != nil {
			return nil, err
		}
		if got != blockSize {
			return nil, corruptf("directory inode %d block %d returned %d of %d bytes",
				inode.Block, index, got, blockSize)
		}
		limit := blockSize
		if superblock.MetaECC() {
			if blockSize <= DirTrailerSize {
				return nil, corruptf("block size %d is too small for the %d-byte directory trailer",
					blockSize, DirTrailerSize)
			}
			if err := validateDirTrailer(file, inode, offset, buf, blockSize); err != nil {
				return nil, err
			}
			limit = blockSize - DirTrailerSize
		}
		entries, err := parseDirEntries(buf, 0, limit,
			"directory inode "+u64Text(inode.Block)+" block "+u64Text(index))
		if err != nil {
			return nil, err
		}
		directory.Entries = append(directory.Entries, entries...)
		directory.Blocks++
	}
	return directory, nil
}

func validateDirTrailer(file *Ocfs2FileSource, inode *Inode, offset uint64, block []byte, blockSize int) error {
	at := blockSize - DirTrailerSize
	if !hasSignature(block[at+0x10:], DirTrailerSignature) {
		return corruptf("directory inode %d: the block at logical byte %d has no DIRTRL1 trailer",
			inode.Block, offset)
	}
	named := le64(block, at+0x28)
	expected, err := file.PhysicalBlockAt(offset)
	if err != nil {
		return err
	}
	if named != expected {
		return corruptf("directory inode %d: the trailer of physical block %d names block %d",
			inode.Block, expected, named)
	}
	parent := le64(block, at+0x30)
	if parent != inode.Block {
		return corruptf("directory inode %d: the trailer of block %d names parent inode %d",
			inode.Block, expected, parent)
	}
	return nil
}

func parseDirEntries(bytes []byte, offset, limit int, what string) ([]DirEntry, error) {
	if limit > len(bytes) {
		return nil, corruptf("%s: %d bytes requested from a %d-byte buffer", what, limit, len(bytes))
	}
	var entries []DirEntry
	for offset < limit {
		if limit-offset < DirMemberLen {
			return nil, corruptf("%s: %d trailing bytes at offset %d are too short for a directory entry",
				what, limit-offset, offset)
		}
		inode := le64(bytes, offset)
		recLen := int(le16(bytes, offset+8))
		nameLen := int(bytes[offset+10])
		fileType := bytes[offset+11]
		if recLen < DirMinRecLen {
			return nil, corruptf("%s: entry at offset %d has rec_len %d, below %d",
				what, offset, recLen, DirMinRecLen)
		}
		if recLen%4 != 0 {
			return nil, corruptf("%s: entry at offset %d has rec_len %d, not a multiple of 4",
				what, offset, recLen)
		}
		if recLen > limit-offset {
			return nil, corruptf("%s: entry at offset %d extends %d bytes, past the usable end %d",
				what, offset, recLen, limit)
		}
		if inode == 0 {
			offset += recLen
			continue
		}
		if nameLen == 0 {
			return nil, corruptf("%s: entry at offset %d names inode %d with an empty name",
				what, offset, inode)
		}
		if DirMemberLen+nameLen > recLen {
			return nil, corruptf("%s: entry at offset %d has name_len %d, past its rec_len %d",
				what, offset, nameLen, recLen)
		}
		if fileType > 7 {
			return nil, corruptf("%s: entry at offset %d has file type %d, outside 0..=7",
				what, offset, fileType)
		}
		nameBytes := bytes[offset+DirMemberLen : offset+DirMemberLen+nameLen]
		for _, value := range nameBytes {
			if value == 0 || value == '/' {
				return nil, corruptf("%s: entry at offset %d has a NUL or slash in its name",
					what, offset)
			}
		}
		entries = append(entries, DirEntry{Name: string(nameBytes), Inode: inode, FileType: fileType})
		offset += recLen
	}
	if offset != limit {
		return nil, corruptf("%s: entries end at offset %d, not the usable end %d", what, offset, limit)
	}
	return entries, nil
}
