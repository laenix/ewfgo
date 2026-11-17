package gfs2

import (
	"github.com/laenix/ewfgo/internal/data/source"
)

// MaxDirectoryBytes is the largest directory stream this reader accepts.
const MaxDirectoryBytes uint64 = 64 * 1024 * 1024

// DirentFixed is the fixed part of a gfs2_dirent, before its name.
const DirentFixed = 40

// DirRecord is one named entry decoded from a directory stream.
type DirRecord struct {
	Name     string
	Formal   uint64
	Inode    uint64
	FileType uint16
}

// Directory is one directory's decoded data.
type Directory struct {
	Entries []DirRecord
	// Blocks is the data blocks read.
	Blocks uint64
	// ExtentBlocks is the indirect blocks read resolving the directory.
	ExtentBlocks uint64
	// ExtentRecords is the pointer slots examined resolving the directory.
	ExtentRecords uint64
}

// readDirectory parses a directory inode's records.
func readDirectory(superblock *Superblock, src source.ByteSource, inode *Dinode) (*Directory, error) {
	if !inode.IsDirectory() {
		return nil, corruptf("dinode block %d is a %s, not a directory", inode.Block, inode.Kind)
	}
	if inode.Size > MaxDirectoryBytes {
		return nil, corruptf("directory inode %d declares %d bytes, more than the %d-byte cap",
			inode.Block, inode.Size, MaxDirectoryBytes)
	}
	if inode.Size == 0 {
		return nil, corruptf("directory inode %d has no data", inode.Block)
	}
	if inode.IsExhash() || inode.Depth != 0 {
		return nil, unsupportedf("directory inode %d uses the hash-indexed (EXHASH) format; only the linear format is decoded", inode.Block)
	}

	directory := &Directory{}

	if inode.Height == 0 {
		if inode.Stuffed == nil {
			return nil, corruptf("stuffed directory inode %d has no inline bytes", inode.Block)
		}
		size := int(inode.Size)
		if size > len(inode.Stuffed) {
			return nil, corruptf("directory inode %d declares %d bytes but stores %d",
				inode.Block, size, len(inode.Stuffed))
		}
		if err := parseEntries(inode.Stuffed[:size], size, &directory.Entries,
			"stuffed directory inode "+u64(inode.Block)); err != nil {
			return nil, err
		}
		return directory, nil
	}

	jdata := superblock.JDataSize()
	if jdata == 0 {
		return nil, corruptf("the block size leaves no room for directory data")
	}
	blocks := (inode.Size + jdata - 1) / jdata
	blockMap, err := resolveMap(superblock, src, inode, blocks)
	if err != nil {
		return nil, err
	}
	directory.ExtentBlocks = blockMap.MetadataBlocks
	directory.ExtentRecords = blockMap.Pointers

	payloadSize := int(jdata)
	raw := make([]byte, int(superblock.BlockSize))
	for index, block := range blockMap.Blocks {
		what := "directory inode " + u64(inode.Block) + " data block " + u64(uint64(index))
		offset, ok := superblock.BlockOffset(block)
		if !ok {
			return nil, corruptf("%s overflows the byte address space", what)
		}
		if err := source.ReadExactAt(src, offset, raw); err != nil {
			return nil, err
		}
		if err := validateMeta(raw, MetaJD, FormatJD, what+" (physical block "+u64(block)+")"); err != nil {
			return nil, err
		}
		start := uint64(index) * jdata
		available := inode.Size - start
		if available > jdata {
			available = jdata
		}
		payload := raw[MetaHeaderSize : MetaHeaderSize+payloadSize]
		if err := parseEntries(payload[:int(available)], payloadSize, &directory.Entries,
			what+" (physical block "+u64(block)+")"); err != nil {
			return nil, err
		}
		directory.Blocks++
	}
	return directory, nil
}

// parseEntries decodes the dirent records in bytes. bytes is the part of the
// payload the directory's declared size reaches; window is the whole payload,
// which a trailing free record may legally fill even when the declared size
// stops earlier.
func parseEntries(bytes []byte, window int, entries *[]DirRecord, what string) error {
	available := len(bytes)
	if available > window {
		return corruptf("%s: %d bytes requested from a %d-byte payload", what, available, window)
	}
	offset := 0
	for offset < available {
		if available-offset < DirentFixed {
			return corruptf("%s: %d trailing bytes at offset %d are too short for a dirent",
				what, available-offset, offset)
		}
		formal := be64(bytes, offset)
		inode := be64(bytes, offset+8)
		recLen := int(be16(bytes, offset+0x14))
		if recLen < DirentFixed {
			return corruptf("%s: dirent at offset %d has rec_len %d, below %d",
				what, offset, recLen, DirentFixed)
		}
		if recLen%8 != 0 {
			return corruptf("%s: dirent at offset %d has rec_len %d, not a multiple of 8",
				what, offset, recLen)
		}
		if offset+recLen > window {
			return corruptf("%s: dirent at offset %d extends %d bytes, past the %d-byte block payload",
				what, offset, recLen, window)
		}
		if inode == 0 || formal == 0 {
			// A free slot may fill the rest of the block even when the
			// directory's declared size ends before it.
			if offset+recLen > available {
				return nil
			}
			offset += recLen
			continue
		}
		if offset+recLen > available {
			return corruptf("%s: dirent at offset %d extends %d bytes, past the directory's declared end %d",
				what, offset, recLen, available)
		}
		nameLen := int(be16(bytes, offset+0x16))
		if nameLen == 0 {
			return corruptf("%s: dirent at offset %d names inode %d with an empty name",
				what, offset, inode)
		}
		if DirentFixed+nameLen > recLen {
			return corruptf("%s: dirent at offset %d has name_len %d, past its rec_len %d",
				what, offset, nameLen, recLen)
		}
		fileType := be16(bytes, offset+0x18)
		if fileType > 7 {
			return corruptf("%s: dirent at offset %d has file type %d, outside 0..=7",
				what, offset, fileType)
		}
		name := bytes[offset+DirentFixed : offset+DirentFixed+nameLen]
		for _, value := range name {
			if value == 0 || value == '/' {
				return corruptf("%s: dirent at offset %d has a NUL or slash in its name", what, offset)
			}
		}
		*entries = append(*entries, DirRecord{
			Name:     string(name),
			Formal:   formal,
			Inode:    inode,
			FileType: fileType,
		})
		offset += recLen
	}
	if offset != available {
		return corruptf("%s: records end at offset %d, not the declared end %d", what, offset, available)
	}
	return nil
}
