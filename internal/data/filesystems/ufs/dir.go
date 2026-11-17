package ufs

import (
	"bytes"
	"strings"
)

// Directory record constants.
const (
	// DirBlockSize is the unit a directory record may not cross.
	DirBlockSize = 512
	// DirEntHeader is the bytes before a record's name.
	DirEntHeader = 8
	// MaxDirSize is the largest directory this reader walks; the kernel's own
	// limit.
	MaxDirSize uint64 = 0x7fff_ffff
)

// Directory entry types (d_type). The values equal (mode & S_IFMT) >> 12.
const (
	DTUnknown uint8 = 0
	DTFifo    uint8 = 1
	DTChr     uint8 = 2
	DTDir     uint8 = 4
	DTBlk     uint8 = 6
	DTReg     uint8 = 8
	DTLnk     uint8 = 10
	DTSock    uint8 = 12
	DTWht     uint8 = 14
)

// Rust-style aliases for the same on-disk values.
const (
	DT_UNKNOWN = DTUnknown
	DT_FIFO    = DTFifo
	DT_CHR     = DTChr
	DT_DIR     = DTDir
	DT_BLK     = DTBlk
	DT_REG     = DTReg
	DT_LNK     = DTLnk
	DT_SOCK    = DTSock
	DT_WHT     = DTWht
)

// direntLen returns the bytes a record with a namlen-byte name must occupy at
// least.
func direntLen(namlen int) int {
	return (DirEntHeader + namlen + 1 + 3) &^ 3
}

// KindForMode maps a mode onto its d_type value.
func KindForMode(mode uint16) uint8 { return uint8((mode & SIFMT) >> 12) }

// KindIsDirectory reports whether a d_type names a directory. The second
// result is false when the value carries no usable type.
func KindIsDirectory(kind uint8) (isDir bool, known bool) {
	switch kind {
	case DTUnknown, DTWht:
		return false, false
	case DTDir:
		return true, true
	case DTFifo, DTChr, DTBlk, DTReg, DTLnk, DTSock:
		return false, true
	default:
		return false, false
	}
}

// KindName returns a display name for a d_type value.
func KindName(kind uint8) string {
	switch kind {
	case DTFifo:
		return "fifo"
	case DTChr:
		return "character device"
	case DTDir:
		return "directory"
	case DTBlk:
		return "block device"
	case DTReg:
		return "regular file"
	case DTLnk:
		return "symbolic link"
	case DTSock:
		return "socket"
	case DTWht:
		return "whiteout"
	default:
		return "unknown"
	}
}

// UsesOldFormat reports whether fs_maxsymlinklen marks old-format
// directories, which store d_namlen where d_type lives.
func UsesOldFormat(maxSymlinkLen int32) bool { return maxSymlinkLen <= 0 }

// CheckDirSize refuses a directory larger than the format's limit.
func CheckDirSize(size uint64) error {
	if size > MaxDirSize {
		return corruptf("directory size %d is past the format's %d-byte limit", size, MaxDirSize)
	}
	return nil
}

// DirRecord is one directory record that names an inode.
type DirRecord struct {
	Inode uint32
	// Kind is d_type; always DTUnknown on an old-format volume.
	Kind uint8
	Name string
	// Offset is the byte offset of the record inside the directory's data.
	Offset uint64
	// RecordLength may exceed the record's minimum size.
	RecordLength uint16
}

// SlackRecord is a record still legible in the slack behind a live record.
//
// FFS does not write a tombstone: a deletion merges the entry into its
// predecessor by growing d_reclen. The predecessor's declared name ends
// earlier than d_reclen, so the bytes between them can still hold the old
// record. They are residue and are never reported as live names.
type SlackRecord struct {
	Inode  uint32
	Kind   uint8
	Name   string
	Offset uint64
}

// DirBlock is one parsed directory buffer.
type DirBlock struct {
	Entries []DirRecord
	// Tiled is false when a record was malformed; entries before it hold.
	Tiled bool
	// FreedBytes is the bytes freed records cover.
	FreedBytes uint64
	// Whiteouts counts union-mount whiteouts, which name no file.
	Whiteouts uint64
	// Slack holds residue behind live records.
	Slack []SlackRecord
}

// ParseDirBlock parses one buffer of directory data. baseOffset is where the
// buffer starts inside the directory, so each record's Offset addresses the
// directory's own bytes.
func ParseDirBlock(raw []byte, baseOffset uint64, endian Endian, oldFormat bool) DirBlock {
	block := DirBlock{Tiled: true}
	pos := 0
	for pos+DirEntHeader <= len(raw) {
		chunkEnd := ((pos / DirBlockSize) + 1) * DirBlockSize
		if chunkEnd > len(raw) {
			chunkEnd = len(raw)
		}
		if chunkEnd-pos < DirEntHeader {
			pos = chunkEnd
			continue
		}
		inode := endian.U32(raw, pos)
		reclen := int(endian.U16(raw, pos+4))
		if inode == 0 {
			if reclen >= DirEntHeader && reclen%4 == 0 && pos+reclen <= chunkEnd {
				block.FreedBytes += uint64(reclen)
				pos += reclen
				continue
			}
			block.FreedBytes += uint64(chunkEnd - pos)
			pos = chunkEnd
			continue
		}
		kind := uint8(DTUnknown)
		namlen := 0
		if oldFormat {
			namlen = int(raw[pos+6])
		} else {
			kind = raw[pos+6]
			namlen = int(raw[pos+7])
		}
		minimum := direntLen(namlen)
		if namlen > MaxNameLen || reclen < minimum || reclen%4 != 0 || pos+reclen > chunkEnd {
			block.Tiled = false
			break
		}
		if inode == Wino {
			block.Whiteouts++
			pos += reclen
			continue
		}
		name := lossyUTF8(raw[pos+DirEntHeader : pos+DirEntHeader+namlen])
		block.Entries = append(block.Entries, DirRecord{
			Inode:        inode,
			Kind:         kind,
			Name:         name,
			Offset:       baseOffset + uint64(pos),
			RecordLength: uint16(reclen),
		})
		if minimum < reclen {
			parseSlack(raw, pos+minimum, pos+reclen, baseOffset, endian, oldFormat, &block.Slack)
		}
		pos += reclen
	}
	return block
}

// parseSlack walks the bytes between a live record's declared name and the end
// of its grown d_reclen. Only a record that parses completely inside the slack
// is returned; malformed residue stops the walk and never marks the block
// untiled.
func parseSlack(raw []byte, cursor, recordEnd int, baseOffset uint64, endian Endian, oldFormat bool, out *[]SlackRecord) {
	for cursor+DirEntHeader <= recordEnd {
		inode := endian.U32(raw, cursor)
		if inode == 0 {
			break
		}
		reclen := int(endian.U16(raw, cursor+4))
		kind := uint8(DTUnknown)
		namlen := 0
		if oldFormat {
			namlen = int(raw[cursor+6])
		} else {
			kind = raw[cursor+6]
			namlen = int(raw[cursor+7])
		}
		if inode == Wino || namlen == 0 || namlen > MaxNameLen ||
			reclen < direntLen(namlen) || reclen%4 != 0 || cursor+reclen > recordEnd {
			break
		}
		nameBytes := raw[cursor+DirEntHeader : cursor+DirEntHeader+namlen]
		if bytes.IndexByte(nameBytes, 0) >= 0 || bytes.IndexByte(nameBytes, '/') >= 0 {
			break
		}
		name := lossyUTF8(nameBytes)
		if name == "." || name == ".." {
			cursor += reclen
			continue
		}
		*out = append(*out, SlackRecord{
			Inode:  inode,
			Kind:   kind,
			Name:   name,
			Offset: baseOffset + uint64(cursor),
		})
		cursor += reclen
	}
}

// ParseDirectory parses a whole directory's data.
func ParseDirectory(raw []byte, oldFormat bool, endian Endian) DirBlock {
	return ParseDirBlock(raw, 0, endian, oldFormat)
}

func lossyUTF8(raw []byte) string {
	return strings.ToValidUTF8(string(raw), "�")
}
