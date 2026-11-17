package befs

import "github.com/laenix/ewfgo/internal/data/source"

// Inode magic.
const InodeMagic1 uint32 = 0x3bbe_0ad9

// Inode flag bits.
const (
	InodeInUse       uint32 = 0x0001
	InodeAttrInode   uint32 = 0x0004
	InodeLogged      uint32 = 0x0008
	InodeDeleted     uint32 = 0x0010
	InodeNotReady    uint32 = 0x0020
	InodeLongSymlink uint32 = 0x0040
)

// Small-data keys that carry a file name.
const (
	FileNameType uint32 = 0x4353_5452 // 'CSTR'
	FileNameName uint8  = 0x13
)

// InodeKind is what an inode's mode bits say it is.
type InodeKind uint8

const (
	KindUnknown InodeKind = iota
	KindFile
	KindDirectory
	KindSymlink
	KindFifo
	KindSocket
	KindBlockDevice
	KindCharDevice
)

func kindFromMode(mode uint32) InodeKind {
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

// String returns the kind in words.
func (k InodeKind) String() string { return k.label() }

func (k InodeKind) label() string {
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

func (k InodeKind) isDirectory() bool { return k == KindDirectory }
func (k InodeKind) isSymlink() bool   { return k == KindSymlink }
func (k InodeKind) isFile() bool      { return k == KindFile }

// inode is one parsed BeFS inode.
type inode struct {
	block       uint64
	inodeNumber blockRun
	uid         int32
	gid         int32
	mode        uint32
	flags       uint32
	// Times are seconds from the high 48 bits; nil is the zero field.
	created    *int64
	modified   *int64
	changed    *int64
	parent     blockRun
	attributes blockRun
	kind       InodeKind
	// size is the logical length. For a short symbolic link it is the target
	// length.
	size uint64
	// data is meaningful for everything except a short symbolic link.
	data dataStream
	// shortSymlink is the raw target of a short symbolic link, no trailing NUL.
	shortSymlink []byte
	// name is the file name from the inode's small-data area, when present.
	name string
}

func (i *inode) isLongSymlink() bool {
	return i.kind.isSymlink() && i.flags&InodeLongSymlink != 0
}

func (i *inode) shortSymlinkText() string {
	if i.shortSymlink == nil {
		return ""
	}
	return string(i.shortSymlink)
}

// timestampValue converts a stored BeFS time to seconds. The zero field is
// unset.
func timestampValue(raw int64) (int64, bool) {
	if raw == 0 {
		return 0, false
	}
	return raw >> 16, true
}

// parseInode decodes one block of inode bytes.
func parseInode(raw []byte, block uint64, sb *superblock) (*inode, error) {
	if len(raw) < InodeFixedBytes {
		return nil, corruptf("inode block %d is %d bytes, shorter than the %d-byte fixed part",
			block, len(raw), InodeFixedBytes)
	}
	magic := le32(raw, 0)
	if magic != InodeMagic1 {
		return nil, corruptf("inode block %d has magic %#08x, expected %#08x", block, magic, InodeMagic1)
	}
	flags := le32(raw, 24)
	if flags&InodeInUse == 0 {
		return nil, corruptf("inode block %d is not in use", block)
	}
	if flags&InodeDeleted != 0 {
		return nil, corruptf("inode block %d is marked deleted; deleted-name recovery is not read", block)
	}
	if flags&InodeNotReady != 0 {
		return nil, corruptf("inode block %d is marked not ready", block)
	}
	if inodeSize := le32(raw, 64); inodeSize != sb.inodeSize {
		return nil, corruptf("inode block %d declares size %d, but the volume's inode size is %d",
			block, inodeSize, sb.inodeSize)
	}

	inodeNumber := parseBlockRun(raw[4:12])
	if inodeNumber.length != 1 {
		return nil, corruptf("inode block %d names itself with a run of length %d, expected 1",
			block, inodeNumber.length)
	}
	numberBlock, ok, err := sb.validateRun(inodeNumber, "the inode number")
	if err != nil {
		return nil, corruptf("inode block %d: %v", block, err)
	}
	if !ok {
		return nil, corruptf("inode block %d has no inode number", block)
	}
	if numberBlock != block {
		return nil, corruptf("inode read from block %d names itself as block %d", block, numberBlock)
	}

	parent := parseBlockRun(raw[44:52])
	if parent.length != 1 {
		return nil, corruptf("inode block %d has a parent run of length %d, expected 1", block, parent.length)
	}
	if _, ok, err := sb.validateRun(parent, "the parent inode"); err != nil {
		return nil, corruptf("inode block %d: %v", block, err)
	} else if !ok {
		return nil, corruptf("inode block %d has no parent inode", block)
	}

	attributes := parseBlockRun(raw[52:60])
	if !attributes.isZero() {
		if _, _, err := sb.validateRun(attributes, "the attribute inode"); err != nil {
			return nil, corruptf("inode block %d: %v", block, err)
		}
	}

	mode := le32(raw, 20)
	kind := kindFromMode(mode)
	data := parseDataStream(raw[72:216])

	var shortSymlink []byte
	size := data.size
	if kind.isSymlink() && flags&InodeLongSymlink == 0 {
		target := raw[72:216]
		end := -1
		for index, value := range target {
			if value == 0 {
				end = index
				break
			}
		}
		if end < 0 {
			return nil, corruptf("short symbolic link inode block %d has no terminating NUL in its 144-byte target", block)
		}
		shortSymlink = append([]byte(nil), target[:end]...)
		size = int64(end)
	} else {
		if data.size < 0 {
			return nil, corruptf("inode block %d declares a negative size %d", block, data.size)
		}
		for _, field := range []struct {
			label string
			value int64
		}{
			{"max_direct_range", data.maxDirectRange},
			{"max_indirect_range", data.maxIndirectRange},
			{"max_double_indirect_range", data.maxDoubleIndirectRange},
		} {
			if field.value < 0 {
				return nil, corruptf("inode block %d has negative %s %d", block, field.label, field.value)
			}
		}
		if data.maxIndirectRange != 0 && data.maxIndirectRange < data.maxDirectRange {
			return nil, corruptf("inode block %d ends its indirect range at %d before its direct range at %d",
				block, data.maxIndirectRange, data.maxDirectRange)
		}
		if data.maxDoubleIndirectRange != 0 && data.maxDoubleIndirectRange < data.maxIndirectRange {
			return nil, corruptf("inode block %d ends its double-indirect range at %d before its indirect range at %d",
				block, data.maxDoubleIndirectRange, data.maxIndirectRange)
		}
	}

	created, hasCreated := timestampValue(int64(le64(raw, 28)))
	modified, hasModified := timestampValue(int64(le64(raw, 36)))
	changed, hasChanged := timestampValue(int64(le64(raw, 216)))
	var createdPtr, modifiedPtr, changedPtr *int64
	if hasCreated {
		createdPtr = &created
	}
	if hasModified {
		modifiedPtr = &modified
	}
	if hasChanged {
		changedPtr = &changed
	}

	return &inode{
		block:        block,
		inodeNumber:  inodeNumber,
		uid:          int32(le32(raw, 12)),
		gid:          int32(le32(raw, 16)),
		mode:         mode,
		flags:        flags,
		created:      createdPtr,
		modified:     modifiedPtr,
		changed:      changedPtr,
		parent:       parent,
		attributes:   attributes,
		kind:         kind,
		size:         uint64(size),
		data:         data,
		shortSymlink: shortSymlink,
		name:         parseInodeName(raw, int(sb.inodeSize)),
	}, nil
}

// parseInodeName reads the file-name small-data attribute from the inode.
func parseInodeName(raw []byte, inodeSize int) string {
	end := inodeSize
	if end > len(raw) {
		end = len(raw)
	}
	offset := InodeFixedBytes
	for offset+8 <= end {
		kind := le32(raw, offset)
		nameSize := int(le16(raw, offset+4))
		dataSize := int(le16(raw, offset+6))
		if nameSize == 0 {
			return ""
		}
		size := 8 + nameSize + 3 + dataSize + 1
		next := offset + size
		if next < offset || next > end {
			return ""
		}
		nameStart := offset + 8
		nameEnd := nameStart + nameSize
		if nameEnd > end {
			return ""
		}
		if kind == FileNameType && nameSize == 1 && raw[nameStart] == FileNameName {
			dataStart := nameEnd + 3
			dataEnd := dataStart + dataSize
			if dataEnd > end {
				return ""
			}
			data := raw[dataStart:dataEnd]
			used := len(data)
			for index, value := range data {
				if value == 0 {
					used = index
					break
				}
			}
			if used == 0 {
				return ""
			}
			return lossyUTF8(data[:used])
		}
		offset = next
	}
	return ""
}

// readInode reads one inode block.
func readInode(src source.ByteSource, sb *superblock, block uint64) (*inode, error) {
	offset := sb.inodeOffset(block)
	if offset == ^uint64(0) {
		return nil, corruptf("inode block %d overflows the byte address space", block)
	}
	size := int(sb.inodeSize)
	if size <= 0 {
		return nil, corruptf("the inode size %d does not fit in memory", sb.inodeSize)
	}
	raw := make([]byte, size)
	if err := source.ReadExactAt(src, offset, raw); err != nil {
		return nil, err
	}
	return parseInode(raw, block, sb)
}
