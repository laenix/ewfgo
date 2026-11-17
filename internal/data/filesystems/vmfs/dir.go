package vmfs

import (
	"bytes"

	"github.com/laenix/ewfgo/internal/data/source"
)

// A VMFS5/VMFS6 directory is a stream of 288-byte records:
//
//	0x000 file_type   u32   0 unused/deleted, 1 file, 2 directory, 3 symlink
//	0x004 block_id    u32   the file descriptor's block id
//	0x008 record_id   u32   the descriptor's generation (id2)
//	0x00c name[276]         NUL-terminated
//
// "." and ".." are ordinary records. A record with type zero is an unused or
// deleted slot: its name is reported when one is still present, but
// deleted-file recovery is not read and no such name becomes a catalog entry.
// A live record whose name is not NUL-terminated, is empty, contains a slash,
// names a zero block id, or has an unknown type is refused by name with its
// byte offset. A trailing partial record is accepted only when it is all-zero
// padding.
const (
	// maxDirectoryBytes is the largest directory stream accepted.
	maxDirectoryBytes uint64 = 64 * 1024 * 1024
	// direntSize is the byte span of one directory record.
	direntSize = 288
	// direntMemberLen is the fixed part of one record.
	direntMemberLen = 12
	// direntNameLen is the name field of one record.
	direntNameLen = direntSize - direntMemberLen
	// maxUnusedNames is the number of deleted names kept per directory.
	maxUnusedNames = 16
)

// dirEntry is one live name inside a directory.
type dirEntry struct {
	name     string
	blockID  uint32
	recordID uint32
	fileType uint32
}

func (e dirEntry) isFile() bool      { return e.fileType == 1 }
func (e dirEntry) isDirectory() bool { return e.fileType == 2 }
func (e dirEntry) isSymlink() bool   { return e.fileType == 3 }

// dirListing is one directory's decoded data.
type dirListing struct {
	entries []dirEntry
	// unusedSlots counts type-zero slots, including all-zero padding records.
	unusedSlots uint64
	// unusedNames holds names still readable in type-zero slots, bounded.
	unusedNames []string
	// blocks is the number of 1 MiB directory blocks read.
	blocks uint64
	// extentBlocks is the number of pointer blocks read resolving the stream.
	extentBlocks uint64
	// extentRecords is the number of file-block addresses examined.
	extentRecords uint64
}

// readDir reads and parses a directory descriptor's stream.
func readDir(sb *superblock, src source.ByteSource, in *inode, pbc *pbc) (*dirListing, error) {
	if !in.kind.isDirectory() {
		return nil, corruptf("file descriptor 0x%08x at byte 0x%x is a %s, not a directory",
			in.blockID, in.at, in.kind.label())
	}
	if in.size > maxDirectoryBytes {
		return nil, corruptf("directory descriptor 0x%08x declares %d bytes, more than the %d-byte cap",
			in.blockID, in.size, maxDirectoryBytes)
	}
	if in.size == 0 {
		return nil, corruptf("directory descriptor 0x%08x at byte 0x%x has no data", in.blockID, in.at)
	}

	file, err := newFileSource(src.SourceID(), src, sb, in, pbc)
	if err != nil {
		return nil, err
	}
	data := make([]byte, int(in.size))
	if err := source.ReadExactAt(file, 0, data); err != nil {
		return nil, err
	}

	listing := &dirListing{
		extentBlocks:  file.extentBlocksRead(),
		extentRecords: file.extentRecords(),
	}
	listing.blocks = (in.size + uint64(sb.blockSize) - 1) / uint64(sb.blockSize)
	if listing.blocks == 0 {
		listing.blocks = 1
	}

	offset := 0
	for offset+direntSize <= len(data) {
		record := data[offset : offset+direntSize]
		fileType := le32(record, 0)
		blockID := le32(record, 4)
		recordID := le32(record, 8)
		if fileType == 0 {
			listing.unusedSlots++
			if len(listing.unusedNames) < maxUnusedNames {
				nameField := record[direntMemberLen:]
				nameLen := bytes.IndexByte(nameField, 0)
				if nameLen < 0 {
					nameLen = len(nameField)
				}
				if nameLen > 0 && !bytes.ContainsRune(nameField[:nameLen], '/') {
					listing.unusedNames = append(listing.unusedNames, string(nameField[:nameLen]))
				}
			}
			offset += direntSize
			continue
		}
		if blockType(blockID) != blkTypeFD {
			return nil, corruptf("directory descriptor 0x%08x: the live entry at stream byte %d has type %d but names block id 0x%08x of type %d, not a file descriptor (type %d)",
				in.blockID, offset, fileType, blockID, blockType(blockID), blkTypeFD)
		}
		nameField := record[direntMemberLen:]
		nameLen := bytes.IndexByte(nameField, 0)
		if nameLen < 0 {
			return nil, corruptf("directory descriptor 0x%08x: the entry at stream byte %d has no NUL in its %d-byte name field",
				in.blockID, offset, direntNameLen)
		}
		if nameLen == 0 {
			return nil, corruptf("directory descriptor 0x%08x: the live entry at stream byte %d has an empty name", in.blockID, offset)
		}
		if bytes.ContainsRune(nameField[:nameLen], '/') {
			return nil, corruptf("directory descriptor 0x%08x: the entry at stream byte %d has a slash in its name", in.blockID, offset)
		}
		switch fileType {
		case 1, 2, 3:
		case 4, 5:
			return nil, unsupportedf("directory descriptor 0x%08x: the entry at stream byte %d is an RDM/raw-device descriptor (type %d), which is not decoded",
				in.blockID, offset, fileType)
		default:
			return nil, corruptf("directory descriptor 0x%08x: the entry at stream byte %d has unknown type %d",
				in.blockID, offset, fileType)
		}
		listing.entries = append(listing.entries, dirEntry{
			name:     string(nameField[:nameLen]),
			blockID:  blockID,
			recordID: recordID,
			fileType: fileType,
		})
		offset += direntSize
	}
	if offset < len(data) {
		for _, b := range data[offset:] {
			if b != 0 {
				return nil, corruptf("directory descriptor 0x%08x: %d trailing bytes at stream byte %d are too short for a %d-byte record and are not zero padding",
					in.blockID, len(data)-offset, offset, direntSize)
			}
		}
	}
	return listing, nil
}
