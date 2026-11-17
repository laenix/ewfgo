package squashfs

import (
	stdbytes "bytes"
	"encoding/binary"
	"math"
)

const (
	dirHeaderBytes      = 12
	dirEntryBytes       = 8
	maxEntriesPerHeader = 256
	maxNameBytes        = 256
)

// dirEntry is one name inside a directory.
type dirEntry struct {
	inodeRef    uint64
	inodeOffset uint16
	inodeNumber uint32
	inodeType   uint16
	name        string
}

// parseDir parses one directory's listing. bytes is exactly the directory
// inode's file_size, so a header or entry that would run past the end is
// corruption rather than a directory that ended early.
func parseDir(bytes []byte) ([]dirEntry, error) {
	var entries []dirEntry
	at := 0
	for at < len(bytes) {
		if at+dirHeaderBytes > len(bytes) {
			return nil, corruptf("a directory header at %d does not fit in the %d listing bytes",
				at, len(bytes))
		}
		count := uint64(binary.LittleEndian.Uint32(bytes[at:])) + 1
		if count > maxEntriesPerHeader {
			return nil, corruptf("a directory header announces %d entries, more than %d",
				count, maxEntriesPerHeader)
		}
		startBlock := binary.LittleEndian.Uint32(bytes[at+4:])
		baseInode := binary.LittleEndian.Uint32(bytes[at+8:])
		at += dirHeaderBytes

		for i := uint64(0); i < count; i++ {
			if at+dirEntryBytes > len(bytes) {
				return nil, corruptf("a directory entry at %d does not fit in the %d listing bytes",
					at, len(bytes))
			}
			inodeOffset := binary.LittleEndian.Uint16(bytes[at:])
			delta := int16(binary.LittleEndian.Uint16(bytes[at+2:]))
			inodeType := binary.LittleEndian.Uint16(bytes[at+4:])
			nameLen := int(binary.LittleEndian.Uint16(bytes[at+6:])) + 1
			at += dirEntryBytes
			if nameLen > maxNameBytes {
				return nil, corruptf("a directory entry names %d bytes, more than %d",
					nameLen, maxNameBytes)
			}
			if at+nameLen > len(bytes) {
				return nil, corruptf("a directory name at %d runs past the %d listing bytes",
					at, len(bytes))
			}
			nameBytes := bytes[at : at+nameLen]
			at += nameLen
			if stdbytes.IndexByte(nameBytes, '/') >= 0 || stdbytes.IndexByte(nameBytes, 0) >= 0 {
				return nil, corruptf("a directory name contains a separator or NUL")
			}
			inodeNumber := int64(baseInode) + int64(delta)
			if inodeNumber < 0 || inodeNumber > int64(math.MaxUint32) {
				return nil, corruptf("a directory entry's inode number is out of range")
			}
			if inodeType == 0 || inodeType > 7 {
				return nil, corruptf("a directory entry records type %d, which does not exist", inodeType)
			}
			entries = append(entries, dirEntry{
				inodeRef:    uint64(startBlock)<<16 | uint64(inodeOffset),
				inodeOffset: inodeOffset,
				inodeNumber: uint32(inodeNumber),
				inodeType:   inodeType,
				name:        string(nameBytes),
			})
		}
	}
	return entries, nil
}
