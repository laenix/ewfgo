package erofs

import "strings"

// Directory blocks: a sorted array of 12-byte dirents, then the names.
//
//	 0  nid       u64   the named node
//	 8  nameoff   u16   the name's offset from the start of the block
//	10  file_type u8
//	11  reserved  u8
//
// The dirent array comes first and the names follow it, so the first entry's
// nameoff is also where the array ends: its value divided by twelve is the
// entry count. Each name runs to the next entry's nameoff, or to the end of
// the block's meaningful bytes for the last one, and is NUL-terminated inside
// that span. EROFS stores no "." or "..": the kernel synthesizes them, and
// this reader does not invent them.

const (
	dirEntryBytes = 12
	maxNameBytes  = 255

	fileTypeDirectory uint8 = 2
	fileTypeSymlink   uint8 = 7
	fileTypeMax       uint8 = 8
)

type dirEntry struct {
	nid        uint64
	name       string
	nameOffset int
	fileType   uint8
}

func (e dirEntry) isDirectoryHint() bool { return e.fileType == fileTypeDirectory }

// parseDirBlock parses one directory block. maxSize is the block's meaningful
// byte count: the block size, or the directory's remaining bytes in its last
// block. Bytes past it are padding and are not read.
func parseDirBlock(bytes []byte, maxSize int) ([]dirEntry, error) {
	if maxSize == 0 {
		return nil, nil
	}
	if maxSize > len(bytes) {
		return nil, corruptf("a directory block declares %d bytes but only %d are available",
			maxSize, len(bytes))
	}
	if maxSize < dirEntryBytes {
		return nil, corruptf("a directory block of %d bytes is shorter than one %d-byte dirent",
			maxSize, dirEntryBytes)
	}
	namesStart := int(uint16(bytes[8]) | uint16(bytes[9])<<8)
	if namesStart < dirEntryBytes || namesStart > maxSize {
		return nil, corruptf("the first dirent names byte %d, outside %d..=%d",
			namesStart, dirEntryBytes, maxSize)
	}
	if namesStart%dirEntryBytes != 0 {
		return nil, corruptf("the dirent array ends at %d, not on a %d-byte boundary",
			namesStart, dirEntryBytes)
	}
	count := namesStart / dirEntryBytes
	entries := make([]dirEntry, 0, count)
	for index := 0; index < count; index++ {
		at := index * dirEntryBytes
		nid := uint64(bytes[at]) | uint64(bytes[at+1])<<8 | uint64(bytes[at+2])<<16 |
			uint64(bytes[at+3])<<24 | uint64(bytes[at+4])<<32 | uint64(bytes[at+5])<<40 |
			uint64(bytes[at+6])<<48 | uint64(bytes[at+7])<<56
		if nid == 0 {
			return nil, corruptf("dirent %d names node zero", index)
		}
		nameOffset := int(uint16(bytes[at+8]) | uint16(bytes[at+9])<<8)
		fileType := bytes[at+10]
		if fileType >= fileTypeMax {
			return nil, corruptf("dirent %d names file type %d, past the defined types",
				index, fileType)
		}
		spanEnd := maxSize
		if index+1 < count {
			next := (index + 1) * dirEntryBytes
			spanEnd = int(uint16(bytes[next+8]) | uint16(bytes[next+9])<<8)
		}
		if nameOffset < namesStart {
			return nil, corruptf(
				"dirent %d's name starts at %d, inside the dirent array ending at %d",
				index, nameOffset, namesStart)
		}
		if nameOffset > spanEnd || spanEnd > maxSize {
			return nil, corruptf(
				"dirent %d's name spans %d..%d, outside the block's %d..=%d",
				index, nameOffset, spanEnd, namesStart, maxSize)
		}
		span := bytes[nameOffset:spanEnd]
		length := len(span)
		for i, b := range span {
			if b == 0 {
				length = i
				break
			}
		}
		if length == 0 {
			return nil, corruptf("dirent %d has an empty name", index)
		}
		if length > maxNameBytes {
			return nil, corruptf("dirent %d names %d bytes, more than the %d a name may hold",
				index, length, maxNameBytes)
		}
		entries = append(entries, dirEntry{
			nid:        nid,
			name:       strings.ToValidUTF8(string(span[:length]), "�"),
			nameOffset: nameOffset,
			fileType:   fileType,
		})
	}
	return entries, nil
}
