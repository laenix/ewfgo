package sysv

import "strings"

// dirEntry is one directory slot that names an inode.
type dirEntry struct {
	inode uint32
	name  string
	slot  uint64
}

// listing is what one directory's bytes parsed into.
type listing struct {
	entries   []dirEntry
	empty     uint64
	malformed uint64
}

// parseDir parses a directory's bytes. Every verified variant stores a 16-bit
// inode number in the filesystem's byte order followed by a 14-byte name. A
// zero inode is a free slot; a non-zero inode with an empty name and a
// trailing partial record are counted as malformed.
func parseDir(bytes []byte, order byteOrder) (*listing, error) {
	out := &listing{}
	whole := len(bytes) / directoryEntrySize
	for slot := 0; slot < whole; slot++ {
		chunk := bytes[slot*directoryEntrySize : slot*directoryEntrySize+directoryEntrySize]
		inode := uint32(order.u16(chunk, 0))
		if inode == 0 {
			out.empty++
			continue
		}
		nameBytes := chunk[2 : 2+nameLength]
		end := len(nameBytes)
		for index, value := range nameBytes {
			if value == 0 {
				end = index
				break
			}
		}
		if end == 0 {
			out.malformed++
			continue
		}
		out.entries = append(out.entries, dirEntry{
			inode: inode,
			name:  strings.ToValidUTF8(string(nameBytes[:end]), "�"),
			slot:  uint64(slot),
		})
	}
	if len(bytes)%directoryEntrySize != 0 {
		out.malformed++
	}
	return out, nil
}
