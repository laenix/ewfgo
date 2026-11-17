package minix

import (
	"encoding/binary"
	"strings"
)

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

// parseDir parses a directory's `bytes`. A slot whose inode number is zero is
// an unused slot; a slot with a non-zero inode and an empty name cannot be a
// name a writer produced, and a trailing partial slot is counted the same way.
func parseDir(bytes []byte, entrySize, nameLen int, magic uint16) (*listing, error) {
	if entrySize != 16 && entrySize != 32 && entrySize != 64 {
		return nil, corruptf("a directory entry size of %d bytes", entrySize)
	}
	if nameLen == 0 || nameLen > entrySize {
		return nil, corruptf("a %d-byte name inside a %d-byte directory entry", nameLen, entrySize)
	}
	inodeSize := 2
	if entrySize == 64 {
		inodeSize = 4
	}
	if magic == magicV3 && inodeSize != 4 {
		return nil, corruptf("a V3 directory with a two-byte inode field")
	}

	out := &listing{}
	whole := len(bytes) / entrySize
	for slot := 0; slot < whole; slot++ {
		chunk := bytes[slot*entrySize : slot*entrySize+entrySize]
		var inode uint32
		if inodeSize == 4 {
			inode = binary.LittleEndian.Uint32(chunk)
		} else {
			inode = uint32(binary.LittleEndian.Uint16(chunk))
		}
		if inode == 0 {
			out.empty++
			continue
		}
		nameBytes := chunk[inodeSize : inodeSize+nameLen]
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
	if len(bytes)%entrySize != 0 {
		out.malformed++
	}
	return out, nil
}
