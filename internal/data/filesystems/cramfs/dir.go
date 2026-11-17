package cramfs

import "strings"

// Directory listings: inodes with their names, one after another.
//
// A directory's "size" is the byte length of its listing. The listing is a
// sequence of entries — a twelve-byte inode followed by the name padded to a
// multiple of four — with no header, no count and no "." or "..". A writer may
// pad the tail with zero bytes; an all-zero inode cannot name anything, so it
// ends the listing. A padded name area that is entirely zero is an error,
// because a zero-length name would become an entry that cannot be addressed.

// dirEntry is one name inside a directory.
type dirEntry struct {
	inode  inode
	name   string
	offset uint64 // absolute image offset where the entry's inode starts
}

// parseDir parses one directory's listing. start is the listing's absolute
// image offset, against which each entry's position is reported.
func parseDir(bytes []byte, start uint64) ([]dirEntry, error) {
	var entries []dirEntry
	at := 0
	for at < len(bytes) {
		if at+inodeBytes > len(bytes) {
			return nil, corruptf("an inode at %d does not fit in the %d listing bytes",
				at, len(bytes))
		}
		raw := bytes[at : at+inodeBytes]
		entryOffset := start + uint64(at)
		if isPadding(raw) {
			break
		}
		in, err := parseInode(raw)
		if err != nil {
			return nil, err
		}
		nameBytes := int(in.nameWords) * 4
		if nameBytes > maxNameBytes {
			return nil, corruptf("an entry at %d declares a %d-byte name",
				entryOffset, nameBytes)
		}
		nameStart := at + inodeBytes
		nameEnd := nameStart + nameBytes
		if nameEnd > len(bytes) {
			return nil, corruptf("the name of the entry at %d runs past the listing",
				entryOffset)
		}
		padded := bytes[nameStart:nameEnd]
		length := len(padded)
		for length > 0 && padded[length-1] == 0 {
			length--
		}
		if length == 0 {
			return nil, corruptf("the entry at %d has no name", entryOffset)
		}
		entries = append(entries, dirEntry{
			inode:  in,
			name:   strings.ToValidUTF8(string(padded[:length]), "�"),
			offset: entryOffset,
		})
		at = nameEnd
	}
	return entries, nil
}
