package reiserfs

import "unicode/utf8"

// ReiserFS directory items: entry headers followed by names. A name's length is
// the distance to the next header's location; the last name runs to the end of
// the item body.
const (
	// DEHeadLen is the bytes in one directory entry header.
	DEHeadLen = 16
	// DEHStatdata is the reserved "entry has stat data" bit.
	DEHStatdata uint16 = 1 << 0
	// DEHVisible is set on a live name.
	DEHVisible uint16 = 1 << 2
	// DEHBadOffset marks an entry fsck wants deleted.
	DEHBadOffset uint16 = 1 << 4
	// DEHBadLocation marks a name offset known to be wrong.
	DEHBadLocation uint16 = 1 << 5
)

// DirEntry is one decoded directory entry.
type DirEntry struct {
	// Offset is the hash word stored in deh_offset.
	Offset uint32
	// DirID is the entry's parent directory object id.
	DirID uint32
	// ObjectID is the referenced object id.
	ObjectID uint32
	// Location is the name's offset inside the item body.
	Location uint16
	// State is the raw deh_state word.
	State uint16
	// Name is the name decoded as UTF-8 with invalid bytes replaced.
	Name string
}

// IsVisible reports a live name.
func (e DirEntry) IsVisible() bool { return e.State&DEHVisible != 0 }

// IsHidden reports a name unlinked but not yet compacted away.
func (e DirEntry) IsHidden() bool { return !e.IsVisible() }

// HasBadOffset reports fsck's delete mark.
func (e DirEntry) HasBadOffset() bool { return e.State&DEHBadOffset != 0 }

// HasBadLocation reports a known-wrong name offset.
func (e DirEntry) HasBadLocation() bool { return e.State&DEHBadLocation != 0 }

// IsFlagged reports either fsck flag.
func (e DirEntry) IsFlagged() bool { return e.HasBadOffset() || e.HasBadLocation() }

// ParseDirectoryItem decodes a directory item body. Hidden names are returned
// too; they are real evidence.
func ParseDirectoryItem(body []byte, entryCount uint16) ([]DirEntry, error) {
	return parseDirectoryItem(body, entryCount)
}

func parseDirectoryItem(body []byte, entryCount uint16) ([]DirEntry, error) {
	count := int(entryCount)
	if count == 0 {
		return []DirEntry{}, nil
	}
	headersLen := count * DEHeadLen
	if headersLen < count || headersLen > len(body) {
		return nil, corruptf("a directory item declares %d entries, needing %d bytes, but its body is %d bytes",
			count, headersLen, len(body))
	}
	locations := make([]int, count)
	for index := 0; index < count; index++ {
		at := index * DEHeadLen
		location := int(le16(body, at+12))
		if location < headersLen || location > len(body) {
			return nil, corruptf("directory entry %d puts its name at %d, outside the name area %d..%d",
				index, location, headersLen, len(body))
		}
		locations[index] = location
	}
	entries := make([]DirEntry, 0, count)
	for index := 0; index < count; index++ {
		at := index * DEHeadLen
		start := locations[index]
		end := len(body)
		if index+1 < count {
			end = locations[index+1]
		}
		if end < start {
			return nil, corruptf("directory entry %d has a name that ends before it begins (%d..%d)",
				index, start, end)
		}
		name := body[start:end]
		for len(name) > 0 && name[len(name)-1] == 0 {
			name = name[:len(name)-1]
		}
		entries = append(entries, DirEntry{
			Offset:   le32(body, at),
			DirID:    le32(body, at+4),
			ObjectID: le32(body, at+8),
			Location: le16(body, at+12),
			State:    le16(body, at+14),
			Name:     lossyUTF8(name),
		})
	}
	return entries, nil
}

// parseDirectoryTail decodes a directory tail stored as a direct item. A
// directory has no file-data stream, so such a body cannot be file bytes: its
// item-head count is still the entry count.
func parseDirectoryTail(body []byte, entryCount uint16) ([]DirEntry, error) {
	if entryCount == 0 && len(body) > 0 {
		return nil, corruptf("a directory tail declares 0 entries but its body is %d bytes", len(body))
	}
	return parseDirectoryItem(body, entryCount)
}

func lossyUTF8(raw []byte) string {
	if utf8.Valid(raw) {
		return string(raw)
	}
	out := make([]rune, 0, len(raw))
	for len(raw) > 0 {
		r, size := utf8.DecodeRune(raw)
		if r == utf8.RuneError && size == 1 {
			out = append(out, utf8.RuneError)
			raw = raw[1:]
			continue
		}
		out = append(out, r)
		raw = raw[size:]
	}
	return string(out)
}
