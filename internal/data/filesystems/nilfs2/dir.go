package nilfs2

// A NILFS2 directory is an ordinary file holding 12-byte-header records. An
// entry never crosses a filesystem-block boundary. An entry with inode number
// zero is a free slot and is skipped, so deleted-name recovery is not
// performed.

const (
	// MaxDirectoryBytes is the largest directory stream accepted.
	MaxDirectoryBytes uint64 = 64 * 1024 * 1024
	// DirentHeader is the fixed part of one directory entry.
	DirentHeader = 12
)

// DirEntry is one name inside a directory.
type DirEntry struct {
	Inode    uint64
	Name     string
	FileType uint8
}

// FileTypeLabel names an on-disk directory file type.
func FileTypeLabel(fileType uint8) string {
	switch fileType {
	case 1:
		return "file"
	case 2:
		return "directory"
	case 3:
		return "character device"
	case 4:
		return "block device"
	case 5:
		return "fifo"
	case 6:
		return "socket"
	case 7:
		return "symlink"
	default:
		return "unknown"
	}
}

// ParseDirectory parses exactly the declared directory bytes.
func ParseDirectory(bytes []byte, blockSize int, size uint64, what string) ([]DirEntry, error) {
	if size == 0 {
		return nil, corruptf("%s has no directory data", what)
	}
	if size > uint64(maxInt()) {
		return nil, corruptf("%s: the directory size does not fit in memory", what)
	}
	declared := int(size)
	if declared > len(bytes) {
		return nil, corruptf("%s declares %d bytes but only %d were read", what, declared, len(bytes))
	}
	if blockSize <= 0 {
		return nil, corruptf("%s: the block size is zero", what)
	}

	var entries []DirEntry
	offset := 0
	for offset < declared {
		blockEnd := (uint64(offset)/uint64(blockSize) + 1) * uint64(blockSize)
		if blockEnd > uint64(declared) || blockEnd < uint64(offset) {
			blockEnd = uint64(declared)
		}
		end := int(blockEnd)
		if end-offset < DirentHeader {
			return nil, corruptf("%s: %d trailing bytes at offset %d are too short for a directory entry",
				what, end-offset, offset)
		}
		inode := le64(bytes, offset)
		recLen := int(le16(bytes, offset+8))
		nameLen := int(bytes[offset+10])
		fileType := bytes[offset+11]
		if recLen < DirentHeader {
			return nil, corruptf("%s: entry at offset %d has rec_len %d, below %d",
				what, offset, recLen, DirentHeader)
		}
		if recLen%4 != 0 {
			return nil, corruptf("%s: entry at offset %d has rec_len %d, not a multiple of 4",
				what, offset, recLen)
		}
		if recLen > end-offset {
			return nil, corruptf("%s: entry at offset %d extends %d bytes past the block end %d",
				what, offset, recLen, end)
		}
		if inode != 0 {
			if nameLen == 0 {
				return nil, corruptf("%s: entry at offset %d names inode %d with an empty name",
					what, offset, inode)
			}
			if DirentHeader+nameLen > recLen {
				return nil, corruptf("%s: entry at offset %d has name_len %d, past its rec_len %d",
					what, offset, nameLen, recLen)
			}
			if fileType > 7 {
				return nil, corruptf("%s: entry at offset %d has file type %d, outside 0..=7",
					what, offset, fileType)
			}
			nameBytes := bytes[offset+DirentHeader : offset+DirentHeader+nameLen]
			for _, value := range nameBytes {
				if value == 0 || value == '/' {
					return nil, corruptf("%s: entry at offset %d has a NUL or slash in its name",
						what, offset)
				}
			}
			entries = append(entries, DirEntry{
				Inode:    inode,
				Name:     string(nameBytes),
				FileType: fileType,
			})
		}
		offset += recLen
	}
	if offset != declared {
		return nil, corruptf("%s: entries end at offset %d, not the declared end %d", what, offset, declared)
	}
	return entries, nil
}
