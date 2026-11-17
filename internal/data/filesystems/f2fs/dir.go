package f2fs

// Directory block layout constants.
const (
	DirSlotSize        = 8
	DirEntrySize       = 11
	DirEntriesPerBlock = 214
	DirBitmapSize      = (DirEntriesPerBlock + 7) / 8
	DirReservedSize    = 3
	DirEntryOffset     = DirBitmapSize + DirReservedSize
	DirFilenameOffset  = DirEntryOffset + DirEntriesPerBlock*DirEntrySize
	DirFilenameBytes   = DirEntriesPerBlock * DirSlotSize
	DirBlockSize       = DirFilenameOffset + DirFilenameBytes
	DirMaxNameLen      = 255
)

// Directory entry file types, matching the platform's DT_* values.
const (
	DTUnknown uint8 = 0
	DTFifo    uint8 = 1
	DTChr     uint8 = 2
	DTDir     uint8 = 4
	DTBlk     uint8 = 6
	DTReg     uint8 = 8
	DTLnk     uint8 = 10
	DTSock    uint8 = 12
)

// DirEntry is one directory entry.
type DirEntry struct {
	// Slot is the slot the entry starts in.
	Slot int
	// Hash is the name hash the filesystem stores (not verified here).
	Hash uint32
	Ino  uint32
	// FileType is the stored file-type hint.
	FileType uint8
	// Name is the name bytes as stored.
	Name []byte
}

// NameString returns the name as text, replacing invalid sequences.
func (e DirEntry) NameString() string { return string(e.Name) }

// SlotsFor returns the slots a name of length bytes needs.
func SlotsFor(length int) int { return (length + DirSlotSize - 1) / DirSlotSize }

// ParseDirBlock parses every entry a directory block holds.
func ParseDirBlock(bytes []byte, blockSize uint32) ([]DirEntry, error) {
	if int(blockSize) != DirBlockSize {
		return nil, unsupportedf("a %d-byte directory block; only %d-byte blocks are laid out this way",
			blockSize, DirBlockSize)
	}
	if len(bytes) < DirBlockSize {
		return nil, invalidf("the directory block is %d bytes, not %d", len(bytes), DirBlockSize)
	}
	var entries []DirEntry
	for slot := 0; slot < DirEntriesPerBlock; slot++ {
		if bytes[slot/8]&(1<<uint(slot%8)) == 0 {
			continue
		}
		at := DirEntryOffset + slot*DirEntrySize
		length, err := u16At(bytes, at+8)
		if err != nil {
			return nil, err
		}
		if length == 0 || int(length) > DirMaxNameLen {
			return nil, invalidf("directory slot %d claims a %d-byte name", slot, length)
		}
		nameAt := DirFilenameOffset + slot*DirSlotSize
		if nameAt+int(length) > DirFilenameOffset+DirFilenameBytes {
			return nil, invalidf("the %d-byte name in slot %d runs past the name area", length, slot)
		}
		hash, err := u32At(bytes, at)
		if err != nil {
			return nil, err
		}
		ino, err := u32At(bytes, at+4)
		if err != nil {
			return nil, err
		}
		fileType, err := u8At(bytes, at+10)
		if err != nil {
			return nil, err
		}
		name := make([]byte, int(length))
		copy(name, bytes[nameAt:nameAt+int(length)])
		entries = append(entries, DirEntry{
			Slot:     slot,
			Hash:     hash,
			Ino:      ino,
			FileType: fileType,
			Name:     name,
		})
	}
	return entries, nil
}

// IsDot reports whether a directory entry names the directory itself or its
// parent.
func IsDot(name []byte) bool {
	return string(name) == "." || string(name) == ".."
}
