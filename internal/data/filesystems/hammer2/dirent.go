package hammer2

import "unicode/utf8"

// InlineNameBytes is the longest name that fits in check.buf.
const InlineNameBytes = 64

// MaxNameBytes is HAMMER2_INODE_MAXNAME, the longest name a writer emits.
const MaxNameBytes = 256

// DirentHead is the fixed part of a directory entry.
type DirentHead struct {
	Inum       uint64
	NameLen    uint16
	ObjectType uint8
}

// ParseDirentHead decodes the head out of a DIRENT block reference. A nil
// head means the slot is empty.
func ParseDirentHead(ref *Blockref, what string) (*DirentHead, error) {
	if ref.BType == BrefTypeEmpty {
		return nil, nil
	}
	inum := le64(ref.Embed[:], 0)
	nameLen := le16(ref.Embed[:], 8)
	if nameLen == 0 {
		return nil, corruptf("%s has a zero-length directory entry name", what)
	}
	if int(nameLen) > MaxNameBytes {
		return nil, corruptf("%s records a %d-byte name, larger than HAMMER2's %d-byte limit",
			what, nameLen, MaxNameBytes)
	}
	return &DirentHead{
		Inum:       inum,
		NameLen:    nameLen,
		ObjectType: ref.Embed[10],
	}, nil
}

// NeedsExternalName reports whether the name lives in an external block.
func (h *DirentHead) NeedsExternalName() bool {
	return int(h.NameLen) > InlineNameBytes
}

// WithName builds the complete entry from name bytes of exactly NameLen
// length.
func (h *DirentHead) WithName(name []byte, what string) (*Dirent, error) {
	if len(name) != int(h.NameLen) {
		return nil, corruptf("%s stores %d name bytes but its head records %d",
			what, len(name), h.NameLen)
	}
	if err := validateName(name, what); err != nil {
		return nil, err
	}
	return &Dirent{Inum: h.Inum, ObjectType: h.ObjectType, NameBytes: append([]byte(nil), name...)}, nil
}

// Dirent is a fully decoded directory entry.
type Dirent struct {
	Inum       uint64
	ObjectType uint8
	NameBytes  []byte
}

// InlineDirent decodes a DIRENT reference whose name is stored inline. A nil
// entry means the name needs an external block.
func InlineDirent(ref *Blockref, what string) (*Dirent, error) {
	if ref.BType != BrefTypeDirent {
		return nil, corruptf("%s is not a directory-entry reference (type %d)", what, ref.BType)
	}
	head, err := ParseDirentHead(ref, what)
	if err != nil || head == nil {
		return nil, err
	}
	if head.NeedsExternalName() {
		return nil, nil
	}
	return head.WithName(ref.Check[:head.NameLen], what)
}

// ExternalDirent decodes a DIRENT reference whose name is stored in an
// external block of the indicated size.
func ExternalDirent(ref *Blockref, block []byte, what string) (*Dirent, error) {
	if ref.BType != BrefTypeDirent {
		return nil, corruptf("%s is not a directory-entry reference (type %d)", what, ref.BType)
	}
	head, err := ParseDirentHead(ref, what)
	if err != nil || head == nil {
		return nil, err
	}
	if !head.NeedsExternalName() {
		return nil, nil
	}
	if len(block) < int(head.NameLen) {
		return nil, corruptf("%s stores a %d-byte name but only %d-byte blocks were read",
			what, head.NameLen, len(block))
	}
	return head.WithName(block[:head.NameLen], what)
}

// Name returns the name as text; non-UTF-8 names are refused rather than
// replaced.
func (d *Dirent) Name() (string, error) {
	if !utf8.Valid(d.NameBytes) {
		return "", unsupportedf("directory entry for inode %d has a name that is not valid UTF-8", d.Inum)
	}
	return string(d.NameBytes), nil
}

// IsDirectory reports whether the entry names a directory.
func (d *Dirent) IsDirectory() bool { return d.ObjectType == ObjtypeDirectory }

func validateName(name []byte, what string) error {
	for _, value := range name {
		if value == 0 {
			return corruptf("%s has a name containing a NUL byte", what)
		}
		if value == '/' {
			return corruptf("%s has a name containing a slash", what)
		}
	}
	if string(name) == "." || string(name) == ".." {
		return corruptf("%s stores the reserved name %q; HAMMER2 synthesizes dot entries", what, string(name))
	}
	return nil
}
