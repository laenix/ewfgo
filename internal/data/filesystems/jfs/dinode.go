package jfs

// Fixed on-disk inode layout.
//
//	0x00 inostamp, fileset, number, generation
//	0x10 inode extent descriptor
//	0x18 size, 0x20 nblocks, 0x28 nlink, 0x2c uid, 0x30 gid, 0x34 mode
//	0x38 atime, ctime, mtime, otime
//	0x58 ACL descriptor, 0x68 extended-attribute descriptor
//	0x78 next directory-table index, 0x7c ACL type
//	0x80 a directory's inline table or unused file bytes
//	0xe0 the directory tree root or the extent tree root (288 bytes)
//	0x100 a device number, fast symbolic-link bytes, or inline data
const (
	// InodeUnionOffset is where the directory or extent tree root starts.
	InodeUnionOffset = 0x80
	// InodeRootOffset is where the tree root starts inside the inode.
	InodeRootOffset = 0xE0
	// InodeInlineOffset is where a fast symlink or inline data starts.
	InodeInlineOffset = 0x100
	// MaxFastSymlink is the largest symlink stored inside its inode.
	MaxFastSymlink = 256
)

// File type bits of di_mode.
const (
	SIFMT   uint32 = 0xF000
	SIFIFO  uint32 = 0x1000
	SIFCHR  uint32 = 0x2000
	SIFDIR  uint32 = 0x4000
	SIFBLK  uint32 = 0x6000
	SIFREG  uint32 = 0x8000
	SIFLNK  uint32 = 0xA000
	SIFSOCK uint32 = 0xC000
)

// Dinode is one parsed 512-byte JFS inode.
type Dinode struct {
	raw [InodeSize]byte
}

// ParseDinode decodes exactly one inode slot.
func ParseDinode(raw []byte) (*Dinode, error) {
	if len(raw) < InodeSize {
		return nil, corruptf("a JFS inode is %d bytes, not %d", InodeSize, len(raw))
	}
	inode := &Dinode{}
	copy(inode.raw[:], raw[:InodeSize])
	return inode, nil
}

// Raw returns the inode's on-disk bytes.
func (d *Dinode) Raw() []byte { return d.raw[:] }

// InoStamp is the per-fileset stamp the inode map checks.
func (d *Dinode) InoStamp() uint32 { return le32(d.raw[:], 0x00) }

// Fileset is the fileset number the inode belongs to.
func (d *Dinode) Fileset() uint32 { return le32(d.raw[:], 0x04) }

// Number is the inode number the inode claims to be.
func (d *Dinode) Number() uint32 { return le32(d.raw[:], 0x08) }

// Generation is the inode generation.
func (d *Dinode) Generation() uint32 { return le32(d.raw[:], 0x0C) }

// IxPxd returns the extent that holds the page this inode lives on.
func (d *Dinode) IxPxd() (Pxd, error) { return ParsePxd(d.raw[:], 0x10) }

// Size is the object's logical size in bytes.
func (d *Dinode) Size() uint64 { return le64(d.raw[:], 0x18) }

// NBlocks is the number of 512-byte blocks the object occupies.
func (d *Dinode) NBlocks() uint64 { return le64(d.raw[:], 0x20) }

// Nlink is the link count.
func (d *Dinode) Nlink() uint32 { return le32(d.raw[:], 0x28) }

// UID is the owner id.
func (d *Dinode) UID() uint32 { return le32(d.raw[:], 0x2C) }

// GID is the group id.
func (d *Dinode) GID() uint32 { return le32(d.raw[:], 0x30) }

// Mode is the full mode word.
func (d *Dinode) Mode() uint32 { return le32(d.raw[:], 0x34) }

// Permissions returns the low permission bits of the mode.
func (d *Dinode) Permissions() uint16 { return uint16(d.Mode()) & 0o7777 }

// FileType returns the S_IFMT bits of the mode.
func (d *Dinode) FileType() uint32 { return d.Mode() & SIFMT }

// FileTypeName names the object's kind.
func (d *Dinode) FileTypeName() string {
	switch d.FileType() {
	case SIFIFO:
		return "FIFO"
	case SIFCHR:
		return "character device"
	case SIFDIR:
		return "directory"
	case SIFBLK:
		return "block device"
	case SIFREG:
		return "regular file"
	case SIFLNK:
		return "symbolic link"
	case SIFSOCK:
		return "socket"
	default:
		return "unknown"
	}
}

// IsDir reports whether the inode is a directory.
func (d *Dinode) IsDir() bool { return d.FileType() == SIFDIR }

// IsRegular reports whether the inode is a regular file.
func (d *Dinode) IsRegular() bool { return d.FileType() == SIFREG }

// IsSymlink reports whether the inode is a symbolic link.
func (d *Dinode) IsSymlink() bool { return d.FileType() == SIFLNK }

// IsFastSymlink reports whether a symbolic link's target lives in the inode.
func (d *Dinode) IsFastSymlink() bool { return d.IsSymlink() && d.Size() < MaxFastSymlink }

// Atime returns the access timestamp.
func (d *Dinode) Atime() Timestamp {
	return Timestamp{Sec: le32(d.raw[:], 0x38), Nsec: le32(d.raw[:], 0x3C)}
}

// Ctime returns the change timestamp.
func (d *Dinode) Ctime() Timestamp {
	return Timestamp{Sec: le32(d.raw[:], 0x40), Nsec: le32(d.raw[:], 0x44)}
}

// Mtime returns the modification timestamp.
func (d *Dinode) Mtime() Timestamp {
	return Timestamp{Sec: le32(d.raw[:], 0x48), Nsec: le32(d.raw[:], 0x4C)}
}

// Otime returns the creation timestamp.
func (d *Dinode) Otime() Timestamp {
	return Timestamp{Sec: le32(d.raw[:], 0x50), Nsec: le32(d.raw[:], 0x54)}
}

// ACL returns the ACL descriptor.
func (d *Dinode) ACL() (Dxd, error) { return ParseDxd(d.raw[:], 0x58) }

// ExtendedAttributes returns the extended-attribute descriptor.
func (d *Dinode) ExtendedAttributes() (Dxd, error) { return ParseDxd(d.raw[:], 0x68) }

// NextIndex is the next free directory-table index.
func (d *Dinode) NextIndex() uint32 { return le32(d.raw[:], 0x78) }

// ACLType is the ACL type word.
func (d *Dinode) ACLType() uint32 { return le32(d.raw[:], 0x7C) }

// DirectoryTreeRoot returns the 288-byte directory tree root.
func (d *Dinode) DirectoryTreeRoot() []byte { return d.raw[InodeRootOffset:] }

// ExtentTreeRoot returns the 288-byte extent tree root.
func (d *Dinode) ExtentTreeRoot() []byte { return d.raw[InodeRootOffset:] }

// InlineData returns the final 256 bytes a fast symlink or inline data uses.
func (d *Dinode) InlineData() []byte { return d.raw[InodeInlineOffset:] }

// FastSymlinkBytes returns the target bytes a fast symbolic link stores.
func (d *Dinode) FastSymlinkBytes() []byte {
	size := d.Size()
	if size > MaxFastSymlink {
		size = MaxFastSymlink
	}
	return d.raw[InodeInlineOffset : InodeInlineOffset+int(size)]
}
