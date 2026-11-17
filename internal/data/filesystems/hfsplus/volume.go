package hfsplus

// An HFS+ volume: header, catalog traversal, directory listing, and forks.
//
// Opening resolves three trees in dependency order.  The volume header
// describes the extents-overflow file, so that tree is opened from its eight
// inline extents (following its own overflow records if needed).  The catalog
// fork's continuation extents may live in that tree, so it is resolved through
// the tree just opened.  Only then can names be looked up.
//
// The catalog is traversed from its B-tree root: child listings are a range
// scan over (parent CNID, name), and a CNID is turned back into a path by
// following thread records.

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	maxOverflowRecords   = 100_000
	maxExtentsFileRounds = 8
	maxPathDepth         = 256
	maxChildren          = 1_000_000
	sIFMT                = 0o170000
	sIFLNK               = 0o120000
)

// Entry is one directory entry's metadata.
type Entry struct {
	Name             string
	Path             string
	IsDir            bool
	Size             uint64
	Mode             uint16
	UID              uint32
	GID              uint32
	Inode            uint32
	Parent           uint32
	CreateTime       Time
	ModTime          Time
	AttributeModTime Time
	AccessTime       Time
	BackupTime       Time
	// Deleted is false for live catalog records.  Deleted names are reported
	// by CatalogResidue instead.
	Deleted   bool
	IsSymlink bool
	HardLink  bool
	// Compressed reports that the file carries a decmpfs marker and Size is
	// its declared uncompressed size.
	Compressed      bool
	Flags           uint16
	Allocated       uint64
	ResourceSize    uint64
	HasResourceFork bool
	Special         uint32
}

// CatalogEntry is a catalog key together with the record it points at.
type CatalogEntry struct {
	Key    CatalogKey
	Record *CatalogRecord
}

// JournalInfo is the journal summary reported by Info.
type JournalInfo struct {
	Offset           uint64
	Size             uint64
	Flags            uint32
	InFS             bool
	OnOtherDevice    bool
	NeedsInit        bool
	HeaderChecksumOK bool
	Start            uint64
	End              uint64
	Pending          bool
	Transactions     int
	Writes           int
	Bytes            uint64
	ChecksumMismatch bool
}

// Info is the volume-wide metadata.
type Info struct {
	Name          string
	UUID          string
	Signature     Signature
	CaseSensitive bool
	Journaled     bool
	Journal       *JournalInfo
	BlockSize     uint32
	TotalBlocks   uint32
	FreeBlocks    uint32
	FileCount     uint32
	FolderCount   uint32
	Created       Time
	Modified      Time
	BackedUp      Time
	Checked       Time
	NextCatalogID uint32
}

// Volume is a parsed HFS+ volume backed by a byte source.
type Volume struct {
	src        source.ByteSource
	header     *Header
	extents    *BTree
	catalog    *BTree
	attributes *BTree
}

// Open parses an HFS+ or HFSX volume: header, extents overflow, catalog, and
// the attributes tree when the header declares one.
func Open(src source.ByteSource) (*Volume, error) {
	header, err := Detect(src)
	if err != nil {
		return nil, err
	}
	if header == nil {
		return nil, invalidf("source does not start with an HFS+ or HFSX volume header")
	}

	extentsTree, err := openExtentsTree(src, header)
	if err != nil {
		return nil, err
	}
	catalogExtents, err := resolveFork(src, extentsTree, header.BlockSize, ForkData, CatalogFileID, header.CatalogFile)
	if err != nil {
		return nil, err
	}
	catalogTree, err := openBTree(src, header.BlockSize, header.CatalogFile, catalogExtents, true)
	if err != nil {
		return nil, err
	}

	var attributesTree *BTree
	if !header.AttributesFile.IsEmpty() {
		extents, err := resolveFork(src, extentsTree, header.BlockSize, ForkData, AttributesFileID, header.AttributesFile)
		if err != nil {
			return nil, err
		}
		attributesTree, err = openBTree(src, header.BlockSize, header.AttributesFile, extents, true)
		if err != nil {
			return nil, err
		}
	}

	volume := &Volume{
		src:        src,
		header:     header,
		extents:    extentsTree,
		catalog:    catalogTree,
		attributes: attributesTree,
	}
	// The root's thread record proves the catalog tree, its comparator, and
	// the fork resolution all work.  A volume that fails this is not silently
	// treated as empty.
	entry, err := volume.lookupKey(CatalogKey{Parent: RootFolder})
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, invalidf("catalog has no thread record for root folder CNID %d", RootFolder)
	}
	return volume, nil
}

// Header returns the volume header.
func (v *Volume) Header() *Header { return v.header }

// Source returns the backing byte source.
func (v *Volume) Source() source.ByteSource { return v.src }

// BlockSize returns the allocation block size.
func (v *Volume) BlockSize() uint32 { return v.header.BlockSize }

// CaseSensitive reports whether the catalog compares names byte-wise.
func (v *Volume) CaseSensitive() bool { return v.header.CaseSensitive() }

// Journaled reports whether the header names a journal info block.
func (v *Volume) Journaled() bool { return v.header.Journaled() }

// CatalogRecordCount returns the leaf records the catalog header claims.
func (v *Volume) CatalogRecordCount() uint32 { return v.catalog.header.LeafRecords }

// RootID returns the root folder's CNID.
func (v *Volume) RootID() uint32 { return RootFolder }

// Info returns the volume-wide metadata, including the catalog's volume name,
// the FinderInfo-derived UUID, and the journal summary.
func (v *Volume) Info() (Info, error) {
	header := v.header
	info := Info{
		Signature:     header.Signature,
		CaseSensitive: header.CaseSensitive(),
		Journaled:     header.Journaled(),
		BlockSize:     header.BlockSize,
		TotalBlocks:   header.TotalBlocks,
		FreeBlocks:    header.FreeBlocks,
		FileCount:     header.FileCount,
		FolderCount:   header.FolderCount,
		Created:       header.Created,
		Modified:      header.Modified,
		BackedUp:      header.BackedUp,
		Checked:       header.Checked,
		NextCatalogID: header.NextCatalogID,
		UUID:          volumeUUID(header.FinderInfo),
	}
	root, err := v.thread(RootFolder)
	if err != nil {
		return info, err
	}
	if root != nil {
		info.Name = root.Name.String()
	}
	if header.Journaled() {
		journal, err := v.Journal()
		if err != nil {
			return info, err
		}
		info.Journal = &JournalInfo{
			Offset:           journal.Head.Info.Offset,
			Size:             journal.Head.Info.Size,
			Flags:            journal.Head.Info.Flags,
			InFS:             journal.Head.Info.InFS(),
			OnOtherDevice:    journal.Head.Info.OnOtherDevice(),
			NeedsInit:        journal.Head.Info.NeedsInit(),
			HeaderChecksumOK: journal.Head.HeaderChecksumOK,
			Start:            journal.Head.Header.Start,
			End:              journal.Head.Header.End,
			Pending:          journal.Pending(),
			Transactions:     journal.Stats.Transactions,
			Writes:           journal.Stats.Writes,
			Bytes:            journal.Stats.Bytes,
			ChecksumMismatch: journal.Stats.ChecksumMismatch,
		}
	}
	return info, nil
}

// volumeUUID derives the HFS+ volume UUID the way libblkid does: MD5 over a
// fixed init vector and the 8-byte FinderInfo volume id, with UUID version and
// variant bits applied.  An all-zero id means the volume has no UUID.
func volumeUUID(finderInfo [8]uint32) string {
	id := uint64(finderInfo[6])<<32 | uint64(finderInfo[7])
	if id == 0 {
		return ""
	}
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], id)
	init := [16]byte{
		0xb3, 0xe2, 0x0f, 0x39, 0xf2, 0x92, 0x11, 0xd6,
		0x97, 0xa4, 0x00, 0x30, 0x65, 0x43, 0xec, 0xac,
	}
	hash := md5.New()
	hash.Write(init[:])
	hash.Write(raw[:])
	sum := hash.Sum(nil)
	sum[6] = 0x30 | (sum[6] & 0x0f)
	sum[8] = 0x80 | (sum[8] & 0x3f)
	text := hex.EncodeToString(sum)
	return text[0:8] + "-" + text[8:12] + "-" + text[12:16] + "-" + text[16:20] + "-" + text[20:32]
}

// ListDir returns the direct children of a directory, in catalog order.
func (v *Volume) ListDir(path string) ([]Entry, error) {
	cleaned, entry, err := v.resolvePath(path)
	if err != nil {
		return nil, err
	}
	folder := RootFolder
	if entry != nil {
		if !entry.Record.IsDirectory() {
			return nil, fmt.Errorf("%w: %s", ErrNotDirectory, path)
		}
		id, ok := entry.Record.ID()
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
		}
		folder = id
	}
	entries, err := v.children(folder)
	if err != nil {
		return nil, err
	}
	for i := range entries {
		entries[i].Path = joinPath(cleaned, entries[i].Name)
	}
	return entries, nil
}

// Stat returns one path's metadata.
func (v *Volume) Stat(path string) (*Entry, error) {
	cleaned, entry, err := v.resolvePath(path)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		root, err := v.rootEntry()
		if err != nil {
			return nil, err
		}
		root.Path = cleaned
		return root, nil
	}
	result := v.entryFor(cleaned, entry)
	if err := v.applyHardLink(&result, entry.Record); err != nil {
		return nil, err
	}
	if err := v.applyCompression(&result, entry.Record); err != nil {
		return nil, err
	}
	return &result, nil
}

// OpenFile opens a file's content as a byte source.  A decmpfs-compressed file
// is transparently decompressed: its dataless data fork is never exposed.
func (v *Volume) OpenFile(path string) (source.ByteSource, error) {
	return v.OpenFork(path, ForkData)
}

// OpenFork opens one of a file's forks as a byte source.  The data fork of a
// decmpfs-compressed file is decoded and served as its real content; the
// resource fork is always served as stored.
func (v *Volume) OpenFork(path string, kind ForkKind) (source.ByteSource, error) {
	_, entry, err := v.resolvePath(path)
	if err != nil {
		return nil, err
	}
	if entry == nil || entry.Record.IsDirectory() {
		return nil, fmt.Errorf("%w: %s", ErrIsDirectory, path)
	}
	id, ok := entry.Record.ID()
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	if kind == ForkData {
		owner, _, found, err := v.fileWithOwner(id)
		if err != nil {
			return nil, err
		}
		if found {
			content, compressed, err := v.decmpfsContent(owner)
			if err != nil {
				return nil, err
			}
			if compressed {
				return v.decmpfsSource(owner, content), nil
			}
		}
	}
	file, err := v.fileSource(id, kind)
	if err != nil {
		return nil, err
	}
	if file == nil {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	return file, nil
}

// ReadFile returns a file's complete content.  For a decmpfs-compressed file
// this is the decompressed bytes and its length is the declared size.
func (v *Volume) ReadFile(path string) ([]byte, error) {
	stream, err := v.OpenFile(path)
	if err != nil {
		return nil, err
	}
	if stream.Len() > uint64(^uint(0)>>1) {
		return nil, unsupportedf("file %q declares %d bytes, above the platform address space", path, stream.Len())
	}
	data := make([]byte, int(stream.Len()))
	if err := source.ReadExactAt(stream, 0, data); err != nil {
		return nil, err
	}
	return data, nil
}

// Attribute reads one extended attribute of a CNID.  A missing attribute is
// (nil, nil).
func (v *Volume) Attribute(fileID uint32, name string) ([]byte, error) {
	if v.attributes == nil {
		return nil, nil
	}
	return readAttribute(v.attributes, v.src, v.header.BlockSize, v.CaseSensitive(), fileID, name)
}

// resolvePath cleans an absolute path and resolves its final component.
// A root path returns (cleaned, nil, nil).
func (v *Volume) resolvePath(path string) (string, *CatalogEntry, error) {
	cleaned, parts, err := splitAbsolutePath(path)
	if err != nil {
		return "", nil, err
	}
	parent := RootFolder
	for i := 0; i < len(parts)-1; i++ {
		entry, err := v.lookup(parent, parts[i])
		if err != nil {
			return "", nil, err
		}
		if entry == nil {
			return "", nil, fmt.Errorf("%w: %s", ErrNotFound, path)
		}
		if !entry.Record.IsDirectory() {
			return "", nil, fmt.Errorf("%w: %s", ErrNotDirectory, path)
		}
		id, ok := entry.Record.ID()
		if !ok {
			return "", nil, fmt.Errorf("%w: %s", ErrNotFound, path)
		}
		parent = id
	}
	if len(parts) == 0 {
		return cleaned, nil, nil
	}
	entry, err := v.lookup(parent, parts[len(parts)-1])
	if err != nil {
		return "", nil, err
	}
	if entry == nil {
		return "", nil, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	return cleaned, entry, nil
}

func splitAbsolutePath(path string) (string, []string, error) {
	if path == "" || path[0] != '/' {
		return "", nil, invalidf("path %q is not absolute", path)
	}
	parts := make([]string, 0, 4)
	for _, part := range strings.Split(path, "/") {
		switch part {
		case "", ".":
			continue
		case "..":
			return "", nil, invalidf("path %q contains a parent reference", path)
		default:
			parts = append(parts, part)
		}
	}
	cleaned := "/" + strings.Join(parts, "/")
	if len(parts) == 0 {
		cleaned = "/"
	}
	return cleaned, parts, nil
}

func joinPath(base, name string) string {
	if base == "/" {
		return "/" + name
	}
	return base + "/" + name
}

// rootEntry builds the root folder's entry from its thread record.
func (v *Volume) rootEntry() (*Entry, error) {
	thread, err := v.thread(RootFolder)
	if err != nil {
		return nil, err
	}
	if thread == nil {
		return nil, invalidf("catalog has no thread record for root folder CNID %d", RootFolder)
	}
	entry, err := v.lookup(thread.Parent, thread.Name.String())
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, invalidf("catalog root thread points at a missing record")
	}
	result := v.entryFor("/", entry)
	return &result, nil
}

// lookup resolves a name directly inside a folder.
func (v *Volume) lookup(parent uint32, name string) (*CatalogEntry, error) {
	return v.lookupKey(CatalogKey{Parent: parent, Name: NewName(name)})
}

// lookupKey resolves a full catalog key.
func (v *Volume) lookupKey(key CatalogKey) (*CatalogEntry, error) {
	if key.Name.Len() > MaxNameUnits {
		return nil, nil
	}
	payload, err := key.Encode()
	if err != nil {
		return nil, err
	}
	compare := func(a, b []byte) int {
		return CompareCatalogPayloads(a, b, v.CaseSensitive())
	}
	foundKey, data, found, err := v.catalog.Lookup(v.src, payload, compare)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	parsedKey, err := ParseCatalogKey(foundKey)
	if err != nil {
		return nil, err
	}
	record, err := ParseCatalogRecord(data)
	if err != nil {
		return nil, err
	}
	return &CatalogEntry{Key: parsedKey, Record: record}, nil
}

// thread returns a CNID's thread record.
func (v *Volume) thread(id uint32) (*CatalogThread, error) {
	entry, err := v.lookupKey(CatalogKey{Parent: id})
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	return entry.Record.Thread, nil
}

// children lists a folder's direct children.
func (v *Volume) children(folder uint32) ([]Entry, error) {
	start, err := CatalogKey{Parent: folder}.Encode()
	if err != nil {
		return nil, err
	}
	compare := func(a, b []byte) int {
		return CompareCatalogPayloads(a, b, v.CaseSensitive())
	}
	entries := make([]Entry, 0, 16)
	err = v.catalog.Scan(v.src, start, compare, func(keyBytes, data []byte) (bool, error) {
		key, err := ParseCatalogKey(keyBytes)
		if err != nil {
			return false, err
		}
		if key.Parent != folder {
			return false, nil
		}
		record, err := ParseCatalogRecord(data)
		if err != nil {
			return false, err
		}
		if record.IsThread() {
			return true, nil
		}
		entry := v.entryFor("", &CatalogEntry{Key: key, Record: record})
		if err := v.applyHardLink(&entry, record); err != nil {
			return false, err
		}
		// A listing falls back to the catalog's size when a decmpfs marker is
		// unreadable; OpenFile and Stat report the explicit error instead.
		_ = v.applyCompression(&entry, record)
		entries = append(entries, entry)
		if len(entries) > maxChildren {
			return false, invalidf("folder %d has more than %d children", folder, maxChildren)
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

// entryFor builds an Entry from a catalog key and record.
func (v *Volume) entryFor(path string, entry *CatalogEntry) Entry {
	key, record := entry.Key, entry.Record
	out := Entry{
		Name:   key.Name.String(),
		Path:   path,
		Inode:  key.Parent, // threads have no id; live records overwrite this
		Parent: key.Parent,
	}
	if id, ok := record.ID(); ok {
		out.Inode = id
	}
	switch record.Type {
	case RecordFolder:
		folder := record.Folder
		out.IsDir = true
		out.Flags = folder.Flags
		out.CreateTime = folder.Created
		out.ModTime = folder.ContentModified
		out.AttributeModTime = folder.AttributeModified
		out.AccessTime = folder.Accessed
		out.BackupTime = folder.BackedUp
		out.Mode = folder.Permissions.FileMode
		out.UID = folder.Permissions.OwnerID
		out.GID = folder.Permissions.GroupID
		out.Special = folder.Permissions.Special
	case RecordFile:
		file := record.File
		out.Flags = file.Flags
		out.CreateTime = file.Created
		out.ModTime = file.ContentModified
		out.AttributeModTime = file.AttributeModified
		out.AccessTime = file.Accessed
		out.BackupTime = file.BackedUp
		out.Mode = file.Permissions.FileMode
		out.UID = file.Permissions.OwnerID
		out.GID = file.Permissions.GroupID
		out.Special = file.Permissions.Special
		out.Size = file.DataFork.LogicalSize
		out.Allocated = uint64(file.DataFork.TotalBlocks) * uint64(v.header.BlockSize)
		out.ResourceSize = file.ResourceFork.LogicalSize
		out.HasResourceFork = file.ResourceFork.LogicalSize > 0 || file.ResourceFork.TotalBlocks > 0
		out.HardLink = file.IsHardLink()
		out.IsSymlink = file.Permissions.FileMode&sIFMT == sIFLNK
	}
	return out
}

// applyHardLink completes a link's size/allocation from its inode file.
func (v *Volume) applyHardLink(entry *Entry, record *CatalogRecord) error {
	if record.Type != RecordFile || !record.File.IsHardLink() {
		return nil
	}
	inode, err := v.inodeFile(record.File.Permissions.Special)
	if err != nil {
		return err
	}
	if inode == nil {
		return nil
	}
	entry.Size = inode.DataFork.LogicalSize
	entry.Allocated = uint64(inode.DataFork.TotalBlocks) * uint64(v.header.BlockSize)
	entry.ResourceSize = inode.ResourceFork.LogicalSize
	entry.HasResourceFork = inode.ResourceFork.LogicalSize > 0 || inode.ResourceFork.TotalBlocks > 0
	return nil
}

// applyCompression reports a decmpfs file's declared uncompressed size.  The
// catalog's data-fork size of a compressed file is zero (the fork is dataless),
// so the header is authoritative.  Hard links are keyed by their inode's CNID.
func (v *Volume) applyCompression(entry *Entry, record *CatalogRecord) error {
	if record.Type != RecordFile {
		return nil
	}
	id, ok := record.ID()
	if !ok {
		return nil
	}
	owner := id
	if record.File.IsHardLink() {
		owner = record.File.Permissions.Special
		if owner == 0 {
			return nil
		}
	}
	header, err := v.decmpfsHeaderFor(owner)
	if err != nil {
		return err
	}
	if header != nil {
		entry.Size = header.Size
		entry.Compressed = true
	}
	return nil
}

// inodeFile resolves the iNode<CNID> file a hard link names.
func (v *Volume) inodeFile(inode uint32) (*CatalogFile, error) {
	name := fmt.Sprintf("%s%d", InodeFilePrefix, inode)
	entry, err := v.lookupKey(CatalogKey{Parent: MetadataFolderID, Name: NewName(name)})
	if err != nil {
		return nil, err
	}
	if entry == nil || entry.Record.Type != RecordFile {
		return nil, nil
	}
	return entry.Record.File, nil
}

// fileWithOwner returns the CNID whose forks a path's file actually owns.
// An ordinary file owns its own; a hard link names an inode file.
func (v *Volume) fileWithOwner(id uint32) (uint32, *CatalogFile, bool, error) {
	thread, err := v.thread(id)
	if err != nil {
		return 0, nil, false, err
	}
	if thread == nil {
		return 0, nil, false, nil
	}
	entry, err := v.lookup(thread.Parent, thread.Name.String())
	if err != nil {
		return 0, nil, false, err
	}
	if entry == nil || entry.Record.Type != RecordFile {
		return 0, nil, false, nil
	}
	file := entry.Record.File
	if !file.IsHardLink() {
		return id, file, true, nil
	}
	inode := file.Permissions.Special
	if inode == 0 {
		return 0, nil, false, invalidf("hard link CNID %d names no inode (special field is zero)", id)
	}
	inodeFile, err := v.inodeFile(inode)
	if err != nil {
		return 0, nil, false, err
	}
	if inodeFile == nil {
		return 0, nil, false, invalidf("hard link CNID %d points at inode %d, but the private data folder holds no iNode%d", id, inode, inode)
	}
	if inodeFile.IsHardLink() {
		return 0, nil, false, invalidf("hard link CNID %d points at inode %d, which is itself a hard link", id, inode)
	}
	return inode, inodeFile, true, nil
}

// extentsFor resolves a fork's full extent list through the overflow tree.
func (v *Volume) extentsFor(kind ForkKind, fileID uint32, fork Fork) (ForkExtents, error) {
	return resolveFork(v.src, v.extents, v.header.BlockSize, kind, fileID, fork)
}

// fileSource opens one fork of a file by CNID.
func (v *Volume) fileSource(id uint32, kind ForkKind) (*FileSource, error) {
	owner, file, ok, err := v.fileWithOwner(id)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	fork := file.DataFork
	if kind == ForkResource {
		fork = file.ResourceFork
	}
	extents, err := v.extentsFor(kind, owner, fork)
	if err != nil {
		return nil, err
	}
	covered := extents.CoveredBytes(v.header.BlockSize)
	if fork.LogicalSize > covered {
		return nil, unsupportedf("%s fork of CNID %d declares %d bytes but its extents cover %d",
			kind, owner, fork.LogicalSize, covered)
	}
	sourceID := source.ID(uint64(owner)<<8 | uint64(kind.Code()))
	return newFileSource(sourceID, v, kind, extents, fork.LogicalSize), nil
}

// extentsKey is the extents-overflow key: fork type, zero pad, file id,
// start block.
func extentsKey(kind ForkKind, fileID, startBlock uint32) []byte {
	key := make([]byte, 10)
	key[0] = kind.Code()
	key[2] = uint8(fileID >> 24)
	key[3] = uint8(fileID >> 16)
	key[4] = uint8(fileID >> 8)
	key[5] = uint8(fileID)
	key[6] = uint8(startBlock >> 24)
	key[7] = uint8(startBlock >> 16)
	key[8] = uint8(startBlock >> 8)
	key[9] = uint8(startBlock)
	return key
}

// openExtentsTree opens the extents-overflow tree, following its own overflow
// records until the tree's declared block count is reachable.
func openExtentsTree(src source.ByteSource, header *Header) (*BTree, error) {
	fork := header.ExtentsFile
	extents := fork.InlineExtents()
	rounds := 0
	for {
		var covered uint64
		for _, extent := range extents {
			covered += uint64(extent.BlockCount)
		}
		tree, err := openBTree(src, header.BlockSize, fork, NewForkExtents(extents), false)
		if err != nil {
			return nil, err
		}
		if covered >= uint64(fork.TotalBlocks) {
			return openBTree(src, header.BlockSize, fork, NewForkExtents(extents), true)
		}
		rounds++
		if rounds > maxExtentsFileRounds {
			return nil, unsupportedf("extents overflow file needs more than %d of its own overflow records to become reachable (stopped at block %d)",
				maxExtentsFileRounds, covered)
		}
		key := extentsKey(ForkData, ExtentsFileID, uint32(covered))
		_, data, found, err := tree.Lookup(src, key, bytesCompare)
		if err != nil {
			return nil, invalidf("extents overflow file's own extent record at block %d could not be read: %v", covered, err)
		}
		if !found {
			return nil, invalidf("extents overflow file has no extent record for its own block %d", covered)
		}
		more, err := ParseExtentsRecord(data)
		if err != nil {
			return nil, err
		}
		var blocks uint64
		for _, extent := range more {
			blocks += uint64(extent.BlockCount)
		}
		if blocks == 0 {
			return nil, invalidf("extents overflow file's own extent record at block %d does not advance coverage", covered)
		}
		next := covered + blocks
		if next > uint64(fork.TotalBlocks) {
			return nil, invalidf("extents overflow file's own extents cover %d blocks, more than its declared %d", next, fork.TotalBlocks)
		}
		extents = append(extents, more...)
	}
}

// resolveFork follows a fork's inline extents into the overflow tree until
// they cover the declared block count.
func resolveFork(src source.ByteSource, tree *BTree, blockSize uint32, kind ForkKind, fileID uint32, fork Fork) (ForkExtents, error) {
	extents := fork.InlineExtents()
	var covered uint64
	for _, extent := range extents {
		covered += uint64(extent.BlockCount)
	}
	records := 0
	for covered < uint64(fork.TotalBlocks) {
		records++
		if records > maxOverflowRecords {
			return ForkExtents{}, invalidf("%s fork of CNID %d needs more than %d overflow records",
				kind, fileID, maxOverflowRecords)
		}
		key := extentsKey(kind, fileID, uint32(covered))
		_, data, found, err := tree.Lookup(src, key, bytesCompare)
		if err != nil {
			return ForkExtents{}, err
		}
		if !found {
			return ForkExtents{}, invalidf("%s fork of CNID %d has no extent overflow record at block %d",
				kind, fileID, covered)
		}
		more, err := ParseExtentsRecord(data)
		if err != nil {
			return ForkExtents{}, err
		}
		var blocks uint64
		for _, extent := range more {
			blocks += uint64(extent.BlockCount)
		}
		if blocks == 0 {
			return ForkExtents{}, invalidf("extent overflow record for CNID %d at block %d is empty", fileID, covered)
		}
		covered += blocks
		extents = append(extents, more...)
	}
	if covered > uint64(fork.TotalBlocks) {
		return ForkExtents{}, invalidf("%s fork of CNID %d extents cover %d blocks, more than its declared %d",
			kind, fileID, covered, fork.TotalBlocks)
	}
	return NewForkExtents(extents), nil
}

// pathOf resolves a CNID to a slash-separated path by following thread
// records.  A chain that does not reach the root returns nil rather than
// fabricating a path.
func (v *Volume) pathOf(id uint32) (string, error) {
	if id == RootFolder {
		return "/", nil
	}
	parts := make([]string, 0, 8)
	current := id
	seen := make(map[uint32]bool)
	for depth := 0; depth < maxPathDepth; depth++ {
		if current == RootFolder {
			for left, right := 0, len(parts)-1; left < right; left, right = left+1, right-1 {
				parts[left], parts[right] = parts[right], parts[left]
			}
			return "/" + strings.Join(parts, "/"), nil
		}
		if seen[current] {
			return "", invalidf("catalog thread chain from CNID %d loops at %d", id, current)
		}
		seen[current] = true
		thread, err := v.thread(current)
		if err != nil {
			return "", err
		}
		if thread == nil {
			return "", nil
		}
		parts = append(parts, thread.Name.String())
		current = thread.Parent
	}
	return "", invalidf("catalog thread chain from CNID %d exceeds %d levels", id, maxPathDepth)
}
