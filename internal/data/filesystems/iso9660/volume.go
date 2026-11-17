package iso9660

import (
	"bytes"
	"fmt"
	pathpkg "path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// kindLabel is the filesystem's name as facts and listings report it.
	kindLabel = "ISO9660"
	// maxDirectoryBytes bounds one directory extent.
	maxDirectoryBytes = 64 * 1024 * 1024
	// maxContinuationDepth bounds one record's CE chain.
	maxContinuationDepth = 4
	// maxContinuationBytes bounds one continuation area.
	maxContinuationBytes = 64 * 1024
	// maxNodes bounds the walk.
	maxNodes = 5_000_000
)

// NameTree says which tree's names a mount reports.
type NameTree uint8

const (
	// TreeRockRidge is the primary descriptor with Rock Ridge names.
	TreeRockRidge NameTree = iota
	// TreeJoliet is the Joliet supplementary descriptor.
	TreeJoliet
	// TreePrimary is the primary descriptor's own upper-case names.
	TreePrimary
)

// String returns the tree's identifier.
func (t NameTree) String() string {
	switch t {
	case TreeRockRidge:
		return "rock-ridge"
	case TreeJoliet:
		return "joliet"
	default:
		return "primary"
	}
}

// Entry describes one name the walk found.
type Entry struct {
	Name string
	Path string

	IsDir     bool
	IsSymlink bool
	IsFile    bool

	// Size is the logical length in bytes: the uncompressed length for a
	// zisofs file.
	Size uint64
	// StoredSize is the length the record declares for stored bytes.
	StoredSize uint64

	SymlinkTarget string

	// Mode is Rock Ridge's PX mode when HasMode is set.
	Mode    uint32
	HasMode bool
	UID     uint32
	GID     uint32
	// HasOwner says Rock Ridge recorded an owner pair.
	HasOwner bool

	Created  time.Time
	Modified time.Time
	Changed  time.Time
	Accessed time.Time

	// Version is the ";version" suffix on a primary-tree name.
	Version    uint16
	HasVersion bool

	// Location is the physical offset of the node's first extent.
	Location uint64
	// Extents are the physical runs, in order.
	Extents []Run

	Interleaved bool
	Zisofs      *ZisofsMark
	Relocated   bool
	// HasXattr is always false: this reader does not model ISO xattrs.
	HasXattr bool
}

// Relocation is a directory Rock Ridge moved out of its parent.
type Relocation struct {
	// Node is the walk handle presented at the placeholder's path.
	Node uint64
	// Block is the logical block the CL entry named.
	Block uint32
	// AlsoAt is the store path the same records were also reachable through.
	AlsoAt string
}

// Info is the volume-level description returned by Volume.Info.
type Info struct {
	Type            string
	Label           string
	VolumeID        string
	SystemID        string
	BlockSize       uint32
	VolumeSpaceSize uint32
	VolumeBytes     uint64
	NameTree        string
	RockRidge       bool
	JolietLevel     uint8
	HasJoliet       bool
	Descriptors     int
	BootRecords     int
	Supplementary   int

	BootCatalogLBA uint32
	HasBootCatalog bool
	BootPlatform   string
	BootID         string
	Bootable       int

	PathTableRecords int
	PathTableError   string

	InterleavedFiles     int
	RelocatedDirectories int
	Unreadable           uint64
	FieldMismatches      uint64
	ZisofsFiles          uint64
}

type node struct {
	name          string
	path          string
	parent        int
	isDirectory   bool
	isSymlink     bool
	symlinkTarget string
	size          uint64
	storedSize    uint64
	zisofs        *ZisofsMark
	extents       []Run

	created, modified, changed, accessed *IsoTime

	mode     uint32
	hasMode  bool
	uid, gid uint32
	hasOwner bool
	version  uint16
	hasVer   bool

	interleaved bool
	relocated   bool
	children    []int
}

// Volume is a mounted ISO 9660 image.
type Volume struct {
	src  source.ByteSource
	set  *DescriptorSet
	tree NameTree

	nodes []node
	paths map[string]int

	unreadable  uint64
	mismatches  uint64
	interleaved int

	boot    *BootCatalog
	bootErr error

	pathTable    *PathTable
	pathTableErr error

	relocations               []Relocation
	relocationDuplicates      uint64
	relocationFieldMismatches uint64
	parentLinks               uint64
	parentLinkMismatches      uint64

	zisofs *zisofsCounters
}

var nextFileSourceID atomic.Uint64

// Open reads the descriptor set, chooses a tree and walks every directory.
func Open(src source.ByteSource) (*Volume, error) {
	set, err := readDescriptorSet(src)
	if err != nil {
		return nil, err
	}
	blockSize := set.Primary.BlockSize
	rootRun, err := pvdRootRun(&set.Primary)
	if err != nil {
		return nil, err
	}
	rockRidge, err := detectRockRidge(src, blockSize, rootRun)
	if err != nil {
		return nil, err
	}

	var tree NameTree
	var descriptor *VolumeDescriptor
	switch {
	case rockRidge:
		tree = TreeRockRidge
		descriptor = &set.Primary
	case set.Joliet != nil:
		tree = TreeJoliet
		descriptor = set.Joliet
	default:
		tree = TreePrimary
		descriptor = &set.Primary
	}

	vol := &Volume{
		src:    src,
		set:    set,
		tree:   tree,
		paths:  make(map[string]int),
		zisofs: &zisofsCounters{},
	}
	if set.HasBootCatalog {
		catalog, err := readBootCatalog(src, uint64(blockSize), set.BootCatalogLBA)
		if err != nil {
			vol.bootErr = err
		} else {
			vol.boot = catalog
		}
	}
	table, err := readPathTable(src, &set.Primary)
	if err != nil {
		vol.pathTableErr = err
	} else {
		vol.pathTable = table
	}
	if err := vol.walk(descriptor); err != nil {
		return nil, err
	}
	return vol, nil
}

func (v *Volume) walk(descriptor *VolumeDescriptor) error {
	blockSize := descriptor.BlockSize
	rootRun, err := pvdRootRun(descriptor)
	if err != nil {
		return err
	}
	v.nodes = append(v.nodes, node{
		name:        "/",
		path:        "/",
		parent:      -1,
		isDirectory: true,
		extents:     []Run{rootRun},
	})
	v.paths["/"] = 0

	visited := map[uint64]bool{rootRun.Offset: true}
	queue := []int{0}
	directories := map[uint64]int{rootRun.Offset: 0}
	claimed := make(map[uint64]bool)
	linked := make(map[int]bool)
	type parentLink struct {
		node  uint64
		block uint32
	}
	var parentLinks []parentLink

	for len(queue) > 0 {
		directory := queue[0]
		queue = queue[1:]
		if len(v.nodes[directory].extents) == 0 {
			continue
		}
		run := v.nodes[directory].extents[0]
		dirBytes, err := v.directoryBytes(run)
		if err != nil {
			v.unreadable++
			continue
		}
		listing, err := records(dirBytes, blockSize)
		if err != nil {
			v.unreadable++
			continue
		}
		parentPath := v.nodes[directory].path

		if v.tree == TreeRockRidge {
			for i := range listing {
				if listing[i].IsDot() {
					area, err := collectRockRidge(v.src, blockSize, listing[i].SystemUse)
					if err != nil {
						return err
					}
					if area.Relocated {
						v.nodes[directory].relocated = true
					}
				}
				if listing[i].IsDotDot() {
					area, err := collectRockRidge(v.src, blockSize, listing[i].SystemUse)
					if err != nil {
						return err
					}
					if area.HasParentLink {
						if v.nodes[directory].relocated {
							parentLinks = append(parentLinks, parentLink{uint64(directory), area.ParentLink})
						}
						v.parentLinks++
					}
				}
			}
		}

		at := 0
		for at < len(listing) {
			record := listing[at]
			at++
			if record.IsDot() || record.IsDotDot() {
				continue
			}
			firstRun, err := dataRun(&record, blockSize)
			if err != nil {
				return err
			}
			extents := []Run{firstRun}
			size := uint64(record.DataLen)
			isMulti := record.IsMultiExtent()
			if !record.IsDirectory() {
				for isMulti && at < len(listing) {
					next := listing[at]
					if next.IsDirectory() || !bytes.Equal(next.Identifier, record.Identifier) {
						break
					}
					nextRun, err := dataRun(&next, blockSize)
					if err != nil {
						return err
					}
					extents = append(extents, nextRun)
					size += uint64(next.DataLen)
					isMulti = next.IsMultiExtent()
					at++
				}
			}
			if len(v.nodes) >= maxNodes {
				return corruptf("the image names more than %d entries", maxNodes)
			}
			if !record.FieldsAgree {
				v.mismatches++
			}

			rockRidge, err := collectRockRidge(v.src, blockSize, record.SystemUse)
			if err != nil {
				return err
			}
			name, ok := v.nameOf(&record, &rockRidge)
			if !ok {
				v.unreadable++
				continue
			}
			path := name
			if parentPath == "/" {
				path = "/" + name
			} else {
				path = parentPath + "/" + name
			}

			isSymlink := rockRidge.HasSymlink ||
				(rockRidge.HasMode && rockRidge.Mode&0o170000 == 0o120000)
			isDirectory := record.IsDirectory()
			var zisofs *ZisofsMark
			if !isDirectory && !isSymlink {
				zisofs = rockRidge.Zisofs
			}
			if zisofs != nil {
				v.zisofs.addFile()
			}

			directoryRun := firstRun
			var viaLink *uint32
			if isDirectory && v.tree == TreeRockRidge && rockRidge.HasChildLink {
				block := rockRidge.ChildLink
				directoryRun, err = relocationRun(block, record.ExtendedAttrLen, blockSize)
				if err != nil {
					return err
				}
				directoryRun.Len, err = v.scanDirectoryLen(directoryRun.Offset, blockSize)
				if err != nil {
					return err
				}
				viaLink = &block
				if rockRidge.LinkMismatch {
					v.relocationFieldMismatches++
				}
			}
			if viaLink != nil {
				claimed[directoryRun.Offset] = true
				if existing, ok := directories[directoryRun.Offset]; ok {
					if linked[existing] || v.isAncestor(existing, directory) {
						v.noteRelocationDuplicate(&existing, path)
					} else {
						store := v.nodes[existing].path
						v.relocations = append(v.relocations, Relocation{
							Node: uint64(existing), Block: *viaLink, AlsoAt: store,
						})
						v.moveNode(existing, directory, name, path, directoryRun)
						linked[existing] = true
					}
					continue
				}
			} else if isDirectory && v.tree == TreeRockRidge && claimed[directoryRun.Offset] {
				var existing *int
				if found, ok := directories[directoryRun.Offset]; ok {
					existing = &found
				}
				v.noteRelocationDuplicate(existing, path)
				continue
			}

			interleaved := record.UnitSize != 0 && record.Gap != 0 && !isDirectory
			if interleaved {
				v.interleaved++
			}

			n := node{
				name:        name,
				path:        path,
				parent:      directory,
				isDirectory: isDirectory,
				isSymlink:   isSymlink,
				size:        size,
				storedSize:  size,
				mode:        rockRidge.Mode,
				hasMode:     rockRidge.HasMode,
				uid:         rockRidge.UID,
				gid:         rockRidge.GID,
				hasOwner:    rockRidge.HasUID || rockRidge.HasGID,
				interleaved: interleaved,
				relocated:   viaLink != nil,
			}
			if isDirectory {
				n.size, n.storedSize = 0, 0
				n.extents = []Run{directoryRun}
			} else {
				n.extents = extents
				if zisofs != nil {
					n.size = uint64(zisofs.UncompressedLen)
				}
				n.zisofs = zisofs
				n.symlinkTarget = rockRidge.Symlink
			}
			if version, ok := record.Version(); ok {
				n.version, n.hasVer = version, true
			}
			if v.tree == TreeRockRidge {
				if rockRidge.HasCreated {
					value := rockRidge.Created
					n.created = &value
				}
				if rockRidge.HasModified {
					value := rockRidge.Modified
					n.modified = &value
				}
				if rockRidge.HasAttrs {
					value := rockRidge.Attributes
					n.changed = &value
				}
				if rockRidge.HasAccessed {
					value := rockRidge.Accessed
					n.accessed = &value
				}
			} else {
				if value, ok := isoTimeFromRecording(record.Recording[:]); ok {
					n.modified = &value
				}
			}

			child := len(v.nodes)
			v.nodes = append(v.nodes, n)
			v.nodes[directory].children = append(v.nodes[directory].children, child)
			v.paths[path] = child
			if isDirectory {
				directories[directoryRun.Offset] = child
				if viaLink != nil {
					linked[child] = true
					v.relocations = append(v.relocations, Relocation{
						Node: uint64(child), Block: *viaLink,
					})
				}
				if !visited[directoryRun.Offset] {
					visited[directoryRun.Offset] = true
					queue = append(queue, child)
				}
			}
		}
	}

	for _, link := range parentLinks {
		var expected uint64
		ok := false
		parent := v.nodes[link.node].parent
		if parent >= 0 && len(v.nodes[parent].extents) > 0 {
			expected = v.nodes[parent].extents[0].Offset / uint64(blockSize)
			ok = true
		}
		if !ok || expected != uint64(link.block) {
			v.parentLinkMismatches++
		}
	}
	return nil
}

func (v *Volume) scanDirectoryLen(offset uint64, blockSize uint32) (uint64, error) {
	if blockSize == 0 {
		return 0, nil
	}
	block := uint64(blockSize)
	var length uint64
	buffer := make([]byte, blockSize)
	for length < maxDirectoryBytes {
		if offset > v.src.Len() || length > v.src.Len()-offset || block > v.src.Len()-offset-length {
			break
		}
		if err := source.ReadExactAt(v.src, offset+length, buffer); err != nil {
			return 0, err
		}
		if buffer[0] == 0 {
			break
		}
		length += block
	}
	return length, nil
}

func (v *Volume) moveNode(index, parent int, name, path string, run Run) {
	oldPath := v.nodes[index].path
	if oldParent := v.nodes[index].parent; oldParent >= 0 {
		children := v.nodes[oldParent].children
		kept := children[:0]
		for _, child := range children {
			if child != index {
				kept = append(kept, child)
			}
		}
		v.nodes[oldParent].children = kept
	}
	v.nodes[index].parent = parent
	v.nodes[index].name = name
	v.nodes[index].relocated = true
	v.nodes[index].extents = []Run{run}
	v.nodes[parent].children = append(v.nodes[parent].children, index)
	v.repath(index, oldPath, path)
}

func (v *Volume) repath(index int, old, new string) {
	pending := []int{index}
	for len(pending) > 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		path := v.nodes[current].path
		if strings.HasPrefix(path, old) {
			if mapped, ok := v.paths[path]; ok && mapped == current {
				delete(v.paths, path)
			}
			v.nodes[current].path = new + path[len(old):]
			v.paths[v.nodes[current].path] = current
		}
		pending = append(pending, v.nodes[current].children...)
	}
}

func (v *Volume) isAncestor(index, descendant int) bool {
	at := descendant
	for at >= 0 {
		if at == index {
			return true
		}
		at = v.nodes[at].parent
	}
	return false
}

func (v *Volume) noteRelocationDuplicate(existing *int, path string) {
	v.relocationDuplicates++
	if existing == nil {
		return
	}
	for i := range v.relocations {
		if v.relocations[i].Node == uint64(*existing) {
			if v.relocations[i].AlsoAt == "" {
				v.relocations[i].AlsoAt = path
			}
			return
		}
	}
}

func (v *Volume) nameOf(record *DirRecord, rockRidge *RockRidge) (string, bool) {
	if v.tree == TreeRockRidge && rockRidge.HasName {
		return rockRidge.Name, true
	}
	if v.tree == TreeJoliet {
		return jolietName(record.Identifier)
	}
	return primaryName(record.Identifier)
}

func (v *Volume) directoryBytes(run Run) ([]byte, error) {
	if run.Len == 0 {
		return nil, nil
	}
	if run.Len > maxDirectoryBytes {
		return nil, corruptf("directory at %d declares %d bytes, more than %d", run.Offset, run.Len, maxDirectoryBytes)
	}
	return source.ReadVecAt(v.src, run.Offset, run.Len)
}

// pvdRootRun returns the root directory's extent from a descriptor's 34-byte
// root record.
func pvdRootRun(descriptor *VolumeDescriptor) (Run, error) {
	listing, err := records(descriptor.Root[:], descriptor.BlockSize)
	if err != nil {
		return Run{}, err
	}
	if len(listing) == 0 {
		return Run{}, corruptf("the root directory record did not parse")
	}
	return dataRun(&listing[0], descriptor.BlockSize)
}

// dataRun returns where a record's data physically lives.
func dataRun(record *DirRecord, blockSize uint32) (Run, error) {
	block := uint64(record.Extent) + uint64(record.ExtendedAttrLen)
	offset, ok := mulU64(block, uint64(blockSize))
	if !ok {
		return Run{}, corruptf("extent %d overflows the address space", record.Extent)
	}
	run := ContiguousRun(offset, uint64(record.DataLen))
	if !record.IsDirectory() && record.UnitSize != 0 && record.Gap != 0 {
		run.Unit = uint64(record.UnitSize) * uint64(blockSize)
		run.Gap = uint64(record.Gap) * uint64(blockSize)
	}
	return run, nil
}

func relocationRun(block uint32, extAttrLen uint8, blockSize uint32) (Run, error) {
	value := uint64(block) + uint64(extAttrLen)
	offset, ok := mulU64(value, uint64(blockSize))
	if !ok {
		return Run{}, corruptf("child link to block %d overflows the address space", block)
	}
	return ContiguousRun(offset, 0), nil
}

func readBootCatalog(src source.ByteSource, blockSize uint64, lba uint32) (*BootCatalog, error) {
	offset, ok := mulU64(uint64(lba), blockSize)
	if !ok {
		return nil, fmt.Errorf("boot catalog block %d overflows the offset", lba)
	}
	if offset > src.Len() {
		return nil, fmt.Errorf("boot catalog block %d is outside the image", lba)
	}
	available := src.Len() - offset
	if available < 2*bootEntryBytes {
		return nil, fmt.Errorf("boot catalog block %d is outside the image (offset %d, %d bytes left)",
			lba, offset, available)
	}
	length := available
	if length > maxCatalogBytes {
		length = maxCatalogBytes
	}
	bytes, err := source.ReadVecAt(src, offset, length)
	if err != nil {
		return nil, fmt.Errorf("boot catalog at block %d could not be read: %w", lba, err)
	}
	return parseBootCatalog(bytes)
}

func detectRockRidge(src source.ByteSource, blockSize uint32, rootRun Run) (bool, error) {
	if rootRun.Len == 0 {
		return false, nil
	}
	length := rootRun.Len
	if length > uint64(blockSize) {
		length = uint64(blockSize)
	}
	bytes, err := source.ReadVecAt(src, rootRun.Offset, length)
	if err != nil {
		return false, err
	}
	listing, err := records(bytes, blockSize)
	if err != nil {
		return false, err
	}
	for i := range listing {
		if listing[i].IsDot() {
			area, err := collectRockRidge(src, blockSize, listing[i].SystemUse)
			if err != nil {
				return false, err
			}
			return area.Sharing, nil
		}
	}
	return false, nil
}

func collectRockRidge(src source.ByteSource, blockSize uint32, area []byte) (RockRidge, error) {
	out := parseSUSP(area)
	depth := 0
	for out.HasContinuation {
		next := out.Continuation
		out.HasContinuation = false
		if depth >= maxContinuationDepth || next.length == 0 || next.length > maxContinuationBytes {
			break
		}
		offset, ok := mulU64(uint64(next.block), uint64(blockSize))
		if !ok {
			return out, corruptf("a Rock Ridge continuation overflows the address space")
		}
		bytes, err := source.ReadVecAt(src, offset+uint64(next.offset), uint64(next.length))
		if err != nil {
			return out, err
		}
		mergeRockRidge(&out, parseSUSP(bytes))
		depth++
	}
	return out, nil
}

func mergeRockRidge(into *RockRidge, next RockRidge) {
	if next.HasName {
		if into.HasName {
			into.Name += next.Name
		} else {
			into.Name, into.HasName = next.Name, true
		}
	}
	if next.HasSymlink {
		if into.HasSymlink {
			into.Symlink += next.Symlink
		} else {
			into.Symlink, into.HasSymlink = next.Symlink, true
		}
	}
	if next.HasMode {
		into.Mode, into.HasMode = next.Mode, true
	}
	if next.HasLinks {
		into.Links, into.HasLinks = next.Links, true
	}
	if next.HasUID {
		into.UID, into.HasUID = next.UID, true
	}
	if next.HasGID {
		into.GID, into.HasGID = next.GID, true
	}
	if next.HasCreated {
		into.Created, into.HasCreated = next.Created, true
	}
	if next.HasModified {
		into.Modified, into.HasModified = next.Modified, true
	}
	if next.HasAccessed {
		into.Accessed, into.HasAccessed = next.Accessed, true
	}
	if next.HasAttrs {
		into.Attributes, into.HasAttrs = next.Attributes, true
	}
	into.HasContinuation = next.HasContinuation
	into.Continuation = next.Continuation
	into.Sharing = into.Sharing || next.Sharing
	if next.Extension != "" {
		into.Extension = next.Extension
	}
	if next.Zisofs != nil {
		into.Zisofs = next.Zisofs
	}
	into.Present = into.Present || next.Present
}

func mulU64(a, b uint64) (uint64, bool) {
	if a != 0 && b > ^uint64(0)/a {
		return 0, false
	}
	return a * b, true
}

func normalizePath(path string) string {
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return pathpkg.Clean(path)
}

func (v *Volume) lookup(path string) (int, error) {
	index, ok := v.paths[normalizePath(path)]
	if !ok {
		return 0, fmt.Errorf("%w: %s", ErrPathNotFound, path)
	}
	return index, nil
}

func timeOf(value *IsoTime) time.Time {
	if value == nil {
		return time.Time{}
	}
	return time.Unix(0, value.UnixNanos()).UTC()
}

func (v *Volume) entryOf(index int) Entry {
	n := v.nodes[index]
	entry := Entry{
		Name:          n.name,
		Path:          n.path,
		IsDir:         n.isDirectory,
		IsSymlink:     n.isSymlink,
		IsFile:        !n.isDirectory && !n.isSymlink,
		Size:          n.size,
		StoredSize:    n.storedSize,
		SymlinkTarget: n.symlinkTarget,
		Mode:          n.mode,
		HasMode:       n.hasMode,
		UID:           n.uid,
		GID:           n.gid,
		HasOwner:      n.hasOwner,
		Created:       timeOf(n.created),
		Modified:      timeOf(n.modified),
		Changed:       timeOf(n.changed),
		Accessed:      timeOf(n.accessed),
		Version:       n.version,
		HasVersion:    n.hasVer,
		Extents:       append([]Run(nil), n.extents...),
		Interleaved:   n.interleaved,
		Zisofs:        n.zisofs,
		Relocated:     n.relocated,
	}
	if len(n.extents) > 0 {
		entry.Location = n.extents[0].Offset
	}
	return entry
}

// ListDir returns the entries of the directory at path, in stored order.
func (v *Volume) ListDir(path string) ([]Entry, error) {
	index, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	if !v.nodes[index].isDirectory {
		return nil, fmt.Errorf("iso9660: %s is not a directory", v.nodes[index].path)
	}
	entries := make([]Entry, 0, len(v.nodes[index].children))
	for _, child := range v.nodes[index].children {
		entries = append(entries, v.entryOf(child))
	}
	return entries, nil
}

// Stat returns the entry at path.
func (v *Volume) Stat(path string) (*Entry, error) {
	index, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	entry := v.entryOf(index)
	return &entry, nil
}

// OpenFile opens a file's data. A zisofs file is served uncompressed.
func (v *Volume) OpenFile(path string) (source.ByteSource, error) {
	index, err := v.lookup(path)
	if err != nil {
		return nil, err
	}
	n := v.nodes[index]
	if n.isDirectory || n.isSymlink {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrNotAFile, n.path)
	}
	id := source.ID(nextFileSourceID.Add(1) + 2_000_000)
	if n.zisofs != nil {
		if len(n.extents) != 1 || n.extents[0].IsInterleaved() {
			v.zisofs.addRefusal()
			return nil, corruptf("zisofs file %s must be one contiguous extent", n.path)
		}
		file, err := openZisofs(v.src, n.extents[0], n.storedSize, n.zisofs, n.path, v.zisofs)
		if err != nil {
			return nil, err
		}
		return newZisofsFileSource(id, v.src, file), nil
	}
	return newFileSource(id, v.src, n.extents, n.size), nil
}

// Boot returns the El Torito boot catalog, when the image carries one.
func (v *Volume) Boot() (*BootCatalog, bool) { return v.boot, v.boot != nil }

// BootError reports why a named catalog could not be read.
func (v *Volume) BootError() error { return v.bootErr }

// PathTable returns the path tables, when the primary descriptor declares
// them.
func (v *Volume) PathTable() (*PathTable, bool) { return v.pathTable, v.pathTable != nil }

// PathTableError reports why a declared path table could not be read.
func (v *Volume) PathTableError() error { return v.pathTableErr }

// Relocations returns the directories Rock Ridge relocated.
func (v *Volume) Relocations() []Relocation { return v.relocations }

// IsRockRidge reports whether Rock Ridge names are the tree being reported.
func (v *Volume) IsRockRidge() bool { return v.tree == TreeRockRidge }

// NameTree returns the tree whose names the mount reports.
func (v *Volume) NameTree() NameTree { return v.tree }

// JolietLevel returns the supplementary descriptor's Joliet level.
func (v *Volume) JolietLevel() (uint8, bool) {
	if v.set.Joliet == nil {
		return 0, false
	}
	return v.set.Joliet.JolietLevel, true
}

// ZisofsStats returns the mount's zisofs counters.
func (v *Volume) ZisofsStats() ZisofsStats { return v.zisofs.snapshot() }

// Info returns volume-level facts.
func (v *Volume) Info() Info {
	var descriptor *VolumeDescriptor
	if v.tree == TreeJoliet && v.set.Joliet != nil {
		descriptor = v.set.Joliet
	} else {
		descriptor = &v.set.Primary
	}
	blockSize := uint64(descriptor.BlockSize)
	info := Info{
		Type:                 kindLabel,
		Label:                descriptor.VolumeID,
		VolumeID:             descriptor.VolumeID,
		SystemID:             descriptor.SystemID,
		BlockSize:            descriptor.BlockSize,
		VolumeSpaceSize:      descriptor.VolumeSpaceSize,
		VolumeBytes:          uint64(descriptor.VolumeSpaceSize) * blockSize,
		NameTree:             v.tree.String(),
		RockRidge:            v.tree == TreeRockRidge,
		Descriptors:          v.set.Descriptors,
		BootRecords:          v.set.BootRecords,
		Supplementary:        v.set.Supplementary,
		BootCatalogLBA:       v.set.BootCatalogLBA,
		HasBootCatalog:       v.set.HasBootCatalog,
		InterleavedFiles:     v.interleaved,
		RelocatedDirectories: len(v.relocations),
		Unreadable:           v.unreadable,
		FieldMismatches:      v.mismatches,
	}
	if level, ok := v.JolietLevel(); ok {
		info.JolietLevel, info.HasJoliet = level, true
	}
	if v.boot != nil {
		info.BootPlatform = v.boot.PlatformLabel
		info.BootID = v.boot.ID
		info.Bootable = v.boot.BootableEntries()
	}
	if v.pathTable != nil {
		info.PathTableRecords = len(v.pathTable.records)
	}
	if v.pathTableErr != nil {
		info.PathTableError = v.pathTableErr.Error()
	}
	info.ZisofsFiles = v.zisofs.snapshot().Files
	return info
}
