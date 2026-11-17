package zfs

import "fmt"

// ZPL directory entries and path traversal.
//
// A dataset's filesystem is a ZPL object set. Its master node maps ROOT to a
// directory object, and every directory is a ZAP whose values are 64-bit
// zfs_dirent_t words: bits 0..48 are the object id, bits 60..64 the POSIX
// d_type.
//
// A directory entry is followed only when its type says directory. When the
// type is DT_UNKNOWN the object's own dnode decides; the reader never guesses
// a type from a name. `..` is resolved through the directories the walk
// actually visited, so it cannot escape the mounted dataset.

// direntObjectBits is the width of the object id in a ZPL directory value.
const direntObjectBits = 48

// direntObjectMask is ZFS_DIRENT_OBJ.
const direntObjectMask uint64 = (1 << direntObjectBits) - 1

// direntTypeShift is ZFS_DIRENT_TYPE's shift.
const direntTypeShift = 60

// direntTypeMask is ZFS_DIRENT_TYPE's width.
const direntTypeMask uint64 = 0xf

// maxPathComponents bounds a caller-supplied path.
const maxPathComponents = 4096

// DType is a POSIX directory-entry type as ZFS records it.
type DType uint8

const (
	DTypeUnknown   DType = 0
	DTypeFIFO      DType = 1
	DTypeChar      DType = 2
	DTypeDirectory DType = 4
	DTypeBlock     DType = 6
	DTypeRegular   DType = 8
	DTypeSymlink   DType = 10
	DTypeSocket    DType = 12
	DTypeWhiteout  DType = 14
)

// Aliases used by the image builder and callers.
const (
	zplDirentTypeRegular   = DTypeRegular
	zplDirentTypeDirectory = DTypeDirectory
	zplDirentTypeSymlink   = DTypeSymlink
)

func dTypeFromBits(bits uint8) DType { return DType(bits) }

func (d DType) label() string {
	switch d {
	case DTypeUnknown:
		return "unknown"
	case DTypeFIFO:
		return "fifo"
	case DTypeChar:
		return "character device"
	case DTypeDirectory:
		return "directory"
	case DTypeBlock:
		return "block device"
	case DTypeRegular:
		return "regular file"
	case DTypeSymlink:
		return "symbolic link"
	case DTypeSocket:
		return "socket"
	case DTypeWhiteout:
		return "whiteout"
	default:
		return "other"
	}
}

// IsDirectory reports a directory type.
func (d DType) IsDirectory() bool { return d == DTypeDirectory }

// IsRegular reports a regular-file type.
func (d DType) IsRegular() bool { return d == DTypeRegular }

// IsSymlink reports a symbolic-link type.
func (d DType) IsSymlink() bool { return d == DTypeSymlink }

// ZplEntry is one name in a ZPL directory.
type ZplEntry struct {
	name   string
	object uint64
	dtype  DType
}

func parseZplEntry(name string, value []byte) (ZplEntry, error) {
	if len(value) != 8 {
		return ZplEntry{}, corruptf("directory entry %q is %d bytes; a ZPL dirent is 8", name, len(value))
	}
	word := leUint64(value)
	object := word & direntObjectMask
	if object == 0 {
		return ZplEntry{}, corruptf("directory entry %q names object 0, which is the object-set dnode", name)
	}
	return ZplEntry{
		name:   name,
		object: object,
		dtype:  dTypeFromBits(uint8((word >> direntTypeShift) & direntTypeMask)),
	}, nil
}

// objectOf returns the object id inside a directory value; ok is false when
// the value is not a word.
func objectOf(value []byte) (uint64, bool) {
	if len(value) != 8 {
		return 0, false
	}
	return leUint64(value) & direntObjectMask, true
}

// Directory is a listing and the object whose data produced it.
type Directory struct {
	object    uint64
	entries   []ZplEntry
	truncated bool
}

// rootObject returns the object the master node's ROOT entry names.
func rootObject(reader *BlockReader, objset *Objset) (uint64, error) {
	master, err := objset.zapObject(reader, masterNodeObject)
	if err != nil {
		return 0, err
	}
	object, ok := master.unsigned(rootObjectEntry)
	if !ok {
		return 0, corruptf("the dataset master node has no %q", rootObjectEntry)
	}
	return object, nil
}

// readDirectory reads one directory object's ZAP, refusing an object that is
// not a directory.
func readDirectory(reader *BlockReader, objset *Objset, object uint64, limit int) (*Directory, error) {
	node, err := objset.dnode(reader, object)
	if err != nil {
		return nil, err
	}
	if node.kind != dmuOtDirectoryContents {
		return nil, corruptf("object %d is %s, not a directory", object, objectTypeName(node.kind))
	}
	zap, err := readZapUpTo(reader, node, limit)
	if err != nil {
		return nil, err
	}
	entries := make([]ZplEntry, 0, zap.len())
	for _, entry := range zap.entries() {
		parsed, err := parseZplEntry(entry.name, entry.value)
		if err != nil {
			return nil, err
		}
		entries = append(entries, parsed)
	}
	return &Directory{object: object, entries: entries, truncated: zap.truncated}, nil
}

// Resolved is the object a path names and the type its last entry recorded.
type Resolved struct {
	Object uint64
	DType  DType
}

// resolvePath resolves path from the dataset root to the object it names.
//
// Empty components and "." are skipped; ".." returns to the last directory
// this walk actually visited and stays at the root above it. Every component
// before the last must be a directory; the last may be any type.
func resolvePath(reader *BlockReader, objset *Objset, path string, limit int) (Resolved, error) {
	root, err := rootObject(reader, objset)
	if err != nil {
		return Resolved{}, err
	}
	stack := []uint64{root}
	current := root
	components := splitPath(path)
	if len(components) > maxPathComponents {
		return Resolved{}, corruptf("path %q has more than %d components", path, maxPathComponents)
	}
	for index, component := range components {
		if component == ".." {
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			current = stack[len(stack)-1]
			continue
		}
		listing, err := readDirectory(reader, objset, current, limit)
		if err != nil {
			return Resolved{}, err
		}
		var found *ZplEntry
		for i := range listing.entries {
			if listing.entries[i].name == component {
				found = &listing.entries[i]
				break
			}
		}
		if found == nil {
			return Resolved{}, notFoundf("%s: %q is not in object %d's directory", path, component, current)
		}
		last := index == len(components)-1
		if !last {
			directory, err := entryIsDirectory(reader, objset, found)
			if err != nil {
				return Resolved{}, err
			}
			if !directory {
				return Resolved{}, notDirf("%s: %q is a %s, not a directory", path, component, found.dtype.label())
			}
			current = found.object
			stack = append(stack, current)
			continue
		}
		return Resolved{Object: found.object, DType: found.dtype}, nil
	}
	return Resolved{Object: current, DType: DTypeDirectory}, nil
}

// resolveDirectory resolves path and lists the directory it names.
func resolveDirectory(reader *BlockReader, objset *Objset, path string, limit int) (*Directory, error) {
	resolved, err := resolvePath(reader, objset, path, limit)
	if err != nil {
		return nil, err
	}
	directory := false
	switch resolved.DType {
	case DTypeDirectory:
		directory = true
	case DTypeUnknown:
		node, err := objset.dnode(reader, resolved.Object)
		if err != nil {
			return nil, err
		}
		directory = node.kind != dmuOtNone && node.kind == dmuOtDirectoryContents
	}
	if !directory {
		return nil, notDirf("%s is a %s, not a directory", path, resolved.DType.label())
	}
	return readDirectory(reader, objset, resolved.Object, limit)
}

// entryIsDirectory reports whether an entry names a directory, using the
// dnode when the type is DT_UNKNOWN.
func entryIsDirectory(reader *BlockReader, objset *Objset, entry *ZplEntry) (bool, error) {
	switch entry.dtype {
	case DTypeDirectory:
		return true, nil
	case DTypeUnknown:
		node, err := objset.dnode(reader, entry.object)
		if err != nil {
			return false, err
		}
		return node.kind != dmuOtNone && node.kind == dmuOtDirectoryContents, nil
	default:
		return false, nil
	}
}

func splitPath(path string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(path); i++ {
		if i == len(path) || path[i] == '/' {
			component := path[start:i]
			start = i + 1
			if component == "" || component == "." {
				continue
			}
			out = append(out, component)
		}
	}
	return out
}

func notDirf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrNotDir, fmt.Sprintf(format, args...))
}
