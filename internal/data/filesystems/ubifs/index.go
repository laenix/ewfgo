package ubifs

import (
	"encoding/binary"
	"sort"
	"strings"
	"time"
)

func readLEU32(bytes []byte, at int) uint32 {
	return binary.LittleEndian.Uint32(bytes[at : at+4])
}

func readLEU64(bytes []byte, at int) uint64 {
	return binary.LittleEndian.Uint64(bytes[at : at+8])
}

func (v *Volume) walkIndex(lnum uint32, offs, length uint64, key *NodeKey, expectedLevel *uint16, depth uint16) error {
	if v.walkedNodes >= MaxNodes {
		v.refuse("node cap reached")
		return nil
	}
	v.walkedNodes++
	if depth > MaxIndexLevels {
		v.refuse("index depth cap reached")
		return nil
	}
	bytes, imageOffset, err := v.device.readNode(lnum, offs, length)
	if err != nil {
		v.undecodable++
		v.refuse("unreadable node")
		return nil
	}
	common, ok := ParseCommon(bytes)
	if !ok {
		v.undecodable++
		v.refuse("unknown node type or truncated common header")
		return nil
	}
	if !common.CRCOK(bytes) {
		v.undecodable++
		v.refuse("corrupted node CRC")
		if common.NodeType == NodeData && len(bytes) >= CommonHeaderBytes {
			if corruptKey, ok := ParseKey(bytes[CommonHeaderBytes:]); ok {
				v.corruptData[dataKey{inum: corruptKey.Inum, block: uint64(corruptKey.Pos)}] = true
			}
		}
		return nil
	}
	if uint64(common.Len) != length {
		v.refuse("node length disagrees with its index branch")
	}
	if common.NodeType == NodeIndex {
		v.indexNodes++
		return v.walkIndexNode(bytes, imageOffset, common, expectedLevel, depth)
	}
	v.leafNodes++
	return v.walkLeaf(bytes, imageOffset, lnum, offs, common, key)
}

func (v *Volume) walkIndexNode(bytes []byte, imageOffset uint64, common Common, expectedLevel *uint16, depth uint16) error {
	if len(bytes) < IndexFixed {
		v.refuse("truncated index node")
		return nil
	}
	childCount := int(binary.LittleEndian.Uint16(bytes[24:26]))
	level := binary.LittleEndian.Uint16(bytes[26:28])
	expectedLen := IndexFixed + childCount*(BranchFixed+KeyBytes)
	aligned := (expectedLen + 7) &^ 7
	if int(common.Len) != aligned {
		v.refuse("index node length disagrees with its child count")
		return nil
	}
	if expectedLevel != nil {
		if level != *expectedLevel {
			v.refuse("index node level disagrees with its parent")
			return nil
		}
	} else {
		v.rootLevel = level
	}
	if uint32(childCount) > v.superblock.Fanout {
		v.refuse("index node has more children than the superblock's fanout")
	}
	var previous *NodeKey
	for child := 0; child < childCount; child++ {
		at := IndexFixed + child*(BranchFixed+KeyBytes)
		if at+BranchFixed+KeyBytes > len(bytes) {
			v.refuse("truncated index branch")
			continue
		}
		lnum := readLEU32(bytes, at)
		offs := readLEU32(bytes, at+4)
		length := readLEU32(bytes, at+8)
		keyValue, ok := ParseKey(bytes[at+BranchFixed : at+BranchFixed+KeyBytes])
		if !ok {
			v.refuse("bad index key (truncated)")
			continue
		}
		key := keyValue
		if !key.validIndexKey() {
			v.refuse("bad index key")
			continue
		}
		if previous != nil {
			old := previous.order()
			current := key.order()
			if current[0] < old[0] ||
				(current[0] == old[0] && (current[1] < old[1] ||
					(current[1] == old[1] && current[2] <= old[2]))) {
				v.refuse("bad index key (out of order)")
				continue
			}
		}
		previous = &key
		if uint64(offs)+uint64(length) > v.device.lebSize || length == 0 {
			v.refuse("bad index branch (range passes the LEB)")
			continue
		}
		if uint64(lnum) >= uint64(v.device.lebCount) {
			v.refuse("bad index branch (LEB past the volume)")
			continue
		}
		var childLevel *uint16
		if level != 0 {
			value := level - 1
			childLevel = &value
		}
		if err := v.walkIndex(lnum, uint64(offs), uint64(length), &key, childLevel, depth+1); err != nil {
			return err
		}
	}
	_ = imageOffset
	return nil
}

func (v *Volume) walkLeaf(bytes []byte, imageOffset uint64, lnum uint32, offs uint64, common Common, branchKey *NodeKey) error {
	switch common.NodeType {
	case NodeInode:
		v.inodeNodes++
		v.parseInode(bytes, imageOffset, lnum, offs, common, branchKey)
	case NodeDent:
		v.dentNodes++
		v.parseDent(bytes, imageOffset, common, branchKey)
	case NodeXent:
		v.xentNodes++
		v.parseXent(bytes, imageOffset, common, branchKey)
	case NodeData:
		v.dataNodes++
		v.parseData(bytes, imageOffset, lnum, offs, common, branchKey)
	case NodeTrun:
		v.trunNodes++
	case NodePad, NodeRef, NodeCS, NodeOrph, NodeAuth, NodeLPT, NodeLPTDent, NodeLPTIndex:
	default:
		v.unknownNodes++
		v.refuse("unknown node type")
	}
	return nil
}

func (v *Volume) parseInode(bytes []byte, imageOffset uint64, lnum uint32, offs uint64, common Common, branchKey *NodeKey) {
	if len(bytes) < InodeFixed {
		v.undecodable++
		v.refuse("truncated inode node")
		return
	}
	key, ok := ParseKey(bytes[CommonHeaderBytes:])
	if !ok {
		v.refuse("inode node has no key")
		return
	}
	if key.Kind != KeyIno {
		v.refuse("bad index key (inode node's key is not an inode key)")
		return
	}
	if branchKey != nil && branchKey.order() != key.order() {
		v.refuse("bad index key (inode key disagrees with its branch)")
	}
	dataLen := readLEU32(bytes, 120)
	available := len(bytes) - InodeFixed
	if int64(dataLen) > MaxInlineBytes {
		v.refuse("inode inline data past the 4096-byte inline bound")
	}
	inlineLen := int(dataLen)
	if inlineLen > available {
		inlineLen = available
	}
	if inlineLen > MaxInlineBytes {
		inlineLen = MaxInlineBytes
	}
	if int(dataLen) > available {
		v.refuse("inode inline data is truncated")
	}
	record := inodeRecord{
		uid:             readLEU32(bytes, 104),
		gid:             readLEU32(bytes, 108),
		mode:            readLEU32(bytes, 112),
		size:            readLEU64(bytes, 56),
		inline:          append([]byte(nil), bytes[InodeFixed:InodeFixed+inlineLen]...),
		inlineLnum:      lnum,
		inlineLEBOffset: offs + InodeFixed,
		nodeOffset:      imageOffset,
		sqnum:           common.Sqnum,
	}
	if seconds, nanos, ok := inodeTime(readLEU64(bytes, 64), readLEU32(bytes, 88)); ok {
		record.atimeSec, record.atimeNanos, record.hasAtime = uint64(seconds), uint32(nanos), true
	} else if !(readLEU64(bytes, 64) == 0 && readLEU32(bytes, 88) == 0) {
		v.refuse("invalid timestamp (nanoseconds past one second)")
	}
	if seconds, nanos, ok := inodeTime(readLEU64(bytes, 72), readLEU32(bytes, 92)); ok {
		record.ctimeSec, record.ctimeNanos, record.hasCtime = uint64(seconds), uint32(nanos), true
	} else if !(readLEU64(bytes, 72) == 0 && readLEU32(bytes, 92) == 0) {
		v.refuse("invalid timestamp (nanoseconds past one second)")
	}
	if seconds, nanos, ok := inodeTime(readLEU64(bytes, 80), readLEU32(bytes, 96)); ok {
		record.mtimeSec, record.mtimeNanos, record.hasMtime = uint64(seconds), uint32(nanos), true
	} else if !(readLEU64(bytes, 80) == 0 && readLEU32(bytes, 96) == 0) {
		v.refuse("invalid timestamp (nanoseconds past one second)")
	}
	previous, found := v.inodes[key.Inum]
	if !found || common.Sqnum >= previous.sqnum {
		v.inodes[key.Inum] = record
	}
}

func (v *Volume) parseDent(bytes []byte, imageOffset uint64, common Common, branchKey *NodeKey) {
	if branchKey == nil {
		v.refuse("dent node has no index key")
		return
	}
	key := *branchKey
	if key.Kind != KeyDent {
		v.refuse("bad index key (dent node's branch is not a dent key)")
		return
	}
	if len(bytes) < DentFixed {
		v.undecodable++
		v.refuse("truncated dent node")
		return
	}
	if embedded, ok := ParseKey(bytes[CommonHeaderBytes:]); ok && embedded.order() != key.order() {
		v.refuse("bad index key (dent key disagrees with its branch)")
	}
	nameLen := int(binary.LittleEndian.Uint16(bytes[54:56]))
	if nameLen == 0 || DentFixed+nameLen > len(bytes) {
		v.undecodable++
		v.refuse("dent name is truncated or empty")
		return
	}
	name := strings.ToValidUTF8(string(bytes[DentFixed:DentFixed+nameLen]), "�")
	v.pendingDents = append(v.pendingDents, dentRecord{
		parent: key.Inum, hash: key.Pos, name: name,
		inum: readLEU64(bytes, 40), dentType: bytes[52],
	})
	_ = imageOffset
	_ = common
}

func (v *Volume) parseXent(bytes []byte, imageOffset uint64, common Common, branchKey *NodeKey) {
	if branchKey == nil {
		v.refuse("xent node has no index key")
		return
	}
	key := *branchKey
	if key.Kind != KeyXent {
		v.refuse("bad index key (xent node's branch is not an xent key)")
		return
	}
	if len(bytes) < DentFixed {
		v.undecodable++
		v.refuse("truncated xent node")
		return
	}
	if embedded, ok := ParseKey(bytes[CommonHeaderBytes:]); ok && embedded.order() != key.order() {
		v.refuse("bad index key (xent key disagrees with its branch)")
	}
	nameLen := int(binary.LittleEndian.Uint16(bytes[54:56]))
	if nameLen == 0 || DentFixed+nameLen > len(bytes) {
		v.undecodable++
		v.refuse("xent name is truncated or empty")
		return
	}
	name := strings.ToValidUTF8(string(bytes[DentFixed:DentFixed+nameLen]), "�")
	inum := readLEU64(bytes, 40)
	v.pendingXents = append(v.pendingXents, xentRecord{
		parent: key.Inum, hash: key.Pos, name: name,
		inum: inum, hasInum: inum != 0, dentType: bytes[52],
		nodeOffset: imageOffset, sqnum: common.Sqnum,
	})
}

func (v *Volume) parseData(bytes []byte, imageOffset uint64, lnum uint32, offs uint64, common Common, branchKey *NodeKey) {
	key, ok := ParseKey(bytes[CommonHeaderBytes:])
	if !ok {
		v.refuse("data node has no key")
		return
	}
	if key.Kind != KeyData {
		v.refuse("bad index key (data node's key is not a data key)")
		return
	}
	if branchKey != nil && branchKey.order() != key.order() {
		v.refuse("bad index key (data key disagrees with its branch)")
	}
	if len(bytes) < DataFixed {
		v.refuse("truncated data node")
		v.corruptData[dataKey{inum: key.Inum, block: uint64(key.Pos)}] = true
		return
	}
	size := readLEU32(bytes, 40)
	compression := binary.LittleEndian.Uint16(bytes[44:46])
	if int64(size) > MaxDecodedBlock {
		v.refuse("data node past the 4096-byte block bound")
		v.corruptData[dataKey{inum: key.Inum, block: uint64(key.Pos)}] = true
		return
	}
	if !compressionSupported(compression) {
		v.refuse("unsupported compression type")
	}
	record := dataRecord{
		block:       uint64(key.Pos),
		lnum:        lnum,
		lebOffset:   offs + DataFixed,
		imageOffset: imageOffset + DataFixed,
		storedLen:   uint64(len(bytes) - DataFixed),
		size:        size,
		compression: compression,
		sqnum:       common.Sqnum,
	}
	previous, found := v.data[dataKey{inum: key.Inum, block: record.block}]
	if !found || common.Sqnum >= previous.sqnum {
		v.data[dataKey{inum: key.Inum, block: record.block}] = record
	}
}

func (v *Volume) buildTree() {
	deletedKeys := make(map[string]bool)
	for _, xent := range v.pendingXents {
		deletedKeys[dentKey(xent.parent, xent.hash, xent.name)] = true
	}
	allDentKeys := make(map[string]bool)
	for _, dent := range v.pendingDents {
		allDentKeys[dentKey(dent.parent, dent.hash, dent.name)] = true
	}
	var live []dentRecord
	for _, dent := range v.pendingDents {
		if deletedKeys[dentKey(dent.parent, dent.hash, dent.name)] {
			continue
		}
		live = append(live, dent)
	}
	for _, xent := range v.pendingXents {
		kind, ok := FromDentType(xent.dentType)
		if !ok {
			kind = KindOther
		}
		v.deleted = append(v.deleted, DeletedName{
			Parent: uint64(xent.parent), Inum: xent.inum, HasInum: xent.hasInum,
			Name: xent.name, Kind: kind, NodeOffset: xent.nodeOffset,
			Sqnum: xent.sqnum, Hash: xent.hash,
			MatchedDent: allDentKeys[dentKey(xent.parent, xent.hash, xent.name)],
		})
	}
	sort.SliceStable(v.deleted, func(left, right int) bool {
		if v.deleted[left].Name != v.deleted[right].Name {
			return v.deleted[left].Name < v.deleted[right].Name
		}
		return v.deleted[left].Parent < v.deleted[right].Parent
	})
	v.pendingDents = nil
	v.pendingXents = nil

	byParent := make(map[uint32][]dentRecord)
	for _, dent := range live {
		byParent[dent.parent] = append(byParent[dent.parent], dent)
	}
	for parent := range byParent {
		sort.SliceStable(byParent[parent], func(left, right int) bool {
			return byParent[parent][left].name < byParent[parent][right].name
		})
	}

	rootInode, found := v.inodes[uint32(RootIno)]
	if !found {
		v.undecodable++
		v.refuse("root inode node is missing")
	}
	v.pushEntry(v.entryFromInode(RootIno, 0, "/", rootInode, found, KindDirectory), "/")

	queue := []struct {
		inum uint32
		path string
	}{{inum: uint32(RootIno), path: "/"}}
	visitedDirs := map[uint32]bool{uint32(RootIno): true}
	listed := 0
walk:
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		for _, dent := range byParent[parent.inum] {
			if listed >= MaxEntries {
				v.refuse("entry cap reached")
				break walk
			}
			listed++
			if dent.inum == 0 || dent.inum > uint64(^uint32(0)) {
				v.undecodable++
				v.refuse("dent names an inode number outside the key range")
				continue
			}
			inode, found := v.inodes[uint32(dent.inum)]
			if !found {
				v.undecodable++
				v.refuse("dent names an inode with no inode node")
			}
			dentKind, named := FromDentType(dent.dentType)
			if !named {
				dentKind = KindOther
			}
			if !found && dentKind == KindOther {
				v.refuse("unknown dent type")
			}
			kind := dentKind
			if found {
				if inodeKind, ok := kindFromMode(inode.mode); ok {
					kind = inodeKind
				}
			}
			childPath := joinPath(parent.path, dent.name)
			entry := v.entryFromInode(dent.inum, uint64(parent.inum), childPath, inode, found, kind)
			v.pushEntry(entry, childPath)
			if parentIndex, ok := v.byPath[parent.path]; ok {
				v.nodes[parentIndex].Children = append(v.nodes[parentIndex].Children, dent.inum)
			}
			if kind.IsDirectory() {
				if visitedDirs[uint32(dent.inum)] {
					v.refuse("directory cycle in the name tree")
				} else {
					visitedDirs[uint32(dent.inum)] = true
					queue = append(queue, struct {
						inum uint32
						path string
					}{inum: uint32(dent.inum), path: childPath})
				}
			}
		}
	}
	for parent := range byParent {
		if parent != uint32(RootIno) && !visitedDirs[parent] {
			v.orphanDents += uint64(len(byParent[parent]))
		}
	}
	sizeCapHit := false
	for _, entry := range v.nodes {
		if entry.Kind == KindFile && entry.Size > MaxFileBytes {
			sizeCapHit = true
			break
		}
	}
	if sizeCapHit {
		v.refuse("file size cap reached")
	}
	for _, entry := range v.nodes {
		if entry.Kind == KindFile && v.fileUnreadable(uint32(entry.Inode), entry.Size) {
			v.unreadable++
		}
	}
}

func dentKey(parent uint32, hash uint32, name string) string {
	return fmtUint32(parent) + "/" + fmtUint32(hash) + "/" + name
}

func (v *Volume) entryFromInode(inum uint64, parent uint64, pathValue string, inode inodeRecord, hasInode bool, fallback NodeKind) Entry {
	kind := fallback
	if hasInode {
		if value, ok := kindFromMode(inode.mode); ok {
			kind = value
		}
	}
	entry := Entry{
		Name: nameOfPath(pathValue), Path: pathValue, Inode: inum,
		ParentInode: parent, Kind: kind, IsDir: kind.IsDirectory(),
		IsFile: kind.IsFile(), IsSymlink: kind.IsSymlink(),
		IsCharDev: kind == KindCharDevice, IsBlockDev: kind == KindBlockDevice,
		IsFifo: kind == KindFifo, IsSocket: kind == KindSocket, IsOther: kind == KindOther,
	}
	if hasInode {
		entry.Mode = inode.mode
		entry.UID = inode.uid
		entry.GID = inode.gid
	}
	switch kind {
	case KindFile:
		if hasInode {
			entry.Size = inode.size
			allocated := inode.size
			var stored uint64
			for key, record := range v.data {
				if key.inum == uint32(inum) {
					stored += record.storedLen
				}
			}
			stored += uint64(len(inode.inline))
			allocated = stored
			entry.Allocated = &allocated
		}
	case KindSymlink:
		if hasInode {
			entry.Size = uint64(len(inode.inline))
			entry.SymlinkTarget = strings.ToValidUTF8(string(inode.inline), "�")
		}
	}
	if hasInode {
		if inode.hasAtime {
			entry.Atime = time.Unix(int64(inode.atimeSec), int64(inode.atimeNanos)).UTC()
			entry.HasAtime = true
		}
		if inode.hasMtime {
			entry.Mtime = time.Unix(int64(inode.mtimeSec), int64(inode.mtimeNanos)).UTC()
			entry.HasMtime = true
		}
		if inode.hasCtime {
			entry.Ctime = time.Unix(int64(inode.ctimeSec), int64(inode.ctimeNanos)).UTC()
			entry.HasCtime = true
		}
	}
	return entry
}

func nameOfPath(pathValue string) string {
	if pathValue == "/" {
		return "/"
	}
	if at := strings.LastIndexByte(pathValue, '/'); at >= 0 {
		return pathValue[at+1:]
	}
	return pathValue
}

func (v *Volume) pushEntry(entry Entry, pathValue string) {
	index := len(v.nodes)
	v.nodes = append(v.nodes, entry)
	if _, found := v.byPath[pathValue]; !found {
		v.byPath[pathValue] = index
	}
	if _, found := v.byInode[entry.Inode]; !found {
		v.byInode[entry.Inode] = index
	}
	if pathValue != "/" {
		parentPath := normalizePath(pathValue[:strings.LastIndexByte(pathValue, '/')])
		if parentPath != pathValue {
			v.children[parentPath] = append(v.children[parentPath], index)
		}
	}
}

func (v *Volume) fileUnreadable(inum uint32, size uint64) bool {
	blocks := (size + BlockSize - 1) / BlockSize
	for block := uint64(0); block < blocks; block++ {
		if v.corruptData[dataKey{inum: inum, block: block}] {
			return true
		}
		if record, found := v.data[dataKey{inum: inum, block: block}]; found &&
			!compressionSupported(record.compression) {
			return true
		}
	}
	return false
}

func fmtUint32(value uint32) string {
	var buf [10]byte
	at := len(buf)
	for {
		at--
		buf[at] = byte('0' + value%10)
		value /= 10
		if value == 0 {
			break
		}
	}
	return string(buf[at:])
}
