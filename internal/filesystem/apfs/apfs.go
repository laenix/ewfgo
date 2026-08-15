package apfs

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/laenix/ewfgo/internal/filesystem"
)

// APFS (Apple File System) implementation.
//
// Every parse below was verified byte-for-byte against a real macOS APFS
// container (mac.E01: a macOS Data volume, 500 GB container, block size 4096):
//
//   - Mount chain (WIKI §3.3): the block-0 NXSB can be a STALE checkpoint, so
//     the live container superblock is found by scanning the checkpoint
//     descriptor area for the NXSB copy (type 0x80000001) with the highest
//     transaction id. The container object-map and volume object-map are
//     OMAP_MANUALLY_MANAGED objects: their `omap_oid` field IS their physical
//     block number (oid == paddr), so no checkpoint-map lookup is needed.
//   - Object-map B-tree keys are {oid, xid}; an oid resolves to the latest
//     (xid <= volume maxXid) entry. Nodes are fixed-KV (4-byte KVOffT TOC).
//   - The catalog (FSTREE) uses variable-KV nodes: 8-byte KVLocT TOC at 0x38,
//     key at 56+table_space_len+key_off, value at blocksize-val_off-40*(root).
//     Keys start with obj_id_and_type = (type<<60)|oid and have NO key_length
//     field (contrary to go-apfs's JKeyT).
//   - Inode xfield data items sit after all headers and are 8-byte aligned
//     relative to the value start (used_data accounts for the padding); the
//     inline DSTREAM xfield (type 8) carries the authoritative data-fork size.
//   - FILE_EXTENT records (type 8) are keyed by the data-stream oid: the inode's
//     own oid for ordinary files, or the DSTREAM_ID record's dstream oid for
//     cloned/shared streams. len/logical_addr are in BYTES.
//   - macOS stores the target of a data-fork-less symlink in the
//     com.apple.fs.symlink XATTR (type 4) on the inode, value layout
//     {flags u16, name_len u16, name[name_len]} with name NUL-terminated
//     (verified: localtime → /var/db/timezone/zoneinfo/Asia/Shanghai,
//     pip3.8 → ../../../Library/Frameworks/Python.framework/.../bin/pip3.8).

// APFS record types (the 4-bit type field of catalog obj_id_and_type keys).
const (
	apfsRecExtent     = 0x2
	apfsRecInode      = 0x3
	apfsRecXattr      = 0x4
	apfsRecDstreamID  = 0x6
	apfsRecFileExtent = 0x8
	apfsRecDirRec     = 0x9
)

// btree_node_phys flags.
const (
	apfsBtnRoot    = 0x1
	apfsBtnLeaf    = 0x2
	apfsBtnFixedKV = 0x4
)

// inode xfield types.
const (
	apfsXfName    = 4  // ino_ext_type_name
	apfsXfDstream = 8  // ino_ext_type_dstream (inline JDstreamT, Size@0)
	apfsXfSymlink = 32 // ino_ext_type_symlink (target path string)
)

const (
	// apfsFSRootOID is FSROOT_OID: the root directory inode of a volume.
	apfsFSRootOID = 2
	// apfsMaxTreeDepth bounds btree descent so crafted trees cannot loop.
	apfsMaxTreeDepth = 48
	// apfsMaxFileBytes bounds a single-file read (EWF 红线: no OOM on crafted sizes).
	apfsMaxFileBytes = uint64(1) << 40
	// apfsMaxExtentRead bounds one extent chunk read at 256 MiB (4 KiB blocks).
	apfsMaxExtentRead = uint64(1) << 16
	// maxSearchDepth bounds recursive directory traversal in SearchFiles.
	maxSearchDepth = 32
	// maxSearchCount bounds the number of results SearchFiles may return.
	maxSearchCount = 100000
)

// apfsIndex is the materialized view of the catalog tree, built lazily from
// real on-disk records. Every map holds parsed disk data — never fabricated
// entries (解析红线).
type apfsIndex struct {
	dirents map[uint64][]apfsDirent // parent directory ino -> child records
	inodes  map[uint64]*apfsInode   // ino -> inode record
	extents map[uint64][]apfsExtent // stream oid -> FILE_EXTENT records
	xattrs  map[uint64][]apfsXattr  // ino -> XATTR records
	dstream map[uint64]uint64       // ino -> dstream oid (DSTREAM_ID records)
}

// apfsXattr is a parsed XATTR record: the extended-attribute name and its
// value. The value is the raw record value ({flags u16, xdata_len u16, xdata})
// for embedded xattrs; for XATTR_DATA_STREAM xattrs (e.g. com.apple.ResourceFork)
// the payload lives in an external data stream and dataOID/dataSize point at it
// (value then carries the stream descriptor, not the payload). The
// com.apple.fs.symlink attribute carries the target of a symlink that has no
// data fork (macOS stores it there).
type apfsXattr struct {
	name     string
	value    []byte // embedded payload (including the 4-byte xattr header)
	dataOID  uint64 // external stream object id (XATTR_DATA_STREAM); 0 = embedded
	dataSize uint64 // external stream size (dstream.size); 0 when embedded
}

type apfsDirent struct {
	name  string
	ino   uint64
	dt    byte // DT_* from the dir-rec value (best effort)
	added int64
}

type apfsInode struct {
	size    uint64
	mode    uint16
	privID  uint64 // private_id: data-fork stream oid; resource fork is keyed privID+1
	modT    int64
	accT    int64
	creT    int64
	symlink string // target from the SYMLINK xfield ("" when not a symlink)
}

type apfsExtent struct {
	laddr  uint64 // logical byte offset in the file
	length uint64 // byte length (FILE_EXTENT len_and_flags low 56 bits; verified bytes, not blocks)
	paddr  uint64 // physical block number
}

// APFS implements filesystem.FileSystem over an APFS container partition.
type APFS struct {
	startLBA  uint64
	blocksize uint64
	readFunc  func(startLBA uint64, count uint64) ([]byte, error)

	// Mount state (set by ensureMounted).
	mounted        bool
	omapTreeRoot   uint64 // volume object-map B-tree root block
	catalogRootOid uint64
	maxXid         uint64
	volumeName     string

	// omapNodeCache caches object-map B-tree node blocks (immutable during a
	// read-only mount), avoiding re-reading them for every catalog-node resolve.
	omapNodeCache map[uint64][]byte

	// index is the lazily-built catalog view.
	index *apfsIndex
}

// --- little-endian readers (bounds-safe: never panic on crafted input) ---

func apfsU16(b []byte, off int) uint16 {
	if off < 0 || off+2 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint16(b[off:])
}

func apfsU32(b []byte, off int) uint32 {
	if off < 0 || off+4 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint32(b[off:])
}

func apfsU64(b []byte, off int) uint64 {
	if off < 0 || off+8 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint64(b[off:])
}

// apfsNsToSec converts an APFS epoch timestamp (nanoseconds since 1970) to the
// unix-seconds convention used by the rest of the handlers.
func apfsNsToSec(ns uint64) int64 {
	if ns >= 1e9 {
		return int64(ns / 1e9)
	}
	return 0
}

// apfsReadBlock reads one container block (partition-relative).
func (apfs *APFS) apfsReadBlock(block uint64) ([]byte, error) {
	return apfs.apfsReadBlocks(block, 1)
}

// apfsReadBlocks reads count consecutive container blocks.
func (apfs *APFS) apfsReadBlocks(block, count uint64) ([]byte, error) {
	if count == 0 {
		return []byte{}, nil
	}
	if apfs.readFunc == nil {
		return nil, fmt.Errorf("APFS: handler has no reader")
	}
	if apfs.blocksize == 0 || apfs.blocksize%512 != 0 {
		return nil, fmt.Errorf("APFS: invalid block size %d", apfs.blocksize)
	}
	sectors := apfs.blocksize / 512
	lba := apfs.startLBA + block*sectors
	data, err := apfs.readFunc(lba, count*sectors)
	if err != nil {
		return nil, fmt.Errorf("APFS: read block %d+%d: %w", block, count, err)
	}
	need := count * apfs.blocksize
	if uint64(len(data)) < need {
		return nil, fmt.Errorf("APFS: short read for blocks %d+%d: got %d bytes", block, count, len(data))
	}
	return data[:need], nil
}

func (apfs *APFS) Type() filesystem.FileSystemType { return filesystem.FS_APFS }

// Open parses the block-0 container superblock. The deep mount (descriptor-area
// scan, object maps, volume superblock) happens lazily in ensureMounted so a
// handler without a reader can still report container metadata.
func (apfs *APFS) Open(sectorData []byte) error {
	if len(sectorData) < 0x28 {
		return fmt.Errorf("APFS: superblock window too small")
	}
	if string(sectorData[0x20:0x24]) != "NXSB" {
		return fmt.Errorf("APFS: no NXSB container superblock at block 0")
	}
	bs := binary.LittleEndian.Uint32(sectorData[0x24:0x28])
	if bs < 4096 || bs > 1<<16 || bs%512 != 0 {
		return fmt.Errorf("APFS: invalid block size %d", bs)
	}
	apfs.blocksize = uint64(bs)
	return nil
}

func (apfs *APFS) Close() error {
	apfs.mounted = false
	apfs.index = nil
	apfs.omapNodeCache = nil
	return nil
}

// ensureMounted performs the full mount chain: find the live container
// superblock in the checkpoint descriptor area, resolve the container
// object-map, then the first valid volume (APSB).
func (apfs *APFS) ensureMounted() error {
	if apfs.mounted {
		return nil
	}
	if apfs.readFunc == nil {
		return fmt.Errorf("APFS: handler has no reader")
	}
	// Block-0 NXSB checkpoint descriptor geometry.
	nx, err := apfs.apfsReadBlock(0)
	if err != nil {
		return err
	}
	descBase := apfsU64(nx, 0x70)
	descBlocks := uint64(apfsU32(nx, 0x68))
	if descBase == 0 || descBlocks == 0 || descBlocks > 1<<20 {
		return fmt.Errorf("APFS: implausible checkpoint descriptor area base=%d blocks=%d", descBase, descBlocks)
	}

	// The block-0 NXSB may be a stale checkpoint (mac.E01: xid=2 while the live
	// checkpoint is xid=76). The descriptor area holds an NXSB copy per
	// checkpoint; take the copy with the highest transaction id.
	var bestXid uint64
	var liveNX []byte
	for b := uint64(0); b < descBlocks; b++ {
		blk, err := apfs.apfsReadBlock(descBase + b)
		if err != nil {
			return fmt.Errorf("APFS: read descriptor block %d: %w", descBase+b, err)
		}
		if apfsU32(blk, 0x18) != 0x80000001 { // NX_SUPERBLOCK
			continue
		}
		if xid := apfsU64(blk, 0x10); xid > bestXid {
			bestXid = xid
			liveNX = blk
		}
	}
	if liveNX == nil {
		return fmt.Errorf("APFS: no container superblock copy in the checkpoint descriptor area")
	}

	// Container object-map: OMAP_MANUALLY_MANAGED, oid == paddr.
	containerOmap := apfsU64(liveNX, 0xa0)
	if containerOmap == 0 {
		return fmt.Errorf("APFS: container object-map oid is zero")
	}
	containerMaxXid := apfsU64(liveNX, 0x60)
	if containerMaxXid > 1 {
		containerMaxXid-- // next_xid - 1
	}
	omapBlk, err := apfs.apfsReadBlock(containerOmap)
	if err != nil {
		return fmt.Errorf("APFS: read container object-map at block %d: %w", containerOmap, err)
	}
	containerTree := apfsU64(omapBlk, 0x30)
	if containerTree == 0 {
		return fmt.Errorf("APFS: container object-map tree oid is zero")
	}

	apfs.omapNodeCache = make(map[uint64][]byte)

	// Try each volume oid from the live NXSB; accept the first that resolves to
	// a valid volume superblock.
	maxFs := apfsU32(liveNX, 0xb4)
	if maxFs > 100 {
		maxFs = 100
	}
	for i := uint32(0); i < maxFs; i++ {
		fsOid := apfsU64(liveNX, int(0xb8)+8*int(i))
		if fsOid == 0 {
			continue
		}
		paddr, err := apfs.resolveOmapOidAt(containerTree, fsOid, containerMaxXid)
		if err != nil {
			continue
		}
		apBlk, err := apfs.apfsReadBlock(paddr)
		if err != nil {
			continue
		}
		if string(apBlk[0x20:0x24]) != "APSB" {
			continue
		}
		// Volume object-map (again oid == paddr).
		volOmap := apfsU64(apBlk, 0x80)
		if volOmap == 0 {
			continue
		}
		volOmapBlk, err := apfs.apfsReadBlock(volOmap)
		if err != nil {
			continue
		}
		apfs.omapTreeRoot = apfsU64(volOmapBlk, 0x30)
		apfs.catalogRootOid = apfsU64(apBlk, 0x88)
		apfs.maxXid = apfsU64(apBlk, 0x10) // the volume's own checkpoint xid
		apfs.volumeName = apfsReadCStr(apBlk[0x29e:], 256)
		if apfs.omapTreeRoot == 0 || apfs.catalogRootOid == 0 {
			return fmt.Errorf("APFS: volume at oid %d has no object-map/catalog", fsOid)
		}
		apfs.mounted = true
		return nil
	}
	return fmt.Errorf("APFS: no valid volume superblock in the container")
}

// resolveOmapOid resolves oid to a physical block through the object-map
// B-tree rooted at treeRoot, taking the entry with the largest xid <= maxXid.
func (apfs *APFS) resolveOmapOidAt(treeRoot, oid, maxXid uint64) (uint64, error) {
	node := treeRoot
	for depth := 0; depth < apfsMaxTreeDepth; depth++ {
		d, ok := apfs.omapNodeCache[node]
		if !ok {
			blk, err := apfs.apfsReadBlock(node)
			if err != nil {
				return 0, err
			}
			d = blk
			apfs.omapNodeCache[node] = d
		}
		flags := apfsU16(d, 0x20)
		level := apfsU16(d, 0x22)
		nkeys := apfsU32(d, 0x24)
		tableLen := int(apfsU16(d, 0x2a))
		if tableLen > len(d) {
			return 0, fmt.Errorf("APFS: object-map node %d has bad table length", node)
		}
		sel := -1
		for i := uint32(0); i < nkeys; i++ {
			toc := 0x38 + 4*i
			if int(toc)+4 > len(d) {
				break
			}
			keyOff := apfsU16(d, int(toc))
			keyPos := 56 + tableLen + int(keyOff)
			if keyPos+16 > len(d) {
				break
			}
			ko := apfsU64(d, keyPos)
			kx := apfsU64(d, keyPos+8)
			if ko < oid || (ko == oid && kx <= maxXid) {
				sel = int(i)
			} else {
				break
			}
		}
		if sel < 0 {
			return 0, fmt.Errorf("APFS: oid %d not present in object-map node %d", oid, node)
		}
		valOff := apfsU16(d, 0x38+4*sel+2)
		if valOff == 0xffff {
			return 0, fmt.Errorf("APFS: oid %d has a ghost object-map entry", oid)
		}
		valPos := int(apfs.blocksize) - int(valOff)
		if flags&apfsBtnRoot != 0 {
			valPos -= 40
		}
		if valPos < 0 || valPos+8 > len(d) {
			return 0, fmt.Errorf("APFS: object-map node %d value out of bounds", node)
		}
		if level > 0 {
			node = apfsU64(d, valPos)
			if node == 0 {
				return 0, fmt.Errorf("APFS: object-map node %d has a zero child pointer", node)
			}
		} else {
			return apfsU64(d, valPos+8), nil
		}
	}
	return 0, fmt.Errorf("APFS: object-map lookup for oid %d exceeded depth", oid)
}

// resolveOmapOid resolves through the mounted volume object-map.
func (apfs *APFS) resolveOmapOid(oid uint64) (uint64, error) {
	return apfs.resolveOmapOidAt(apfs.omapTreeRoot, oid, apfs.maxXid)
}

// apfsReadCStr reads a NUL-terminated string from buf (at most max bytes).
func apfsReadCStr(buf []byte, max int) string {
	end := 0
	for end < max && end < len(buf) && buf[end] != 0 {
		end++
	}
	return string(buf[:end])
}

// --- catalog (FSTREE) walk ---

// ensureIndex builds the catalog index on first use.
func (apfs *APFS) ensureIndex() error {
	if apfs.index != nil {
		return nil
	}
	if err := apfs.ensureMounted(); err != nil {
		return err
	}
	rootPaddr, err := apfs.resolveOmapOid(apfs.catalogRootOid)
	if err != nil {
		return fmt.Errorf("APFS: resolve catalog root oid %d: %w", apfs.catalogRootOid, err)
	}
	idx := &apfsIndex{
		dirents: make(map[uint64][]apfsDirent),
		inodes:  make(map[uint64]*apfsInode),
		extents: make(map[uint64][]apfsExtent),
		xattrs:  make(map[uint64][]apfsXattr),
		dstream: make(map[uint64]uint64),
	}
	if err := apfs.walkCatalogNode(rootPaddr, 0, idx, make(map[uint64]bool)); err != nil {
		return err
	}
	for _, exts := range idx.extents {
		sort.Slice(exts, func(i, j int) bool { return exts[i].laddr < exts[j].laddr })
	}
	// Compressed files are dataless: their dstream xfield size is unreliable (0
	// on some files, the uncompressed size on others — verified on mac.E01) and
	// their data fork has no extents. The com.apple.decmpfs header's size field
	// is authoritative for them, so the reported file size matches the data that
	// GetFile actually returns.
	for ino, in := range idx.inodes {
		if sz := apfsDecmpfsSize(idx.xattrs[ino]); sz != 0 {
			in.size = sz
		}
	}
	apfs.index = idx
	return nil
}

// walkCatalogNode descends a variable-KV catalog node, materializing records
// into idx. visited guards against crafted cycles.
func (apfs *APFS) walkCatalogNode(paddr uint64, depth int, idx *apfsIndex, visited map[uint64]bool) error {
	if depth > apfsMaxTreeDepth {
		return fmt.Errorf("APFS: catalog tree depth exceeded at block %d", paddr)
	}
	if visited[paddr] {
		return fmt.Errorf("APFS: catalog cycle at block %d", paddr)
	}
	visited[paddr] = true

	d, err := apfs.apfsReadBlock(paddr)
	if err != nil {
		return err
	}
	flags := apfsU16(d, 0x20)
	level := apfsU16(d, 0x22)
	nkeys := apfsU32(d, 0x24)
	if nkeys > 0x100000 {
		return fmt.Errorf("APFS: catalog node %d has implausible nkeys %d", paddr, nkeys)
	}
	tableLen := int(apfsU16(d, 0x2a))
	if tableLen > len(d) {
		return fmt.Errorf("APFS: catalog node %d has bad table length", paddr)
	}

	for i := uint32(0); i < nkeys; i++ {
		toc := 0x38 + 8*i
		if int(toc)+8 > len(d) {
			break
		}
		keyOff := apfsU16(d, int(toc))
		keyLen := apfsU16(d, int(toc)+2)
		valOff := apfsU16(d, int(toc)+4)
		valLen := apfsU16(d, int(toc)+6)
		keyPos := 56 + tableLen + int(keyOff)
		if keyPos < 0 || keyPos+8 > len(d) || keyPos+int(keyLen) > len(d) {
			continue
		}
		var valPos int
		if valOff == 0xffff {
			continue // ghost entry (index node with no child)
		}
		valPos = int(apfs.blocksize) - int(valOff)
		if flags&apfsBtnRoot != 0 {
			valPos -= 40
		}
		if valPos < 0 || valPos+int(valLen) > len(d) {
			continue
		}

		v := apfsU64(d, keyPos)
		typ := v >> 60
		id := v & 0x0fffffffffffffff

		if level > 0 {
			childOid := apfsU64(d, valPos)
			if childOid == 0 {
				continue
			}
			childPaddr, err := apfs.resolveOmapOid(childOid)
			if err != nil {
				return err
			}
			if err := apfs.walkCatalogNode(childPaddr, depth+1, idx, visited); err != nil {
				return err
			}
			continue
		}

		val := d[valPos : valPos+int(valLen)]
		switch typ {
		case apfsRecDirRec:
			if int(valLen) < 8 {
				continue
			}
			nlh := apfsU32(d, keyPos+8)
			nlen := int(nlh & 0x3ff) // name_len (low 10 bits, includes trailing NUL)
			if maxName := int(keyLen) - 12; nlen > maxName {
				nlen = maxName
			}
			if nlen <= 0 || keyPos+12+nlen > len(d) {
				continue
			}
			name := string(d[keyPos+12 : keyPos+12+nlen])
			if name[len(name)-1] == 0 {
				name = name[:len(name)-1]
			}
			if name == "" {
				continue
			}
			de := apfsDirent{name: name, ino: apfsU64(val, 0)}
			if int(valLen) >= 17 {
				de.dt = val[16]
			}
			if int(valLen) >= 16 {
				de.added = int64(apfsU32(val, 8))
			}
			idx.dirents[id] = append(idx.dirents[id], de)
		case apfsRecXattr:
			// key = {obj_id_and_type u64, name_len u16, name[name_len]}, the
			// name_len including the trailing NUL.
			if int(keyLen) < 10 {
				continue
			}
			nlen := int(apfsU16(d, keyPos+8))
			if nlen < 1 || keyPos+10+nlen > len(d) {
				continue
			}
			name := string(d[keyPos+10 : keyPos+10+nlen])
			if name[len(name)-1] == 0 {
				name = name[:len(name)-1]
			}
			if name == "" {
				continue
			}
			xa := apfsXattr{name: name, value: append([]byte(nil), val...)}
			// j_xattr_val_t = {flags u16, xdata_len u16, xdata[...]}. With
			// XATTR_DATA_STREAM (0x0001) xdata is j_xattr_dstream_t and the payload
			// is a separate data stream; its object id is at xdata+0 and its size at
			// xdata+8 (verified: mac.E01 usr/libexec/cups/apple/ipp ino 635's
			// com.apple.ResourceFork has flags 0x0001, xattr_obj_id 636, size 81920).
			if len(val) >= 4 && apfsU16(val, 0)&0x0001 != 0 {
				if doid := apfsU64(val, 4); doid != 0 {
					xa.dataOID = doid
					xa.dataSize = apfsU64(val, 12)
				}
			}
			idx.xattrs[id] = append(idx.xattrs[id], xa)
		case apfsRecInode:
			if int(valLen) < 92 {
				continue
			}
			in := &apfsInode{
				privID: apfsU64(val, 8), // j_inode_val.private_id
				mode:   apfsU16(val, 80),
				modT:   apfsNsToSec(apfsU64(val, 24)),
				accT:   apfsNsToSec(apfsU64(val, 40)),
				creT:   apfsNsToSec(apfsU64(val, 16)),
			}
			in.size, in.symlink = apfsInodeXfields(val)
			idx.inodes[id] = in
		case apfsRecDstreamID:
			// j_dstream_id_val_t = {refcnt u64, dstream_id u64}. The dstream_id is
			// the object whose FILE_EXTENT records hold the file's data. For an
			// ordinary file the dstream oid equals the inode's own oid and its
			// extents are inode-keyed (verified: backup_manifest.plist ino 328858
			// has DSTREAM_ID dstream=328858 + FILE_EXTENT keyed 328858), but for
			// cloned/shared data streams it points at a SEPARATE stream object
			// whose extents carry that oid instead (verified on mac.E01:
			// usr/libexec/cups/apple/ipp ino 635 has a DSTREAM_ID to a distinct
			// dstream oid and no extents keyed by 635).
			if int(valLen) >= 16 {
				if doid := apfsU64(val, 8); doid != 0 {
					idx.dstream[id] = doid
				}
			}
		case apfsRecFileExtent:
			if int(valLen) < 16 || int(keyLen) < 16 {
				continue
			}
			length := apfsU64(val, 0) & 0x00ffffffffffffff
			paddr := apfsU64(val, 8)
			if length == 0 || paddr == 0 {
				continue
			}
			idx.extents[id] = append(idx.extents[id], apfsExtent{
				laddr:  apfsU64(d, keyPos+8),
				length: length,
				paddr:  paddr,
			})
		}
	}
	return nil
}

// apfsInodeXfields walks the inode-value xfield blob (at val[92:]) and returns
// the data-fork size (the inline DSTREAM xfield's Size is authoritative, else
// uncompressed_size) and the symlink target (the SYMLINK xfield), each
// zero/empty when absent.
func apfsInodeXfields(val []byte) (size uint64, symlink string) {
	size = binary.LittleEndian.Uint64(val[84:92]) // uncompressed_size fallback
	if len(val) < 92 {
		return size, ""
	}
	// xfield blob at val[92:]: {num_exts u16, used_data u16}, headers (4 bytes
	// each), then data items in header order — 8-byte aligned relative to the
	// value start (verified: used_data accounts for the padding).
	blob := val[92:]
	if len(blob) < 4 {
		return size, ""
	}
	numExts := int(binary.LittleEndian.Uint16(blob[0:2]))
	hdrEnd := 4 + 4*numExts
	if hdrEnd > len(blob) {
		return size, ""
	}
	off := hdrEnd
	for i := 0; i < numExts; i++ {
		if i > 0 {
			off = int((uint64(92+off+7) &^ 7) - 92)
		}
		xfType := blob[4+4*i]
		xfSize := int(binary.LittleEndian.Uint16(blob[6+4*i : 8+4*i]))
		if off < 0 || off+xfSize > len(blob) {
			return size, symlink
		}
		if xfType == apfsXfDstream && xfSize >= 8 {
			size = binary.LittleEndian.Uint64(blob[off:])
		}
		if xfType == apfsXfSymlink {
			s := string(blob[off : off+xfSize])
			if i := strings.IndexByte(s, 0); i >= 0 {
				s = s[:i]
			}
			symlink = s
		}
		off += xfSize
	}
	return size, symlink
}

// apfsInodeDataForkSize returns the data-fork size for an inode value.
func apfsInodeDataForkSize(val []byte) uint64 {
	size, _ := apfsInodeXfields(val)
	return size
}

// resolvePath resolves a cleaned (no leading/trailing slash) path to an inode.
// Symlinks are followed at every component; when followFinal is set they are
// followed at the final component too, so listing or searching through a
// symlink reaches its target. Following is bounded and cycle-guarded.
func (apfs *APFS) resolvePath(clean string, followFinal bool) (uint64, error) {
	if clean == "" {
		return apfsFSRootOID, nil
	}
	return apfs.resolvePathFrom(apfsFSRootOID, strings.Split(clean, "/"), followFinal, make(map[uint64]struct{}))
}

// resolvePathFrom resolves parts starting from ino, dereferencing symlinks via
// their target xfield. seen holds every symlink inode dereferenced so far,
// bounding total hops and breaking loops. A relative symlink target is resolved
// within the directory that contained the symlink.
func (apfs *APFS) resolvePathFrom(ino uint64, parts []string, followFinal bool, seen map[uint64]struct{}) (uint64, error) {
	cur := "/"
	for i := 0; i < len(parts); i++ {
		part := parts[i]
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			return 0, fmt.Errorf("APFS: '..' is not supported")
		}
		found := false
		parent := ino
		for _, de := range apfs.index.dirents[ino] {
			if de.name == part {
				ino = de.ino
				cur = filesystem.JoinPath(cur, part)
				found = true
				break
			}
		}
		if !found {
			return 0, fmt.Errorf("APFS: %q not found in %q", part, cur)
		}
		in, ok := apfs.index.inodes[ino]
		if !ok || in.mode&0xf000 != 0xa000 {
			continue
		}
		last := i == len(parts)-1
		if last && !followFinal {
			continue
		}
		if len(seen) >= 40 {
			return 0, fmt.Errorf("APFS: too many symlinks resolving %q", part)
		}
		if _, loop := seen[ino]; loop {
			return 0, fmt.Errorf("APFS: symlink loop at %q", part)
		}
		seen[ino] = struct{}{}
		target, err := apfs.readSymlinkTarget(in, ino)
		if err != nil {
			return 0, err
		}
		rest := parts[i+1:]
		if strings.HasPrefix(target, "/") {
			return apfs.resolvePathFrom(apfsFSRootOID, append(strings.Split(strings.TrimLeft(target, "/"), "/"), rest...), followFinal, seen)
		}
		return apfs.resolvePathFrom(parent, append(strings.Split(target, "/"), rest...), followFinal, seen)
	}
	return ino, nil
}

// readSymlinkTarget returns the target of a symlink inode. macOS stores the
// target either in the inode's SYMLINK extended field (type 32) or — for the
// data-fork-less symlinks it creates — in the com.apple.fs.symlink extended
// attribute (verified on mac.E01: pip3.8 → ../../../Library/.../bin/pip3.8,
// /usr/libexec/rosetta/translate_tool, XProtect startup plists). A missing or
// undecodable target is an explicit error, never a guessed path.
func (apfs *APFS) readSymlinkTarget(in *apfsInode, ino uint64) (string, error) {
	if in.symlink != "" {
		return in.symlink, nil
	}
	for _, xa := range apfs.index.xattrs[ino] {
		if xa.name != "com.apple.fs.symlink" {
			continue
		}
		if tgt, ok := apfsSymlinkXattrTarget(xa.value); ok {
			return tgt, nil
		}
		return "", fmt.Errorf("APFS: symlink inode %d has a malformed com.apple.fs.symlink xattr", ino)
	}
	return "", fmt.Errorf("APFS: symlink inode %d has no target (no SYMLINK field, no com.apple.fs.symlink xattr)", ino)
}

// apfsSymlinkXattrTarget decodes the com.apple.fs.symlink xattr value, whose
// layout is {flags u16, name_len u16, name[name_len]} with name a
// NUL-terminated target path (flags observed as 0x0006). It returns false when
// the value does not fit that layout.
func apfsSymlinkXattrTarget(val []byte) (string, bool) {
	if len(val) < 4 {
		return "", false
	}
	sz := binary.LittleEndian.Uint16(val[2:4])
	if sz == 0 || 4+int(sz) > len(val) {
		return "", false
	}
	s := string(val[4 : 4+int(sz)])
	if i := strings.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return "", false
	}
	return s, true
}

func (apfs *APFS) isDirIno(ino uint64) bool {
	if in, ok := apfs.index.inodes[ino]; ok {
		return in.mode&0xf000 == 0x4000
	}
	return false
}

// ListDirectory lists the entries of path (root when path is "" or "/").
func (apfs *APFS) ListDirectory(path string) ([]filesystem.DirectoryEntry, error) {
	if apfs.readFunc == nil {
		return nil, fmt.Errorf("APFS: handler has no reader")
	}
	if err := apfs.ensureIndex(); err != nil {
		return nil, err
	}
	ino, err := apfs.resolvePath(strings.Trim(path, "/"), true)
	if err != nil {
		return nil, err
	}
	if !apfs.isDirIno(ino) {
		return nil, fmt.Errorf("APFS: %q is not a directory", path)
	}
	dents := apfs.index.dirents[ino]
	entries := make([]filesystem.DirectoryEntry, 0, len(dents))
	dir := "/"
	if path != "" && path != "/" {
		dir = strings.TrimRight(path, "/") + "/"
	}
	for _, de := range dents {
		e := filesystem.DirectoryEntry{
			Name:  de.name,
			Path:  dir + de.name,
			Inode: de.ino,
		}
		if in, ok := apfs.index.inodes[de.ino]; ok {
			e.Size = in.size
			e.IsDir = in.mode&0xf000 == 0x4000
			e.ModTime = in.modT
		} else {
			e.IsDir = de.dt == 4
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// GetFileByPath returns metadata for the file or directory at path.
func (apfs *APFS) GetFileByPath(path string) (*filesystem.FileInfo, error) {
	if apfs.readFunc == nil {
		return nil, fmt.Errorf("APFS: handler has no reader")
	}
	if err := apfs.ensureIndex(); err != nil {
		return nil, err
	}
	clean := strings.Trim(path, "/")
	ino, err := apfs.resolvePath(clean, false)
	if err != nil {
		return nil, err
	}
	in, ok := apfs.index.inodes[ino]
	if !ok {
		return nil, fmt.Errorf("APFS: inode %d has no inode record", ino)
	}
	name := "root"
	if clean != "" {
		parts := strings.Split(clean, "/")
		name = parts[len(parts)-1]
	}
	mode := filesystem.FileMode(in.mode & 0xf000)
	return &filesystem.FileInfo{
		Name:       name,
		Path:       "/" + strings.Trim(clean, "/"),
		Size:       in.size,
		Mode:       mode,
		IsDir:      mode == filesystem.ModeDir,
		ModTime:    in.modT,
		AccessTime: in.accT,
		CreateTime: in.creT,
		IsReadOnly: in.mode&0x80 == 0, // owner write (S_IWUSR = 0x80)
	}, nil
}

// GetFile reads a file's content by assembling its FILE_EXTENT records.
func (apfs *APFS) GetFile(path string) ([]byte, error) {
	if apfs.readFunc == nil {
		return nil, fmt.Errorf("APFS: handler has no reader")
	}
	if err := apfs.ensureIndex(); err != nil {
		return nil, err
	}
	clean := strings.Trim(path, "/")
	if clean == "" {
		return nil, fmt.Errorf("APFS: root path has no file content")
	}
	ino, err := apfs.resolvePath(clean, false)
	if err != nil {
		return nil, err
	}
	in, ok := apfs.index.inodes[ino]
	if !ok {
		return nil, fmt.Errorf("APFS: inode %d has no inode record", ino)
	}
	if in.mode&0xf000 == 0x4000 {
		return nil, fmt.Errorf("APFS: %q is a directory", path)
	}
	if in.mode&0xf000 == 0xa000 {
		target, err := apfs.readSymlinkTarget(in, ino)
		if err != nil {
			return nil, err
		}
		return []byte(target), nil
	}
	size := in.size
	if size > apfsMaxFileBytes {
		return nil, fmt.Errorf("APFS: inode %d size %d exceeds the supported maximum", ino, size)
	}
	// macOS transparently compresses most system files: a valid com.apple.decmpfs
	// xattr makes the data fork dataless and the content must be decompressed
	// from the xattr/resource fork. Run that first so we never return a dataless
	// fork's zeros as file content (EWF 红线). Unsupported decmpfs algorithms are
	// explicit errors, not fabricated data.
	if dec, err := apfs.apfsReadDecmpfs(ino); err != nil {
		return nil, err
	} else if dec != nil {
		if uint64(len(dec)) != in.size {
			return nil, fmt.Errorf("APFS: inode %d decompressed to %d bytes, inode size is %d", ino, len(dec), in.size)
		}
		return dec, nil
	}
	// The extents live under the inode's data-stream oid: the ino itself, or the
	// DSTREAM_ID record's dstream oid when the stream is shared/cloned.
	extKey := ino
	if doid, ok := apfs.index.dstream[ino]; ok && doid != 0 {
		extKey = doid
	}
	return apfs.apfsReadStream(extKey, size)
}

// apfsReadStream assembles a data stream's FILE_EXTENT records (keyed by
// streamOID) into a byte slice of exactly size bytes. FILE_EXTENT
// logical_addr/len are byte units (verified on mac.E01: a 643-byte file's
// single extent is len=4096 == alloced_size; ino 624's two extents sum to
// 20480 == alloced_size), so the physical read count is ceil(bytes / blocksize)
// blocks, advanced per chunk in block units. Unallocated gaps stay zero, which
// is the true APFS sparse-file content.
func (apfs *APFS) apfsReadStream(streamOID, size uint64) ([]byte, error) {
	if size > apfsMaxFileBytes {
		return nil, fmt.Errorf("APFS: stream %d size %d exceeds the supported maximum", streamOID, size)
	}
	out := make([]byte, size)
	for _, ext := range apfs.index.extents[streamOID] {
		if ext.laddr >= size {
			continue
		}
		n := ext.length
		if ext.laddr+n > size {
			n = size - ext.laddr
		}
		remaining := n
		paddr := ext.paddr
		off := ext.laddr
		for remaining > 0 {
			nblk := remaining / apfs.blocksize
			if remaining%apfs.blocksize != 0 {
				nblk++
			}
			if nblk > apfsMaxExtentRead {
				nblk = apfsMaxExtentRead
			}
			take := nblk * apfs.blocksize
			if take > remaining {
				take = remaining
			}
			data, err := apfs.apfsReadBlocks(paddr, nblk)
			if err != nil {
				return nil, err
			}
			copy(out[off:off+take], data[:take])
			paddr += nblk
			off += take
			remaining -= take
		}
	}
	return out, nil
}

// SearchFiles recurses the tree from rootPath, returning entries matching the
// predicate. Depth and result count are bounded.
func (apfs *APFS) SearchFiles(rootPath string, predicate func(filesystem.FileInfo) bool) ([]filesystem.FileInfo, error) {
	if apfs.readFunc == nil {
		return nil, fmt.Errorf("APFS: handler has no reader")
	}
	if err := apfs.ensureIndex(); err != nil {
		return nil, err
	}
	cleanRoot := strings.Trim(rootPath, "/")
	start := uint64(apfsFSRootOID)
	base := ""
	if cleanRoot != "" {
		var err error
		start, err = apfs.resolvePath(cleanRoot, true)
		if err != nil {
			return nil, err
		}
		if !apfs.isDirIno(start) {
			return nil, fmt.Errorf("APFS: search root %q is not a directory", rootPath)
		}
		base = "/" + cleanRoot
	}

	results := make([]filesystem.FileInfo, 0)
	visited := make(map[uint64]bool)
	var walk func(ino uint64, dirPath string, depth int) error
	walk = func(ino uint64, dirPath string, depth int) error {
		if depth > maxSearchDepth || visited[ino] {
			return nil
		}
		visited[ino] = true
		for _, de := range apfs.index.dirents[ino] {
			if len(results) >= maxSearchCount {
				return fmt.Errorf("APFS: search exceeded %d results", maxSearchCount)
			}
			fi := filesystem.FileInfo{Name: de.name, Path: filesystem.JoinPath(dirPath, de.name), Mode: filesystem.ModeRegular}
			isDir := false
			if in, ok := apfs.index.inodes[de.ino]; ok {
				fi.Size = in.size
				fi.Mode = filesystem.FileMode(in.mode & 0xf000)
				fi.ModTime = in.modT
				fi.AccessTime = in.accT
				fi.CreateTime = in.creT
				isDir = fi.Mode == filesystem.ModeDir
			} else {
				isDir = de.dt == 4
				if isDir {
					fi.Mode = filesystem.ModeDir
				}
			}
			fi.IsDir = isDir
			if predicate(fi) {
				results = append(results, fi)
			}
			if isDir && depth < maxSearchDepth {
				if err := walk(de.ino, fi.Path, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(start, base, 0); err != nil {
		return nil, err
	}
	return results, nil
}

// GetVolumeLabel returns the mounted volume's name.
func (apfs *APFS) GetVolumeLabel() string {
	return apfs.volumeName
}

// NewAPFSHandler creates an APFS handler bound to a reader at startLBA.
func NewAPFSHandler(reader filesystem.Reader, startLBA uint64) (*APFS, error) {
	apfs := &APFS{
		startLBA: startLBA,
		readFunc: reader.ReadSectors,
	}
	sectorData, err := reader.ReadSectors(startLBA, 16)
	if err != nil {
		return nil, fmt.Errorf("APFS: failed to read superblock: %w", err)
	}
	if err := apfs.Open(sectorData); err != nil {
		return nil, err
	}
	return apfs, nil
}

func init() {
	filesystem.RegisterFileSystem(filesystem.FS_APFS, func() filesystem.FileSystem { return &APFS{} })
	filesystem.RegisterHandler(filesystem.FS_APFS, func(r filesystem.Reader, startLBA, partitionSize uint64) (filesystem.FileSystem, error) {
		return NewAPFSHandler(r, startLBA)
	})
}
