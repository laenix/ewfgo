package ubifs

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Entry is one live name inside a mounted volume.
type Entry struct {
	Name        string
	Path        string
	Inode       uint64
	ParentInode uint64
	Kind        NodeKind

	IsDir      bool
	IsFile     bool
	IsSymlink  bool
	IsCharDev  bool
	IsBlockDev bool
	IsFifo     bool
	IsSocket   bool
	IsOther    bool

	Mode uint32
	UID  uint32
	GID  uint32
	Size uint64
	// Allocated is the bytes live data nodes store.  It is nil for a
	// directory, symlink or special file.
	Allocated *uint64

	SymlinkTarget string

	Atime time.Time
	Mtime time.Time
	Ctime time.Time
	// HasAtime, HasMtime and HasCtime are false when the inode's seconds and
	// nanoseconds pair was zero.
	HasAtime bool
	HasMtime bool
	HasCtime bool

	// Children holds child inode numbers for a directory.
	Children []uint64

	// Deleted is always false for UBIFS: xent names are reported through
	// Deleted() rather than given live paths.
	Deleted bool
}

// IsDirectory reports whether the entry is a directory.
func (e Entry) IsDirectory() bool { return e.Kind.IsDirectory() }

// IsRegularFile reports whether the entry is a regular file.
func (e Entry) IsRegularFile() bool { return e.Kind.IsFile() }

// IsSymbolicLink reports whether the entry is a symbolic link.
func (e Entry) IsSymbolicLink() bool { return e.Kind.IsSymlink() }

// UBIInfo describes the UBI layer when the volume is mounted through UBI.
type UBIInfo struct {
	VolID      uint32
	VolumeName string
	Layout     Layout
	TableState TableState
}

// Info is a volume report.
type Info struct {
	Kind     string
	SourceID source.ID

	LEBSize           uint32
	LEBCount          uint32
	MaxLEBCount       uint32
	MinIOSize         uint32
	Fanout            uint32
	FormatVersion     uint32
	KeyHash           uint8
	KeyFormat         uint8
	Flags             uint32
	DefaultCompressor uint16
	UUID              [16]byte

	MasterSelection MasterSelection
	Master1         *MasterNode
	Master2         *MasterNode
	RootInode       uint64
	RootLnum        uint32
	RootOffs        uint32
	RootLen         uint32
	RootLevel       uint16

	Entries      uint64
	IndexNodes   uint64
	LeafNodes    uint64
	InodeNodes   uint64
	DentNodes    uint64
	XentNodes    uint64
	DataNodes    uint64
	TrunNodes    uint64
	UnknownNodes uint64
	OrphanDents  uint64
	DeletedNames uint64
	Holes        uint64
	HoleBytes    uint64
	Unreadable   uint64
	Undecodable  uint64
	Refusals     []Refusal
	UBI          *UBIInfo
}

type inodeRecord struct {
	mode            uint32
	uid             uint32
	gid             uint32
	size            uint64
	atimeSec        uint64
	atimeNanos      uint32
	hasAtime        bool
	mtimeSec        uint64
	mtimeNanos      uint32
	hasMtime        bool
	ctimeSec        uint64
	ctimeNanos      uint32
	hasCtime        bool
	inline          []byte
	inlineLnum      uint32
	inlineLEBOffset uint64
	nodeOffset      uint64
	sqnum           uint64
}

func (r inodeRecord) kind() (NodeKind, bool) { return kindFromMode(r.mode) }

func (r inodeRecord) isFile() bool {
	kind, ok := r.kind()
	return ok && kind.IsFile()
}

type dentRecord struct {
	parent   uint32
	hash     uint32
	name     string
	inum     uint64
	dentType uint8
}

type xentRecord struct {
	parent     uint32
	hash       uint32
	name       string
	inum       uint64
	hasInum    bool
	dentType   uint8
	nodeOffset uint64
	sqnum      uint64
}

type dataKey struct {
	inum  uint32
	block uint64
}

type dataRecord struct {
	block       uint64
	lnum        uint32
	lebOffset   uint64
	imageOffset uint64
	storedLen   uint64
	size        uint32
	compression uint16
	sqnum       uint64
}

// Volume is a mounted UBIFS volume.
type Volume struct {
	source     source.ByteSource
	device     Device
	superblock *Superblock
	master1    *MasterNode
	master2    *MasterNode
	selection  MasterSelection

	rootLnum  uint32
	rootOffs  uint32
	rootLen   uint32
	rootLevel uint16

	nodes        []Entry
	byPath       map[string]int
	byInode      map[uint64]int
	children     map[string][]int
	inodes       map[uint32]inodeRecord
	data         map[dataKey]dataRecord
	pendingDents []dentRecord
	pendingXents []xentRecord
	corruptData  map[dataKey]bool
	deleted      []DeletedName
	refusals     map[string]uint64

	walkedNodes  uint64
	indexNodes   uint64
	leafNodes    uint64
	inodeNodes   uint64
	dentNodes    uint64
	xentNodes    uint64
	dataNodes    uint64
	trunNodes    uint64
	unknownNodes uint64
	orphanDents  uint64
	undecodable  uint64
	unreadable   uint64
	holes        uint64
	holeBytes    uint64

	ubi      *UbiImage
	ubiVolID uint32
	hasUBI   bool

	fileID atomic.Uint64
}

// Detect reports whether src looks like a UBIFS volume or a UBI image with a
// UBIFS volume.
func Detect(src source.ByteSource) (bool, error) {
	if src.Len() < MasterPage {
		return false, nil
	}
	hasUBI, err := HasECMagic(src)
	if err != nil {
		return false, err
	}
	if hasUBI {
		image, err := OpenUBI(src)
		if err != nil {
			return false, err
		}
		for _, volume := range image.volumes {
			if volume.UBIFS {
				return true, nil
			}
		}
		return false, nil
	}
	var magic [4]byte
	if err := source.ReadExactAt(src, 0, magic[:]); err != nil {
		return false, err
	}
	if u32At(magic[:]) != Magic {
		return false, nil
	}
	bytes, err := source.ReadVecAt(src, 0, MasterPage)
	if err != nil {
		return false, err
	}
	if _, err := ParseSuperblock(bytes); err != nil {
		return false, err
	}
	return true, nil
}

// Open mounts a source.  A UBI image mounts its first volume whose LEB 0 is a
// UBIFS superblock; a bare UBIFS image mounts directly.
func Open(src source.ByteSource) (*Volume, error) {
	hasUBI, err := HasECMagic(src)
	if err != nil {
		return nil, err
	}
	if hasUBI {
		image, err := OpenUBI(src)
		if err != nil {
			return nil, err
		}
		volumes := image.Volumes()
		if volumes == nil {
			return nil, unsupportedf("the two UBI volume-table copies disagree; the volume list is ambiguous")
		}
		for _, volume := range volumes {
			if volume.UBIFS {
				return openUBIVolume(image, volume.VolID)
			}
		}
		return nil, unsupportedf("the UBI image has no user volume whose LEB 0 is a UBIFS superblock")
	}
	return openBare(src)
}

// OpenVolume mounts a named volume.  A bare UBIFS source accepts only zero.
func OpenVolume(src source.ByteSource, volID uint32) (*Volume, error) {
	hasUBI, err := HasECMagic(src)
	if err != nil {
		return nil, err
	}
	if !hasUBI {
		if volID != 0 {
			return nil, unsupportedf("volume %d does not exist: the source is a bare UBIFS image", volID)
		}
		return openBare(src)
	}
	image, err := OpenUBI(src)
	if err != nil {
		return nil, err
	}
	return openUBIVolume(image, volID)
}

func openBare(src source.ByteSource) (*Volume, error) {
	if src.Len() < MasterPage {
		return nil, source.NewUnexpectedEOF(src.Len())
	}
	bytes, err := source.ReadVecAt(src, 0, MasterPage)
	if err != nil {
		return nil, err
	}
	superblock, err := ParseSuperblock(bytes)
	if err != nil {
		return nil, err
	}
	device := Device{
		backing:  backing{source: src, bare: true},
		lebSize:  uint64(superblock.LEBSize),
		lebCount: superblock.LEBCount,
	}
	return mountDevice(src, device, superblock, nil, 0, false)
}

func openUBIVolume(image *UbiImage, volID uint32) (*Volume, error) {
	if image.table.State == TableDisagreement {
		return nil, unsupportedf("the two UBI volume-table copies disagree; the volume list is ambiguous")
	}
	if volID >= LayoutVolumeID {
		return nil, unsupportedf("volume %#x is reserved for UBI itself and is not mounted", volID)
	}
	layout := image.layout
	bytes := make([]byte, MasterPage)
	if err := image.ReadLEB(volID, 0, 0, bytes); err != nil {
		return nil, err
	}
	superblock, err := ParseSuperblock(bytes)
	if err != nil {
		return nil, err
	}
	if uint64(superblock.LEBSize) > layout.LEBSize {
		return nil, corruptf("UBIFS declares LEB size %d but the UBI volume's LEB is %d bytes",
			superblock.LEBSize, layout.LEBSize)
	}
	device := Device{
		backing:  backing{source: image.source, ubi: image, volID: volID},
		lebSize:  uint64(superblock.LEBSize),
		lebCount: superblock.LEBCount,
	}
	return mountDevice(image.source, device, superblock, image, volID, true)
}

func mountDevice(src source.ByteSource, device Device, superblock *Superblock, ubi *UbiImage, ubiVolID uint32, hasUBI bool) (*Volume, error) {
	master1, err := readMaster(&device, 1)
	if err != nil {
		return nil, err
	}
	master2, err := readMaster(&device, 2)
	if err != nil {
		return nil, err
	}
	master, selection, err := selectMaster(master1, master2)
	if err != nil {
		return nil, err
	}
	if uint64(master.RootOffs)+uint64(master.RootLen) > device.lebSize {
		return nil, corruptf("master names an index root at LEB %d offset %d length %d, which passes the LEB",
			master.RootLnum, master.RootOffs, master.RootLen)
	}
	volume := &Volume{
		source: src, device: device, superblock: superblock,
		master1: master1, master2: master2, selection: selection,
		rootLnum: master.RootLnum, rootOffs: master.RootOffs, rootLen: master.RootLen,
		byPath: make(map[string]int), byInode: make(map[uint64]int),
		children: make(map[string][]int),
		inodes:   make(map[uint32]inodeRecord), data: make(map[dataKey]dataRecord),
		corruptData: make(map[dataKey]bool),
		refusals:    make(map[string]uint64),
		ubi:         ubi, ubiVolID: ubiVolID, hasUBI: hasUBI,
	}
	volume.fileID.Store(uint64(src.SourceID()) + 1)
	if err := volume.walkIndex(master.RootLnum, uint64(master.RootOffs), uint64(master.RootLen), nil, nil, 0); err != nil {
		return nil, err
	}
	volume.buildTree()
	return volume, nil
}

// Source returns the volume's byte source.
func (v *Volume) Source() source.ByteSource { return v.source }

// Superblock returns a copy of the parsed superblock.
func (v *Volume) Superblock() Superblock { return *v.superblock }

// Master1 returns the first master node, when readable.
func (v *Volume) Master1() *MasterNode { return v.master1 }

// Master2 returns the second master node, when readable.
func (v *Volume) Master2() *MasterNode { return v.master2 }

// MasterSelection returns how the committed master was chosen.
func (v *Volume) MasterSelection() MasterSelection { return v.selection }

// RootRecord returns UBIFS's root inode number.
func (v *Volume) RootRecord() uint64 { return RootIno }

// Entries returns every live entry, root first.
func (v *Volume) Entries() []Entry {
	out := make([]Entry, len(v.nodes))
	copy(out, v.nodes)
	return out
}

// Nodes is an alias for Entries.
func (v *Volume) Nodes() []Entry { return v.Entries() }

// EntryByInode returns the first live entry for an inode number.
func (v *Volume) EntryByInode(inode uint64) (*Entry, bool) {
	index, found := v.byInode[inode]
	if !found {
		return nil, false
	}
	entry := v.nodes[index]
	return &entry, true
}

// Deleted returns the xent deletion records.
func (v *Volume) Deleted() []DeletedName {
	out := make([]DeletedName, len(v.deleted))
	copy(out, v.deleted)
	return out
}

// DeletedNames returns the number of xent deletion records.
func (v *Volume) DeletedNames() uint64 { return uint64(len(v.deleted)) }

// Undecodable returns names whose inode was missing or whose dent node could
// not be read.
func (v *Volume) Undecodable() uint64 { return v.undecodable }

// Unreadable returns files with a corrupt or unsupported data block.
func (v *Volume) Unreadable() uint64 { return v.unreadable }

// Refusals returns named conditions, sorted by feature.
func (v *Volume) Refusals() []Refusal {
	names := make([]string, 0, len(v.refusals))
	for name := range v.refusals {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]Refusal, 0, len(names))
	for _, name := range names {
		out = append(out, Refusal{Feature: name, Count: v.refusals[name]})
	}
	return out
}

// Info returns the volume report.
func (v *Volume) Info() Info {
	info := Info{
		Kind: KindLabel, SourceID: v.source.SourceID(),
		LEBSize: v.superblock.LEBSize, LEBCount: v.superblock.LEBCount,
		MaxLEBCount: v.superblock.MaxLEBCount, MinIOSize: v.superblock.MinIOSize,
		Fanout: v.superblock.Fanout, FormatVersion: v.superblock.FmtVersion,
		KeyHash: v.superblock.KeyHash, KeyFormat: v.superblock.KeyFormat,
		Flags: v.superblock.Flags, DefaultCompressor: v.superblock.DefaultCompr,
		UUID:            v.superblock.UUID,
		MasterSelection: v.selection, Master1: v.master1, Master2: v.master2,
		RootInode: RootIno, RootLnum: v.rootLnum, RootOffs: v.rootOffs,
		RootLen: v.rootLen, RootLevel: v.rootLevel,
		Entries: uint64(len(v.nodes)), IndexNodes: v.indexNodes, LeafNodes: v.leafNodes,
		InodeNodes: v.inodeNodes, DentNodes: v.dentNodes, XentNodes: v.xentNodes,
		DataNodes: v.dataNodes, TrunNodes: v.trunNodes, UnknownNodes: v.unknownNodes,
		OrphanDents: v.orphanDents, DeletedNames: uint64(len(v.deleted)),
		Holes: v.holes, HoleBytes: v.holeBytes, Unreadable: v.unreadable,
		Undecodable: v.undecodable, Refusals: v.Refusals(),
	}
	if v.hasUBI {
		info.UBI = &UBIInfo{
			VolID: v.ubiVolID, Layout: v.ubi.layout, TableState: v.ubi.table.State,
		}
		for _, volume := range v.ubi.volumes {
			if volume.VolID == v.ubiVolID {
				info.UBI.VolumeName = volume.Name
				break
			}
		}
	}
	return info
}

// Facts returns the reference reader's key/value report.
func (v *Volume) Facts() [][2]string {
	sb := v.superblock
	facts := [][2]string{
		{"type", KindLabel},
		{"entries", fmt.Sprint(len(v.nodes))},
		{"root_ino", fmt.Sprint(RootIno)},
		{"leb_size", fmt.Sprint(sb.LEBSize)},
		{"leb_cnt", fmt.Sprint(sb.LEBCount)},
		{"min_io_size", fmt.Sprint(sb.MinIOSize)},
		{"fanout", fmt.Sprint(sb.Fanout)},
		{"fmt_version", fmt.Sprint(sb.FmtVersion)},
		{"key_hash", fmt.Sprint(sb.KeyHash)},
		{"timestamps", "inode seconds and nanoseconds; a zero/zero pair is unset"},
		{"master_selection", v.selection.Label()},
	}
	if v.master1 != nil {
		facts = append(facts, [2]string{"master1", describeMaster(v.master1)})
	}
	if v.master2 != nil {
		facts = append(facts, [2]string{"master2", describeMaster(v.master2)})
	}
	if v.master1 != nil && v.master2 != nil && v.master1.CRCOK && v.master2.CRCOK &&
		v.master1.Sqnum != v.master2.Sqnum {
		stale, live := v.master1, v.master2
		if stale.Sqnum > live.Sqnum {
			stale, live = live, stale
		}
		facts = append(facts, [2]string{"master_stale",
			fmt.Sprintf("the other master (sqnum %d < %d) is stale", stale.Sqnum, live.Sqnum)})
	}
	facts = append(facts, [2]string{"index_root",
		fmt.Sprintf("LEB %d offset %d length %d level %d", v.rootLnum, v.rootOffs, v.rootLen, v.rootLevel)})
	facts = append(facts, [2]string{"index",
		fmt.Sprintf("%d index node(s), %d leaf node(s)", v.indexNodes, v.leafNodes)})
	facts = append(facts, [2]string{"nodes",
		fmt.Sprintf("inode %d, dent %d, xent %d, data %d, trunc %d",
			v.inodeNodes, v.dentNodes, v.xentNodes, v.dataNodes, v.trunNodes)})
	if len(v.deleted) > 0 {
		facts = append(facts, [2]string{"deleted_names", fmt.Sprint(len(v.deleted))})
	}
	if v.holes > 0 {
		facts = append(facts, [2]string{"holes", fmt.Sprint(v.holes)})
		facts = append(facts, [2]string{"hole_bytes", fmt.Sprint(v.holeBytes)})
	}
	if v.unreadable > 0 {
		facts = append(facts, [2]string{"unreadable", fmt.Sprint(v.unreadable)})
	}
	if v.undecodable > 0 {
		facts = append(facts, [2]string{"undecodable", fmt.Sprint(v.undecodable)})
	}
	if v.orphanDents > 0 {
		facts = append(facts, [2]string{"orphan_dents", fmt.Sprint(v.orphanDents)})
	}
	if v.unknownNodes > 0 {
		facts = append(facts, [2]string{"unknown_nodes", fmt.Sprint(v.unknownNodes)})
	}
	if v.hasUBI {
		if v.ubiVolID != 0 || v.ubi != nil {
			for _, volume := range v.ubi.volumes {
				if volume.VolID == v.ubiVolID {
					facts = append(facts, [2]string{"ubi_volume",
						fmt.Sprintf("vol %d %s", v.ubiVolID, volume.Name)})
					break
				}
			}
		}
		facts = append(facts, v.ubi.Facts()...)
	}
	for _, refusal := range v.Refusals() {
		facts = append(facts, [2]string{"refused",
			fmt.Sprintf("%s (%d)", refusal.Feature, refusal.Count)})
	}
	return facts
}

func describeMaster(master *MasterNode) string {
	suffix := ""
	if !master.CRCOK {
		suffix = " (CRC mismatch)"
	}
	return fmt.Sprintf("sqnum %d root LEB %d offs %d len %d%s",
		master.Sqnum, master.RootLnum, master.RootOffs, master.RootLen, suffix)
}

// Lookup returns the entry at an exact path.
func (v *Volume) Lookup(pathValue string) (*Entry, error) {
	index, found := v.byPath[normalizePath(pathValue)]
	if !found {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, pathValue)
	}
	entry := v.nodes[index]
	return &entry, nil
}

// Stat returns the entry named by path.
func (v *Volume) Stat(pathValue string) (*Entry, error) { return v.Lookup(pathValue) }

// ListDir lists a directory's live entries, sorted by name.
func (v *Volume) ListDir(pathValue string) ([]Entry, error) {
	clean := normalizePath(pathValue)
	entry, err := v.Lookup(clean)
	if err != nil {
		return nil, err
	}
	if !entry.IsDir {
		return nil, fmt.Errorf("%w: %s", ErrNotDir, pathValue)
	}
	indexes := v.children[clean]
	out := make([]Entry, 0, len(indexes))
	for _, index := range indexes {
		out = append(out, v.nodes[index])
	}
	sort.SliceStable(out, func(left, right int) bool { return out[left].Name < out[right].Name })
	return out, nil
}

// SymlinkTarget returns a symbolic link's target.
func (v *Volume) SymlinkTarget(pathValue string) (string, error) {
	entry, err := v.Lookup(pathValue)
	if err != nil {
		return "", err
	}
	if !entry.IsSymlink {
		return "", fmt.Errorf("%w: %s", ErrNotSymlink, pathValue)
	}
	return entry.SymlinkTarget, nil
}

func normalizePath(value string) string {
	if value == "" || value == "/" {
		return "/"
	}
	clean := path.Clean("/" + strings.TrimPrefix(value, "/"))
	if clean == "." || clean == "" {
		return "/"
	}
	return clean
}

func joinPath(parent, name string) string {
	if parent == "/" {
		return "/" + name
	}
	return parent + "/" + name
}

func (v *Volume) refuse(feature string) { v.refusals[feature]++ }

func u32At(bytes []byte) uint32 {
	return uint32(bytes[0]) | uint32(bytes[1])<<8 | uint32(bytes[2])<<16 | uint32(bytes[3])<<24
}
