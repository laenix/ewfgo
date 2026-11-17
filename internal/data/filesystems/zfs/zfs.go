// Package zfs reads ZFS pools, read-only, from a source.ByteSource. It is a
// Go port of forensic-core's ZFS reader.
//
// ZFS has no boot sector and no superblock at a fixed offset. A pool
// identifies itself in four vdev labels — two at the start of each leaf
// device, two at the end — and the current state lives in uberblocks inside
// those labels. The bootstrap chain is:
//
//	vdev label (256 KiB)                       label.go
//	  -> vdev_phys nvlist (pool name and tree)  nvlist.go
//	  -> uberblock ring                         uberblock.go
//	    -> root block pointer                   blkptr.go, block.go
//	      -> MOS object set                     objset.go, dnode.go
//	        -> object directory ZAP (object 1)  zap.go
//	          -> root_dataset -> DSL directory  dataset.go
//	            -> dd_head_dataset_obj -> DSL dataset
//	              -> ds_bp -> dataset object set
//	              -> master node ZAP (object 1)
//	                -> "ROOT" -> root directory ZAP
//
// Every block along that chain is checksummed, so a candidate uberblock is
// accepted only when its whole bootstrap reads. The newest transaction group
// whose chain verifies is the state this reader reports.
//
// The standard filesystem API operates on the pool's root dataset. Other
// datasets are exposed by OpenDataset and snapshots by OpenSnapshot; both
// return views with the same ListDir, Stat, OpenFile, OpenSymlink and
// SymlinkTarget methods. Paths inside a view are dataset-relative, "/" is the
// dataset root, ".." cannot climb above it, and symbolic links are reported
// rather than followed.
//
// Deliberately unported branches, each refused or reported rather than
// silently guessed at:
//
//   - pools whose vdev tree names more than one leaf (mirrors, multiple data
//     vdevs, log/cache/spare devices, RAID-Z and dRAID) are refused by name;
//     only a single-image, single-leaf pool is assembled. DVA vdev ids other
//     than 0 are refused, because no sibling image exists to read them;
//   - zstd compression is refused by name (CompressionZstd), as are unknown
//     compression and checksum ids; lzjb, zle, lz4, gzip and empty are
//     decoded, and fletcher2, fletcher4, sha256 and off are verified;
//   - gang blocks are refused by name; their child pointers are not followed;
//   - encrypted or authenticated block pointers are refused because no key is
//     available;
//   - a big-endian pool's byte-order bit is reported but the little-endian
//     layout is always read, so such a pool fails its checksums rather than
//     being quietly misread;
//   - zvol datasets are refused as filesystems;
//   - ZIL replay, deleted-name recovery, snapshot-to-snapshot change
//     computation and ds_prev_snap_obj chains are not implemented; only the
//     current tree and explicitly named snapshot roots are read.
//
// A micro or fat ZAP whose pointer-table shift exceeds 20 is refused: that
// table would address more than the 1<<20 entries this reader already caps.
package zfs

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

// KindLabel is the label this reader reports.
const KindLabel = "ZFS"

// Default bounds. They are large enough for real pools and small enough that
// a hostile image cannot make opening allocate without limit.
const (
	DefaultDatasetLimit   = 4096
	DefaultRootEntryLimit = 5000
	DefaultSnapshotLimit  = 4096
	DefaultPathEntryLimit = 5000
)

const (
	maxSnapshotNameBytes = 255
	maxUberblockAttempts = 32
	maxDslParentDepth    = 128
	maxPropertyBytes     = 1024
	snapshotNamesInError = 32
	// mountpointProperty is the property that tells a mount where a dataset
	// belongs.
	mountpointProperty = "mountpoint"
	receivedSuffix     = "$recvd"
	inheritSuffix      = "$inherit"
	indexUpdateSuffix  = "$iuv"
)

// Options bounds the work Open performs. A zero field takes its default.
type Options struct {
	// DatasetLimit bounds the dataset tree walk.
	DatasetLimit int
	// RootEntryLimit bounds the root directory listing.
	RootEntryLimit int
	// SnapshotLimit bounds the snapshot names collected.
	SnapshotLimit int
	// PathEntryLimit bounds each directory listed while resolving a path.
	PathEntryLimit int
}

func (o Options) withDefaults() Options {
	if o.DatasetLimit <= 0 {
		o.DatasetLimit = DefaultDatasetLimit
	}
	if o.RootEntryLimit <= 0 {
		o.RootEntryLimit = DefaultRootEntryLimit
	}
	if o.SnapshotLimit <= 0 {
		o.SnapshotLimit = DefaultSnapshotLimit
	}
	if o.PathEntryLimit <= 0 {
		o.PathEntryLimit = DefaultPathEntryLimit
	}
	return o
}

// Dataset is one filesystem dataset in the pool.
type Dataset struct {
	// Name is the full dataset name, '/'-separated from the root.
	Name string
	// Object is the object id in the MOS.
	Object uint64
	GUID   uint64
	// CreationTime is UTC seconds since the Unix epoch; zero means the field
	// was never written.
	CreationTime uint64
	CreationTXG  uint64

	ReferencedBytes   uint64
	CompressedBytes   uint64
	UncompressedBytes uint64
	Flags             uint64
}

// Snapshot is one snapshot, named by its dataset and the short name.
type Snapshot struct {
	// Name is "dataset@snapshot".
	Name      string
	Dataset   string
	ShortName string
	// Object is the MOS object id of the snapshot's dsl_dataset.
	Object       uint64
	CreationTime uint64
	CreationTXG  uint64
	// NumChildren is ds_num_children; non-zero marks a snapshot.
	NumChildren     uint64
	ReferencedBytes uint64
	// HasBP reports whether ds_bp names a location (it is not a hole).
	HasBP bool
	// UnresolvedReason says why this name could not be proved to be a
	// snapshot dnode, when it could not. Empty means the dnode was read and
	// proved to be a snapshot.
	UnresolvedReason string
}

// IsResolved reports whether the snapshot's dnode was read and proved to be a
// snapshot. It says nothing about whether ds_bp can be mounted.
func (s Snapshot) IsResolved() bool { return s.UnresolvedReason == "" }

// Entry is one name a listing or lookup found.
type Entry struct {
	Name string
	// Path is the display path, '/'-separated. The dataset root's path is "/".
	Path string

	// Object is the ZPL object number the directory value names. Inode is an
	// alias kept for the data layer's other filesystem adapters.
	Object uint64
	Inode  uint64
	// Dataset is the dataset whose namespace this entry lives in.
	Dataset string

	Kind DType

	IsDir         bool
	IsFile        bool
	IsSymlink     bool
	IsFIFO        bool
	IsSocket      bool
	IsBlockDevice bool
	IsCharDevice  bool
	IsUnknown     bool
	IsWhiteout    bool

	// Mode is the permission and type bits exactly as recorded.
	Mode     uint32
	HasMode  bool
	UID      uint64
	GID      uint64
	Links    uint64
	HasUID   bool
	HasGID   bool
	HasLinks bool

	// Size is the logical length in bytes.
	Size    uint64
	HasSize bool
	// Allocated is the bytes the file's block pointers store. HasAllocated is
	// false for directories, special files and files whose block map was not
	// walked within the provenance bound.
	Allocated    uint64
	HasAllocated bool

	// Times come from the object's SA or znode buffer. HasX is true when the
	// attribute is present; a stored epoch is reported as such, not dropped.
	Atime    time.Time
	Mtime    time.Time
	Ctime    time.Time
	Btime    time.Time
	HasAtime bool
	HasMtime bool
	HasCtime bool
	HasBtime bool

	// SymlinkTarget is the link text when the object is a symbolic link.
	SymlinkTarget string

	// Deleted is always false: ZFS deleted names are not recovered.
	Deleted bool
}

// VolumeStats counts what opening found.
type VolumeStats struct {
	Labels              int
	UberblockCandidates int
	UberblocksAttempted int
	Datasets            int
	Snapshots           int
	RootEntries         int
}

// Info is the volume-level report.
type Info struct {
	Type string

	PoolName        string
	PoolGUID        uint64
	PoolGUIDPresent bool
	PoolVersion     uint64
	TXG             uint64
	// Timestamp is UTC seconds when the selected uberblock's sync completed.
	Timestamp uint64

	UberblockVersion uint64
	SoftwareVersion  uint64

	Ashift        uint64
	AshiftPresent bool
	VdevType      string

	Labels             int
	Datasets           int
	Snapshots          int
	SnapshotsTruncated bool
	RootEntries        int
	RootTruncated      bool

	FeaturesForRead []string
	LabelChecksums  []string
	Warnings        []string

	Stats VolumeStats
}

// Volume is an opened ZFS pool.
type Volume struct {
	source source.ByteSource

	pool      PoolConfig
	labels    []LabelReport
	uberblock Uberblock
	mos       *Objset

	rootDatasetObject uint64
	rootObjset        *Objset
	rootObject        uint64

	datasets           []Dataset
	snapshots          []Snapshot
	snapshotsTruncated bool

	rootEntries   []ZplEntry
	rootTruncated bool

	root *Mount

	pathLimit           int
	warnings            []string
	uberblockTried      int
	uberblockCandidates int

	fileID atomic.Uint64
}

// Detect reports whether src starts with a verified ZFS vdev label. A magic
// with no verifying label is an error, because the device does claim to be
// ZFS and a caller should hear why it could not be read.
func Detect(src source.ByteSource) (bool, error) {
	length := src.Len()
	if length < LabelPhysOffset+LabelPhysSize {
		return false, nil
	}
	found := false
	for _, at := range labelOffsets(length) {
		position := at.offset + LabelPhysOffset + LabelPhysSize - LabelECKSize
		if position+8 > length {
			continue
		}
		var magic [8]byte
		n, err := src.ReadAt(position, magic[:])
		if err != nil || n != len(magic) {
			continue
		}
		if leUint64(magic[:]) == ZECMagic {
			found = true
			break
		}
	}
	if !found {
		return false, nil
	}
	if _, _, err := readLabels(src); err != nil {
		return false, err
	}
	return true, nil
}

// Open reads a single-image pool and walks the datasets reachable from its
// root. A pool whose vdev tree names more than one leaf is refused by name.
func Open(src source.ByteSource) (*Volume, error) {
	return OpenWithOptions(src, Options{})
}

// OpenWithOptions opens a pool with explicit bounds.
func OpenWithOptions(src source.ByteSource, options Options) (*Volume, error) {
	options = options.withDefaults()
	labels, problems, err := readLabels(src)
	if err != nil {
		return nil, err
	}
	warnings := append([]string(nil), problems...)
	pool, err := choosePool(labels, &warnings)
	if err != nil {
		return nil, err
	}
	reader := newBlockReader(src)
	boot, attempted, candidates, err := bootstrapFromLabels(labels, &pool, reader, options.RootEntryLimit, &warnings)
	if err != nil {
		return nil, err
	}

	rootName := pool.Name
	if rootName == "" {
		rootName = "pool"
	}
	datasets, snapshots, snapshotsTruncated, walkWarnings := enumerateDatasets(
		reader, boot.mos, rootName, boot.rootDatasetObject,
		options.DatasetLimit, options.SnapshotLimit)
	warnings = append(warnings, walkWarnings...)

	volume := &Volume{
		source:              src,
		pool:                pool,
		labels:              labelReports(labels),
		uberblock:           boot.uberblock,
		mos:                 boot.mos,
		rootDatasetObject:   boot.rootDatasetObject,
		rootObjset:          boot.rootObjset,
		rootObject:          boot.rootObject,
		datasets:            datasets,
		snapshots:           snapshots,
		snapshotsTruncated:  snapshotsTruncated,
		rootEntries:         boot.rootEntries,
		rootTruncated:       boot.rootTruncated,
		pathLimit:           options.PathEntryLimit,
		warnings:            warnings,
		uberblockTried:      attempted,
		uberblockCandidates: candidates,
	}
	volume.fileID.Store(uint64(src.SourceID()) + 1)

	rootDataset := Dataset{Name: rootName, Object: boot.rootDatasetObject}
	for _, dataset := range datasets {
		if dataset.Object == boot.rootDatasetObject {
			rootDataset = dataset
			break
		}
	}
	rootView := &view{
		volume:         volume,
		objset:         boot.rootObjset,
		rootObject:     boot.rootObject,
		dataset:        rootDataset.Name,
		pathLimit:      options.PathEntryLimit,
		rootEntryCount: len(boot.rootEntries),
		rootTruncated:  boot.rootTruncated,
	}
	volume.root = &Mount{
		view:       rootView,
		dataset:    rootDataset,
		mountedTXG: boot.uberblock.Root.logicalBirth(),
	}
	return volume, nil
}

// KindLabel returns the filesystem's name.
func (v *Volume) KindLabel() string { return KindLabel }

// Source returns the pool's byte source.
func (v *Volume) Source() source.ByteSource { return v.source }

// Pool returns the chosen pool configuration.
func (v *Volume) Pool() PoolConfig { return v.pool }

// Labels returns the verified label reports.
func (v *Volume) Labels() []LabelReport { return append([]LabelReport(nil), v.labels...) }

// Uberblock returns the transaction group the pool was opened at.
func (v *Volume) Uberblock() Uberblock { return v.uberblock }

// MOS returns the pool's metadata object set.
func (v *Volume) MOS() *Objset { return v.mos }

// RootDatasetObject returns the MOS object id of the root dataset.
func (v *Volume) RootDatasetObject() uint64 { return v.rootDatasetObject }

// Datasets returns every filesystem dataset the walk reached, root first.
func (v *Volume) Datasets() []Dataset { return append([]Dataset(nil), v.datasets...) }

// Snapshots returns every snapshot the walk resolved, in dataset order.
func (v *Volume) Snapshots() []Snapshot { return append([]Snapshot(nil), v.snapshots...) }

// SnapshotsTruncated reports whether the snapshot listing stopped at its
// bound.
func (v *Volume) SnapshotsTruncated() bool { return v.snapshotsTruncated }

// Warnings returns the pool's retained warnings.
func (v *Volume) Warnings() []string { return append([]string(nil), v.warnings...) }

// RootDataset returns the root dataset's metadata.
func (v *Volume) RootDataset() Dataset { return v.root.dataset }

// Root returns the root dataset's mounted view.
func (v *Volume) Root() *Mount { return v.root }

// Info returns the volume-level report.
func (v *Volume) Info() Info {
	checksums := map[string]struct{}{}
	for _, label := range v.labels {
		checksums[label.Verified] = struct{}{}
	}
	orderedChecksums := make([]string, 0, len(checksums))
	for checksum := range checksums {
		orderedChecksums = append(orderedChecksums, checksum)
	}
	sort.Strings(orderedChecksums)
	vdevType := ""
	if v.pool.Vdev != nil {
		vdevType = v.pool.Vdev.Kind
	}
	return Info{
		Type:               KindLabel,
		PoolName:           poolName(v.pool),
		PoolGUID:           v.pool.GUID,
		PoolGUIDPresent:    v.pool.GUIDPresent,
		PoolVersion:        v.pool.Version,
		TXG:                v.uberblock.TXG,
		Timestamp:          v.uberblock.Timestamp,
		UberblockVersion:   v.uberblock.Version,
		SoftwareVersion:    v.uberblock.SoftwareVersion,
		Ashift:             v.pool.Ashift,
		AshiftPresent:      v.pool.AshiftPresent,
		VdevType:           vdevType,
		Labels:             len(v.labels),
		Datasets:           len(v.datasets),
		Snapshots:          len(v.snapshots),
		SnapshotsTruncated: v.snapshotsTruncated,
		RootEntries:        len(v.rootEntries),
		RootTruncated:      v.rootTruncated,
		FeaturesForRead:    append([]string(nil), v.pool.FeaturesForRead...),
		LabelChecksums:     orderedChecksums,
		Warnings:           append([]string(nil), v.warnings...),
		Stats: VolumeStats{
			Labels:              len(v.labels),
			UberblockCandidates: v.uberblockCandidates,
			UberblocksAttempted: v.uberblockTried,
			Datasets:            len(v.datasets),
			Snapshots:           len(v.snapshots),
			RootEntries:         len(v.rootEntries),
		},
	}
}

func poolName(pool PoolConfig) string {
	if pool.Name == "" {
		return "unknown"
	}
	return pool.Name
}

// ListDir lists the root dataset's directory at path.
func (v *Volume) ListDir(path string) ([]Entry, error) { return v.root.ListDir(path) }

// Stat returns the root dataset's entry at path.
func (v *Volume) Stat(path string) (*Entry, error) { return v.root.Stat(path) }

// OpenFile opens the root dataset's regular file at path.
func (v *Volume) OpenFile(path string) (source.ByteSource, error) { return v.root.OpenFile(path) }

// OpenSymlink opens the root dataset's symbolic link target at path.
func (v *Volume) OpenSymlink(path string) (source.ByteSource, error) {
	return v.root.OpenSymlink(path)
}

// SymlinkTarget returns the link text at path.
func (v *Volume) SymlinkTarget(path string) (string, error) {
	return v.root.SymlinkTarget(path)
}

// Attributes returns the ZPL attributes of the object at path.
func (v *Volume) Attributes(path string) (*ZplAttributes, error) {
	return v.root.Attributes(path)
}

// Mount is a live dataset mounted read-only from its own ds_bp.
type Mount struct {
	*view
	dataset    Dataset
	mountedTXG uint64
	warnings   []string
}

// Dataset returns the dataset this mount serves.
func (m *Mount) Dataset() Dataset { return m.dataset }

// MountedTXG returns the logical birth transaction of the ds_bp that was
// read.
func (m *Mount) MountedTXG() uint64 { return m.mountedTXG }

// Warnings returns facts discovered while mounting.
func (m *Mount) Warnings() []string { return append([]string(nil), m.warnings...) }

// SnapshotMount is a snapshot root mounted read-only from the snapshot's own
// ds_bp.
type SnapshotMount struct {
	*view
	snapshot   Snapshot
	mountedTXG uint64
	warnings   []string
}

// Snapshot returns the snapshot this mount serves.
func (m *SnapshotMount) Snapshot() Snapshot { return m.snapshot }

// MountedTXG returns the logical birth transaction of the ds_bp that was
// read.
func (m *SnapshotMount) MountedTXG() uint64 { return m.mountedTXG }

// Warnings returns facts discovered while mounting.
func (m *SnapshotMount) Warnings() []string { return append([]string(nil), m.warnings...) }

// view is the shared namespace of a dataset or snapshot root.
type view struct {
	volume     *Volume
	objset     *Objset
	rootObject uint64
	dataset    string
	pathLimit  int

	rootEntryCount int
	rootTruncated  bool

	tablesOnce sync.Once
	tables     *SaTables
	tablesErr  error
}

// RootObject returns the ZPL object the dataset's ROOT entry names.
func (v *view) RootObject() uint64 { return v.rootObject }

// DatasetName returns the dataset namespace this view serves.
func (v *view) DatasetName() string { return v.dataset }

// RootEntryCount returns the number of names the root listing held.
func (v *view) RootEntryCount() int { return v.rootEntryCount }

// RootTruncated reports whether the root listing stopped at its bound.
func (v *view) RootTruncated() bool { return v.rootTruncated }

func (v *view) saTables() (*SaTables, error) {
	v.tablesOnce.Do(func() {
		reader := newBlockReader(v.volume.source)
		v.tables, v.tablesErr = loadSATables(reader, v.objset)
	})
	return v.tables, v.tablesErr
}

func (v *view) attributesObject(reader *BlockReader, object uint64) (*ZplAttributes, error) {
	tables, err := v.saTables()
	if err != nil {
		return nil, err
	}
	return readAttributes(reader, v.objset, object, tables)
}

// Attributes returns the ZPL attributes of the object at path.
func (v *view) Attributes(path string) (*ZplAttributes, error) {
	reader := newBlockReader(v.volume.source)
	resolved, err := resolvePath(reader, v.objset, path, v.pathLimit)
	if err != nil {
		return nil, err
	}
	return v.attributesObject(reader, resolved.Object)
}

// ObjectAttributes returns the ZPL attributes of one object in this namespace.
func (v *view) ObjectAttributes(object uint64) (*ZplAttributes, error) {
	return v.attributesObject(newBlockReader(v.volume.source), object)
}

// ListDir lists the directory path names.
func (v *view) ListDir(path string) ([]Entry, error) {
	reader := newBlockReader(v.volume.source)
	directory, err := resolveDirectory(reader, v.objset, path, v.pathLimit)
	if err != nil {
		return nil, err
	}
	base := displayPath(path)
	out := make([]Entry, 0, len(directory.entries))
	for i := range directory.entries {
		entry := directory.entries[i]
		entryPath := joinPath(base, entry.name)
		attributes, attrErr := v.attributesObject(reader, entry.object)
		if attrErr != nil {
			attributes = nil
		}
		kind := entry.dtype
		if kind == DTypeUnknown && (attributes == nil || attributes.Kind == DTypeUnknown) {
			if resolved, err := dnodeDType(reader, v.objset, entry.object); err == nil {
				kind = resolved
			}
		}
		out = append(out, v.entryFor(entry.name, entryPath, entry.object, kind, attributes))
	}
	return out, nil
}

// Stat returns the entry path names.
func (v *view) Stat(path string) (*Entry, error) {
	reader := newBlockReader(v.volume.source)
	resolved, err := resolvePath(reader, v.objset, path, v.pathLimit)
	if err != nil {
		return nil, err
	}
	attributes, err := v.attributesObject(reader, resolved.Object)
	if err != nil {
		return nil, err
	}
	display := displayPath(path)
	entry := v.entryFor(entryName(display), display, resolved.Object, resolved.DType, attributes)
	if entry.IsFile && entry.HasSize {
		if allocated, ok := allocatedBytes(reader, v.objset, resolved.Object, entry.Size); ok {
			entry.Allocated, entry.HasAllocated = allocated, true
		}
	}
	return &entry, nil
}

// OpenFile opens the regular file path names as a byte source.
func (v *view) OpenFile(path string) (source.ByteSource, error) {
	reader := newBlockReader(v.volume.source)
	resolved, err := resolvePath(reader, v.objset, path, v.pathLimit)
	if err != nil {
		return nil, err
	}
	attributes, err := v.attributesObject(reader, resolved.Object)
	if err != nil {
		return nil, err
	}
	switch attributes.Kind {
	case DTypeDirectory:
		return nil, fmt.Errorf("%w: %s", ErrIsDir, path)
	case DTypeRegular:
	case DTypeUnknown:
		return nil, fmt.Errorf("%w: %s has no mode that proves it is a regular file", ErrNotFile, path)
	default:
		return nil, fmt.Errorf("%w: %s is a %s", ErrNotFile, path, attributes.Kind.label())
	}
	if attributes.Size == nil {
		return nil, corruptf("object %d carries no %s; its length is not guessed", resolved.Object, zplSize)
	}
	node, err := v.objset.dnode(reader, resolved.Object)
	if err != nil {
		return nil, err
	}
	if node.kind != dmuOtPlainFile {
		return nil, corruptf("object %d is %s, not a regular file, though its mode says otherwise",
			resolved.Object, objectTypeName(node.kind))
	}
	id := source.ID(v.volume.fileID.Add(1))
	return newFileSource(id, v.volume.source, v.objset, node, *attributes.Size), nil
}

// OpenSymlink opens the symbolic link target at path as a byte source.
func (v *view) OpenSymlink(path string) (source.ByteSource, error) {
	reader := newBlockReader(v.volume.source)
	resolved, err := resolvePath(reader, v.objset, path, v.pathLimit)
	if err != nil {
		return nil, err
	}
	attributes, err := v.attributesObject(reader, resolved.Object)
	if err != nil {
		return nil, err
	}
	if attributes.Kind != DTypeSymlink || attributes.Symlink == nil {
		return nil, fmt.Errorf("%w: %s", ErrNotSymlink, path)
	}
	id := source.ID(v.volume.fileID.Add(1))
	return newSliceSource(id, v.volume.source.ImageID(), v.volume.source.SectorSize(), attributes.Symlink), nil
}

// SymlinkTarget returns the link text path names.
func (v *view) SymlinkTarget(path string) (string, error) {
	reader := newBlockReader(v.volume.source)
	resolved, err := resolvePath(reader, v.objset, path, v.pathLimit)
	if err != nil {
		return "", err
	}
	attributes, err := v.attributesObject(reader, resolved.Object)
	if err != nil {
		return "", err
	}
	if attributes.Kind != DTypeSymlink || attributes.Symlink == nil {
		return "", fmt.Errorf("%w: %s", ErrNotSymlink, path)
	}
	return string(attributes.Symlink), nil
}

func (v *view) entryFor(name, path string, object uint64, kind DType, attributes *ZplAttributes) Entry {
	entry := Entry{
		Name:    name,
		Path:    path,
		Object:  object,
		Inode:   object,
		Dataset: v.dataset,
		Kind:    kind,
	}
	if attributes != nil && attributes.Kind != DTypeUnknown {
		entry.Kind = attributes.Kind
	}
	switch entry.Kind {
	case DTypeDirectory:
		entry.IsDir = true
	case DTypeRegular:
		entry.IsFile = true
	case DTypeSymlink:
		entry.IsSymlink = true
	case DTypeFIFO:
		entry.IsFIFO = true
	case DTypeSocket:
		entry.IsSocket = true
	case DTypeBlock:
		entry.IsBlockDevice = true
	case DTypeChar:
		entry.IsCharDevice = true
	case DTypeWhiteout:
		entry.IsWhiteout = true
	default:
		entry.IsUnknown = true
	}
	if attributes == nil {
		return entry
	}
	if attributes.Mode != nil {
		entry.Mode, entry.HasMode = *attributes.Mode, true
	}
	if attributes.Size != nil {
		entry.Size, entry.HasSize = *attributes.Size, true
	}
	if attributes.UID != nil {
		entry.UID, entry.HasUID = *attributes.UID, true
	}
	if attributes.GID != nil {
		entry.GID, entry.HasGID = *attributes.GID, true
	}
	if attributes.Links != nil {
		entry.Links, entry.HasLinks = *attributes.Links, true
	}
	entry.Atime, entry.HasAtime = zfsTime(attributes.Atime)
	entry.Mtime, entry.HasMtime = zfsTime(attributes.Mtime)
	entry.Ctime, entry.HasCtime = zfsTime(attributes.Ctime)
	entry.Btime, entry.HasBtime = zfsTime(attributes.Btime)
	if attributes.Symlink != nil {
		entry.SymlinkTarget = string(attributes.Symlink)
	}
	return entry
}

func zfsTime(value *Time) (time.Time, bool) {
	if value == nil {
		return time.Time{}, false
	}
	return time.Unix(value.Seconds, int64(value.Nanos)).UTC(), true
}

func dnodeDType(reader *BlockReader, objset *Objset, object uint64) (DType, error) {
	node, err := objset.dnode(reader, object)
	if err != nil {
		return DTypeUnknown, err
	}
	switch node.kind {
	case dmuOtDirectoryContents:
		return DTypeDirectory, nil
	case dmuOtPlainFile:
		return DTypeRegular, nil
	default:
		return DTypeUnknown, nil
	}
}

// allocatedBytes sums the stored sizes of the file's non-hole blocks. It is
// bounded by the provenance cap; a file whose map is larger keeps HasAllocated
// false rather than reporting a partial sum.
func allocatedBytes(reader *BlockReader, objset *Objset, object uint64, size uint64) (uint64, bool) {
	if size == 0 {
		return 0, true
	}
	node, err := objset.dnode(reader, object)
	if err != nil {
		return 0, false
	}
	var blocks []ObjectBlock
	if err := dataBlocksInto(reader, node, 0, size, &blocks); err != nil {
		return 0, false
	}
	var total uint64
	for _, block := range blocks {
		if block.pointer.isHole() {
			continue
		}
		stored := block.pointer.psize()
		if total > ^uint64(0)-stored {
			return 0, false
		}
		total += stored
	}
	return total, true
}

func joinPath(base, name string) string {
	if base == "" || base == "/" {
		return "/" + name
	}
	return base + "/" + name
}

func displayPath(path string) string {
	components := splitPath(path)
	cleaned := make([]string, 0, len(components))
	for _, component := range components {
		if component == ".." {
			if len(cleaned) > 0 {
				cleaned = cleaned[:len(cleaned)-1]
			}
			continue
		}
		cleaned = append(cleaned, component)
	}
	if len(cleaned) == 0 {
		return "/"
	}
	return "/" + strings.Join(cleaned, "/")
}

func entryName(display string) string {
	if display == "/" {
		return "/"
	}
	if at := strings.LastIndexByte(display, '/'); at >= 0 {
		return display[at+1:]
	}
	return display
}

// --- bootstrap ------------------------------------------------------------

func labelReports(labels []Label) []LabelReport {
	out := make([]LabelReport, 0, len(labels))
	for _, label := range labels {
		out = append(out, LabelReport{
			Index:    label.Index,
			Offset:   label.Offset,
			Verified: label.Verified,
			TXG:      label.TXG,
		})
	}
	return out
}

// choosePool selects the newest verified label's configuration, refusing a
// device whose labels name different pools or a pool with several leaves.
func choosePool(labels []Label, warnings *[]string) (PoolConfig, error) {
	guids := map[uint64]struct{}{}
	for _, label := range labels {
		if label.Pool.GUIDPresent {
			guids[label.Pool.GUID] = struct{}{}
		}
	}
	if len(guids) > 1 {
		return PoolConfig{}, corruptf("the verified labels name %d different pools; they are not copies of one label", len(guids))
	}
	chosen := labels[0]
	for _, label := range labels[1:] {
		if label.TXG > chosen.TXG {
			chosen = label
		}
	}
	leaves := chosen.Pool.leaves()
	if len(leaves) == 0 {
		return PoolConfig{}, corruptf("the label's vdev tree names no leaf device")
	}
	if len(leaves) > 1 {
		return PoolConfig{}, unsupportedf("a pool of %d leaf vdevs; this reader reads one image at a time", len(leaves))
	}
	for _, label := range labels {
		if label.TXG != chosen.TXG {
			*warnings = append(*warnings,
				fmt.Sprintf("label %d is at txg %d while the newest is %d", label.Index, label.TXG, chosen.TXG))
		}
	}
	return chosen.Pool, nil
}

func collectUberblocks(labels []Label, warnings *[]string) []Uberblock {
	var found []Uberblock
	for _, label := range labels {
		blocks, problems := label.Uberblocks()
		*warnings = append(*warnings, problems...)
		found = append(found, blocks...)
	}
	sort.SliceStable(found, func(i, j int) bool { return found[i].TXG > found[j].TXG })
	return found
}

// guidSums returns the sums an uberblock could legitimately name. OpenZFS's
// ub_guid_sum is the sum of every vdev guid in the tree; a config that omits
// the root's guid and one that writes it both occur, so all readings are
// accepted.
func guidSums(pool *PoolConfig) []uint64 {
	if pool.Vdev == nil {
		return nil
	}
	var full, leaves uint64
	var walk func(vdev *VdevConfig)
	walk = func(vdev *VdevConfig) {
		if vdev.GUIDPresent {
			full += vdev.GUID
			if len(vdev.Children) == 0 {
				leaves += vdev.GUID
			}
		}
		for i := range vdev.Children {
			walk(&vdev.Children[i])
		}
	}
	walk(pool.Vdev)
	sums := []uint64{full, leaves}
	if pool.GUIDPresent {
		sums = append(sums, pool.GUID+leaves)
	}
	sort.Slice(sums, func(i, j int) bool { return sums[i] < sums[j] })
	unique := sums[:0]
	for _, sum := range sums {
		if sum == 0 {
			continue
		}
		if len(unique) == 0 || unique[len(unique)-1] != sum {
			unique = append(unique, sum)
		}
	}
	if len(unique) == 0 {
		return nil
	}
	return unique
}

type bootstrapResult struct {
	uberblock         Uberblock
	mos               *Objset
	rootDatasetObject uint64
	rootObjset        *Objset
	rootObject        uint64
	rootEntries       []ZplEntry
	rootTruncated     bool
}

type uberblockKey struct {
	txg  uint64
	root BlockPointer
}

// bootstrapFromLabels tries every candidate transaction group, newest first,
// until its whole chain verifies.
func bootstrapFromLabels(labels []Label, pool *PoolConfig, reader *BlockReader,
	rootLimit int, warnings *[]string) (bootstrapResult, int, int, error) {
	expected := guidSums(pool)
	candidates := collectUberblocks(labels, warnings)
	seen := map[uberblockKey]struct{}{}
	attempted := 0
	var lastErr error
	for _, candidate := range candidates {
		key := uberblockKey{txg: candidate.TXG, root: candidate.Root}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if attempted >= maxUberblockAttempts {
			break
		}
		if expected != nil && !containsUint64(expected, candidate.GUIDSum) {
			*warnings = append(*warnings, fmt.Sprintf(
				"uberblock txg %d names guid sum %d, which the label's vdev tree does not",
				candidate.TXG, candidate.GUIDSum))
			continue
		}
		attempted++
		boot, err := bootstrapPool(reader, &candidate, rootLimit)
		if err == nil {
			return boot, attempted, len(candidates), nil
		}
		// An older transaction group may still be readable; the newest slot
		// is only preferred, not assumed.
		lastErr = err
	}
	if lastErr != nil {
		return bootstrapResult{}, attempted, len(candidates), lastErr
	}
	return bootstrapResult{}, attempted, len(candidates),
		corruptf("no uberblock whose object set, root dataset and root directory all verify")
}

func containsUint64(values []uint64, value uint64) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

// bootstrapPool follows one uberblock through the MOS to the root directory.
func bootstrapPool(reader *BlockReader, uberblock *Uberblock, rootLimit int) (bootstrapResult, error) {
	mos, err := readObjset(reader, &uberblock.Root, "the MOS")
	if err != nil {
		return bootstrapResult{}, err
	}
	if err := mos.requireMeta(); err != nil {
		return bootstrapResult{}, err
	}
	directory, err := mos.zapObject(reader, poolDirectoryID)
	if err != nil {
		return bootstrapResult{}, err
	}
	rootDirObject, ok := directory.unsigned(rootDatasetEntry)
	if !ok {
		return bootstrapResult{}, corruptf("the MOS object directory has no %q", rootDatasetEntry)
	}
	// root_dataset names the pool's root DSL directory; its head dataset is
	// loaded next, exactly as OpenZFS's dsl_pool_open does.
	rootDatasetObject, err := headDatasetObject(reader, mos, rootDirObject)
	if err != nil {
		return bootstrapResult{}, corruptf("%q: %v", rootDatasetEntry, err)
	}
	dataset, err := readDataset(reader, mos, rootDatasetObject)
	if err != nil {
		return bootstrapResult{}, err
	}
	rootObjset, err := readObjset(reader, &dataset.bp, "the root dataset")
	if err != nil {
		return bootstrapResult{}, err
	}
	if err := rootObjset.requireZFS(); err != nil {
		return bootstrapResult{}, err
	}
	rootObject, entries, truncated, err := rootFromObjset(reader, rootObjset, rootLimit)
	if err != nil {
		return bootstrapResult{}, err
	}
	return bootstrapResult{
		uberblock:         *uberblock,
		mos:               mos,
		rootDatasetObject: rootDatasetObject,
		rootObjset:        rootObjset,
		rootObject:        rootObject,
		rootEntries:       entries,
		rootTruncated:     truncated,
	}, nil
}

func readObjset(reader *BlockReader, pointer *BlockPointer, what string) (*Objset, error) {
	if pointer.isHole() {
		return nil, corruptf("%s's root block pointer is a hole", what)
	}
	data, err := reader.read(*pointer)
	if err != nil {
		return nil, err
	}
	return parseObjset(data)
}

// readDslDir reads one DSL directory's phys struct.
func readDslDir(reader *BlockReader, mos *Objset, object uint64) (*DslDirPhys, error) {
	node, err := mos.dnode(reader, object)
	if err != nil {
		return nil, err
	}
	// A DSL directory is identified by its bonus type. A directory with no
	// struct data of its own is zapified and keeps dsl_dir_phys_t in the
	// bonus, so the data type is not the check.
	if node.bonustype != dmuOtDslDir {
		return nil, corruptf("object %d has bonus type %s, not a DSL directory",
			object, objectTypeName(node.bonustype))
	}
	return parseDslDirPhys(node.bonus)
}

func headDatasetObject(reader *BlockReader, mos *Objset, dirObject uint64) (uint64, error) {
	dir, err := readDslDir(reader, mos, dirObject)
	if err != nil {
		return 0, err
	}
	if dir.headDatasetObj == 0 {
		return 0, corruptf("DSL directory object %d names no head dataset", dirObject)
	}
	return dir.headDatasetObj, nil
}

// readDataset reads a dataset's dsl_dataset_phys_t from its bonus. The object
// is identified by its bonus type, which is what OpenZFS checks; a dataset
// with no data of its own is zapified and keeps the struct in its bonus.
func readDataset(reader *BlockReader, mos *Objset, object uint64) (*DatasetPhys, error) {
	node, err := mos.dnode(reader, object)
	if err != nil {
		return nil, err
	}
	if node.bonustype != dmuOtDslDataset {
		return nil, corruptf("object %d has bonus type %s, not a DSL dataset",
			object, objectTypeName(node.bonustype))
	}
	return parseDatasetPhys(node.bonus)
}

// rootFromObjset resolves ROOT through a dataset's master node and lists that
// directory. A head dataset and a mounted snapshot take this same path, so a
// snapshot root is read exactly as the live root is.
func rootFromObjset(reader *BlockReader, objset *Objset, limit int) (uint64, []ZplEntry, bool, error) {
	root, err := rootObject(reader, objset)
	if err != nil {
		return 0, nil, false, err
	}
	node, err := objset.dnode(reader, root)
	if err != nil {
		return 0, nil, false, err
	}
	if node.kind != dmuOtDirectoryContents {
		return 0, nil, false, corruptf("the root object is %s, not a directory", objectTypeName(node.kind))
	}
	directory, err := readDirectory(reader, objset, root, limit)
	if err != nil {
		return 0, nil, false, err
	}
	return root, directory.entries, directory.truncated, nil
}

// checkDatasetBP proves from the block pointer alone that a dataset's ds_bp
// can be read.
func checkDatasetBP(what string, bp *BlockPointer, currentTXG uint64) error {
	if bp.isHole() {
		return corruptf("%s's ds_bp is a hole; it records no root block", what)
	}
	if bp.embedded() {
		return corruptf("%s's ds_bp is embedded; an object set is a block, not an inline payload", what)
	}
	if bp.level() != 0 {
		return corruptf("%s's ds_bp is a level-%d pointer; an object set root is level 0", what, bp.level())
	}
	if bp.objectType() != dmuOtObjset {
		return corruptf("%s's ds_bp holds %s (type %d), not an object set (type %d)",
			what, objectTypeName(bp.objectType()), bp.objectType(), dmuOtObjset)
	}
	if dva, ok := bp.dva(0); !ok || dva.asize() == 0 {
		return corruptf("%s's ds_bp names a DVA that allocates no bytes", what)
	}
	if bp.lsize() < metaDslSizeV1 {
		return corruptf("%s's ds_bp is %d bytes; an object set needs at least %d", what, bp.lsize(), metaDslSizeV1)
	}
	if bp.logicalBirth() > currentTXG {
		return corruptf("%s's ds_bp was born at txg %d, after the pool's current txg %d",
			what, bp.logicalBirth(), currentTXG)
	}
	return nil
}

// --- datasets and snapshots -----------------------------------------------

type namedObject struct {
	name   string
	object uint64
}

func enumerateDatasets(reader *BlockReader, mos *Objset, rootName string, rootObject uint64,
	limit, snapshotLimit int) ([]Dataset, []Snapshot, bool, []string) {
	var datasets []Dataset
	var snapshots []Snapshot
	snapshotsTruncated := false
	var warnings []string
	queue := []namedObject{{name: rootName, object: rootObject}}
	seen := map[uint64]struct{}{}
	for head := 0; head < len(queue); head++ {
		item := queue[head]
		if _, ok := seen[item.object]; ok {
			warnings = append(warnings, fmt.Sprintf("dataset object %d is named twice", item.object))
			continue
		}
		seen[item.object] = struct{}{}
		if len(datasets) >= limit {
			warnings = append(warnings, fmt.Sprintf("dataset walk stopped at %d; deeper datasets are not listed", limit))
			break
		}
		phys, err := readDataset(reader, mos, item.object)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("dataset %q (object %d): %v", item.name, item.object, err))
			continue
		}
		datasets = append(datasets, Dataset{
			Name:              item.name,
			Object:            item.object,
			GUID:              phys.guid,
			CreationTime:      phys.creationTime,
			CreationTXG:       phys.creationTXG,
			ReferencedBytes:   phys.referencedBytes,
			CompressedBytes:   phys.compressedBytes,
			UncompressedBytes: phys.uncompressedBytes,
			Flags:             phys.flags,
		})
		budget := snapshotLimit - len(snapshots)
		if budget < 0 {
			budget = 0
		}
		records, cut, err := snapshotRecords(reader, mos, phys, budget)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("dataset %q snapshots: %v", item.name, err))
		} else {
			snapshotsTruncated = snapshotsTruncated || cut
			if cut {
				warnings = append(warnings,
					fmt.Sprintf("snapshot listing stopped at %d entries for dataset %q", snapshotLimit, item.name))
			}
			for _, record := range records {
				if len(snapshots) >= snapshotLimit {
					snapshotsTruncated = true
					warnings = append(warnings, fmt.Sprintf("snapshot listing stopped at %d entries", snapshotLimit))
					break
				}
				if len(record.name) > maxSnapshotNameBytes {
					warnings = append(warnings, fmt.Sprintf(
						"dataset %q has a snapshot name of %d bytes, past the %d a ZFS name allows; it is not listed",
						item.name, len(record.name), maxSnapshotNameBytes))
					continue
				}
				object, ok := objectOf(record.value)
				if !ok {
					object = 0
				}
				snapshot, warning := snapshotEntry(reader, mos, item.name, record.name, object, ok)
				if warning != "" {
					warnings = append(warnings, warning)
				}
				snapshots = append(snapshots, snapshot)
			}
		}
		children, childWarnings, err := childObjects(reader, mos, phys)
		warnings = append(warnings, childWarnings...)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("dataset %q children: %v", item.name, err))
			continue
		}
		for _, child := range children {
			queue = append(queue, namedObject{name: item.name + "/" + child.name, object: child.object})
		}
	}
	return datasets, snapshots, snapshotsTruncated, warnings
}

// snapshotRecords reads a dataset's ds_snapnames_zapobj, bounded by the
// caller's remaining snapshot budget.
func snapshotRecords(reader *BlockReader, mos *Objset, dataset *DatasetPhys, limit int) ([]ZapEntry, bool, error) {
	if dataset.snapnamesZapObj == 0 {
		return nil, false, nil
	}
	zap, err := mos.zapObjectUpTo(reader, dataset.snapnamesZapObj, limit)
	if err != nil {
		return nil, false, err
	}
	return zap.entries(), zap.truncated, nil
}

// snapshotEntry builds the report entry for one snapshot-ZAP record. The name
// is reported whenever it genuinely appears in the ZAP, even when the object
// behind it cannot be proved to be a snapshot.
func snapshotEntry(reader *BlockReader, mos *Objset, dataset, shortName string, object uint64, objectOK bool) (Snapshot, string) {
	name := dataset + "@" + shortName
	if !objectOK || object == 0 {
		reason := "the ds_snapnames_zapobj value is not an 8-byte object id"
		return Snapshot{
			Name: name, Dataset: dataset, ShortName: shortName, Object: object,
			UnresolvedReason: reason,
		}, fmt.Sprintf("snapshot %q: %s", name, reason)
	}
	phys, err := readDataset(reader, mos, object)
	if err != nil {
		reason := err.Error()
		return Snapshot{
			Name: name, Dataset: dataset, ShortName: shortName, Object: object,
			UnresolvedReason: reason,
		}, fmt.Sprintf("snapshot %q (object %d): %s", name, object, reason)
	}
	snapshot := Snapshot{
		Name:            name,
		Dataset:         dataset,
		ShortName:       shortName,
		Object:          object,
		CreationTime:    phys.creationTime,
		CreationTXG:     phys.creationTXG,
		NumChildren:     phys.numChildren,
		ReferencedBytes: phys.referencedBytes,
		HasBP:           !phys.bp.isHole(),
	}
	if !phys.isSnapshot() {
		snapshot.UnresolvedReason = fmt.Sprintf(
			"object %d is a DSL dataset with ds_num_children 0; it is a head dataset, not a snapshot", object)
		return snapshot, fmt.Sprintf("snapshot %q: %s", name, snapshot.UnresolvedReason)
	}
	return snapshot, ""
}

// childObjects returns a dataset's child names and head-dataset objects.
//
// dd_child_dir_zapobj maps a relative name to the child's DSL directory, not
// to its dataset, so each entry is resolved through dd_head_dataset_obj.
func childObjects(reader *BlockReader, mos *Objset, dataset *DatasetPhys) ([]namedObject, []string, error) {
	if dataset.dirObj == 0 {
		return nil, nil, corruptf("the dataset names no DSL directory")
	}
	dir, err := readDslDir(reader, mos, dataset.dirObj)
	if err != nil {
		return nil, nil, err
	}
	if dir.childDirZapObj == 0 {
		return nil, nil, nil
	}
	zap, err := mos.zapObject(reader, dir.childDirZapObj)
	if err != nil {
		return nil, nil, err
	}
	var children []namedObject
	var warnings []string
	for _, entry := range zap.entries() {
		object, ok := objectOf(entry.value)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("child %q's value is not an 8-byte object id", entry.name))
			continue
		}
		child, err := readDslDir(reader, mos, object)
		switch {
		case err == nil && child.headDatasetObj != 0:
			children = append(children, namedObject{name: entry.name, object: child.headDatasetObj})
		case err == nil:
			// $MOS and $FREE are the pool's internal directories; OpenZFS
			// creates them with no head dataset and they are not filesystems.
			if entry.name == "$MOS" || entry.name == "$FREE" {
				continue
			}
			warnings = append(warnings, fmt.Sprintf(
				"child %q (DSL directory object %d) names no head dataset", entry.name, object))
		default:
			warnings = append(warnings, fmt.Sprintf(
				"child %q (DSL directory object %d): %v", entry.name, object, err))
		}
	}
	return children, warnings, nil
}

// OpenDataset mounts a live dataset's root read-only from its own ds_bp.
func (v *Volume) OpenDataset(name string) (*Mount, error) {
	dataset, err := v.findDataset(name)
	if err != nil {
		return nil, err
	}
	reader := newBlockReader(v.source)
	phys, err := readDataset(reader, v.mos, dataset.Object)
	if err != nil {
		return nil, corruptf("dataset %q (object %d): %v", name, dataset.Object, err)
	}
	if phys.isSnapshot() {
		return nil, corruptf("dataset %q (object %d) has ds_num_children %d; it is a snapshot, not a live dataset",
			name, dataset.Object, phys.numChildren)
	}
	if err := checkDatasetBP(fmt.Sprintf("dataset %q", name), &phys.bp, v.uberblock.TXG); err != nil {
		return nil, err
	}
	objset, err := readObjset(reader, &phys.bp, fmt.Sprintf("dataset %q", name))
	if err != nil {
		return nil, corruptf("dataset %q's ds_bp block: %v", name, err)
	}
	if err := objset.requireZFS(); err != nil {
		return nil, corruptf("dataset %q's ds_bp: %v", name, err)
	}
	rootObject, entries, truncated, err := rootFromObjset(reader, objset, v.pathLimit)
	if err != nil {
		return nil, corruptf("dataset %q's object set: %v", name, err)
	}
	mount := &Mount{
		view: &view{
			volume:         v,
			objset:         objset,
			rootObject:     rootObject,
			dataset:        dataset.Name,
			pathLimit:      v.pathLimit,
			rootEntryCount: len(entries),
			rootTruncated:  truncated,
		},
		dataset:    *dataset,
		mountedTXG: phys.bp.logicalBirth(),
	}
	if truncated {
		mount.warnings = append(mount.warnings,
			fmt.Sprintf("dataset %q's root listing stopped at %d entries", name, v.pathLimit))
	}
	return mount, nil
}

// OpenSnapshot mounts a snapshot root read-only from the snapshot's own ds_bp.
//
// name is either dataset@snapshot or a short snapshot name. A short name that
// matches snapshots in several datasets is refused as ambiguous rather than
// guessing which dataset was meant.
func (v *Volume) OpenSnapshot(name string) (*SnapshotMount, error) {
	if name == "" {
		return nil, corruptf("an empty snapshot name")
	}
	var matches []Snapshot
	if strings.ContainsRune(name, '@') {
		for _, snapshot := range v.snapshots {
			if snapshot.Name == name {
				matches = append(matches, snapshot)
			}
		}
	} else {
		for _, snapshot := range v.snapshots {
			if snapshot.ShortName == name {
				matches = append(matches, snapshot)
			}
		}
	}
	switch len(matches) {
	case 0:
		return nil, corruptf("no snapshot named %q; recorded: %s", name, recordedSnapshotNames(v.snapshots))
	case 1:
	default:
		names := make([]string, 0, len(matches))
		for _, snapshot := range matches {
			names = append(names, fmt.Sprintf("%q", snapshot.Name))
		}
		return nil, corruptf("snapshot name %q is ambiguous; it matches %s", name, strings.Join(names, ", "))
	}
	snapshot := matches[0]
	if snapshot.UnresolvedReason != "" {
		return nil, corruptf("snapshot %q cannot be mounted: %s", snapshot.Name, snapshot.UnresolvedReason)
	}
	reader := newBlockReader(v.source)
	phys, err := readDataset(reader, v.mos, snapshot.Object)
	if err != nil {
		return nil, corruptf("snapshot %q (object %d): %v", snapshot.Name, snapshot.Object, err)
	}
	if !phys.isSnapshot() {
		return nil, corruptf("snapshot %q (object %d) has ds_num_children 0; it is a head dataset, not a snapshot",
			snapshot.Name, snapshot.Object)
	}
	if err := checkDatasetBP(fmt.Sprintf("snapshot %q", snapshot.Name), &phys.bp, v.uberblock.TXG); err != nil {
		return nil, err
	}
	objset, err := readObjset(reader, &phys.bp, fmt.Sprintf("snapshot %q", snapshot.Name))
	if err != nil {
		return nil, corruptf("snapshot %q's ds_bp block: %v", snapshot.Name, err)
	}
	if err := objset.requireZFS(); err != nil {
		return nil, corruptf("snapshot %q's ds_bp: %v", snapshot.Name, err)
	}
	rootObject, entries, truncated, err := rootFromObjset(reader, objset, v.pathLimit)
	if err != nil {
		return nil, corruptf("snapshot %q's object set: %v", snapshot.Name, err)
	}
	mount := &SnapshotMount{
		view: &view{
			volume:         v,
			objset:         objset,
			rootObject:     rootObject,
			dataset:        snapshot.Dataset,
			pathLimit:      v.pathLimit,
			rootEntryCount: len(entries),
			rootTruncated:  truncated,
		},
		snapshot:   snapshot,
		mountedTXG: phys.bp.logicalBirth(),
	}
	if truncated {
		mount.warnings = append(mount.warnings,
			fmt.Sprintf("snapshot %q's root listing stopped at %d entries", snapshot.Name, v.pathLimit))
	}
	return mount, nil
}

func (v *Volume) findDataset(name string) (*Dataset, error) {
	for i := range v.datasets {
		if v.datasets[i].Name == name {
			return &v.datasets[i], nil
		}
	}
	names := make([]string, 0, len(v.datasets))
	for i := range v.datasets {
		if i >= snapshotNamesInError {
			break
		}
		names = append(names, fmt.Sprintf("%q", v.datasets[i].Name))
	}
	recorded := "none"
	if len(names) > 0 {
		recorded = strings.Join(names, ", ")
		if len(v.datasets) > snapshotNamesInError {
			recorded += fmt.Sprintf(" (and %d more)", len(v.datasets)-snapshotNamesInError)
		}
	}
	return nil, corruptf("no dataset named %q; recorded: %s", name, recorded)
}

func recordedSnapshotNames(snapshots []Snapshot) string {
	if len(snapshots) == 0 {
		return "none"
	}
	names := make([]string, 0, minIntTest(len(snapshots), snapshotNamesInError))
	for i := 0; i < len(snapshots) && i < snapshotNamesInError; i++ {
		names = append(names, fmt.Sprintf("%q", snapshots[i].Name))
	}
	recorded := strings.Join(names, ", ")
	if len(snapshots) > snapshotNamesInError {
		recorded += fmt.Sprintf(" (and %d more)", len(snapshots)-snapshotNamesInError)
	}
	return recorded
}

func minIntTest(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// DatasetMountpoint returns the mountpoint a head dataset resolves to, as
// stored on the media. nil means no ancestor recorded a value.
func (v *Volume) DatasetMountpoint(datasetName string) (*string, error) {
	dataset, err := v.findDataset(datasetName)
	if err != nil {
		return nil, err
	}
	reader := newBlockReader(v.source)
	phys, err := readDataset(reader, v.mos, dataset.Object)
	if err != nil {
		return nil, corruptf("dataset %q (object %d): %v", datasetName, dataset.Object, err)
	}
	if phys.isSnapshot() {
		return nil, corruptf("dataset %q (object %d) has ds_num_children %d; a snapshot's mountpoint is not a live dataset's",
			datasetName, dataset.Object, phys.numChildren)
	}
	if phys.dirObj == 0 {
		return nil, corruptf("dataset %q (object %d) names no DSL directory", datasetName, dataset.Object)
	}
	dir, err := readDslDir(reader, v.mos, phys.dirObj)
	if err != nil {
		return nil, corruptf("dataset %q's DSL directory (object %d): %v", datasetName, phys.dirObj, err)
	}
	return resolveDatasetMountpoint(reader, v.mos, phys.dirObj, dir.parentObj == 0)
}

func resolveDatasetMountpoint(reader *BlockReader, mos *Objset, dirObject uint64, poolRoot bool) (*string, error) {
	current := dirObject
	seen := map[uint64]struct{}{}
	reachedRoot := false
	for depth := 0; depth < maxDslParentDepth; depth++ {
		if _, ok := seen[current]; ok {
			return nil, corruptf("the DSL directory chain revisits object %d", current)
		}
		seen[current] = struct{}{}
		dir, err := readDslDir(reader, mos, current)
		if err != nil {
			return nil, err
		}
		if dir.propsZapObj != 0 {
			zap, err := mos.zapObject(reader, dir.propsZapObj)
			if err != nil {
				return nil, corruptf("DSL directory object %d's property map (object %d): %v",
					current, dir.propsZapObj, err)
			}
			value, err := mountpointFromProps(zap, current)
			if err != nil {
				return nil, err
			}
			if value != nil {
				return value, nil
			}
		}
		if dir.parentObj == 0 {
			reachedRoot = true
			break
		}
		current = dir.parentObj
	}
	if !reachedRoot {
		return nil, corruptf("the DSL directory chain from object %d is longer than %d", dirObject, maxDslParentDepth)
	}
	if poolRoot {
		root := "/"
		return &root, nil
	}
	return nil, nil
}

func mountpointFromProps(zap *Zap, dirObject uint64) (*string, error) {
	if entry, ok := zap.get(mountpointProperty + indexUpdateSuffix); ok {
		if value, ok := propertyString(entry.value); ok {
			return &value, nil
		}
	}
	if entry, ok := zap.get(mountpointProperty); ok {
		value, ok := propertyString(entry.value)
		if !ok {
			return nil, corruptf("DSL directory object %d's mountpoint is not a NUL-terminated UTF-8 string", dirObject)
		}
		return &value, nil
	}
	if _, ok := zap.get(mountpointProperty + inheritSuffix); ok {
		return nil, nil
	}
	if entry, ok := zap.get(mountpointProperty + receivedSuffix); ok {
		value, ok := propertyString(entry.value)
		if !ok {
			return nil, corruptf("DSL directory object %d's received mountpoint is not a NUL-terminated UTF-8 string", dirObject)
		}
		return &value, nil
	}
	return nil, nil
}

// propertyString decodes a ZAP property value as a NUL-terminated string.
// Everything after the first NUL must be zero, so a padded micro-ZAP slot and
// an exactly-sized fat-ZAP value are both accepted.
func propertyString(value []byte) (string, bool) {
	if len(value) > maxPropertyBytes {
		return "", false
	}
	end := -1
	for i, b := range value {
		if b == 0 {
			end = i
			break
		}
	}
	if end < 0 {
		return "", false
	}
	for _, b := range value[end:] {
		if b != 0 {
			return "", false
		}
	}
	if !validUTF8(value[:end]) {
		return "", false
	}
	return string(value[:end]), true
}
