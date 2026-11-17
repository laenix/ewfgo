// Package qcow2 exposes QEMU QCOW2 virtual disks as a ByteSource. It is a
// pure-Go port of forensic-core's data/containers/qcow2.rs, covering versions
// 2 and 3 with classic L2 entries, unallocated/zero clusters, zlib-compressed
// clusters, and an explicit backing file.
package qcow2

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// Signature is the QCOW magic at offset 0.
	Signature = "QFI\xfb"
	// HeaderV2Bytes and HeaderV3Bytes are the header prefixes this reader uses.
	HeaderV2Bytes = 72
	HeaderV3Bytes = 104
	// MinClusterBits and MaxClusterBits bound the cluster exponent.
	MinClusterBits = 9
	MaxClusterBits = 21

	compressionTypeOffset = 104
	compressionZlib       = 0
	compressionZstd       = 1
	compressedAlignment   = 512
	tablePageEntries      = 512

	compressedFlag uint64 = 1 << 62
	zeroFlag       uint64 = 1
	reservedFlags  uint64 = 0x1fe
	offsetFlags    uint64 = 0x00FFFFFFFFFFFFFE00

	incompatibleDirty        uint64 = 1 << 0
	incompatibleCorrupt      uint64 = 1 << 1
	incompatibleExternalData uint64 = 1 << 2
	incompatibleCompression  uint64 = 1 << 3
	incompatibleExtendedL2   uint64 = 1 << 4
	incompatibleKnown        uint64 = incompatibleDirty | incompatibleCorrupt |
		incompatibleExternalData | incompatibleCompression | incompatibleExtendedL2

	autoclearBitmaps         uint64 = 1 << 0
	autoclearRawExternalData uint64 = 1 << 1
	autoclearKnown           uint64 = autoclearBitmaps | autoclearRawExternalData

	maxBackingName = 4096
)

// Info is the QCOW2 geometry and identity.
type Info struct {
	Version              uint32
	ClusterBits          uint32
	VirtualSize          uint64
	L1Entries            uint64
	L1TableOffset        uint64
	CryptMethod          uint32
	IncompatibleFeatures uint64
	CompatibleFeatures   uint64
	AutoclearFeatures    uint64
	RefcountOrder        uint32
	CompressionType      uint8
	ExtendedL2           bool
	ExternalDataFile     bool
	DataFileRaw          bool
	Snapshots            uint32
	HeaderBytes          uint64
	BackingOffset        uint64
	BackingFile          string
	HasBacking           bool
}

// ClusterBytes returns the cluster size in bytes.
func (i Info) ClusterBytes() uint64 { return uint64(1) << i.ClusterBits }

// IsDirty reports the DIRTY incompatible bit.
func (i Info) IsDirty() bool { return i.IncompatibleFeatures&incompatibleDirty != 0 }

// IsCorrupt reports the CORRUPT incompatible bit.
func (i Info) IsCorrupt() bool { return i.IncompatibleFeatures&incompatibleCorrupt != 0 }

type unitKind uint8

const (
	unitUnallocated unitKind = iota
	unitZero
	unitData
	unitCompressed
)

type unitMap struct {
	kind   unitKind
	offset uint64
	bytes  uint64
}

type l1Page struct {
	first   uint64
	entries []uint64
}

type l2Entry struct {
	descriptor uint64
	bitmap     uint64
}

type l2Page struct {
	table   uint64
	entries []l2Entry
}

// Source is a read-only QCOW2 virtual disk.
type Source struct {
	id           source.ID
	parent       source.ByteSource
	backing      *Source
	dataFile     source.ByteSource
	dataFileRaw  bool
	length       uint64
	clusterBytes uint64
	unitBytes    uint64
	entryBytes   uint64
	extendedL2   bool
	entriesPerL2 uint64
	l1Offset     uint64
	l1Entries    uint64
	info         Info
	mu           sync.Mutex
	l1Cache      *l1Page
	l2Cache      *l2Page
	grainCache   *grainCache
	counters     source.Counters
}

type grainCache struct {
	cluster uint64
	data    []byte
}

// MatchesSignature reports whether head starts with QFI\xfb.
func MatchesSignature(head []byte) bool {
	return len(head) >= 4 && string(head[:4]) == Signature
}

// Options are the explicit side files a QCOW2 image may need.
type Options struct {
	Backing  *Source
	DataFile source.ByteSource
}

// Open opens a standalone QCOW2 image. An image with a backing file is refused.
func Open(id source.ID, parent source.ByteSource) (*Source, error) {
	return openInner(id, parent, Options{})
}

// OpenWithParent opens a backing image over an already-opened parent.
func OpenWithParent(id source.ID, child source.ByteSource, backing *Source) (*Source, error) {
	return openInner(id, child, Options{Backing: backing})
}

// OpenWithOptions opens an image over the side files the caller supplies.
func OpenWithOptions(id source.ID, parent source.ByteSource, options Options) (*Source, error) {
	return openInner(id, parent, options)
}

func openInner(id source.ID, parent source.ByteSource, options Options) (*Source, error) {
	backing := options.Backing
	dataFile := options.DataFile
	if parent.Len() < HeaderV2Bytes {
		return nil, unsupported("QFI signature")
	}
	readLen := uint64(HeaderV3Bytes)
	if parent.Len() < readLen {
		readLen = parent.Len()
	}
	header, err := source.ReadVecAt(parent, 0, readLen)
	if err != nil {
		return nil, err
	}
	if string(header[:4]) != Signature {
		return nil, unsupported("QFI signature")
	}
	version := be32(header, 4)
	if version != 2 && version != 3 {
		return nil, unsupported(fmt.Sprintf("format version %d", version))
	}
	backingOffset := be64(header, 8)
	backingSize := be32(header, 16)
	clusterBits := be32(header, 20)
	virtualSize := be64(header, 24)
	cryptMethod := be32(header, 32)
	l1Size := uint64(be32(header, 36))
	l1Offset := be64(header, 40)
	snapshots := be32(header, 60)

	var incompatible, compatible, autoclear uint64
	var refcountOrder uint32
	headerBytes := uint64(HeaderV2Bytes)
	if version == 3 {
		if len(header) < HeaderV3Bytes {
			return nil, corrupt(0, "version 3 header is truncated")
		}
		incompatible = be64(header, 72)
		compatible = be64(header, 80)
		autoclear = be64(header, 88)
		refcountOrder = be32(header, 96)
		headerBytes = uint64(be32(header, 100))
	}

	if clusterBits < MinClusterBits || clusterBits > MaxClusterBits {
		return nil, corrupt(20, fmt.Sprintf("cluster bits %d is outside %d..=%d", clusterBits, MinClusterBits, MaxClusterBits))
	}
	clusterBytes := uint64(1) << clusterBits
	minimumHeader := uint64(HeaderV2Bytes)
	if version == 3 {
		minimumHeader = HeaderV3Bytes
	}
	if headerBytes < minimumHeader || headerBytes > clusterBytes {
		return nil, corrupt(100, fmt.Sprintf("header length %d is outside %d..=%d", headerBytes, minimumHeader, clusterBytes))
	}
	if virtualSize == 0 {
		return nil, corrupt(24, "virtual disk size is zero")
	}
	if cryptMethod != 0 {
		return nil, unsupported(fmt.Sprintf("an encrypted image (crypt method %d)", cryptMethod))
	}
	if unknown := incompatible &^ incompatibleKnown; unknown != 0 {
		return nil, unsupported(fmt.Sprintf("unknown incompatible feature bits %#x; the known bits are 0..=4", unknown))
	}
	if unknown := autoclear &^ autoclearKnown; unknown != 0 {
		return nil, unsupported(fmt.Sprintf("unknown autoclear feature bits %#x; the known bits are 0..=1", unknown))
	}
	externalData := incompatible&incompatibleExternalData != 0
	dataFileRaw := autoclear&autoclearRawExternalData != 0
	extendedL2 := incompatible&incompatibleExtendedL2 != 0
	if extendedL2 && clusterBits < 14 {
		return nil, unsupported(fmt.Sprintf("extended L2 entries with %d-bit clusters; the format requires at least 14", clusterBits))
	}
	if dataFileRaw && !externalData {
		return nil, unsupported("the raw external data autoclear bit without an external data file")
	}
	compressionType := byte(compressionZlib)
	if version == 3 && incompatible&incompatibleCompression != 0 {
		if parent.Len() <= compressionTypeOffset {
			return nil, corrupt(compressionTypeOffset, "compression type byte is past the end of the file")
		}
		value, err := source.ReadVecAt(parent, compressionTypeOffset, 1)
		if err != nil {
			return nil, err
		}
		compressionType = value[0]
	}
	if compressionType != compressionZlib && compressionType != compressionZstd {
		return nil, unsupported(fmt.Sprintf("compression type %d; only 0 (zlib) and 1 (zstd) are defined", compressionType))
	}
	if compressionType == compressionZstd {
		return nil, unsupported("zstd-compressed clusters are not ported yet")
	}

	hasBacking := backingOffset != 0 && backingSize != 0
	var backingFile string
	if hasBacking {
		name, err := readBackingName(parent, backingOffset, uint64(backingSize))
		if err != nil {
			return nil, err
		}
		backingFile = name
	}
	if externalData {
		if snapshots != 0 {
			return nil, unsupported(fmt.Sprintf("internal snapshots in an image with an external data file (%d recorded)", snapshots))
		}
		if dataFileRaw && hasBacking {
			return nil, unsupported("a raw external data file combined with a backing file; the format forbids it")
		}
		if dataFile == nil {
			return nil, unsupported("an external data file; supply it explicitly (the recorded name is a hint only)")
		}
		if dataFile.Len() != virtualSize {
			return nil, unsupported(fmt.Sprintf("an external data file of %d bytes but the header declares a %d byte disk", dataFile.Len(), virtualSize))
		}
	} else if dataFile != nil {
		return nil, unsupported("an external data file supplied for a QCOW2 image that does not declare one")
	}
	if hasBacking && backing == nil {
		name := backingFile
		if name == "" {
			name = "an unnamed file"
		}
		return nil, unsupported(fmt.Sprintf("a backing file (%s); reading it alone would return only the delta's changes", name))
	}
	if !hasBacking && backing != nil {
		return nil, unsupported("parent supplied for a QCOW2 image that does not declare a backing file")
	}
	if backing != nil && virtualSize != backing.length {
		return nil, unsupported(fmt.Sprintf("backing child virtual size %d does not match the parent's %d", virtualSize, backing.length))
	}

	entryBytes := uint64(8)
	if extendedL2 {
		entryBytes = 16
	}
	entriesPerL2 := clusterBytes / entryBytes
	unitBytes := clusterBytes
	if extendedL2 {
		unitBytes = clusterBytes / 32
	}
	bytesPerL1 := entriesPerL2 * clusterBytes
	expectedL1 := (virtualSize + bytesPerL1 - 1) / bytesPerL1
	if l1Size != expectedL1 {
		return nil, corrupt(36, fmt.Sprintf("L1 table holds %d entries but a %d byte disk with %d byte clusters needs %d",
			l1Size, virtualSize, clusterBytes, expectedL1))
	}
	if l1Offset == 0 || l1Offset%clusterBytes != 0 {
		return nil, corrupt(40, fmt.Sprintf("L1 table offset %d is not a cluster boundary", l1Offset))
	}
	l1Bytes := l1Size * 8
	if l1Offset+l1Bytes < l1Offset || l1Offset+l1Bytes > parent.Len() {
		return nil, corrupt(40, fmt.Sprintf("L1 table at %d (%d bytes) is outside the %d byte file", l1Offset, l1Bytes, parent.Len()))
	}

	info := Info{
		Version:              version,
		ClusterBits:          clusterBits,
		VirtualSize:          virtualSize,
		L1Entries:            l1Size,
		L1TableOffset:        l1Offset,
		CryptMethod:          cryptMethod,
		IncompatibleFeatures: incompatible,
		CompatibleFeatures:   compatible,
		AutoclearFeatures:    autoclear,
		RefcountOrder:        refcountOrder,
		CompressionType:      compressionType,
		ExtendedL2:           extendedL2,
		ExternalDataFile:     externalData,
		DataFileRaw:          dataFileRaw,
		Snapshots:            snapshots,
		HeaderBytes:          headerBytes,
		BackingOffset:        backingOffset,
		BackingFile:          backingFile,
		HasBacking:           hasBacking,
	}
	return &Source{
		id:           id,
		parent:       parent,
		backing:      backing,
		dataFile:     dataFile,
		dataFileRaw:  dataFileRaw,
		length:       virtualSize,
		clusterBytes: clusterBytes,
		unitBytes:    unitBytes,
		entryBytes:   entryBytes,
		extendedL2:   extendedL2,
		entriesPerL2: entriesPerL2,
		l1Offset:     l1Offset,
		l1Entries:    l1Size,
		info:         info,
	}, nil
}

// Info returns the image geometry and features.
func (s *Source) Info() Info { return s.info }

// Parent returns the container source.
func (s *Source) Parent() source.ByteSource { return s.parent }

// Backing returns the backing image, when opened over one.
func (s *Source) Backing() *Source { return s.backing }

// ClusterBytes returns the cluster size.
func (s *Source) ClusterBytes() uint64 { return s.clusterBytes }

func (s *Source) SourceID() source.ID     { return s.id }
func (s *Source) Len() uint64             { return s.length }
func (s *Source) ImageID() source.ImageID { return s.parent.ImageID() }
func (s *Source) SectorSize() uint32      { return 512 }
func (s *Source) IsEmpty() bool           { return s.length == 0 }
func (s *Source) Stats() source.Stats     { return s.counters.Snapshot() }

func (s *Source) checkRange(offset, length uint64) error {
	if offset > s.length || length > s.length-offset {
		return source.NewOutOfRange(offset, length, s.length)
	}
	return nil
}

func (s *Source) dataSource() source.ByteSource {
	if s.dataFile != nil {
		return s.dataFile
	}
	return s.parent
}

func (s *Source) l1Entry(index uint64) (uint64, error) {
	s.mu.Lock()
	if page := s.l1Cache; page != nil && index >= page.first {
		if at := index - page.first; at < uint64(len(page.entries)) {
			entry := page.entries[at]
			s.mu.Unlock()
			return entry, nil
		}
	}
	s.mu.Unlock()

	first := index - index%tablePageEntries
	count := uint64(tablePageEntries)
	if remaining := s.l1Entries - first; remaining < count {
		count = remaining
	}
	bytes, err := source.ReadVecAt(s.parent, s.l1Offset+first*8, count*8)
	if err != nil {
		return 0, err
	}
	entries := make([]uint64, count)
	for i := range entries {
		entries[i] = be64(bytes, i*8)
	}
	s.mu.Lock()
	s.l1Cache = &l1Page{first: first, entries: entries}
	s.mu.Unlock()
	return entries[index-first], nil
}

func (s *Source) l2Entry(cluster uint64) (l2Entry, error) {
	l1Index := cluster / s.entriesPerL2
	index := cluster % s.entriesPerL2
	table, err := s.l1Entry(l1Index)
	if err != nil {
		return l2Entry{}, err
	}
	if table == 0 {
		return l2Entry{}, nil
	}
	if table%s.clusterBytes != 0 {
		return l2Entry{}, corrupt(s.l1Offset+l1Index*8,
			fmt.Sprintf("L2 table offset %d is not a cluster boundary", table))
	}
	if table+s.clusterBytes < table || table+s.clusterBytes > s.parent.Len() {
		return l2Entry{}, corrupt(s.l1Offset+l1Index*8,
			fmt.Sprintf("L2 table at %d (%d bytes) is outside the %d byte file",
				table, s.clusterBytes, s.parent.Len()))
	}

	s.mu.Lock()
	if page := s.l2Cache; page != nil && page.table == table {
		if index < uint64(len(page.entries)) {
			entry := page.entries[index]
			s.mu.Unlock()
			return entry, nil
		}
	}
	s.mu.Unlock()

	first := index - index%tablePageEntries
	count := uint64(tablePageEntries)
	if remaining := s.entriesPerL2 - first; remaining < count {
		count = remaining
	}
	width := int(s.entryBytes)
	bytes, err := source.ReadVecAt(s.parent, table+first*s.entryBytes, count*s.entryBytes)
	if err != nil {
		return l2Entry{}, err
	}
	entries := make([]l2Entry, count)
	for i := range entries {
		at := i * width
		entries[i].descriptor = be64(bytes, at)
		if width == 16 {
			entries[i].bitmap = be64(bytes, at+8)
		}
	}
	s.mu.Lock()
	s.l2Cache = &l2Page{table: table, entries: entries}
	s.mu.Unlock()
	return entries[index-first], nil
}

func (s *Source) visibleBytes(cluster uint64) uint64 {
	start := cluster * s.clusterBytes
	if start >= s.length {
		return 0
	}
	return minU64(s.length-start, s.clusterBytes)
}

func (s *Source) subclusterVisibleBytes(cluster, sub uint64) uint64 {
	start := cluster*s.clusterBytes + sub*s.unitBytes
	if start >= s.length {
		return 0
	}
	return minU64(s.unitBytes, s.length-start)
}

func (s *Source) unitMapFor(cluster, sub uint64) (unitMap, error) {
	entry, err := s.l2Entry(cluster)
	if err != nil {
		return unitMap{}, err
	}
	if s.extendedL2 {
		return s.extendedUnitMap(cluster, sub, entry)
	}
	return s.classicUnitMap(cluster, entry.descriptor)
}

func (s *Source) classicUnitMap(cluster uint64, entry uint64) (unitMap, error) {
	if entry == 0 {
		return unitMap{kind: unitUnallocated}, nil
	}
	if entry&compressedFlag != 0 {
		return s.compressedUnitMap(cluster, entry)
	}
	if entry&zeroFlag != 0 {
		if s.info.Version < 3 {
			return unitMap{}, corrupt(s.l1Offset,
				fmt.Sprintf("version 2 L2 entry for cluster %d sets the reserved bit 0", cluster))
		}
		return unitMap{kind: unitZero}, nil
	}
	if entry&reservedFlags != 0 {
		return unitMap{}, corrupt(s.l1Offset,
			fmt.Sprintf("L2 entry for cluster %d sets a reserved bit", cluster))
	}
	offset := entry & offsetFlags
	if err := s.checkDataCluster(cluster, offset); err != nil {
		return unitMap{}, err
	}
	return unitMap{kind: unitData, offset: offset}, nil
}

func (s *Source) extendedUnitMap(cluster, sub uint64, entry l2Entry) (unitMap, error) {
	descriptor := entry.descriptor
	bitmap := entry.bitmap
	if descriptor&zeroFlag != 0 {
		return unitMap{}, corrupt(s.l1Offset,
			fmt.Sprintf("extended L2 entry for cluster %d sets bit 0, which is reserved when extended L2 is enabled", cluster))
	}
	if descriptor&compressedFlag != 0 {
		if bitmap != 0 {
			return unitMap{}, corrupt(s.l1Offset,
				fmt.Sprintf("compressed extended L2 entry for cluster %d has non-zero subcluster bits %#x; they are reserved", cluster, bitmap))
		}
		return s.compressedUnitMap(cluster, descriptor)
	}
	if descriptor&reservedFlags != 0 {
		return unitMap{}, corrupt(s.l1Offset,
			fmt.Sprintf("extended L2 entry for cluster %d sets a reserved descriptor bit", cluster))
	}
	if sub >= 32 {
		return unitMap{}, corrupt(s.l1Offset, fmt.Sprintf("subcluster %d is outside 0..32", sub))
	}
	allocated := bitmap&(uint64(1)<<sub) != 0
	zero := bitmap&(uint64(1)<<(sub+32)) != 0
	if allocated && zero {
		return unitMap{}, corrupt(s.l1Offset,
			fmt.Sprintf("extended L2 entry for cluster %d marks subcluster %d both allocated and zero", cluster, sub))
	}
	if allocated {
		offset := descriptor & offsetFlags
		if offset == 0 {
			return unitMap{}, corrupt(s.l1Offset,
				fmt.Sprintf("extended L2 entry for cluster %d marks subcluster %d allocated without a data offset", cluster, sub))
		}
		subOffset := offset + sub*s.unitBytes
		need := s.subclusterVisibleBytes(cluster, sub)
		end := subOffset + need
		if end < subOffset || end > s.parent.Len() {
			return unitMap{}, corrupt(s.l1Offset,
				fmt.Sprintf("cluster %d subcluster %d maps to bytes %d..%d beyond the %d byte file",
					cluster, sub, subOffset, end, s.parent.Len()))
		}
		return unitMap{kind: unitData, offset: subOffset}, nil
	}
	if zero {
		return unitMap{kind: unitZero}, nil
	}
	return unitMap{kind: unitUnallocated}, nil
}

func (s *Source) checkDataCluster(cluster, offset uint64) error {
	if offset%s.clusterBytes != 0 {
		return corrupt(s.l1Offset, fmt.Sprintf("cluster %d maps to %d, not a cluster boundary", cluster, offset))
	}
	if s.dataFile != nil {
		guest := cluster * s.clusterBytes
		if offset != guest {
			return corrupt(s.l1Offset,
				fmt.Sprintf("external data file descriptor offset %d for cluster %d does not match the guest offset %d", offset, cluster, guest))
		}
	}
	need := s.visibleBytes(cluster)
	end := offset + need
	dataLen := s.dataSource().Len()
	if end < offset || end > dataLen {
		return corrupt(s.l1Offset,
			fmt.Sprintf("cluster %d maps to bytes %d..%d beyond the %d byte data source", cluster, offset, end, dataLen))
	}
	return nil
}

func (s *Source) compressedMasks() (offsetMask uint64, sizeShift uint32, sizeMask uint64) {
	offsetMask = (uint64(1) << (63 - s.info.ClusterBits)) - 1
	sizeShift = 62 - (s.info.ClusterBits - 8)
	sizeMask = (uint64(1) << (s.info.ClusterBits - 8)) - 1
	return
}

func (s *Source) compressedUnitMap(cluster, entry uint64) (unitMap, error) {
	if s.dataFile != nil {
		return unitMap{}, unsupported(fmt.Sprintf("a compressed cluster (%d) in an image with an external data file; the format does not support it", cluster))
	}
	offsetMask, sizeShift, sizeMask := s.compressedMasks()
	offset := (entry & offsetMask) &^ (compressedAlignment - 1)
	sectors := ((entry >> sizeShift) & sizeMask) + 1
	bytes := sectors * compressedAlignment
	if offset+bytes < offset || offset+bytes > s.parent.Len() {
		return unitMap{}, corrupt(s.l1Offset,
			fmt.Sprintf("compressed cluster %d maps to bytes %d..%d beyond the %d byte file",
				cluster, offset, offset+bytes, s.parent.Len()))
	}
	return unitMap{kind: unitCompressed, offset: offset, bytes: bytes}, nil
}

func (s *Source) compressedCluster(cluster, offset, compressedBytes uint64) ([]byte, error) {
	s.mu.Lock()
	if cache := s.grainCache; cache != nil && cache.cluster == cluster {
		data := cache.data
		s.mu.Unlock()
		s.counters.AddCacheHit()
		return data, nil
	}
	s.mu.Unlock()
	s.counters.AddCacheMiss()

	stream, err := source.ReadVecAt(s.parent, offset, compressedBytes)
	if err != nil {
		return nil, err
	}
	zr, err := zlib.NewReader(bytes.NewReader(stream))
	if err != nil {
		return nil, corrupt(offset, fmt.Sprintf("compressed cluster %d does not inflate: %v", cluster, err))
	}
	decoded, err := io.ReadAll(io.LimitReader(zr, int64(s.clusterBytes)+1))
	closeErr := zr.Close()
	if err != nil {
		return nil, corrupt(offset, fmt.Sprintf("compressed cluster %d does not inflate: %v", cluster, err))
	}
	if closeErr != nil {
		return nil, corrupt(offset, fmt.Sprintf("compressed cluster %d does not inflate: %v", cluster, closeErr))
	}
	if uint64(len(decoded)) > s.clusterBytes {
		return nil, corrupt(offset, fmt.Sprintf("compressed cluster %d inflates past its %d-byte cluster", cluster, s.clusterBytes))
	}
	if uint64(len(decoded)) < s.visibleBytes(cluster) {
		return nil, corrupt(offset, fmt.Sprintf("compressed cluster %d inflates to %d bytes but holds %d guest bytes",
			cluster, len(decoded), s.visibleBytes(cluster)))
	}
	for uint64(len(decoded)) < s.clusterBytes {
		decoded = append(decoded, 0)
	}
	s.counters.AddDecompressed(uint64(len(decoded)))
	s.mu.Lock()
	s.grainCache = &grainCache{cluster: cluster, data: decoded}
	s.mu.Unlock()
	return decoded, nil
}

func (s *Source) ReadAt(offset uint64, buf []byte) (int, error) {
	return s.readInner(offset, buf, false)
}

func (s *Source) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	return s.readInner(offset, buf, true)
}

func (s *Source) readInner(offset uint64, buf []byte, lossy bool) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= s.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), s.length)
	}
	want := int(minU64(s.length-offset, uint64(len(buf))))
	if s.dataFileRaw {
		if err := readFull(s.dataFile, offset, buf[:want], lossy); err != nil {
			return 0, err
		}
		s.counters.AddRead(want)
		return want, nil
	}
	done := 0
	for done < want {
		position := offset + uint64(done)
		unit := position / s.unitBytes
		cluster := unit
		sub := uint64(0)
		if s.extendedL2 {
			cluster = unit / 32
			sub = unit % 32
		}
		within := position % s.unitBytes
		chunk := int(minU64(s.unitBytes-within, uint64(want-done)))
		mapping, err := s.unitMapFor(cluster, sub)
		if err != nil {
			return 0, err
		}
		switch mapping.kind {
		case unitUnallocated:
			if s.backing != nil {
				if err := readFull(s.backing, position, buf[done:done+chunk], lossy); err != nil {
					return 0, err
				}
			} else {
				clear(buf[done : done+chunk])
			}
			done += chunk
		case unitZero:
			clear(buf[done : done+chunk])
			done += chunk
		case unitData:
			if err := readFull(s.dataSource(), mapping.offset+within, buf[done:done+chunk], lossy); err != nil {
				return 0, err
			}
			done += chunk
		case unitCompressed:
			decoded, err := s.compressedCluster(cluster, mapping.offset, mapping.bytes)
			if err != nil {
				return 0, err
			}
			inCluster := position - cluster*s.clusterBytes
			copy(buf[done:done+chunk], decoded[inCluster:inCluster+uint64(chunk)])
			done += chunk
		}
	}
	s.counters.AddRead(done)
	return done, nil
}

func (s *Source) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if err := s.checkRange(offset, length); err != nil {
		return out, err
	}
	if s.dataFileRaw {
		out = append(out, source.ParentRange{
			Parent: s.dataFile.SourceID(), ParentOffset: offset, Len: length, Kind: source.RangeData,
		})
		return out, nil
	}
	cursor := offset
	end := offset + length
	for cursor < end {
		unit := cursor / s.unitBytes
		cluster := unit
		sub := uint64(0)
		if s.extendedL2 {
			cluster = unit / 32
			sub = unit % 32
		}
		within := cursor % s.unitBytes
		stop := minU64(end, (unit+1)*s.unitBytes)
		chunk := stop - cursor
		mapping, err := s.unitMapFor(cluster, sub)
		if err != nil {
			return out, err
		}
		switch mapping.kind {
		case unitUnallocated:
			if s.backing != nil {
				out = append(out, source.ParentRange{
					Parent: s.backing.SourceID(), ParentOffset: cursor, Len: chunk, Kind: source.RangeData,
				})
			} else {
				out = append(out, source.ParentRange{
					Parent: s.parent.SourceID(), ParentOffset: 0, Len: chunk, Kind: source.RangeZero,
				})
			}
		case unitZero:
			out = append(out, source.ParentRange{
				Parent: s.parent.SourceID(), ParentOffset: 0, Len: chunk, Kind: source.RangeZero,
			})
		case unitData:
			out = append(out, source.ParentRange{
				Parent: s.dataSource().SourceID(), ParentOffset: mapping.offset + within,
				Len: chunk, Kind: source.RangeData,
			})
		case unitCompressed:
			out = append(out, source.ParentRange{
				Parent: s.parent.SourceID(), ParentOffset: mapping.offset,
				Len: mapping.bytes, Kind: source.RangeData,
			})
		}
		cursor = stop
	}
	return out, nil
}

func (s *Source) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

func (s *Source) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	extents, err := s.Extents(offset, length)
	if err != nil {
		return nil, err
	}
	var out []source.ImageRange
	for _, extent := range extents {
		if extent.Kind != source.RangeData {
			out = append(out, source.ImageRange{
				ImageID: s.parent.ImageID(), ImageOffset: 0, Len: extent.Len, Kind: extent.Kind,
			})
			continue
		}
		if s.dataFile != nil && extent.Parent == s.dataFile.SourceID() {
			mapped, err := s.dataFile.MapToImage(extent.ParentOffset, extent.Len)
			if err != nil {
				return nil, err
			}
			out = append(out, mapped...)
			continue
		}
		if s.backing != nil && extent.Parent == s.backing.SourceID() {
			mapped, err := s.backing.MapToImage(extent.ParentOffset, extent.Len)
			if err != nil {
				return nil, err
			}
			out = append(out, mapped...)
			continue
		}
		mapped, err := s.parent.MapToImage(extent.ParentOffset, extent.Len)
		if err != nil {
			return nil, err
		}
		out = append(out, mapped...)
	}
	return out, nil
}

var _ source.ByteSource = (*Source)(nil)

func readBackingName(parent source.ByteSource, offset, size uint64) (string, error) {
	if size == 0 || size > maxBackingName {
		return "", corrupt(16, fmt.Sprintf("backing file name length %d is outside 1..=%d", size, maxBackingName))
	}
	if offset+size < offset || offset+size > parent.Len() {
		return "", corrupt(8, fmt.Sprintf("backing file name at %d (+%d) is outside the %d byte file", offset, size, parent.Len()))
	}
	bytes, err := source.ReadVecAt(parent, offset, size)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(strings.ToValidUTF8(string(bytes), "�"), "\x00"), nil
}

func readFull(src source.ByteSource, offset uint64, target []byte, lossy bool) error {
	var (
		n   int
		err error
	)
	if lossy {
		n, err = src.ReadAtLossy(offset, target)
	} else {
		n, err = src.ReadAt(offset, target)
	}
	if err != nil {
		return err
	}
	if n < len(target) {
		return source.NewUnexpectedEOF(offset)
	}
	return nil
}

func corrupt(offset uint64, reason string) error {
	return &source.Error{Kind: source.ErrCorrupt, Offset: offset, Reason: reason}
}

func unsupported(reason string) error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: reason}
}

func be32(bytes []byte, at int) uint32 {
	return uint32(bytes[at])<<24 | uint32(bytes[at+1])<<16 | uint32(bytes[at+2])<<8 | uint32(bytes[at+3])
}

func be64(bytes []byte, at int) uint64 {
	return uint64(be32(bytes, at))<<32 | uint64(be32(bytes, at+4))
}

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
