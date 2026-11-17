// Package thin reads LVM2 thin volumes through their pool's persistent-data
// metadata: the 4096-byte superblock, the per-device mapping btree, the
// device-details tree, and the data logical volume those mappings name. It is
// a pure-Go port of forensic-core's lvm/thin.rs.
package thin

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/laenix/ewfgo/internal/data/lvm"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// ThinMagic is the superblock magic.
	ThinMagic uint64 = 27022010
	// MetadataBlockBytes is the persistent-data block size.
	MetadataBlockBytes uint64 = 4096
	// SuperblockCsumXor is XORed into the superblock checksum.
	SuperblockCsumXor uint32 = 160774
	// BtreeCsumXor is XORed into every node checksum.
	BtreeCsumXor uint32 = 121107
	// MaxTreeDepth bounds one descent.
	MaxTreeDepth = 16
	// NodeCacheNodes bounds the decoded-node cache.
	NodeCacheNodes = 256
	// MaxTreeBlocks bounds the metadata block count.
	MaxTreeBlocks uint64 = 1048576
	// MaxExtentBlocks bounds one range translation.
	MaxExtentBlocks uint64 = 4 * 1024 * 1024

	internalID uint64 = 1 << 63
	metadataID uint64 = 1 << 62
)

// Errors. Callers test them with errors.Is.
var (
	ErrCorrupt     = errors.New("thin: corrupt metadata")
	ErrUnsupported = errors.New("thin: unsupported")
	ErrUnknownPool = errors.New("thin: unknown pool")
	ErrPoolShape   = errors.New("thin: pool shape")
	ErrVolumeShape = errors.New("thin: volume shape")
	ErrPoolVolume  = errors.New("thin: pool volume")
)

// Superblock is the persistent-data superblock at metadata block zero.
type Superblock struct {
	Flags             uint32
	BlockNr           uint64
	UUID              [16]byte
	Magic             uint64
	Version           uint32
	Time              uint32
	TransID           uint64
	MetadataSnap      uint64
	DataMappingRoot   uint64
	DeviceDetailsRoot uint64
	DataBlockSize     uint32 // 512-byte sectors
	MetadataBlockSize uint32
	MetadataNrBlocks  uint64
	CompatFlags       uint32
	CompatROFlags     uint32
	IncompatFlags     uint32
}

// NeedsCheck reports whether the pool was closed with a consistency check
// pending.
func (s *Superblock) NeedsCheck() bool { return s.Flags&1 != 0 }

// DataBlockBytes returns the data block size in bytes.
func (s *Superblock) DataBlockBytes() uint64 { return uint64(s.DataBlockSize) * 512 }

// ParseSuperblock decodes and verifies the 4096-byte superblock.
func ParseSuperblock(block []byte) (*Superblock, error) {
	if len(block) < int(MetadataBlockBytes) {
		return nil, fmt.Errorf("%w: superblock block is %d bytes, not %d",
			ErrCorrupt, len(block), MetadataBlockBytes)
	}
	stored := le32(block[0:4])
	computed := thinChecksum(block[:MetadataBlockBytes], SuperblockCsumXor)
	if stored != computed {
		return nil, fmt.Errorf("%w: superblock checksum is 0x%08x, computed 0x%08x",
			ErrCorrupt, stored, computed)
	}
	magic := le64(block[32:40])
	if magic != ThinMagic {
		return nil, fmt.Errorf("%w: superblock magic is %d, not %d", ErrCorrupt, magic, ThinMagic)
	}
	version := le32(block[40:44])
	metadataBlockSize := le32(block[340:344])
	switch version {
	case 1:
		if metadataBlockSize != 8 && metadataBlockSize != 4096 {
			return nil, fmt.Errorf("%w: thin metadata version 1 with metadata_block_size %d",
				ErrUnsupported, metadataBlockSize)
		}
	case 2:
		if metadataBlockSize != 4096 {
			return nil, fmt.Errorf("%w: thin metadata metadata_block_size %d, not 4096",
				ErrUnsupported, metadataBlockSize)
		}
	default:
		return nil, fmt.Errorf("%w: thin metadata version %d", ErrUnsupported, version)
	}

	flags := le32(block[4:8])
	if flags&^uint32(1) != 0 {
		return nil, fmt.Errorf("%w: superblock flags 0x%08x", ErrUnsupported, flags)
	}
	compatFlags := le32(block[352:356])
	compatROFlags := le32(block[356:360])
	incompatFlags := le32(block[360:364])
	if compatFlags != 0 || compatROFlags != 0 || incompatFlags != 0 {
		return nil, fmt.Errorf("%w: superblock feature flags compat=0x%08x compat_ro=0x%08x incompat=0x%08x",
			ErrUnsupported, compatFlags, compatROFlags, incompatFlags)
	}
	dataBlockSize := le32(block[336:340])
	if dataBlockSize == 0 {
		return nil, fmt.Errorf("%w: data block size is zero", ErrCorrupt)
	}
	metadataNrBlocks := le64(block[344:352])
	if metadataNrBlocks == 0 || metadataNrBlocks > MaxTreeBlocks {
		return nil, fmt.Errorf("%w: metadata claims %d blocks, limit %d",
			ErrUnsupported, metadataNrBlocks, MaxTreeBlocks)
	}
	dataMappingRoot := le64(block[320:328])
	deviceDetailsRoot := le64(block[328:336])
	for _, entry := range []struct {
		name string
		root uint64
		at   uint64
	}{
		{"mapping tree", dataMappingRoot, 320},
		{"details tree", deviceDetailsRoot, 328},
	} {
		if entry.root == 0 || entry.root >= metadataNrBlocks {
			return nil, fmt.Errorf("%w: %s root %d is outside the %d-block metadata area",
				ErrCorrupt, entry.name, entry.root, metadataNrBlocks)
		}
	}

	var uuid [16]byte
	copy(uuid[:], block[16:32])
	return &Superblock{
		Flags:             flags,
		BlockNr:           le64(block[8:16]),
		UUID:              uuid,
		Magic:             magic,
		Version:           version,
		Time:              le32(block[44:48]),
		TransID:           le64(block[48:56]),
		MetadataSnap:      le64(block[56:64]),
		DataMappingRoot:   dataMappingRoot,
		DeviceDetailsRoot: deviceDetailsRoot,
		DataBlockSize:     dataBlockSize,
		MetadataBlockSize: metadataBlockSize,
		MetadataNrBlocks:  metadataNrBlocks,
		CompatFlags:       compatFlags,
		CompatROFlags:     compatROFlags,
		IncompatFlags:     incompatFlags,
	}, nil
}

// DeviceDetails is the device-details record that proves a thin device exists.
type DeviceDetails struct {
	MappedBlocks    uint64
	TransactionID   uint64
	CreationTime    uint32
	SnapshottedTime uint32
}

type node struct {
	flags     uint32
	valueSize uint32
	keys      []uint64
	values    []byte
}

func (n *node) isInternal() bool { return n.flags&1 != 0 }

func (n *node) value(index int) []byte {
	size := int(n.valueSize)
	return n.values[index*size : (index+1)*size]
}

func decodeNode(block []byte, location uint64, leafValueSize uint32) (*node, error) {
	size := int(MetadataBlockBytes)
	if len(block) < size {
		return nil, fmt.Errorf("%w: node block is %d bytes, not %d", ErrCorrupt, len(block), size)
	}
	stored := le32(block[0:4])
	computed := thinChecksum(block[:size], BtreeCsumXor)
	if stored != computed {
		return nil, fmt.Errorf("%w: node %d checksum is 0x%08x, computed 0x%08x",
			ErrCorrupt, location, stored, computed)
	}
	flags := le32(block[4:8])
	blocknr := le64(block[8:16])
	nrEntries := le32(block[16:20])
	maxEntries := le32(block[20:24])
	valueSize := le32(block[24:28])
	if blocknr != location {
		return nil, fmt.Errorf("%w: node read from block %d records blocknr %d",
			ErrCorrupt, location, blocknr)
	}
	if flags != 0 && flags != 1 {
		return nil, fmt.Errorf("%w: node flags are 0x%08x, neither leaf nor internal",
			ErrCorrupt, flags)
	}
	internal := flags == 1
	expectedValueSize := leafValueSize
	if internal {
		if valueSize != 8 {
			return nil, fmt.Errorf("%w: internal node value size is %d, not 8",
				ErrCorrupt, valueSize)
		}
		expectedValueSize = 8
	}
	if valueSize != expectedValueSize {
		return nil, fmt.Errorf("%w: node value size is %d, expected %d for this tree",
			ErrCorrupt, valueSize, expectedValueSize)
	}
	expectedMax := (uint64(size) - 32) / (8 + uint64(valueSize))
	if uint64(maxEntries) != expectedMax {
		return nil, fmt.Errorf("%w: node max_entries is %d, expected %d",
			ErrCorrupt, maxEntries, expectedMax)
	}
	if nrEntries > maxEntries {
		return nil, fmt.Errorf("%w: node holds %d entries, maximum %d",
			ErrCorrupt, nrEntries, maxEntries)
	}
	if internal && nrEntries == 0 {
		return nil, fmt.Errorf("%w: internal node holds no entries", ErrCorrupt)
	}

	count := int(nrEntries)
	keysAt := 32
	valuesAt := keysAt + int(maxEntries)*8
	valueBytes := count * int(valueSize)
	if valuesAt+valueBytes > size {
		return nil, fmt.Errorf("%w: node values run past the end of the block", ErrCorrupt)
	}
	keys := make([]uint64, count)
	for index := 0; index < count; index++ {
		keys[index] = le64(block[keysAt+index*8:])
	}
	for index := 1; index < count; index++ {
		if keys[index-1] >= keys[index] {
			return nil, fmt.Errorf("%w: node keys are not strictly ascending", ErrCorrupt)
		}
	}
	values := append([]byte(nil), block[valuesAt:valuesAt+valueBytes]...)
	return &node{flags: flags, valueSize: valueSize, keys: keys, values: values}, nil
}

type reader struct {
	metadata    source.ByteSource
	superblock  *Superblock
	mu          sync.Mutex
	cache       map[uint64]*node
	cacheCapped bool
	cacheHits   atomic.Uint64
	cacheMisses atomic.Uint64
}

func newReader(metadata source.ByteSource) (*reader, error) {
	length := metadata.Len()
	if length < MetadataBlockBytes {
		return nil, fmt.Errorf("%w: metadata logical volume is %d bytes, shorter than one block",
			ErrCorrupt, length)
	}
	block, err := source.ReadVecAt(metadata, 0, MetadataBlockBytes)
	if err != nil {
		return nil, err
	}
	superblock, err := ParseSuperblock(block)
	if err != nil {
		return nil, err
	}
	covered := superblock.MetadataNrBlocks * MetadataBlockBytes
	if covered/MetadataBlockBytes != superblock.MetadataNrBlocks {
		return nil, fmt.Errorf("%w: metadata block count overflows", ErrCorrupt)
	}
	if covered > length {
		return nil, fmt.Errorf("%w: metadata claims %d bytes but the logical volume holds %d",
			ErrCorrupt, covered, length)
	}
	return &reader{metadata: metadata, superblock: superblock, cache: make(map[uint64]*node)}, nil
}

func (r *reader) readNode(block uint64, leafValueSize uint32) (*node, error) {
	r.mu.Lock()
	if cached, ok := r.cache[block]; ok {
		r.mu.Unlock()
		r.cacheHits.Add(1)
		return cached, nil
	}
	r.mu.Unlock()
	r.cacheMisses.Add(1)

	if block >= r.superblock.MetadataNrBlocks {
		return nil, fmt.Errorf("%w: tree block %d is outside the %d-block metadata area",
			ErrCorrupt, block, r.superblock.MetadataNrBlocks)
	}
	bytes, err := source.ReadVecAt(r.metadata, block*MetadataBlockBytes, MetadataBlockBytes)
	if err != nil {
		return nil, err
	}
	decoded, err := decodeNode(bytes, block, leafValueSize)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	if len(r.cache) < NodeCacheNodes {
		r.cache[block] = decoded
	} else {
		r.cacheCapped = true
	}
	r.mu.Unlock()
	return decoded, nil
}

func (r *reader) lookup(root, key uint64, leafValueSize uint32) ([]byte, bool, error) {
	block := root
	seen := make(map[uint64]bool)
	for depth := 0; depth < MaxTreeDepth; depth++ {
		if seen[block] {
			return nil, false, fmt.Errorf("%w: btree revisits block %d on one descent", ErrCorrupt, block)
		}
		seen[block] = true
		current, err := r.readNode(block, leafValueSize)
		if err != nil {
			return nil, false, err
		}
		if current.isInternal() {
			below := sort.Search(len(current.keys), func(i int) bool { return current.keys[i] > key })
			if below == 0 {
				return nil, false, nil
			}
			value := current.value(below - 1)
			child := le64(value[:8])
			if child == 0 || child >= r.superblock.MetadataNrBlocks {
				return nil, false, fmt.Errorf("%w: btree child %d is outside the %d-block metadata area",
					ErrCorrupt, child, r.superblock.MetadataNrBlocks)
			}
			block = child
			continue
		}
		index := sort.Search(len(current.keys), func(i int) bool { return current.keys[i] >= key })
		if index < len(current.keys) && current.keys[index] == key {
			return append([]byte(nil), current.value(index)...), true, nil
		}
		return nil, false, nil
	}
	return nil, false, fmt.Errorf("%w: btree is deeper than %d levels", ErrCorrupt, MaxTreeDepth)
}

func (r *reader) mappingRoot(deviceID uint64) (uint64, bool, error) {
	value, ok, err := r.lookup(r.superblock.DataMappingRoot, deviceID, 8)
	if err != nil || !ok {
		return 0, ok, err
	}
	root := le64(value[:8])
	if root == 0 || root >= r.superblock.MetadataNrBlocks {
		return 0, false, fmt.Errorf("%w: mapping subtree root for device %d is %d, outside the %d-block metadata area",
			ErrCorrupt, deviceID, root, r.superblock.MetadataNrBlocks)
	}
	return root, true, nil
}

func (r *reader) deviceDetails(deviceID uint64) (DeviceDetails, error) {
	value, ok, err := r.lookup(r.superblock.DeviceDetailsRoot, deviceID, 24)
	if err != nil {
		return DeviceDetails{}, err
	}
	if !ok {
		return DeviceDetails{}, fmt.Errorf("%w: the details tree has no record for thin device %d",
			ErrCorrupt, deviceID)
	}
	if len(value) < 24 {
		return DeviceDetails{}, fmt.Errorf("%w: details record for device %d is %d bytes, not 24",
			ErrCorrupt, deviceID, len(value))
	}
	return DeviceDetails{
		MappedBlocks:    le64(value[0:8]),
		TransactionID:   le64(value[8:16]),
		CreationTime:    le32(value[16:20]),
		SnapshottedTime: le32(value[20:24]),
	}, nil
}

func (r *reader) mapping(root uint64, block uint64) (uint64, bool, error) {
	value, ok, err := r.lookup(root, block, 8)
	if err != nil || !ok {
		return 0, ok, err
	}
	// pack_block_time: top 40 bits are the data block, low 24 the time.
	return le64(value[:8]) >> 24, true, nil
}

// VolumeInfo is what the pool metadata and the group text agree on.
type VolumeInfo struct {
	MetadataLV              string
	DataLV                  string
	Pool                    string
	DeviceID                uint64
	SegmentTransactionID    uint64
	HasSegmentTransaction   bool
	DetailsTransactionID    uint64
	SuperblockTransactionID uint64
	MetadataVersion         uint32
	DataBlockBytes          uint64
	MappedBlocks            uint64
	MetadataNrBlocks        uint64
	MetadataLVBytes         uint64
	DataLVBytes             uint64
	DataPVs                 int
	NeedsCheck              bool
}

// Source is a thin logical volume read through its pool's metadata.
type Source struct {
	id             source.ID
	reader         *reader
	data           source.ByteSource
	info           VolumeInfo
	length         uint64
	dataBlockBytes uint64
	mappingRoot    uint64
	hasMappingRoot bool
	counters       source.Counters
}

// OpenInGroup exposes thin logical volume name of group over pvs.
func OpenInGroup(id source.ID, group *lvm.VolumeGroup, pvs []lvm.PhysicalVolumeSource, name string) (*Source, error) {
	volume, ok := findLogicalVolume(group, name)
	if !ok {
		return nil, fmt.Errorf("%w: %q", lvm.ErrUnknownVolume, name)
	}
	segment, err := thinSegment(volume)
	if err != nil {
		return nil, err
	}
	poolName, ok := segmentOption(segment, "thin_pool")
	if !ok {
		return nil, fmt.Errorf("%w: thin logical volume %q records no `thin_pool`", ErrVolumeShape, name)
	}
	deviceText, ok := segmentOption(segment, "device_id")
	if !ok {
		return nil, fmt.Errorf("%w: thin logical volume %q records no `device_id`", ErrVolumeShape, name)
	}
	deviceID, err := parseUint(deviceText)
	if err != nil {
		return nil, fmt.Errorf("%w: thin logical volume %q has an invalid `device_id`", ErrVolumeShape, name)
	}
	var segmentTransaction uint64
	hasSegmentTransaction := false
	if text, ok := segmentOption(segment, "transaction_id"); ok {
		if parsed, err := parseUint(text); err == nil {
			segmentTransaction, hasSegmentTransaction = parsed, true
		}
	}
	extentBytes, ok := group.ExtentBytes()
	if !ok || extentBytes == 0 {
		return nil, fmt.Errorf("%w", lvm.ErrNoExtentSize)
	}
	length := segment.ExtentCount * extentBytes
	if length/extentBytes != segment.ExtentCount {
		return nil, fmt.Errorf("%w: thin extent count overflows the volume length", ErrUnsupported)
	}

	pool, ok := findLogicalVolume(group, poolName)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownPool, poolName)
	}
	var poolSegments []*lvm.Segment
	for i := range pool.Segments {
		if pool.Segments[i].Kind == "thin-pool" {
			poolSegments = append(poolSegments, &pool.Segments[i])
		}
	}
	if len(poolSegments) != 1 {
		return nil, fmt.Errorf("%w: thin pool %q records %d `thin-pool` segment(s), expected one",
			ErrPoolShape, poolName, len(poolSegments))
	}
	poolSegment := poolSegments[0]
	metadataLV, ok := segmentOption(poolSegment, "metadata")
	if !ok {
		metadataLV, ok = segmentOption(poolSegment, "metadata_lv")
	}
	if !ok {
		return nil, fmt.Errorf("%w: thin pool %q records no `metadata` logical volume", ErrPoolShape, poolName)
	}
	dataLV, ok := segmentOption(poolSegment, "pool")
	if !ok {
		dataLV, ok = segmentOption(poolSegment, "data_lv")
	}
	if !ok {
		return nil, fmt.Errorf("%w: thin pool %q records no `pool` data logical volume", ErrPoolShape, poolName)
	}

	metadata, err := lvm.OpenInGroup(source.ID(uint64(id)|internalID|metadataID), group, pvs, metadataLV)
	if err != nil {
		return nil, fmt.Errorf("%w: thin pool %q metadata logical volume %q: %v",
			ErrPoolVolume, poolName, metadataLV, err)
	}
	data, err := lvm.OpenInGroup(source.ID(uint64(id)|internalID), group, pvs, dataLV)
	if err != nil {
		return nil, fmt.Errorf("%w: thin pool %q data logical volume %q: %v",
			ErrPoolVolume, poolName, dataLV, err)
	}

	r, err := newReader(metadata)
	if err != nil {
		return nil, err
	}
	dataBlockBytes := r.superblock.DataBlockBytes()
	if dataBlockBytes == 0 {
		return nil, fmt.Errorf("%w: data block size is zero", ErrCorrupt)
	}
	if dataBlockBytes > data.Len() {
		return nil, fmt.Errorf("%w: data block size %d exceeds the %d-byte pool data logical volume",
			ErrCorrupt, dataBlockBytes, data.Len())
	}
	details, err := r.deviceDetails(deviceID)
	if err != nil {
		return nil, err
	}
	if details.TransactionID > r.superblock.TransID {
		return nil, fmt.Errorf("%w: device %d records transaction %d, newer than the pool's %d",
			ErrCorrupt, deviceID, details.TransactionID, r.superblock.TransID)
	}
	if hasSegmentTransaction && segmentTransaction > r.superblock.TransID {
		return nil, fmt.Errorf("%w: thin segment records transaction %d, newer than the pool's %d",
			ErrCorrupt, segmentTransaction, r.superblock.TransID)
	}
	mappingRoot, hasMappingRoot, err := r.mappingRoot(deviceID)
	if err != nil {
		return nil, err
	}

	info := VolumeInfo{
		MetadataLV:              metadataLV,
		DataLV:                  dataLV,
		Pool:                    poolName,
		DeviceID:                deviceID,
		SegmentTransactionID:    segmentTransaction,
		HasSegmentTransaction:   hasSegmentTransaction,
		DetailsTransactionID:    details.TransactionID,
		SuperblockTransactionID: r.superblock.TransID,
		MetadataVersion:         r.superblock.Version,
		DataBlockBytes:          dataBlockBytes,
		MappedBlocks:            details.MappedBlocks,
		MetadataNrBlocks:        r.superblock.MetadataNrBlocks,
		MetadataLVBytes:         metadata.Len(),
		DataLVBytes:             data.Len(),
		DataPVs:                 len(data.Parents()),
		NeedsCheck:              r.superblock.NeedsCheck(),
	}
	return &Source{
		id:             id,
		reader:         r,
		data:           data,
		info:           info,
		length:         length,
		dataBlockBytes: dataBlockBytes,
		mappingRoot:    mappingRoot,
		hasMappingRoot: hasMappingRoot,
	}, nil
}

// Info returns what the pool metadata and group text agree on.
func (s *Source) Info() VolumeInfo { return s.info }

// DeviceID returns the thin device id.
func (s *Source) DeviceID() uint64 { return s.info.DeviceID }

// DataBlockBytes returns the data block size in bytes.
func (s *Source) DataBlockBytes() uint64 { return s.dataBlockBytes }

// MappingRoot returns the per-device mapping subtree root.
func (s *Source) MappingRoot() (uint64, bool) { return s.mappingRoot, s.hasMappingRoot }

func (s *Source) SourceID() source.ID     { return s.id }
func (s *Source) Len() uint64             { return s.length }
func (s *Source) ImageID() source.ImageID { return s.data.ImageID() }
func (s *Source) SectorSize() uint32      { return s.data.SectorSize() }
func (s *Source) IsEmpty() bool           { return s.length == 0 }

func (s *Source) Stats() source.Stats {
	stats := s.counters.Snapshot()
	stats.CacheHits += s.reader.cacheHits.Load()
	stats.CacheMisses += s.reader.cacheMisses.Load()
	return stats
}

func (s *Source) blockData(block uint64) (uint64, bool, error) {
	if !s.hasMappingRoot {
		return 0, false, nil
	}
	return s.reader.mapping(s.mappingRoot, block)
}

func (s *Source) physicalOffset(block, dataBlock, within uint64) (uint64, error) {
	start := dataBlock * s.dataBlockBytes
	if start/s.dataBlockBytes != dataBlock {
		return 0, &source.Error{Kind: source.ErrCorrupt, Offset: block, Reason: "thin data offset overflows"}
	}
	start += within
	if start < within {
		return 0, &source.Error{Kind: source.ErrCorrupt, Offset: block, Reason: "thin data offset overflows"}
	}
	if start >= s.data.Len() {
		return 0, &source.Error{Kind: source.ErrCorrupt, Offset: start,
			Reason: fmt.Sprintf("thin device %d block %d maps to data block %d, past the %d-byte pool data volume",
				s.info.DeviceID, block, dataBlock, s.data.Len())}
	}
	return start, nil
}

func (s *Source) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	n, err := s.readInto(offset, buf)
	if err != nil {
		return 0, err
	}
	s.counters.AddRead(n)
	return n, nil
}

func (s *Source) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	return s.ReadAt(offset, buf)
}

func (s *Source) readInto(offset uint64, buf []byte) (int, error) {
	if offset >= s.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), s.length)
	}
	want := int(minU64(s.length-offset, uint64(len(buf))))
	clear(buf[:want])
	done := 0
	for done < want {
		logical := offset + uint64(done)
		block := logical / s.dataBlockBytes
		within := logical % s.dataBlockBytes
		chunk := int(minU64(s.dataBlockBytes-within, uint64(want-done)))
		dataBlock, ok, err := s.blockData(block)
		if err != nil {
			return 0, err
		}
		if ok {
			physical, err := s.physicalOffset(block, dataBlock, within)
			if err != nil {
				return 0, err
			}
			read, err := s.data.ReadAt(physical, buf[done:done+chunk])
			if err != nil {
				return 0, err
			}
			if read < chunk {
				return done + read, nil
			}
		}
		done += chunk
	}
	return want, nil
}

func (s *Source) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > s.length || length > s.length-offset {
		return out, source.NewOutOfRange(offset, length, s.length)
	}
	if length == 0 {
		return out, nil
	}
	blocks := (length + s.dataBlockBytes - 1) / s.dataBlockBytes
	if blocks > MaxExtentBlocks {
		return out, &source.Error{Kind: source.ErrUnsupported, Reason: fmt.Sprintf(
			"a %d-byte range covers %d thin blocks, limit %d", length, blocks, MaxExtentBlocks)}
	}
	end := offset + length
	parent := s.data.SourceID()
	cursor := offset
	for cursor < end {
		block := cursor / s.dataBlockBytes
		within := cursor % s.dataBlockBytes
		chunk := minU64(s.dataBlockBytes-within, end-cursor)
		dataBlock, ok, err := s.blockData(block)
		if err != nil {
			return out, err
		}
		if ok {
			at, err := s.physicalOffset(block, dataBlock, within)
			if err != nil {
				return out, err
			}
			out = pushRange(out, parent, at, chunk, source.RangeData)
		} else {
			out = pushRange(out, parent, 0, chunk, source.RangeHole)
		}
		cursor += chunk
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
		if extent.Kind == source.RangeData {
			mapped, err := s.data.MapToImage(extent.ParentOffset, extent.Len)
			if err != nil {
				return nil, err
			}
			out = append(out, mapped...)
			continue
		}
		out = append(out, source.ImageRange{
			ImageID: s.data.ImageID(), ImageOffset: 0, Len: extent.Len, Kind: extent.Kind,
		})
	}
	return out, nil
}

var _ source.ByteSource = (*Source)(nil)

func findLogicalVolume(group *lvm.VolumeGroup, name string) (*lvm.LogicalVolume, bool) {
	for i := range group.LogicalVolumes {
		if group.LogicalVolumes[i].Name == name {
			return &group.LogicalVolumes[i], true
		}
	}
	return nil, false
}

func thinSegment(volume *lvm.LogicalVolume) (*lvm.Segment, error) {
	var thin *lvm.Segment
	for i := range volume.Segments {
		segment := &volume.Segments[i]
		if segment.ExtentCount == 0 {
			continue
		}
		if segment.Kind == "thin" {
			if thin != nil {
				return nil, fmt.Errorf("%w: %q records more than one thin segment", ErrVolumeShape, volume.Name)
			}
			thin = segment
			continue
		}
		kind := segment.Kind
		if kind == "" {
			kind = "striped"
		}
		return nil, fmt.Errorf("%w: %q records a `%s` segment as well as a thin segment",
			ErrVolumeShape, volume.Name, kind)
	}
	if thin == nil {
		return nil, fmt.Errorf("%w: %q records no thin segment", ErrVolumeShape, volume.Name)
	}
	if thin.StartExtent != 0 {
		return nil, fmt.Errorf("%w: %q thin segment starts at extent %d, not 0",
			ErrVolumeShape, volume.Name, thin.StartExtent)
	}
	return thin, nil
}

func segmentOption(segment *lvm.Segment, key string) (string, bool) {
	for _, entry := range segment.Other {
		if entry.Key == key {
			return entry.Value, true
		}
	}
	return "", false
}

func pushRange(out []source.ParentRange, parent source.ID, offset, length uint64, kind source.RangeKind) []source.ParentRange {
	if n := len(out); n > 0 {
		last := &out[n-1]
		if last.Parent == parent && last.Kind == kind {
			contiguous := kind != source.RangeData || last.ParentOffset+last.Len == offset
			if contiguous {
				last.Len += length
				return out
			}
		}
	}
	return append(out, source.ParentRange{Parent: parent, ParentOffset: offset, Len: length, Kind: kind})
}

func parseUint(text string) (uint64, error) {
	return strconv.ParseUint(text, 10, 64)
}

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func le32(bytes []byte) uint32 {
	return uint32(bytes[0]) | uint32(bytes[1])<<8 | uint32(bytes[2])<<16 | uint32(bytes[3])<<24
}

func le64(bytes []byte) uint64 {
	return uint64(le32(bytes)) | uint64(le32(bytes[4:]))<<32
}
