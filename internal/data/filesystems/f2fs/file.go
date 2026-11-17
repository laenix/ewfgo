package f2fs

import (
	"fmt"
	"sync"

	"github.com/laenix/ewfgo/internal/data/source"
)

// NodeEntries returns the entries a direct or indirect node block holds.
func NodeEntries(blockSize uint32) uint64 {
	return (uint64(blockSize) - NodeFooterSize) / 4
}

// CompressionReport counts what happened to the compressed clusters a file
// read touched.
type CompressionReport struct {
	// Decoded is the clusters decoded successfully.
	Decoded uint64
	// Refused is the clusters whose algorithm this reader does not decode.
	Refused uint64
	// Corrupt is the clusters whose header or decoded bytes were invalid.
	Corrupt uint64
	// Notes holds a bounded note for each failure, oldest first.
	Notes []string
}

const maxCompressionNotes = 8

// ClusterPlan is the checked geometry and stored-block count of one compressed
// cluster.
type clusterPlan struct {
	start        uint64
	header       *ClusterHeader
	storedBlocks uint64
}

// FileMap resolves a file's block map against the volume that holds it.
type FileMap struct {
	source         source.ByteSource
	nat            *NATTable
	blockSize      uint32
	entriesPerNode uint64
	addresses      []uint32
	nids           [NIDsPerInode]uint32
	inline         []byte
	inlineAt       uint64
	length         uint64
	logClusterSize uint8
	algorithm      uint8

	nodeMu    sync.Mutex
	nodeNID   uint32
	nodeValid bool
	nodeData  []uint32

	decodedMu    sync.Mutex
	decodedStart uint64
	decodedOK    bool
	decodedData  []byte

	reportMu sync.Mutex
	report   CompressionReport
}

// NewFileMap builds the block map for inode, refusing one whose contents cannot
// be read.
func NewFileMap(src source.ByteSource, nat *NATTable, inode *Inode) (*FileMap, error) {
	if err := inode.CheckReadable(); err != nil {
		return nil, err
	}
	blockSize := inode.BlockSize
	entriesPerNode := NodeEntries(blockSize)
	if entriesPerNode == 0 {
		return nil, invalidf("a %d-byte node block cannot hold an address", blockSize)
	}
	var inlineAt uint64
	if inode.Inline != nil {
		block, err := nat.NodeBlock(src, inode.NID)
		if err != nil {
			return nil, err
		}
		inlineAt = uint64(block)*uint64(blockSize) + uint64(inode.AddressesOffset)
	}
	return &FileMap{
		source:         src,
		nat:            nat,
		blockSize:      blockSize,
		entriesPerNode: entriesPerNode,
		addresses:      append([]uint32(nil), inode.Addresses...),
		nids:           inode.NIDs,
		inline:         append([]byte(nil), inode.Inline...),
		inlineAt:       inlineAt,
		length:         inode.Size,
		logClusterSize: inode.LogClusterSize,
		algorithm:      inode.CompressAlgorithm,
	}, nil
}

// Len returns the file's length.
func (m *FileMap) Len() uint64 { return m.length }

// IsEmpty reports whether the file has no bytes.
func (m *FileMap) IsEmpty() bool { return m.length == 0 }

// BlockSize returns the volume's block size.
func (m *FileMap) BlockSize() uint32 { return m.blockSize }

// IsInline reports whether the file's bytes live inside its inode.
func (m *FileMap) IsInline() bool { return m.inline != nil }

// IsCompressed reports whether the inode records compressed clusters.
func (m *FileMap) IsCompressed() bool { return m.logClusterSize > 0 }

// CompressAlgorithm returns the algorithm byte the inode carries.
func (m *FileMap) CompressAlgorithm() uint8 { return m.algorithm }

// CompressAlgorithmName returns the algorithm's name.
func (m *FileMap) CompressAlgorithmName() string { return AlgorithmName(m.algorithm) }

// CompressionReport returns a snapshot of the clusters this map touched.
func (m *FileMap) CompressionReport() CompressionReport {
	m.reportMu.Lock()
	defer m.reportMu.Unlock()
	return CompressionReport{
		Decoded: m.report.Decoded,
		Refused: m.report.Refused,
		Corrupt: m.report.Corrupt,
		Notes:   append([]string(nil), m.report.Notes...),
	}
}

// DataBlock returns the block holding file block index.  The bool is false for
// a hole.
func (m *FileMap) DataBlock(index uint64) (uint32, bool, error) {
	if start, compressed, err := m.compressedClusterStart(index); err != nil {
		return 0, false, err
	} else if compressed {
		return 0, false, unsupportedf(
			"the compressed cluster at block %d, whose file blocks are served decompressed rather than as stored blocks", start)
	}
	address, err := m.rawAddress(index)
	if err != nil {
		return 0, false, err
	}
	return m.resolve(address)
}

// rawAddress returns the stored address of logical block index, sentinels
// included.
func (m *FileMap) rawAddress(index uint64) (uint32, error) {
	direct := uint64(len(m.addresses))
	first := m.entriesPerNode
	if index < direct {
		return m.addresses[index], nil
	}
	rest := index - direct
	if rest < 2*first {
		node := m.nids[rest/first]
		if node == NullAddr {
			return NullAddr, nil
		}
		entries, err := m.nodeAddresses(node)
		if err != nil {
			return 0, err
		}
		return entries[rest%first], nil
	}
	rest -= 2 * first
	second := first * first
	if rest < 2*second {
		upper := m.nids[2+rest/second]
		if upper == NullAddr {
			return NullAddr, nil
		}
		indirect, err := m.nodeAddresses(upper)
		if err != nil {
			return 0, err
		}
		lower := indirect[(rest%second)/first]
		if lower == NullAddr {
			return NullAddr, nil
		}
		entries, err := m.nodeAddresses(lower)
		if err != nil {
			return 0, err
		}
		return entries[rest%first], nil
	}
	rest -= 2 * second
	third := first * second
	if rest < third {
		if m.nids[4] == NullAddr {
			return NullAddr, nil
		}
		double, err := m.nodeAddresses(m.nids[4])
		if err != nil {
			return 0, err
		}
		upper := double[rest/second]
		if upper == NullAddr {
			return NullAddr, nil
		}
		indirect, err := m.nodeAddresses(upper)
		if err != nil {
			return 0, err
		}
		lower := indirect[(rest%second)/first]
		if lower == NullAddr {
			return NullAddr, nil
		}
		entries, err := m.nodeAddresses(lower)
		if err != nil {
			return 0, err
		}
		return entries[rest%first], nil
	}
	maximum := direct + 2*first + 2*second + third
	return 0, invalidf("block %d is past the %d this block size can address", index, maximum)
}

// compressedClusterStart returns the starting block of the compressed cluster
// index belongs to, when that cluster is marked and the inode uses compression.
func (m *FileMap) compressedClusterStart(index uint64) (uint64, bool, error) {
	if m.logClusterSize == 0 {
		return 0, false, nil
	}
	blocks := uint64(1) << m.logClusterSize
	start := index / blocks * blocks
	address, err := m.rawAddress(start)
	if err != nil {
		return 0, false, err
	}
	return start, address == CompressAddr, nil
}

func (m *FileMap) clusterPlan(start uint64) (*clusterPlan, error) {
	plan, err := m.readClusterPlan(start)
	if err != nil {
		m.recordFailure(err)
	}
	return plan, err
}

func (m *FileMap) readClusterPlan(start uint64) (*clusterPlan, error) {
	blockSize := uint64(m.blockSize)
	firstStreamBlock := start + 1
	address, err := m.rawAddress(firstStreamBlock)
	if err != nil {
		return nil, err
	}
	block, err := m.storedBlock(address, start, 0)
	if err != nil {
		return nil, err
	}
	first, err := source.ReadVecAt(m.source, uint64(block)*blockSize, blockSize)
	if err != nil {
		return nil, err
	}
	header, err := ParseClusterHeader(first, m.blockSize, m.logClusterSize, m.algorithm, start)
	if err != nil {
		return nil, err
	}
	storedBlocks := header.StoredBlocks(m.blockSize)
	clusterBlocks := uint64(1) << m.logClusterSize
	if storedBlocks > clusterBlocks-1 {
		return nil, invalidf("the compressed cluster at block %d needs %d stored blocks, more than the %d its cluster holds after the marker",
			start, storedBlocks, clusterBlocks-1)
	}
	return &clusterPlan{start: start, header: header, storedBlocks: storedBlocks}, nil
}

func (m *FileMap) storedBlock(address uint32, start uint64, streamBlock uint64) (uint32, error) {
	switch address {
	case NullAddr:
		return 0, invalidf("the compressed cluster at block %d has no address for its stored block %d", start, streamBlock)
	case NewAddr:
		return 0, unsupportedf("the compressed cluster at block %d, whose stored block %d is still in a current segment", start, streamBlock)
	case CompressAddr:
		return 0, invalidf("the compressed cluster at block %d carries a second cluster marker where stored block %d belongs", start, streamBlock)
	}
	if !m.nat.InMain(address) {
		return 0, invalidf("the compressed cluster at block %d names stored block %d, outside the main area", start, address)
	}
	return address, nil
}

func (m *FileMap) decodedCluster(start uint64) ([]byte, error) {
	m.decodedMu.Lock()
	if m.decodedOK && m.decodedStart == start {
		data := m.decodedData
		m.decodedMu.Unlock()
		return data, nil
	}
	m.decodedMu.Unlock()

	plan, err := m.clusterPlan(start)
	if err != nil {
		return nil, err
	}
	blockSize := uint64(m.blockSize)
	total := uint64(CompressHeaderSize) + uint64(plan.header.Clen)
	stored := make([]byte, total)
	var done uint64
	for done < total {
		streamBlock := done / blockSize
		within := done % blockSize
		take := total - done
		if remaining := blockSize - within; take > remaining {
			take = remaining
		}
		address, err := m.rawAddress(start + 1 + streamBlock)
		if err != nil {
			return nil, err
		}
		block, err := m.storedBlock(address, start, streamBlock)
		if err != nil {
			return nil, err
		}
		if err := source.ReadExactAt(m.source, uint64(block)*blockSize+within, stored[done:done+take]); err != nil {
			return nil, err
		}
		done += take
	}
	if plan.storedBlocks != (done+blockSize-1)/blockSize {
		return nil, invalidf("the compressed cluster at block %d planned %d stored blocks but occupies %d",
			start, plan.storedBlocks, (done+blockSize-1)/blockSize)
	}
	decoded, err := DecodeCluster(plan.header, stored[CompressHeaderSize:])
	if err != nil {
		m.recordFailure(err)
		return nil, err
	}
	m.decodedMu.Lock()
	m.decodedStart = start
	m.decodedOK = true
	m.decodedData = decoded
	m.decodedMu.Unlock()
	m.reportMu.Lock()
	m.report.Decoded++
	m.reportMu.Unlock()
	return decoded, nil
}

func (m *FileMap) recordFailure(err error) {
	m.reportMu.Lock()
	defer m.reportMu.Unlock()
	if isUnsupported(err) {
		m.report.Refused++
	} else {
		m.report.Corrupt++
	}
	if len(m.report.Notes) < maxCompressionNotes {
		m.report.Notes = append(m.report.Notes, err.Error())
	}
}

func (m *FileMap) storedRanges(plan *clusterPlan) ([][2]uint64, error) {
	blockSize := uint64(m.blockSize)
	total := uint64(CompressHeaderSize) + uint64(plan.header.Clen)
	ranges := make([][2]uint64, 0, plan.storedBlocks)
	var done uint64
	for streamBlock := uint64(0); streamBlock < plan.storedBlocks; streamBlock++ {
		address, err := m.rawAddress(plan.start + 1 + streamBlock)
		if err != nil {
			return nil, err
		}
		block, err := m.storedBlock(address, plan.start, streamBlock)
		if err != nil {
			return nil, err
		}
		take := total - done
		if take > blockSize {
			take = blockSize
		}
		at := uint64(block) * blockSize
		if len(ranges) > 0 {
			last := &ranges[len(ranges)-1]
			if last[0]+last[1] == at {
				last[1] += take
				done += take
				continue
			}
		}
		ranges = append(ranges, [2]uint64{at, take})
		done += take
	}
	return ranges, nil
}

// ReadAt reads up to len(buf) bytes starting at file offset offset.  The return
// is the number of bytes available from offset, which is short only at EOF.
func (m *FileMap) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= m.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), m.length)
	}
	want := len(buf)
	if remaining := m.length - offset; uint64(want) > remaining {
		want = int(remaining)
	}
	if m.IsCompressed() && uint64(want) > MaxDecompressed {
		return 0, invalidf("a %d-byte read of a compressed file exceeds the %d-byte decompression budget; read it in smaller pieces",
			want, MaxDecompressed)
	}
	out := buf[:want]
	clear(out)
	if m.inline != nil {
		start := int(offset)
		stop := start + want
		if stop > len(m.inline) {
			stop = len(m.inline)
		}
		if start < stop {
			copy(out[:stop-start], m.inline[start:stop])
		}
		return want, nil
	}
	blockSize := uint64(m.blockSize)
	done := 0
	for done < want {
		position := offset + uint64(done)
		index := position / blockSize
		start, compressed, err := m.compressedClusterStart(index)
		if err != nil {
			return done, err
		}
		if compressed {
			decoded, err := m.decodedCluster(start)
			if err != nil {
				return done, err
			}
			into := int(position - start*blockSize)
			if into >= len(decoded) {
				return done, invalidf("the compressed cluster at block %d decoded to %d bytes, fewer than the file block read from it",
					start, len(decoded))
			}
			take := want - done
			if remaining := len(decoded) - into; take > remaining {
				take = remaining
			}
			copy(out[done:done+take], decoded[into:into+take])
			done += take
			continue
		}
		within := int(position % blockSize)
		take := want - done
		if remaining := int(m.blockSize) - within; take > remaining {
			take = remaining
		}
		block, present, err := m.DataBlock(index)
		if err != nil {
			return done, err
		}
		if present {
			if err := source.ReadExactAt(m.source, uint64(block)*blockSize+uint64(within), out[done:done+take]); err != nil {
				return done, err
			}
		}
		done += take
	}
	return want, nil
}

// ExtentsInto translates a file range into ranges of the volume that holds it.
func (m *FileMap) ExtentsInto(parent source.ID, offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > m.length || length > m.length-offset {
		return out, source.NewOutOfRange(offset, length, m.length)
	}
	if length == 0 {
		return out, nil
	}
	if m.inline != nil {
		return append(out, source.ParentRange{
			Parent:       parent,
			ParentOffset: m.inlineAt + offset,
			Len:          length,
			Kind:         source.RangeData,
		}), nil
	}
	blockSize := uint64(m.blockSize)
	end := offset + length
	cursor := offset
	for cursor < end {
		index := cursor / blockSize
		start, compressed, err := m.compressedClusterStart(index)
		if err != nil {
			return out, err
		}
		if compressed {
			plan, err := m.clusterPlan(start)
			if err != nil {
				return out, err
			}
			ranges, err := m.storedRanges(plan)
			if err != nil {
				return out, err
			}
			for _, run := range ranges {
				out = append(out, source.ParentRange{
					Parent:       parent,
					ParentOffset: run[0],
					Len:          run[1],
					Kind:         source.RangeData,
				})
			}
			blocks := uint64(1) << m.logClusterSize
			cursor = end
			if next := (start + blocks) * blockSize; next < cursor {
				cursor = next
			}
			continue
		}
		within := cursor % blockSize
		take := end - cursor
		if remaining := blockSize - within; take > remaining {
			take = remaining
		}
		block, present, err := m.DataBlock(index)
		if err != nil {
			return out, err
		}
		if present {
			at := uint64(block)*blockSize + within
			merged := false
			if len(out) > 0 {
				last := &out[len(out)-1]
				if last.Kind == source.RangeData && last.Parent == parent && last.ParentOffset+last.Len == at {
					last.Len += take
					merged = true
				}
			}
			if !merged {
				out = append(out, source.ParentRange{
					Parent:       parent,
					ParentOffset: at,
					Len:          take,
					Kind:         source.RangeData,
				})
			}
		} else {
			merged := false
			if len(out) > 0 {
				last := &out[len(out)-1]
				if last.Kind == source.RangeHole {
					last.Len += take
					merged = true
				}
			}
			if !merged {
				out = append(out, source.ParentRange{
					Parent:       parent,
					ParentOffset: 0,
					Len:          take,
					Kind:         source.RangeHole,
				})
			}
		}
		cursor += take
	}
	return out, nil
}

func (m *FileMap) nodeAddresses(nid uint32) ([]uint32, error) {
	m.nodeMu.Lock()
	if m.nodeValid && m.nodeNID == nid {
		entries := m.nodeData
		m.nodeMu.Unlock()
		return entries, nil
	}
	m.nodeMu.Unlock()

	block, err := m.nat.NodeBlock(m.source, nid)
	if err != nil {
		return nil, err
	}
	bytes, err := source.ReadVecAt(m.source, uint64(block)*uint64(m.blockSize), uint64(m.blockSize))
	if err != nil {
		return nil, err
	}
	footer, err := ParseNodeFooter(bytes, int(m.blockSize))
	if err != nil {
		return nil, err
	}
	if footer.NID != nid {
		return nil, invalidf("the node block read for id %d carries id %d", nid, footer.NID)
	}
	entries := make([]uint32, m.entriesPerNode)
	for index := range entries {
		entries[index], err = u32At(bytes, index*4)
		if err != nil {
			return nil, err
		}
	}
	m.nodeMu.Lock()
	m.nodeNID = nid
	m.nodeValid = true
	m.nodeData = entries
	m.nodeMu.Unlock()
	return entries, nil
}

func (m *FileMap) resolve(address uint32) (uint32, bool, error) {
	switch address {
	case NullAddr:
		return 0, false, nil
	case NewAddr:
		return 0, false, unsupportedf("a data block still in a current segment, which the checkpoint has not committed")
	case CompressAddr:
		return 0, false, unsupportedf("a compressed cluster marker on an inode with no compression cluster size")
	}
	if !m.nat.InMain(address) {
		return 0, false, invalidf("a data block at %d, outside the main area", address)
	}
	return address, true, nil
}

// F2fsFileSource is a file inside an F2FS volume, readable as a byte source.
type F2fsFileSource struct {
	id       source.ID
	mapData  *FileMap
	ino      uint32
	counters source.Counters
}

// NewFileSource wraps a file map as a byte source.
func NewFileSource(id source.ID, mapData *FileMap, ino uint32) *F2fsFileSource {
	return &F2fsFileSource{id: id, mapData: mapData, ino: ino}
}

// Map returns the file's block map.
func (f *F2fsFileSource) Map() *FileMap { return f.mapData }

// Ino returns the file's inode number.
func (f *F2fsFileSource) Ino() uint32 { return f.ino }

// CompressionReport returns a snapshot of the compressed clusters this file
// touched.
func (f *F2fsFileSource) CompressionReport() CompressionReport {
	return f.mapData.CompressionReport()
}

// SourceID implements source.ByteSource.
func (f *F2fsFileSource) SourceID() source.ID { return f.id }

// Len implements source.ByteSource.
func (f *F2fsFileSource) Len() uint64 { return f.mapData.Len() }

// ImageID implements source.ByteSource.
func (f *F2fsFileSource) ImageID() source.ImageID { return f.mapData.source.ImageID() }

// SectorSize implements source.ByteSource.
func (f *F2fsFileSource) SectorSize() uint32 { return f.mapData.BlockSize() }

// ReadAt implements source.ByteSource with strict semantics.
func (f *F2fsFileSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		f.counters.AddRead(0)
		return 0, nil
	}
	got, err := f.mapData.ReadAt(offset, buf)
	if err != nil {
		return got, mapSourceError(err)
	}
	f.counters.AddRead(got)
	return got, nil
}

// ReadAtLossy implements source.ByteSource's best-effort mode.
func (f *F2fsFileSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.mapData.Len() {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.mapData.Len())
	}
	want := len(buf)
	if remaining := f.mapData.Len() - offset; uint64(want) > remaining {
		want = int(remaining)
	}
	got, err := f.ReadAt(offset, buf[:want])
	if err != nil {
		clear(buf[:want])
		f.counters.AddCorrupt(uint64(want))
		return want, nil
	}
	return got, nil
}

// ExtentsInto implements source.ByteSource.
func (f *F2fsFileSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	return f.mapData.ExtentsInto(f.mapData.source.SourceID(), offset, length, out)
}

// Extents implements source.ByteSource.
func (f *F2fsFileSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return f.ExtentsInto(offset, length, nil)
}

// MapToImage implements source.ByteSource.
func (f *F2fsFileSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	ranges, err := f.Extents(offset, length)
	if err != nil {
		return nil, err
	}
	out := make([]source.ImageRange, 0, len(ranges))
	for _, r := range ranges {
		if r.Kind == source.RangeData {
			imageRanges, err := f.mapData.source.MapToImage(r.ParentOffset, r.Len)
			if err != nil {
				return nil, err
			}
			out = append(out, imageRanges...)
		} else {
			out = append(out, source.ImageRange{
				ImageID:     f.mapData.source.ImageID(),
				ImageOffset: 0,
				Len:         r.Len,
				Kind:        r.Kind,
			})
		}
	}
	return out, nil
}

// Stats implements source.ByteSource.
func (f *F2fsFileSource) Stats() source.Stats { return f.counters.Snapshot() }

// IsEmpty implements source.ByteSource.
func (f *F2fsFileSource) IsEmpty() bool { return f.mapData.IsEmpty() }

func mapSourceError(err error) error {
	if err == nil {
		return nil
	}
	var sourceErr *source.Error
	if ok := asSourceError(err, &sourceErr); ok {
		return err
	}
	if isUnsupported(err) {
		return &source.Error{Kind: source.ErrUnsupported, Reason: err.Error(), Err: err}
	}
	if isInvalid(err) {
		return &source.Error{Kind: source.ErrCorrupt, Reason: err.Error(), Err: err}
	}
	return err
}

func asSourceError(err error, target **source.Error) bool {
	for err != nil {
		if typed, ok := err.(*source.Error); ok {
			*target = typed
			return true
		}
		type unwrapper interface{ Unwrap() error }
		next, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = next.Unwrap()
	}
	return false
}

func isUnsupported(err error) bool {
	for err != nil {
		if err == ErrUnsupported {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		next, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = next.Unwrap()
	}
	return false
}

func isInvalid(err error) bool {
	for err != nil {
		if err == ErrInvalid {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		next, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = next.Unwrap()
	}
	return false
}

var _ source.ByteSource = (*F2fsFileSource)(nil)

// String renders a file source for debugging.
func (f *F2fsFileSource) String() string {
	return fmt.Sprintf("f2fs file ino=%d len=%d inline=%v compressed=%v",
		f.ino, f.mapData.Len(), f.mapData.IsInline(), f.mapData.IsCompressed())
}
