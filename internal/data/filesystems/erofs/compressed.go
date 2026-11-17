package erofs

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"io"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Compressed inodes: the pcluster index and the extents it names.
//
// A compressed inode stores its own 8-byte map header, then an index that
// walks the file in logical clusters of 1<<lclusterbits bytes. Every index
// entry is one lcluster and names one of four things:
//
//	PLAIN    (0)  the lclusters are stored uncompressed from this pcluster
//	HEAD1    (1)  a compressed pcluster using algorithm format 1
//	NONHEAD  (2)  a continuation lcluster, not the start of a pcluster
//	HEAD2    (3)  a compressed pcluster using algorithm format 2
//
// A pcluster is the compression unit. Its first lcluster is a HEAD and every
// lcluster it covers after that is a NONHEAD whose delta[0] says how far back
// the HEAD lies; delta[1] says how far forward the next HEAD lies, which
// bounds the decompressed length without reading the whole index.
//
// The full form is one 8-byte record per lcluster, eight bytes after the map
// header. The compact form packs records into words whose last four bytes hold
// the first physical block of the pack; it may switch to two-byte records in
// the middle of the file (ADVISE_COMPACTED_2B).
//
// Refused by name: a whole file packed into the shared inode, a pcluster
// stored inline in the inode block, a tail shared through the packed inode,
// the newer extent table, and the interlaced PLAIN layout. LZ4, MicroLZMA and
// Zstandard pclusters are refused at decode time, naming the algorithm;
// uncompressed and DEFLATE files remain readable.

const (
	mapHeaderBytes  uint64 = 8
	fullRecordBytes uint64 = 8

	adviseExtents           uint16 = 0x0001
	adviseCompacted2B       uint16 = 0x0001
	adviseBigPcluster1      uint16 = 0x0002
	adviseBigPcluster2      uint16 = 0x0004
	adviseInlinePcluster    uint16 = 0x0008
	adviseInterlacedCluster uint16 = 0x0010
	adviseFragmentPcluster  uint16 = 0x0020

	liHole        uint16 = 1 << 14
	liD0CblkCount uint16 = 1 << 11

	typePlain   uint8 = 0
	typeHead1   uint8 = 1
	typeNonhead uint8 = 2
	typeHead2   uint8 = 3

	compressionLZ4     uint8 = 0
	compressionLZMA    uint8 = 1
	compressionDeflate uint8 = 2
	compressionZstd    uint8 = 3

	maxPclusterBytes uint64 = 12 * 1024 * 1024
	maxStoredBytes   uint64 = 2 * 1024 * 1024
	maxExtents              = 1_000_000
)

type algorithm uint8

const (
	algShifted algorithm = iota
	algLZ4
	algLZMA
	algDeflate
	algZstd
)

func (a algorithm) label() string {
	switch a {
	case algShifted:
		return "shifted"
	case algLZ4:
		return "LZ4"
	case algLZMA:
		return "LZMA"
	case algDeflate:
		return "DEFLATE"
	default:
		return "Zstandard"
	}
}

func algorithmFromID(id uint8) (algorithm, bool) {
	switch id {
	case compressionLZ4:
		return algLZ4, true
	case compressionLZMA:
		return algLZMA, true
	case compressionDeflate:
		return algDeflate, true
	case compressionZstd:
		return algZstd, true
	default:
		return algShifted, false
	}
}

func (a algorithm) availabilityBit() uint16 {
	switch a {
	case algLZ4:
		return 1 << compressionLZ4
	case algLZMA:
		return 1 << compressionLZMA
	case algDeflate:
		return 1 << compressionDeflate
	case algZstd:
		return 1 << compressionZstd
	default:
		return 0
	}
}

type compressionHeader struct {
	advise       uint16
	algorithm    [2]algorithm
	lclusterbits uint8
}

func (h compressionHeader) lclusterSize() uint64 { return uint64(1) << h.lclusterbits }
func (h compressionHeader) hasAdvise(bit uint16) bool {
	return h.advise&bit != 0
}

type extent struct {
	logical   uint64
	length    uint64
	pblk      uint32
	stored    uint64
	algorithm algorithm
	hole      bool
}

// readHeader reads and validates an inode's eight-byte map header.
func readHeader(src source.ByteSource, sb *superblock, in inode, inodeOffset uint64) (compressionHeader, error) {
	limit := sb.limit()
	end, ok := checkedAdd(inodeOffset, in.headerBytes())
	if !ok {
		return compressionHeader{}, corruptf("a compressed inode's header runs past the address space")
	}
	at, ok := checkedAdd(end, 7)
	if !ok {
		return compressionHeader{}, corruptf("a compressed inode's header overflows the address space")
	}
	at &^= 7
	if at > limit || limit-at < mapHeaderBytes {
		return compressionHeader{}, corruptf(
			"a compressed inode's map header at %d runs past the image's %d bytes", at, limit)
	}
	var raw [mapHeaderBytes]byte
	if err := source.ReadExactAt(src, at, raw[:]); err != nil {
		return compressionHeader{}, err
	}

	clusterBits := raw[7]
	if clusterBits&0x80 != 0 {
		return compressionHeader{}, unsupportedf(
			"a file stored whole in the packed inode (bit 7 of h_clusterbits)")
	}
	if clusterBits&0x70 != 0 {
		return compressionHeader{}, unsupportedf("reserved bits %#04x in h_clusterbits",
			clusterBits&0x70)
	}
	lclusterbits := sb.blockBits + (clusterBits & 0x0f)
	if lclusterbits < sb.blockBits || lclusterbits > 15 {
		return compressionHeader{}, unsupportedf(
			"logical clusters of %d bits, outside the reader's %d..=15",
			lclusterbits, sb.blockBits)
	}

	advise := binary.LittleEndian.Uint16(raw[4:])
	if advise&adviseFragmentPcluster != 0 {
		return compressionHeader{}, unsupportedf(
			"a fragment pcluster (a file tail shared through the packed inode)")
	}
	if advise&adviseInlinePcluster != 0 {
		return compressionHeader{}, unsupportedf(
			"an inline pcluster (a file tail stored inside the inode block)")
	}
	if in.layout == layoutCompressedFull && advise&adviseExtents != 0 {
		return compressionHeader{}, unsupportedf("the extent-table index (ADVISE_EXTENTS)")
	}

	algorithmByte := raw[6]
	var formats [2]algorithm
	for slot, id := range [2]uint8{algorithmByte & 0x0f, algorithmByte >> 4} {
		format, ok := algorithmFromID(id)
		if !ok {
			return compressionHeader{}, unsupportedf(
				"compression algorithm id %d in h_algorithmtype", id)
		}
		formats[slot] = format
	}
	available := sb.availableComprAlgs
	for _, format := range formats {
		if available != 0 && available&format.availabilityBit() == 0 {
			return compressionHeader{}, unsupportedf(
				"the %s algorithm, which the image's available set %#06x does not name",
				format.label(), available)
		}
	}

	return compressionHeader{advise: advise, algorithm: formats, lclusterbits: lclusterbits}, nil
}

// extents walks the index and returns the file's pclusters in logical order.
func extents(src source.ByteSource, sb *superblock, in inode, inodeOffset uint64,
	header compressionHeader) ([]extent, error) {
	size := in.size
	if size == 0 {
		return nil, nil
	}
	lclusterSize := header.lclusterSize()
	totalidx := size / lclusterSize
	if size%lclusterSize != 0 {
		totalidx++
	}
	loader, err := newIndexLoader(src, sb, in, inodeOffset, header, totalidx)
	if err != nil {
		return nil, err
	}

	var out []extent
	var lcn, logical uint64
	for lcn < totalidx {
		if len(out) >= maxExtents {
			return nil, unsupportedf("more than %d pclusters", maxExtents)
		}
		head, err := loader.load(lcn, false)
		if err != nil {
			return nil, err
		}
		if head.kind == typeNonhead {
			return nil, corruptf(
				"logical cluster %d is a continuation, not the head of a pcluster", lcn)
		}
		scaled, ok := checkedMul(lcn, lclusterSize)
		if !ok {
			return nil, corruptf("a logical cluster offset overflows the address space")
		}
		start, ok := checkedAdd(scaled, uint64(head.clusterofs))
		if !ok {
			return nil, corruptf("a logical cluster offset overflows the address space")
		}
		if start != logical {
			return nil, corruptf(
				"the pcluster at logical byte %d does not continue the previous one, which ends at %d",
				start, logical)
		}

		next, ok := checkedAdd(lcn, 1)
		if !ok {
			return nil, corruptf("a logical cluster overflows the address space")
		}
		var end uint64
		for {
			scaledNext, ok := checkedMul(next, lclusterSize)
			if !ok {
				return nil, corruptf("a logical cluster offset overflows the address space")
			}
			if scaledNext >= size {
				end = size
				break
			}
			record, err := loader.load(next, true)
			if err != nil {
				return nil, err
			}
			if record.kind != typeNonhead {
				end, ok = checkedAdd(scaledNext, uint64(record.clusterofs))
				if !ok {
					return nil, corruptf("a pcluster end overflows the address space")
				}
				break
			}
			delta := record.delta1
			if delta < 1 {
				// A zero distance was written by a pre-1.0 mkfs; one lcluster
				// is the only reading that makes progress.
				delta = 1
			}
			next, ok = checkedAdd(next, uint64(delta))
			if !ok {
				return nil, corruptf("a lookahead distance overflows the file")
			}
		}
		if end <= start {
			return nil, corruptf("the pcluster at logical byte %d ends at %d, not after its start",
				start, end)
		}
		length := end - start
		if length > maxPclusterBytes {
			return nil, unsupportedf(
				"a pcluster covering %d bytes, more than the reader's %d-byte bound",
				length, maxPclusterBytes)
		}

		var format algorithm
		if head.hole {
			format = algShifted
		} else {
			switch head.kind {
			case typePlain:
				if header.hasAdvise(adviseInterlacedCluster) {
					return nil, unsupportedf(
						"an interlaced PLAIN pcluster (ADVISE_INTERLACED_PCLUSTER)")
				}
				format = algShifted
			case typeHead1:
				format = header.algorithm[0]
			case typeHead2:
				format = header.algorithm[1]
			default:
				return nil, corruptf("pcluster head type %d at logical byte %d", head.kind, start)
			}
		}

		var stored uint64
		if !head.hole {
			blocks, err := loader.storedBlocks(lcn, head.kind,
				head.hasCompressed, head.compressedblks)
			if err != nil {
				return nil, err
			}
			var ok bool
			stored, ok = checkedMul(uint64(blocks), loader.blockSize)
			if !ok {
				return nil, corruptf("a pcluster's stored size overflows the address space")
			}
			if stored > maxStoredBytes {
				return nil, unsupportedf(
					"a pcluster storing %d bytes, more than the reader's %d-byte bound",
					stored, maxStoredBytes)
			}
			at, ok := checkedMul(uint64(head.pblk), loader.blockSize)
			if !ok {
				return nil, corruptf("a pcluster's address overflows the address space")
			}
			if at > loader.limit || stored > loader.limit-at {
				return nil, corruptf(
					"the pcluster at logical byte %d stores %d bytes at byte %d, past the image's %d bytes",
					start, stored, at, loader.limit)
			}
			if format == algShifted && stored < length {
				return nil, corruptf(
					"an uncompressed pcluster stores %d bytes but covers %d", stored, length)
			}
		}

		out = append(out, extent{
			logical:   start,
			length:    length,
			pblk:      head.pblk,
			stored:    stored,
			algorithm: format,
			hole:      head.hole,
		})
		logical = end
		lcn = next
	}
	return out, nil
}

// decodeExtent turns one pcluster into its logical bytes.
func decodeExtent(src source.ByteSource, e extent, blockSize, lclusterSize uint64) ([]byte, error) {
	if e.length > uint64(maxInt()) {
		return nil, unsupportedf("a pcluster longer than the address space")
	}
	outLen := int(e.length)
	if e.hole {
		return make([]byte, outLen), nil
	}

	at, ok := checkedMul(uint64(e.pblk), blockSize)
	if !ok {
		return nil, corruptf("a pcluster address overflows the address space")
	}
	if e.algorithm == algShifted {
		out := make([]byte, outLen)
		if err := source.ReadExactAt(src, at, out); err != nil {
			return nil, err
		}
		return out, nil
	}

	if e.stored > uint64(maxInt()) {
		return nil, unsupportedf("a stored pcluster longer than the address space")
	}
	raw := make([]byte, int(e.stored))
	if err := source.ReadExactAt(src, at, raw); err != nil {
		return nil, err
	}
	clusters := e.length / lclusterSize
	if e.length%lclusterSize != 0 {
		clusters++
	}
	padded, ok := checkedMul(clusters, lclusterSize)
	if !ok || padded > maxPclusterBytes {
		padded = maxPclusterBytes
	}
	bound := padded
	if bound < e.length {
		bound = e.length
	}
	limit := int(bound)

	var decoded []byte
	var err error
	switch e.algorithm {
	case algDeflate:
		decoded, err = decodeDeflate(raw, limit)
	case algLZ4, algLZMA, algZstd:
		return nil, unsupportedf(
			"the %s compression algorithm: this build has no pure-Go decoder for it",
			e.algorithm.label())
	default:
		return nil, corruptf("pcluster algorithm %d is not a compressed stream", e.algorithm)
	}
	if err != nil {
		return nil, err
	}
	if len(decoded) < outLen {
		return nil, corruptf("a %s pcluster decoded to %d bytes but covers %d",
			e.algorithm.label(), len(decoded), outLen)
	}
	return decoded[:outLen], nil
}

// decodeDeflate decodes one bare DEFLATE pcluster, refusing output past bound.
func decodeDeflate(raw []byte, bound int) ([]byte, error) {
	reader := flate.NewReader(bytes.NewReader(raw))
	defer reader.Close()
	out, err := io.ReadAll(io.LimitReader(reader, int64(bound)+1))
	if err != nil {
		return nil, corruptf("a DEFLATE pcluster did not decode: %v", err)
	}
	if len(out) > bound {
		return nil, corruptf("a DEFLATE pcluster decoded past its %d-byte bound", bound)
	}
	return out, nil
}

// -- the index ---------------------------------------------------------------

type indexRecord struct {
	kind           uint8
	clusterofs     uint16
	pblk           uint32
	delta0, delta1 uint16
	hasCompressed  bool
	compressedblks uint32
	hole           bool
}

const indexWindow = 64 * 1024

// indexIO is a windowed reader over the index region.
type indexIO struct {
	src    source.ByteSource
	limit  uint64
	window []byte
	start  uint64
	filled uint64
}

func newIndexIO(src source.ByteSource, limit uint64) *indexIO {
	return &indexIO{src: src, limit: limit}
}

func (io *indexIO) read(at uint64, out []byte) error {
	if len(out) == 0 {
		return nil
	}
	end, ok := checkedAdd(at, uint64(len(out)))
	if !ok {
		return corruptf("an index offset overflows the address space")
	}
	if end > io.limit {
		return corruptf("an index read at byte %d of %d bytes runs past the image's %d bytes",
			at, len(out), io.limit)
	}
	if at >= io.start && end <= io.start+io.filled {
		from := at - io.start
		copy(out, io.window[from:from+uint64(len(out))])
		return nil
	}
	if len(out) >= indexWindow {
		return source.ReadExactAt(io.src, at, out)
	}
	want := minU64(io.limit-at, indexWindow)
	if uint64(cap(io.window)) < want {
		io.window = make([]byte, want)
	} else {
		io.window = io.window[:want]
	}
	if err := source.ReadExactAt(io.src, at, io.window); err != nil {
		return err
	}
	io.start = at
	io.filled = want
	copy(out, io.window[:len(out)])
	return nil
}

// indexLoader reads one lcluster record at a time from either encoding.
type indexLoader struct {
	io                 *indexIO
	limit              uint64
	blockSize          uint64
	size               uint64
	lclusterbits       uint8
	lclusterSize       uint64
	totalidx           uint64
	full               bool
	advise             uint16
	indexStart         uint64
	ebase              uint64
	compacted4bInitial uint64
	compacted2b        uint64
}

func newIndexLoader(src source.ByteSource, sb *superblock, in inode, inodeOffset uint64,
	header compressionHeader, totalidx uint64) (*indexLoader, error) {
	limit := sb.limit()
	end, ok := checkedAdd(inodeOffset, in.headerBytes())
	if !ok {
		return nil, corruptf("a compressed inode's index overflows the address space")
	}
	headerAt, ok := checkedAdd(end, 7)
	if !ok {
		return nil, corruptf("a compressed inode's map header overflows the address space")
	}
	headerAt &^= 7
	ebase, ok := checkedAdd(headerAt, mapHeaderBytes)
	if !ok {
		return nil, corruptf("a compressed inode's index overflows the address space")
	}
	full := in.layout == layoutCompressedFull
	lclusterbits := header.lclusterbits
	if !full && lclusterbits > 14 {
		return nil, unsupportedf(
			"a compact index with %d-bit logical clusters (the compact form tops out at 14)",
			lclusterbits)
	}
	if full && ebase > limit || (full && limit-ebase < fullRecordBytes) {
		return nil, corruptf("the first full-index record at %d runs past the image's %d bytes",
			ebase, limit)
	}
	initial := uint64(0)
	if !full {
		initial = ((32 - ebase%32) / 4) & 7
	}
	compacted2b := uint64(0)
	if !full && header.advise&adviseCompacted2B != 0 && initial < totalidx {
		compacted2b = (totalidx - initial) / 16 * 16
	}
	if compacted2b > 0 && lclusterbits > 12 {
		return nil, unsupportedf(
			"a compacted-2b index with %d-bit logical clusters (the two-byte form tops out at 12)",
			lclusterbits)
	}
	if !full && totalidx > 0 && ebase >= limit {
		return nil, corruptf("the compact index at %d starts past the image's %d bytes",
			ebase, limit)
	}
	indexStart, ok := checkedAdd(ebase, fullRecordBytes)
	if !ok {
		return nil, corruptf("a compressed inode's index overflows the address space")
	}
	return &indexLoader{
		io:                 newIndexIO(src, limit),
		limit:              limit,
		blockSize:          sb.blockSize(),
		size:               in.size,
		lclusterbits:       lclusterbits,
		lclusterSize:       1 << lclusterbits,
		totalidx:           totalidx,
		full:               full,
		advise:             header.advise,
		indexStart:         indexStart,
		ebase:              ebase,
		compacted4bInitial: initial,
		compacted2b:        compacted2b,
	}, nil
}

func (l *indexLoader) load(lcn uint64, lookahead bool) (indexRecord, error) {
	var record indexRecord
	var err error
	if l.full {
		record, err = l.loadFull(lcn)
	} else {
		record, err = l.loadCompact(lcn, lookahead)
	}
	if err != nil {
		return indexRecord{}, err
	}
	if record.kind != typeNonhead && uint64(record.clusterofs) >= l.lclusterSize {
		return indexRecord{}, corruptf(
			"logical cluster %d starts at %d bytes, outside its %d-byte cluster",
			lcn, record.clusterofs, l.lclusterSize)
	}
	return record, nil
}

func (l *indexLoader) loadFull(lcn uint64) (indexRecord, error) {
	delta, ok := checkedMul(lcn, fullRecordBytes)
	if !ok {
		return indexRecord{}, corruptf("a full-index record offset overflows")
	}
	at, ok := checkedAdd(l.indexStart, delta)
	if !ok {
		return indexRecord{}, corruptf("a full-index record offset overflows")
	}
	var raw [fullRecordBytes]byte
	if err := l.io.read(at, raw[:]); err != nil {
		return indexRecord{}, err
	}
	advise := binary.LittleEndian.Uint16(raw[0:])
	record := indexRecord{kind: uint8(advise & 0x3)}
	if record.kind == typeNonhead {
		record.clusterofs = uint16(1) << l.lclusterbits
		delta0 := binary.LittleEndian.Uint16(raw[4:])
		if delta0&liD0CblkCount != 0 {
			if l.advise&(adviseBigPcluster1|adviseBigPcluster2) == 0 {
				return indexRecord{}, corruptf(
					"logical cluster %d counts compressed blocks without a big-pcluster feature",
					lcn)
			}
			record.hasCompressed = true
			record.compressedblks = uint32(delta0 &^ liD0CblkCount)
			delta0 = 1
		}
		record.delta0 = delta0
		record.delta1 = binary.LittleEndian.Uint16(raw[6:])
	} else {
		record.clusterofs = binary.LittleEndian.Uint16(raw[2:])
		if advise&liHole != 0 {
			record.hole = true
			record.hasCompressed = true
			record.compressedblks = 0
		} else {
			record.pblk = binary.LittleEndian.Uint32(raw[4:])
		}
	}
	return record, nil
}

func (l *indexLoader) loadCompact(lcn uint64, lookahead bool) (indexRecord, error) {
	if lcn >= l.totalidx {
		return indexRecord{}, corruptf("logical cluster %d is past the file's %d-cluster index",
			lcn, l.totalidx)
	}
	pos := l.ebase
	index := lcn
	shift := uint32(2)
	var ok bool
	if index >= l.compacted4bInitial {
		initialBytes, ok := checkedMul(l.compacted4bInitial, 4)
		if !ok {
			return indexRecord{}, corruptf("a compact index offset overflows")
		}
		pos, ok = checkedAdd(pos, initialBytes)
		if !ok {
			return indexRecord{}, corruptf("a compact index offset overflows")
		}
		index -= l.compacted4bInitial
		if index < l.compacted2b {
			shift = 1
		} else {
			twoByteBytes, ok := checkedMul(l.compacted2b, 2)
			if !ok {
				return indexRecord{}, corruptf("a compact index offset overflows")
			}
			pos, ok = checkedAdd(pos, twoByteBytes)
			if !ok {
				return indexRecord{}, corruptf("a compact index offset overflows")
			}
			index -= l.compacted2b
		}
	}
	entryBytes, ok := checkedMul(index, uint64(1)<<shift)
	if !ok {
		return indexRecord{}, corruptf("a compact index offset overflows")
	}
	pos, ok = checkedAdd(pos, entryBytes)
	if !ok {
		return indexRecord{}, corruptf("a compact index offset overflows")
	}

	packBytes, vcnt := 8, 2
	if shift == 1 {
		packBytes, vcnt = 32, 16
	}
	encodebits := uint32((packBytes - 4) * 8 / vcnt)
	lobits := uint32(l.lclusterbits)
	if lobits < 12 {
		lobits = 12
	}
	pack := pos - pos%uint64(packBytes)
	var raw [32]byte
	if err := l.io.read(pack, raw[:packBytes]); err != nil {
		return indexRecord{}, err
	}
	entry := int((pos - pack) >> shift)
	lo, kind, err := decodeBits(raw[:packBytes], encodebits, entry, lobits)
	if err != nil {
		return indexRecord{}, err
	}
	record := indexRecord{kind: kind}
	if kind == typeNonhead {
		record.clusterofs = uint16(1) << l.lclusterbits
		if lookahead {
			record.delta1, err = l.laDistance(raw[:packBytes], encodebits, vcnt, entry, lobits)
			if err != nil {
				return indexRecord{}, err
			}
		}
		if lo&uint32(liD0CblkCount) != 0 {
			if l.advise&adviseBigPcluster1 == 0 {
				return indexRecord{}, corruptf(
					"logical cluster %d counts compressed blocks without ADVISE_BIG_PCLUSTER_1",
					lcn)
			}
			record.hasCompressed = true
			record.compressedblks = lo &^ uint32(liD0CblkCount)
			record.delta0 = 1
			return record, nil
		}
		if entry+1 != vcnt {
			record.delta0 = uint16(lo)
			return record, nil
		}
		// The last record in a pack keeps the lookahead distance in its low
		// bits; the distance back to the HEAD comes from its neighbour.
		previous, previousKind, err := decodeBits(raw[:packBytes], encodebits, entry-1, lobits)
		if err != nil {
			return indexRecord{}, err
		}
		switch {
		case previousKind != typeNonhead:
			record.delta0 = 1
		case previous&uint32(liD0CblkCount) != 0:
			record.delta0 = 2
		default:
			record.delta0 = uint16(previous + 1)
		}
		return record, nil
	}

	record.clusterofs = uint16(lo)
	base := binary.LittleEndian.Uint32(raw[packBytes-4 : packBytes])
	big := l.advise&adviseBigPcluster1 != 0
	blocks, err := l.blocksBefore(raw[:packBytes], encodebits, entry, vcnt, lobits, big)
	if err != nil {
		return indexRecord{}, err
	}
	record.pblk = base + blocks
	return record, nil
}

// decodeBits decodes the low bits and type of record entry in a pack.
func decodeBits(pack []byte, encodebits uint32, entry int, lobits uint32) (uint32, uint8, error) {
	bit := int(encodebits) * entry
	byteAt := bit / 8
	if byteAt < 0 || byteAt+4 > len(pack) {
		return 0, 0, corruptf(
			"compact record %d at bit %d runs past its %d-byte pack",
			entry, bit, len(pack))
	}
	word := binary.LittleEndian.Uint32(pack[byteAt:])
	value := word >> uint(bit%8)
	lo := value & ((uint32(1) << lobits) - 1)
	kind := uint8((value >> lobits) & 3)
	return lo, kind, nil
}

// laDistance is how far the next HEAD lies, as delta[1] records it.
func (l *indexLoader) laDistance(pack []byte, encodebits uint32, vcnt, start int, lobits uint32) (uint16, error) {
	distance := uint32(0)
	entry := start
	for {
		lo, kind, err := decodeBits(pack, encodebits, entry, lobits)
		if err != nil {
			return 0, err
		}
		if kind != typeNonhead {
			return uint16(distance), nil
		}
		distance++
		entry++
		if entry >= vcnt {
			if lo&uint32(liD0CblkCount) == 0 {
				if lo == 0 {
					return 0, corruptf(
						"the last compact record names a zero lookahead distance")
				}
				distance += lo - 1
			}
			return uint16(distance), nil
		}
	}
}

// blocksBefore counts the compressed blocks before entry's pcluster in its pack.
func (l *indexLoader) blocksBefore(pack []byte, encodebits uint32, entry, vcnt int,
	lobits uint32, big bool) (uint32, error) {
	blocks := uint32(0)
	if !big {
		blocks = 1
	}
	index := entry
	for index > 0 {
		index--
		lo, kind, err := decodeBits(pack, encodebits, index, lobits)
		if err != nil {
			return 0, err
		}
		if kind == typeNonhead {
			if big {
				if lo&uint32(liD0CblkCount) != 0 {
					index--
					blocks += lo &^ uint32(liD0CblkCount)
					continue
				}
				if lo <= 1 {
					return 0, corruptf(
						"a compact continuation at entry %d names a distance %d, which no big pcluster can continue",
						index, lo)
				}
				index -= int(lo) - 2
			} else {
				index -= int(lo)
			}
		}
		if index >= 0 {
			blocks++
		}
	}
	return blocks, nil
}

// storedBlocks is the compressed blocks a HEAD's pcluster stores.
func (l *indexLoader) storedBlocks(lcn uint64, kind uint8, hasCompressed bool,
	compressedblks uint32) (uint32, error) {
	if hasCompressed {
		return compressedblks, nil
	}
	var big bool
	switch kind {
	case typeHead1:
		big = l.advise&adviseBigPcluster1 != 0
	case typePlain, typeHead2:
		big = l.advise&adviseBigPcluster2 != 0
	default:
		return 0, corruptf("logical cluster %d names a pcluster head type %d", lcn, kind)
	}
	if !big {
		return 1, nil
	}
	nextBlock, ok := checkedAdd(lcn, 1)
	if !ok {
		return 0, corruptf("a logical cluster overflows")
	}
	scaled, ok := checkedMul(nextBlock, l.lclusterSize)
	if !ok {
		return 0, corruptf("a logical cluster offset overflows")
	}
	if scaled >= l.size {
		return 1, nil
	}
	next, err := l.load(nextBlock, false)
	if err != nil {
		return 0, err
	}
	if next.kind != typeNonhead {
		return 1, nil
	}
	if next.hasCompressed && next.delta0 == 1 {
		return next.compressedblks, nil
	}
	return 0, corruptf(
		"the first continuation at logical cluster %d does not count the pcluster's compressed blocks",
		nextBlock)
}

func maxInt() int { return int(^uint(0) >> 1) }
