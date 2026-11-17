// Package dmg reads Apple Disk Images (UDIF) as a read-only ByteSource.
//
// A `.dmg` is not a disk: its last 512 bytes are a `koly` trailer naming a
// property list, whose `resource-fork` dictionary lists one `blkx` table per
// partition (or free region). Each table's runs say, for a range of 512-byte
// sectors, whether the guest's bytes are stored raw, compressed, or were never
// stored at all. This reader merges every table into one flat virtual disk and
// exposes it through source.ByteSource, so a macOS disk image is inventoried
// like a physical disk.
//
// Supported encodings:
//
//   - raw and unstored (zero) runs;
//   - zlib, bzip2, LZMA and Apple Data Compression (ADC) runs;
//   - both property-list dialects hdiutil writes: Apple XML and `bplist00`.
//
// Trailer version 2 (the AES-encrypted layout) is refused
// with source.ErrDecrypt; other versions, segmented images and oversized
// properties are refused by name. The trailer's checksum fields are reported
// but not verified: the data checksum covers the compressed fork, and a
// mismatch says nothing about the sector mapping. A run that would collide
// with another, a compressed stream that does not produce exactly the declared
// sector count, and a stored range outside the file are corruption.
package dmg

import (
	"bytes"
	"compress/bzip2"
	"compress/zlib"
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/laenix/ewfgo/internal/data/compression/lzfse"
	"github.com/laenix/ewfgo/internal/data/containers/lzma"
	"github.com/laenix/ewfgo/internal/data/source"
)

// TrailerSignature is the magic at the start of the last 512 bytes.
const TrailerSignature = "koly"

// BlkxSignature is the magic at the start of a blkx blob.
const BlkxSignature = "mish"

const (
	// TrailerBytes is the size of the UDIF trailer.
	TrailerBytes = 512
	// SectorSize is the UDIF guest sector size.
	SectorSize = 512
	// BlkxHeaderBytes is the fixed part of a mish table.
	BlkxHeaderBytes = 204
	// RunBytes is the size of one run descriptor.
	RunBytes = 40
)

// Run types. The top bit marks compressed runs; zero and sparse are the
// unstored types.
const (
	RunZero       uint32 = 0x00000000
	RunRaw        uint32 = 0x00000001
	RunSparse     uint32 = 0x00000002
	RunComment    uint32 = 0x7ffffffe
	RunAdc        uint32 = 0x80000004
	RunZlib       uint32 = 0x80000005
	RunBzip2      uint32 = 0x80000006
	RunLzfse      uint32 = 0x80000007
	RunLzma       uint32 = 0x80000008
	RunTerminator uint32 = 0xffffffff
)

const (
	// MaxXMLBytes bounds the resource-fork property list.
	MaxXMLBytes uint64 = 32 * 1024 * 1024
	// MaxBlkxBytes bounds one decoded blkx table.
	MaxBlkxBytes = 8 * 1024 * 1024
	// MaxTables bounds the tables one image may declare.
	MaxTables = 64
	// cacheBytes is the total decompressed run cache.
	cacheBytes = 32 * 1024 * 1024
	// MaxCachedRunBytes is the largest run kept in the cache.
	MaxCachedRunBytes uint64 = 16 * 1024 * 1024
	// MaxWholeRunBytes is the largest stored or decoded whole-stream run.
	MaxWholeRunBytes uint64 = 256 * 1024 * 1024
)

// Table is one blkx table as reported.
type Table struct {
	// Name is the table's Name, or CFName as a fallback.
	Name *string
	// FirstSector is the first sector the table claims.
	FirstSector uint64
	// SectorCount is the sectors the table claims.
	SectorCount uint64
	// Runs is the runs the table declares, excluding comments and the
	// terminator.
	Runs int
}

// Info is the trailer's fields and the merged block tables.
type Info struct {
	Version            uint32
	Flags              uint32
	ImageVariant       uint32
	DataForkOffset     uint64
	DataForkLength     uint64
	RsrcForkOffset     uint64
	RsrcForkLength     uint64
	SegmentNumber      uint32
	SegmentCount       uint32
	SectorCount        uint64
	XMLOffset          uint64
	XMLLength          uint64
	DataChecksumType   uint32
	MasterChecksumType uint32
	Tables             []Table
	RawRuns            int
	ZeroRuns           int
	ZlibRuns           int
	Bzip2Runs          int
	LzfseRuns          int
	LzmaRuns           int
	AdcRuns            int
	RawBytes           uint64
	CompressedBytes    uint64
}

// VirtualDiskSize is the guest disk size in bytes.
func (i Info) VirtualDiskSize() uint64 { return i.SectorCount * SectorSize }

// IsCompressed reports whether any run is compressed.
func (i Info) IsCompressed() bool {
	return i.ZlibRuns+i.Bzip2Runs+i.LzfseRuns+i.LzmaRuns+i.AdcRuns > 0
}

// IsRaw reports whether no run is compressed.
func (i Info) IsRaw() bool { return !i.IsCompressed() }

// StorageLabel describes the run types for a report.
func (i Info) StorageLabel() string {
	var parts []string
	if i.RawRuns > 0 {
		parts = append(parts, fmt.Sprintf("%d raw", i.RawRuns))
	}
	for _, entry := range []struct {
		label string
		count int
	}{
		{"zlib", i.ZlibRuns},
		{"bzip2", i.Bzip2Runs},
		{"LZFSE", i.LzfseRuns},
		{"LZMA", i.LzmaRuns},
		{"ADC", i.AdcRuns},
	} {
		if entry.count > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", entry.count, entry.label))
		}
	}
	if i.ZeroRuns > 0 {
		parts = append(parts, fmt.Sprintf("%d unstored", i.ZeroRuns))
	}
	if len(parts) == 0 {
		return "no runs"
	}
	out := ""
	for index, part := range parts {
		if index > 0 {
			out += ", "
		}
		out += part
	}
	return out
}

type runKind uint8

const (
	runZero runKind = iota
	runRaw
	runZlib
	runBzip2
	runLzfse
	runLzma
	runAdc
)

func (k runKind) label() string {
	switch k {
	case runZero:
		return "unstored"
	case runRaw:
		return "raw"
	case runZlib:
		return "zlib"
	case runBzip2:
		return "bzip2"
	case runLzfse:
		return "LZFSE"
	case runLzma:
		return "LZMA"
	case runAdc:
		return "ADC"
	default:
		return "unknown"
	}
}

type dmgRun struct {
	start      uint64
	length     uint64
	kind       runKind
	fileOffset uint64
	fileLen    uint64
}

type runCounts struct {
	raw, zero, zlib, bzip2, lzfse, lzma, adc int
	rawBytes, compressedBytes                uint64
}

type cacheEntry struct {
	index int
	data  []byte
}

// Container is a read-only view of a UDIF image's virtual disk.
type Container struct {
	id       source.ID
	parent   source.ByteSource
	length   uint64
	runs     []dmgRun
	info     Info
	mu       sync.Mutex
	cache    []cacheEntry
	cacheLen int
	counters source.Counters
}

var nextSourceID atomic.Uint64

// Detect reports whether head carries the UDIF trailer. It accepts either the
// whole file or the final 512-byte trailer slice.
func Detect(head []byte) bool {
	signature := []byte(TrailerSignature)
	if len(head) == TrailerBytes && bytes.HasPrefix(head, signature) {
		return true
	}
	if len(head) > TrailerBytes && bytes.HasPrefix(head[len(head)-TrailerBytes:], signature) {
		return true
	}
	return false
}

// Open parses the trailer and block tables and returns the virtual disk.
func Open(src source.ByteSource) (*Container, error) {
	if src == nil {
		return nil, &source.Error{Kind: source.ErrInvalidArgument, Reason: "nil source"}
	}
	parentLen := src.Len()
	if parentLen < TrailerBytes {
		return nil, unsupportedDMG("a file too short to hold a UDIF trailer")
	}
	trailerOffset := parentLen - TrailerBytes
	trailer, err := source.ReadVecAt(src, trailerOffset, TrailerBytes)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(trailer, []byte(TrailerSignature)) {
		return nil, unsupportedDMG("the koly trailer")
	}

	version := be32(trailer, 4)
	headerSize := be32(trailer, 8)
	flags := be32(trailer, 12)
	dataForkOffset := be64(trailer, 24)
	dataForkLength := be64(trailer, 32)
	rsrcForkOffset := be64(trailer, 40)
	rsrcForkLength := be64(trailer, 48)
	segmentNumber := be32(trailer, 56)
	segmentCount := be32(trailer, 60)
	dataChecksumType := be32(trailer, 80)
	xmlOffset := be64(trailer, 216)
	xmlLength := be64(trailer, 224)
	masterChecksumType := be32(trailer, 352)
	imageVariant := be32(trailer, 488)
	sectorCount := be64(trailer, 492)

	if headerSize != TrailerBytes {
		return nil, unsupportedDMG(fmt.Sprintf("a %d-byte trailer layout", headerSize))
	}
	if version == 2 {
		return nil, &source.Error{
			Kind: source.ErrDecrypt, Offset: trailerOffset + 4,
			Reason: "an AES-encrypted UDIF image (trailer version 2); decryption is not supported",
		}
	}
	if version != 4 {
		return nil, unsupportedDMG(fmt.Sprintf("trailer version %d", version))
	}
	if segmentCount > 1 {
		return nil, unsupportedDMG(fmt.Sprintf(
			"a segmented image (segment %d of %d); a segment holds only part of the disk",
			segmentNumber, segmentCount))
	}
	if sectorCount == 0 {
		return nil, corruptDMG(492, "the trailer declares no sectors")
	}
	if sectorCount > ^uint64(0)/SectorSize {
		return nil, corruptDMG(492, "the virtual disk size overflows")
	}
	length := sectorCount * SectorSize

	for _, fork := range []struct {
		name   string
		offset uint64
		length uint64
	}{
		{"data fork", dataForkOffset, dataForkLength},
		{"resource fork", rsrcForkOffset, rsrcForkLength},
		{"property list", xmlOffset, xmlLength},
	} {
		end := fork.offset + fork.length
		if end < fork.offset {
			return nil, corruptDMG(0, fmt.Sprintf("the %s offset overflows", fork.name))
		}
		if end > parentLen {
			return nil, corruptDMG(minU64DMG(fork.offset, parentLen), fmt.Sprintf(
				"the %s (%d..%d) is outside the %d byte file",
				fork.name, fork.offset, end, parentLen))
		}
	}
	if xmlLength == 0 {
		return nil, corruptDMG(224, "the trailer names no resource-fork property list")
	}
	if xmlLength > MaxXMLBytes {
		return nil, unsupportedDMG(fmt.Sprintf(
			"a %d byte resource-fork property list", xmlLength))
	}

	xmlBytes, err := source.ReadVecAt(src, xmlOffset, xmlLength)
	if err != nil {
		return nil, err
	}
	tables, err := parsePropertyList(xmlBytes)
	if err != nil {
		return nil, err
	}
	if len(tables) == 0 {
		return nil, corruptDMG(xmlOffset, "the property list carries no blkx table")
	}
	if len(tables) > MaxTables {
		return nil, unsupportedDMG(fmt.Sprintf("%d block tables in one image", len(tables)))
	}

	var (
		runs            []dmgRun
		tableInfo       []Table
		rawRuns         int
		zeroRuns        int
		zlibRuns        int
		bzip2Runs       int
		lzfseRuns       int
		lzmaRuns        int
		adcRuns         int
		rawBytes        uint64
		compressedBytes uint64
	)
	for _, table := range tables {
		end := table.firstSector + table.sectorCount
		if end < table.firstSector {
			return nil, corruptDMG(xmlOffset, "a block table's sector range overflows")
		}
		if end > sectorCount {
			return nil, corruptDMG(xmlOffset, fmt.Sprintf(
				"table %q covers sectors %d..%d, past the %d the trailer declares",
				tableLabel(table.name), table.firstSector, end, sectorCount))
		}
		tableRuns, counts, err := parseTable(table, sectorCount, parentLen)
		if err != nil {
			return nil, err
		}
		rawRuns += counts.raw
		zeroRuns += counts.zero
		zlibRuns += counts.zlib
		bzip2Runs += counts.bzip2
		lzfseRuns += counts.lzfse
		lzmaRuns += counts.lzma
		adcRuns += counts.adc
		rawBytes += counts.rawBytes
		compressedBytes += counts.compressedBytes
		tableInfo = append(tableInfo, Table{
			Name:        table.name,
			FirstSector: table.firstSector,
			SectorCount: table.sectorCount,
			Runs:        len(tableRuns),
		})
		runs = append(runs, tableRuns...)
	}

	sort.Slice(runs, func(i, j int) bool { return runs[i].start < runs[j].start })
	for index := 1; index < len(runs); index++ {
		left, right := runs[index-1], runs[index]
		if left.start+left.length > right.start {
			return nil, corruptDMG(right.start, fmt.Sprintf(
				"sector %d is claimed by two runs (one ends at sector %d)",
				right.start/SectorSize, (left.start+left.length)/SectorSize))
		}
	}

	info := Info{
		Version:            version,
		Flags:              flags,
		ImageVariant:       imageVariant,
		DataForkOffset:     dataForkOffset,
		DataForkLength:     dataForkLength,
		RsrcForkOffset:     rsrcForkOffset,
		RsrcForkLength:     rsrcForkLength,
		SegmentNumber:      segmentNumber,
		SegmentCount:       segmentCount,
		SectorCount:        sectorCount,
		XMLOffset:          xmlOffset,
		XMLLength:          xmlLength,
		DataChecksumType:   dataChecksumType,
		MasterChecksumType: masterChecksumType,
		Tables:             tableInfo,
		RawRuns:            rawRuns,
		ZeroRuns:           zeroRuns,
		ZlibRuns:           zlibRuns,
		Bzip2Runs:          bzip2Runs,
		LzfseRuns:          lzfseRuns,
		LzmaRuns:           lzmaRuns,
		AdcRuns:            adcRuns,
		RawBytes:           rawBytes,
		CompressedBytes:    compressedBytes,
	}
	return &Container{
		id:     source.ID(nextSourceID.Add(1)),
		parent: src,
		length: length,
		runs:   runs,
		info:   info,
	}, nil
}

func tableLabel(name *string) string {
	if name == nil {
		return "<unnamed>"
	}
	return *name
}

// parseTable decodes one table's runs, checking every range against the disk
// and the file.
func parseTable(table rawTable, diskSectors, parentLen uint64) ([]dmgRun, runCounts, error) {
	body := table.data
	version := be32(body, 4)
	if version != 1 {
		return nil, runCounts{}, unsupportedDMG(fmt.Sprintf("block-table version %d", version))
	}
	count64 := uint64(be32(body, 36))
	if count64 == 0 && len(body) >= BlkxHeaderBytes {
		count64 = uint64(be32(body, BlkxHeaderBytes-4))
	}
	available := (len(body) - BlkxHeaderBytes) / RunBytes
	if count64 > uint64(available) {
		return nil, runCounts{}, corruptDMG(BlkxHeaderBytes, fmt.Sprintf(
			"table %q declares %d runs but stores %d", tableLabel(table.name), count64, available))
	}
	count := int(count64)

	runs := make([]dmgRun, 0, count)
	var counts runCounts
	for index := 0; index < count; index++ {
		base := BlkxHeaderBytes + index*RunBytes
		entryType := be32(body, base)
		start := be64(body, base+8)
		sectors := be64(body, base+16)
		fileOffset := be64(body, base+24)
		fileLen := be64(body, base+32)
		if entryType == RunTerminator {
			break
		}
		if entryType == RunComment || sectors == 0 {
			continue
		}
		end := start + sectors
		if end < start {
			return nil, runCounts{}, corruptDMG(uint64(base), "a run's sector range overflows")
		}
		if end > diskSectors {
			return nil, runCounts{}, corruptDMG(uint64(base), fmt.Sprintf(
				"run %d covers sectors %d..%d, past the %d the image declares",
				index, start, end, diskSectors))
		}
		var kind runKind
		switch entryType {
		case RunZero, RunSparse:
			kind = runZero
		case RunRaw:
			kind = runRaw
		case RunZlib:
			kind = runZlib
		case RunBzip2:
			kind = runBzip2
		case RunLzfse:
			kind = runLzfse
		case RunLzma:
			kind = runLzma
		case RunAdc:
			kind = runAdc
		default:
			return nil, runCounts{}, corruptDMG(uint64(base), fmt.Sprintf(
				"run %d has unknown type 0x%08x", index, entryType))
		}
		if kind != runZero && fileLen == 0 {
			return nil, runCounts{}, corruptDMG(uint64(base), fmt.Sprintf(
				"stored run %d declares no stored bytes", index))
		}
		if kind != runZero {
			storedEnd := fileOffset + fileLen
			if storedEnd < fileOffset {
				return nil, runCounts{}, corruptDMG(uint64(base), "a run's stored range overflows")
			}
			if storedEnd > parentLen {
				return nil, runCounts{}, corruptDMG(uint64(base), fmt.Sprintf(
					"run %d stores bytes %d..%d, outside the %d byte file",
					index, fileOffset, storedEnd, parentLen))
			}
		}
		switch kind {
		case runZero:
			counts.zero++
		case runRaw:
			counts.raw++
			counts.rawBytes += fileLen
		case runZlib:
			counts.zlib++
			counts.compressedBytes += fileLen
		case runBzip2:
			counts.bzip2++
			counts.compressedBytes += fileLen
		case runLzfse:
			counts.lzfse++
			counts.compressedBytes += fileLen
		case runLzma:
			counts.lzma++
			counts.compressedBytes += fileLen
		case runAdc:
			counts.adc++
			counts.compressedBytes += fileLen
		}
		if start > ^uint64(0)/SectorSize || sectors > ^uint64(0)/SectorSize {
			return nil, runCounts{}, corruptDMG(uint64(base), "a run's byte offset overflows")
		}
		runs = append(runs, dmgRun{
			start:      start * SectorSize,
			length:     sectors * SectorSize,
			kind:       kind,
			fileOffset: fileOffset,
			fileLen:    fileLen,
		})
	}
	return runs, counts, nil
}

// Info returns the trailer's fields and the block tables.
func (c *Container) Info() Info { return c.info }

// Parent returns the underlying source.
func (c *Container) Parent() source.ByteSource { return c.parent }

// VirtualDiskSize is the guest disk size in bytes.
func (c *Container) VirtualDiskSize() uint64 { return c.length }

// TableNames returns the table names in property-list order.
func (c *Container) TableNames() []string {
	names := make([]string, 0, len(c.info.Tables))
	for _, table := range c.info.Tables {
		if table.Name != nil {
			names = append(names, *table.Name)
		}
	}
	return names
}

func (c *Container) SourceID() source.ID     { return c.id }
func (c *Container) ImageID() source.ImageID { return c.parent.ImageID() }
func (c *Container) Len() uint64             { return c.length }
func (c *Container) SectorSize() uint32      { return SectorSize }
func (c *Container) IsEmpty() bool           { return c.length == 0 }
func (c *Container) Stats() source.Stats     { return c.counters.Snapshot() }

func (c *Container) checkRange(offset, length uint64) error {
	if offset > c.length || length > c.length-offset {
		return source.NewOutOfRange(offset, length, c.length)
	}
	return nil
}

func (c *Container) coveringRun(offset uint64) (int, uint64, bool) {
	index := sort.Search(len(c.runs), func(i int) bool { return c.runs[i].start > offset })
	if index == 0 {
		return 0, 0, false
	}
	run := c.runs[index-1]
	if offset < run.start+run.length {
		return index - 1, offset - run.start, true
	}
	return 0, 0, false
}

func (c *Container) gapEnd(offset uint64) uint64 {
	index := sort.Search(len(c.runs), func(i int) bool { return c.runs[i].start > offset })
	if index < len(c.runs) {
		return minU64DMG(c.runs[index].start, c.length)
	}
	return c.length
}

// ReadAt reads guest sectors.
func (c *Container) ReadAt(offset uint64, buf []byte) (int, error) {
	return c.readInner(offset, buf)
}

// ReadAtLossy reads guest sectors, zero-filling a damaged range.
func (c *Container) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		c.counters.AddRead(0)
		return 0, nil
	}
	if offset >= c.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), c.length)
	}
	want := int(minU64DMG(c.length-offset, uint64(len(buf))))
	n, err := c.readInner(offset, buf[:want])
	if err != nil {
		clear(buf[:want])
		c.counters.AddCorrupt(uint64(want))
		return want, nil
	}
	return n, nil
}

func (c *Container) readInner(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		c.counters.AddRead(0)
		return 0, nil
	}
	if offset >= c.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), c.length)
	}
	want := int(minU64DMG(c.length-offset, uint64(len(buf))))
	done := 0
	for done < want {
		position := offset + uint64(done)
		remaining := want - done
		if index, inRun, ok := c.coveringRun(position); ok {
			run := c.runs[index]
			chunk := remaining
			if available := run.length - inRun; available < uint64(chunk) {
				chunk = int(available)
			}
			target := buf[done : done+chunk]
			switch run.kind {
			case runZero:
				clear(target)
			case runRaw:
				if _, err := readFullDMG(c.parent, run.fileOffset+inRun, target); err != nil {
					return 0, err
				}
			case runZlib:
				if run.length <= MaxCachedRunBytes {
					data, err := c.cachedRun(index, run)
					if err != nil {
						return 0, err
					}
					copy(target, data[int(inRun):int(inRun)+chunk])
				} else if err := c.inflateAt(run, inRun, target); err != nil {
					return 0, err
				}
			default:
				var data []byte
				var err error
				if run.length <= MaxCachedRunBytes {
					data, err = c.cachedRun(index, run)
				} else {
					data, err = c.decodeWhole(run)
				}
				if err != nil {
					return 0, err
				}
				copy(target, data[int(inRun):int(inRun)+chunk])
			}
			done += chunk
			continue
		}
		stop := c.gapEnd(position)
		if stop > position+uint64(remaining) {
			stop = position + uint64(remaining)
		}
		if stop <= position {
			return 0, corruptDMG(position, fmt.Sprintf(
				"sector %d is not covered by any run or gap", position/SectorSize))
		}
		chunk := int(stop - position)
		clear(buf[done : done+chunk])
		done += chunk
	}
	c.counters.AddRead(done)
	return done, nil
}

func (c *Container) cachedRun(index int, run dmgRun) ([]byte, error) {
	c.mu.Lock()
	for position := range c.cache {
		if c.cache[position].index != index {
			continue
		}
		entry := c.cache[position]
		c.cache = append(c.cache[:position], c.cache[position+1:]...)
		c.cache = append(c.cache, entry)
		c.mu.Unlock()
		c.counters.AddCacheHit()
		return entry.data, nil
	}
	c.mu.Unlock()
	c.counters.AddCacheMiss()
	data, err := c.decodeWhole(run)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	for c.cacheLen+len(data) > cacheBytes && len(c.cache) > 0 {
		evicted := c.cache[0]
		c.cache = c.cache[1:]
		c.cacheLen -= len(evicted.data)
	}
	c.cache = append(c.cache, cacheEntry{index: index, data: data})
	c.cacheLen += len(data)
	c.mu.Unlock()
	return data, nil
}

func (c *Container) readStored(run dmgRun) ([]byte, error) {
	if run.fileLen > MaxWholeRunBytes {
		return nil, unsupportedDMG(fmt.Sprintf(
			"a %s run of %d stored bytes at sector %d (the bound is %d)",
			run.kind.label(), run.fileLen, run.start/SectorSize, MaxWholeRunBytes))
	}
	stored, err := source.ReadVecAt(c.parent, run.fileOffset, run.fileLen)
	if err != nil {
		return nil, err
	}
	if uint64(len(stored)) != run.fileLen {
		return nil, corruptDMG(run.fileOffset, fmt.Sprintf(
			"the %s run at sector %d stores %d bytes, the table declares %d",
			run.kind.label(), run.start/SectorSize, len(stored), run.fileLen))
	}
	return stored, nil
}

// decodeWhole decodes one complete non-raw run into memory and insists on the
// declared sector count.
func (c *Container) decodeWhole(run dmgRun) ([]byte, error) {
	if run.kind == runZlib {
		return c.inflateRun(run)
	}
	if run.length > MaxWholeRunBytes {
		return nil, unsupportedDMG(fmt.Sprintf(
			"a %s run of %d decoded bytes at sector %d (the bound is %d)",
			run.kind.label(), run.length, run.start/SectorSize, MaxWholeRunBytes))
	}
	switch run.kind {
	case runLzfse:
		stored, err := c.readStored(run)
		if err != nil {
			return nil, err
		}
		decoded, err := lzfse.Decode(stored, lzfse.Limits{MaxOutputBytes: run.length})
		if err != nil {
			return nil, corruptDMG(run.fileOffset, fmt.Sprintf(
				"the LZFSE run at sector %d did not decode: %v", run.start/SectorSize, err))
		}
		if uint64(len(decoded)) != run.length {
			return nil, corruptDMG(run.fileOffset, fmt.Sprintf(
				"the LZFSE run at sector %d decodes to %d bytes, the table declares %d",
				run.start/SectorSize, len(decoded), run.length))
		}
		c.counters.AddDecompressed(run.length)
		return decoded, nil
	case runLzma:
		stored, err := c.readStored(run)
		if err != nil {
			return nil, err
		}
		decoded, err := lzma.Decode(stored, lzma.Limits{
			MaxDecodedBytes:    run.length,
			MaxCompressedBytes: uint64(len(stored)),
		})
		if err != nil {
			return nil, corruptDMG(run.fileOffset, fmt.Sprintf(
				"the LZMA run at sector %d did not decode: %v", run.start/SectorSize, err))
		}
		if uint64(len(decoded)) != run.length {
			return nil, corruptDMG(run.fileOffset, fmt.Sprintf(
				"the LZMA run at sector %d decodes to %d bytes, the table declares %d",
				run.start/SectorSize, len(decoded), run.length))
		}
		c.counters.AddDecompressed(run.length)
		return decoded, nil
	}
	stored, err := c.readStored(run)
	if err != nil {
		return nil, err
	}
	var decoded []byte
	switch run.kind {
	case runBzip2:
		reader := bzip2.NewReader(bytes.NewReader(stored))
		decoded, err = io.ReadAll(io.LimitReader(reader, int64(run.length)+1))
		if err != nil {
			return nil, corruptDMG(run.fileOffset, fmt.Sprintf(
				"the bzip2 run at sector %d did not decode: %v", run.start/SectorSize, err))
		}
	case runAdc:
		decoded, err = adcDecompress(stored, int(run.length))
		if err != nil {
			return nil, corruptDMG(run.fileOffset, fmt.Sprintf(
				"the ADC run at sector %d did not decode: %v", run.start/SectorSize, err))
		}
	default:
		return nil, corruptDMG(run.fileOffset, fmt.Sprintf(
			"the run at sector %d has no whole-stream decoder", run.start/SectorSize))
	}
	if uint64(len(decoded)) != run.length {
		return nil, corruptDMG(run.fileOffset, fmt.Sprintf(
			"the %s run at sector %d decodes to %d bytes, the table declares %d",
			run.kind.label(), run.start/SectorSize, len(decoded), run.length))
	}
	c.counters.AddDecompressed(run.length)
	return decoded, nil
}

func (c *Container) inflateRun(run dmgRun) ([]byte, error) {
	if run.length > MaxWholeRunBytes {
		return nil, unsupportedDMG(fmt.Sprintf(
			"a zlib run of %d decoded bytes at sector %d (the bound is %d)",
			run.length, run.start/SectorSize, MaxWholeRunBytes))
	}
	stored, err := c.readStored(run)
	if err != nil {
		return nil, err
	}
	reader, err := zlib.NewReader(bytes.NewReader(stored))
	if err != nil {
		return nil, corruptDMG(run.fileOffset, fmt.Sprintf(
			"the zlib run at sector %d did not inflate: %v", run.start/SectorSize, err))
	}
	decoded, err := io.ReadAll(io.LimitReader(reader, int64(run.length)+1))
	closeErr := reader.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, corruptDMG(run.fileOffset, fmt.Sprintf(
			"the zlib run at sector %d did not inflate: %v", run.start/SectorSize, err))
	}
	if uint64(len(decoded)) != run.length {
		return nil, corruptDMG(run.fileOffset, fmt.Sprintf(
			"the zlib run at sector %d inflates to %d bytes, the table declares %d",
			run.start/SectorSize, len(decoded), run.length))
	}
	c.counters.AddDecompressed(run.length)
	return decoded, nil
}

// inflateAt streams a zlib run too large to cache, skipping to the requested
// offset. Sequential reads through such a run cost one pass plus the bytes
// read; random reads cost a pass each.
func (c *Container) inflateAt(run dmgRun, offset uint64, target []byte) error {
	if run.fileOffset > uint64(maxIntDMG()) || run.fileLen > uint64(maxIntDMG()) {
		return unsupportedDMG("a zlib run larger than the address space")
	}
	section := io.NewSectionReader(source.ReaderAt(c.parent), int64(run.fileOffset), int64(run.fileLen))
	reader, err := zlib.NewReader(section)
	if err != nil {
		return corruptDMG(run.fileOffset, fmt.Sprintf(
			"the zlib run at sector %d did not inflate: %v", run.start/SectorSize, err))
	}
	defer reader.Close()
	if offset > 0 {
		skipped, err := io.CopyN(io.Discard, reader, int64(offset))
		if err != nil {
			return corruptDMG(run.fileOffset, fmt.Sprintf(
				"the zlib run at sector %d ended before offset %d: %v",
				run.start/SectorSize, offset, err))
		}
		if uint64(skipped) != offset {
			return corruptDMG(run.fileOffset, fmt.Sprintf(
				"the zlib run at sector %d holds %d bytes, the table declares %d",
				run.start/SectorSize, skipped, run.length))
		}
	}
	done, err := io.ReadFull(reader, target)
	if err != nil {
		return corruptDMG(run.fileOffset, fmt.Sprintf(
			"the zlib run at sector %d did not inflate: %v", run.start/SectorSize, err))
	}
	c.counters.AddDecompressed(offset + uint64(done))
	return nil
}

// ExtentsInto translates a guest range to its parent.
func (c *Container) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if err := c.checkRange(offset, length); err != nil {
		return out, err
	}
	cursor := offset
	end := offset + length
	for cursor < end {
		if index, inRun, ok := c.coveringRun(cursor); ok {
			run := c.runs[index]
			stop := end
			if run.start+run.length < stop {
				stop = run.start + run.length
			}
			chunk := stop - cursor
			switch run.kind {
			case runZero:
				out = append(out, source.ParentRange{
					Parent: c.parent.SourceID(), ParentOffset: 0,
					Len: chunk, Kind: source.RangeZero,
				})
			case runRaw:
				out = append(out, source.ParentRange{
					Parent: c.parent.SourceID(), ParentOffset: run.fileOffset + inRun,
					Len: chunk, Kind: source.RangeData,
				})
			default:
				// A compressed run does not map linearly onto guest bytes, so
				// the extent states where the stream is and how long it is.
				out = append(out, source.ParentRange{
					Parent: c.parent.SourceID(), ParentOffset: run.fileOffset,
					Len: run.fileLen, Kind: source.RangeData,
				})
			}
			cursor = stop
			continue
		}
		stop := c.gapEnd(cursor)
		if stop > end {
			stop = end
		}
		if stop <= cursor {
			return out, corruptDMG(cursor, fmt.Sprintf(
				"sector %d is not covered by any run or gap", cursor/SectorSize))
		}
		out = append(out, source.ParentRange{
			Parent: c.parent.SourceID(), ParentOffset: 0,
			Len: stop - cursor, Kind: source.RangeZero,
		})
		cursor = stop
	}
	return out, nil
}

// Extents translates a guest range.
func (c *Container) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return c.ExtentsInto(offset, length, nil)
}

// MapToImage translates a guest range all the way to image offsets.
func (c *Container) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	extents, err := c.Extents(offset, length)
	if err != nil {
		return nil, err
	}
	var out []source.ImageRange
	for _, extent := range extents {
		if extent.Kind == source.RangeData {
			mapped, err := c.parent.MapToImage(extent.ParentOffset, extent.Len)
			if err != nil {
				return nil, err
			}
			out = append(out, mapped...)
			continue
		}
		out = append(out, source.ImageRange{
			ImageID: c.parent.ImageID(), ImageOffset: 0, Len: extent.Len, Kind: extent.Kind,
		})
	}
	return out, nil
}

var _ source.ByteSource = (*Container)(nil)

func readFullDMG(src source.ByteSource, offset uint64, target []byte) (int, error) {
	n, err := src.ReadAt(offset, target)
	if err != nil {
		return n, err
	}
	if n < len(target) {
		return n, source.NewUnexpectedEOF(offset)
	}
	return n, nil
}

func be32(bytes []byte, at int) uint32 {
	return uint32(bytes[at])<<24 | uint32(bytes[at+1])<<16 |
		uint32(bytes[at+2])<<8 | uint32(bytes[at+3])
}

func be64(bytes []byte, at int) uint64 {
	return uint64(be32(bytes, at))<<32 | uint64(be32(bytes, at+4))
}
