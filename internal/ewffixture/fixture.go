// Package ewffixture builds synthetic single-volume E01 forensic images for
// testing. It is pure Go and cross-platform; tests call WrapDisk directly and
// never depend on external tools.
//
// Layouts follow the EWF specification shipped in the repo
// ("Expert Witness Compression Format (EWF).asciidoc"):
//   - EnCase 1: chunk data lives inside the table section after the footer;
//     table offsets are relative to the file start.
//   - FTK/EnCase 2-5: chunk data lives in the sectors section; table offsets
//     are relative to the file start.
//   - EnCase 6-7: same as 2-5 but table offsets are relative to the table
//     base offset field (table header offset 8..16).
package ewffixture

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"hash/adler32"
)

const (
	sectionLen          = 76
	tableHeaderLen      = 24
	chunkFooterLen      = 4
	sectorSize          = 512
	defaultChunkSectors = 64
	fileHeaderLen       = 13
)

// Layout selects which EWF section layout to emit.
type Layout int

const (
	// LayoutEnCase2_5 is the FTK Imager / EnCase 2-5 layout: chunks in the
	// sectors section, table offsets relative to the file start. It is the
	// zero value so a default Options{} emits this layout.
	LayoutEnCase2_5 Layout = iota
	// LayoutEnCase1 stores chunks inside the table section (EnCase 1). The
	// ewfgo parser does not support this layout; use it to assert clean errors.
	LayoutEnCase1
	// LayoutEnCase6 uses the table base offset field (EnCase 6-7).
	LayoutEnCase6
)

// CompressMode selects how chunk data is stored.
type CompressMode int

const (
	// CompressZlib stores each chunk as a zlib stream.
	CompressZlib CompressMode = iota
	// CompressNone stores each chunk raw, followed by a 4-byte Adler-32
	// checksum of the chunk data (spec: uncompressed chunk layout).
	CompressNone
)

// Options controls E01 construction.
type Options struct {
	ChunkSectors uint32       // sectors per chunk (default 64)
	Layout       Layout       // default LayoutEnCase2_5
	Compress     CompressMode // default CompressZlib
	SlackBytes   int          // padding between section descriptor and chunk data
	NoTable2     bool         // omit the mirror table2 section (default: emitted)
	SkipTable    bool         // emit sectors section but omit the table section (malformed)
	Sections     int          // split chunks across this many sectors/table pairs (default 1)
	MD5Hash      []byte       // 16 bytes; when set, "digest" (MD5+SHA1) and "hash" sections are emitted
	SHA1Hash     []byte       // 20 bytes; stored in the "digest" section (only read with MD5Hash)
	ShortFinalChunk bool      // store the last chunk only as its valid sectors (no zero padding)
}

// DiskPattern returns nSectors of deterministic, non-zero pattern data.
func DiskPattern(nSectors uint64) []byte {
	p := make([]byte, nSectors*sectorSize)
	for i := uint64(0); i < nSectors; i++ {
		for j := 0; j < sectorSize; j++ {
			p[i*sectorSize+uint64(j)] = byte((i*17 + uint64(j)*7) & 0xFF)
		}
	}
	return p
}

// WrapMBRDisk wraps fsImage into a full disk with a single MBR partition.
// Returns a sector-aligned disk image: MBR at sector 0, the partition starting
// at startLBA holding fsImage.
func WrapMBRDisk(fsImage []byte, partType byte, startLBA uint64) []byte {
	if len(fsImage)%sectorSize != 0 {
		panic("ewffixture: fsImage not sector-aligned")
	}
	fsSectors := uint64(len(fsImage) / sectorSize)
	totalSectors := startLBA + fsSectors + 1
	disk := make([]byte, totalSectors*sectorSize)

	entry := disk[446 : 446+16] // MBR partition entry 1
	entry[0] = 0x00             // not bootable
	entry[4] = partType
	binary.LittleEndian.PutUint32(entry[8:], uint32(startLBA))
	binary.LittleEndian.PutUint32(entry[12:], uint32(fsSectors))
	disk[510], disk[511] = 0x55, 0xAA

	copy(disk[startLBA*sectorSize:], fsImage)
	return disk
}

type builder struct{ buf []byte }

func (b *builder) offset() int64 { return int64(len(b.buf)) }

func (b *builder) writeSection(name string, payload []byte) (descAddr int64, size int64) {
	descAddr = b.offset()
	desc := make([]byte, sectionLen)
	copy(desc[0:16], name)
	b.buf = append(b.buf, desc...)
	b.buf = append(b.buf, payload...)
	size = b.offset() - descAddr
	binary.LittleEndian.PutUint64(b.buf[descAddr+16:], uint64(descAddr+size))
	binary.LittleEndian.PutUint64(b.buf[descAddr+24:], uint64(size))
	chk := adler32.Checksum(b.buf[descAddr : descAddr+72])
	binary.LittleEndian.PutUint32(b.buf[descAddr+72:], chk)
	return descAddr, size
}

func (b *builder) patchNextOffset(descAddr int64, next uint64) {
	binary.LittleEndian.PutUint64(b.buf[descAddr+16:], next)
	chk := adler32.Checksum(b.buf[descAddr : descAddr+72])
	binary.LittleEndian.PutUint32(b.buf[descAddr+72:], chk)
}

const headerText = "1\nmain\na\tc\tn\te\nfixture-desc\tfixture-case\tfixture-evidence\tfixture-examiner\n\n"

func zlibBytes(in []byte) []byte {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(in); err != nil {
		panic(err)
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// diskSmart builds the 1052-byte FTK/EnCase 1-7 volume (== disk) section data.
func diskSmart(chunkCount, chunkSectors, sectorBytes uint32, sectorsCount uint64) []byte {
	d := make([]byte, 1052)
	d[0] = 0x01 // media type: fixed storage media device
	binary.LittleEndian.PutUint32(d[4:], chunkCount)
	binary.LittleEndian.PutUint32(d[8:], chunkSectors)
	binary.LittleEndian.PutUint32(d[12:], sectorBytes)
	binary.LittleEndian.PutUint64(d[16:], sectorsCount)
	d[36] = 0x01 // media flags: image file
	d[52] = 0x01 // compression level: good
	binary.LittleEndian.PutUint32(d[56:], 64)
	copy(d[64:80], []byte("FIXTURE-GUID-001"))
	binary.LittleEndian.PutUint32(d[1048:], adler32.Checksum(d[0:1048]))
	return d
}

// tablePayload builds the table header + entries + footer. If base != 0 an
// EnCase 6 base offset field is written and entries are relative to base;
// otherwise entries are absolute file offsets.
func tablePayload(entryCount uint32, entries []uint32, base uint64) []byte {
	th := make([]byte, tableHeaderLen)
	binary.LittleEndian.PutUint32(th[0:], entryCount)
	if base != 0 {
		binary.LittleEndian.PutUint64(th[8:], base)
	}
	binary.LittleEndian.PutUint32(th[20:], adler32.Checksum(th[0:20]))

	out := make([]byte, 0, tableHeaderLen+4*len(entries)+chunkFooterLen)
	out = append(out, th...)
	for _, e := range entries {
		var eb [4]byte
		binary.LittleEndian.PutUint32(eb[:], e)
		out = append(out, eb[:]...)
	}
	var fb [4]byte // Adler-32 of the offset array (table footer)
	binary.LittleEndian.PutUint32(fb[:], adler32.Checksum(out[tableHeaderLen:]))
	out = append(out, fb[:]...)
	return out
}

// tablePayloadV1 builds an EnCase 1 table payload: table header (with the base
// offset field written at bytes [8:16]) + entries + footer. Entries are
// relative to base, so a chunk's file offset is base + (entry & 0x7fffffff),
// matching the parser's unified offset model.
func tablePayloadV1(entryCount uint32, entries []uint32, base uint64) []byte {
	th := make([]byte, tableHeaderLen)
	binary.LittleEndian.PutUint32(th[0:], entryCount)
	binary.LittleEndian.PutUint64(th[8:], base)
	binary.LittleEndian.PutUint32(th[20:], adler32.Checksum(th[0:20]))

	out := make([]byte, 0, tableHeaderLen+4*len(entries)+chunkFooterLen)
	out = append(out, th...)
	for _, e := range entries {
		var eb [4]byte
		binary.LittleEndian.PutUint32(eb[:], e)
		out = append(out, eb[:]...)
	}
	var fb [4]byte // Adler-32 of the offset array (table footer)
	binary.LittleEndian.PutUint32(fb[:], adler32.Checksum(out[tableHeaderLen:]))
	out = append(out, fb[:]...)
	return out
}

// chunkPayload returns the stored form of one chunk.
func chunkPayload(data []byte, mode CompressMode) []byte {
	if mode == CompressNone {
		out := make([]byte, 0, len(data)+chunkFooterLen)
		out = append(out, data...)
		var fb [4]byte
		binary.LittleEndian.PutUint32(fb[:], adler32.Checksum(data))
		out = append(out, fb[:]...)
		return out
	}
	return zlibBytes(data)
}

// WrapDisk wraps a sector-aligned disk image into a single-volume E01 and
// returns the E01 file bytes.
func WrapDisk(disk []byte, opts Options) []byte {
	if opts.ChunkSectors == 0 {
		opts.ChunkSectors = defaultChunkSectors
	}
	if len(disk)%sectorSize != 0 {
		panic("ewffixture: disk not sector-aligned")
	}
	chunkBytes := int(opts.ChunkSectors) * sectorSize
	diskSectors := uint64(len(disk) / sectorSize)
	nChunks := (len(disk) + chunkBytes - 1) / chunkBytes

	b := &builder{}
	fh := make([]byte, fileHeaderLen)
	copy(fh[0:8], []byte{'E', 'V', 'F', 0x09, 0x0d, 0x0a, 0xff, 0x00})
	fh[8] = 0x01
	binary.LittleEndian.PutUint16(fh[9:], 1)
	b.buf = append(b.buf, fh...)

	hz := zlibBytes([]byte(headerText))
	b.writeSection("header2", hz)
	b.writeSection("header", hz)

	vol := diskSmart(uint32(nChunks), opts.ChunkSectors, sectorSize, diskSectors)
	b.writeSection("volume", vol)
	b.writeSection("disk", vol)

	// Build each stored chunk. By default the final partial chunk is zero-padded
	// to full size; with ShortFinalChunk it is stored as only its valid sectors,
	// matching real writers when the acquired media is not chunk-aligned.
	chunkStored := make([][]byte, nChunks)
	for i := 0; i < nChunks; i++ {
		cd := make([]byte, chunkBytes)
		copy(cd, disk[i*chunkBytes:])
		if opts.ShortFinalChunk && i == nChunks-1 && len(disk)%chunkBytes != 0 {
			cd = disk[i*chunkBytes:]
		}
		chunkStored[i] = chunkPayload(cd, opts.Compress)
	}

	switch opts.Layout {
	case LayoutEnCase1:
		// EnCase 1 stores chunk data inside the table section AFTER the table
		// footer (never before the table header). Byte layout:
		//   [table desc][table header (24)][entries (4n)][Adler-32 footer (4)][chunk data...]
		// The table header sits at the section payload start (the parser reads
		// it there). base_offset (table header bytes [8:16]) is an absolute file
		// pointer to the chunk data region at the end of the section, and the
		// entries are relative to it, matching the unified offset model
		// chunkOffset = baseOffset + (entry & 0x7fffffff). The section's declared
		// size covers only the table data (header+entries+footer) so ParseTable
		// derives the exact entry count; NextOffset skips the chunk data to reach
		// the next section.
		tableDescAddr := b.offset()
		desc := make([]byte, sectionLen)
		copy(desc[0:16], "table")
		b.buf = append(b.buf, desc...)

		baseOff := tableDescAddr + sectionLen + tableHeaderLen + int64(4*nChunks) + chunkFooterLen
		entries := make([]uint32, nChunks)
		rel := int64(0)
		for i := range entries {
			if opts.Compress == CompressZlib {
				entries[i] = 0x80000000 | uint32(rel)
			} else {
				entries[i] = uint32(rel)
			}
			rel += int64(len(chunkStored[i]))
		}
		b.buf = append(b.buf, tablePayloadV1(uint32(nChunks), entries, uint64(baseOff))...)
		for _, cs := range chunkStored {
			b.buf = append(b.buf, cs...)
		}
		// Patch the table descriptor: SectionSize covers header+entries+footer
		// only, NextOffset points past the chunk data to the next section.
		sectionSize := uint64(sectionLen + tableHeaderLen + 4*nChunks + chunkFooterLen)
		binary.LittleEndian.PutUint64(b.buf[tableDescAddr+24:], sectionSize)
		binary.LittleEndian.PutUint64(b.buf[tableDescAddr+16:], uint64(b.offset()))
		chk := adler32.Checksum(b.buf[tableDescAddr : tableDescAddr+72])
		binary.LittleEndian.PutUint32(b.buf[tableDescAddr+72:], chk)
		b.writeSection("data", vol)

	default: // LayoutEnCase2_5 / LayoutEnCase6
		// Split the chunks across opts.Sections sectors/table pairs so tests can
		// exercise reads that span section boundaries. Each sectors section holds
		// a contiguous run of chunks and is followed by its own table.
		numSections := opts.Sections
		if numSections < 1 {
			numSections = 1
		}
		if numSections > nChunks {
			numSections = nChunks
		}
		if numSections < 1 {
			numSections = 1
		}
		sectionChunkCounts := make([]int, numSections)
		base, rem := nChunks/numSections, nChunks%numSections
		for s := 0; s < numSections; s++ {
			sectionChunkCounts[s] = base
			if s < rem {
				sectionChunkCounts[s]++
			}
		}

		globalChunk := 0
		for s := 0; s < numSections; s++ {
			nSec := sectionChunkCounts[s]
			sectorsDescAddr := b.offset()
			sectorsPayload := make([]byte, opts.SlackBytes)
			chunkOffsets := make([]uint64, nSec)
			off := sectorsDescAddr + sectionLen + int64(opts.SlackBytes)
			for i := 0; i < nSec; i++ {
				chunkOffsets[i] = uint64(off)
				sectorsPayload = append(sectorsPayload, chunkStored[globalChunk+i]...)
				off += int64(len(chunkStored[globalChunk+i]))
			}
			globalChunk += nSec
			b.writeSection("sectors", sectorsPayload)

			base := uint64(0)
			if opts.Layout == LayoutEnCase6 && nSec > 0 {
				base = chunkOffsets[0]
			}
			entries := make([]uint32, nSec)
			for i := range entries {
				rel := chunkOffsets[i]
				if base != 0 {
					rel -= base
				}
				if opts.Compress == CompressZlib {
					entries[i] = 0x80000000 | uint32(rel)
				} else {
					entries[i] = uint32(rel)
				}
			}
			if !opts.SkipTable {
				b.writeSection("table", tablePayload(uint32(nSec), entries, base))
				if !opts.NoTable2 {
					b.writeSection("table2", tablePayload(uint32(nSec), entries, base))
				}
			}
		}
		b.writeSection("data", vol)
	}

	// Acquisition hashes, modeled on the section shapes real writers emit:
	//   - "hash" section = MD5 only (16-byte hash + 16 zero bytes + 4-byte data
	//     checksum = 36 bytes); server.E01 has this and no digest section.
	//   - "digest" section = MD5+SHA1 (16 + 20 + 40 zero bytes + 4-byte data
	//     checksum = 80 bytes) or SHA1 only (20 bytes); mac.E01 has digest+hash.
	// Only the leading hash bytes are parsed by ewfgo, so the trailing zeros
	// stand in for the data checksum.
	switch {
	case opts.MD5Hash != nil && opts.SHA1Hash != nil:
		digest := make([]byte, 80)
		copy(digest, opts.MD5Hash)
		copy(digest[16:], opts.SHA1Hash)
		hash := make([]byte, 36)
		copy(hash, opts.MD5Hash)
		b.writeSection("digest", digest)
		b.writeSection("hash", hash)
	case opts.MD5Hash != nil:
		hash := make([]byte, 36)
		copy(hash, opts.MD5Hash)
		b.writeSection("hash", hash)
	case opts.SHA1Hash != nil:
		digest := make([]byte, 20)
		copy(digest, opts.SHA1Hash)
		b.writeSection("digest", digest)
	}

	doneDesc, _ := b.writeSection("done", nil)
	b.patchNextOffset(doneDesc, uint64(doneDesc))
	return b.buf
}

// WrapDiskSegments wraps a sector-aligned disk into a two-segment E01 image
// (segment files E01 and E02) and returns the two files in order. It exercises
// the multi-segment parser paths: per-segment section chains, offset resolution
// against cumulative segment sizes, and the sibling-segment validation in Open
// (both files carry the EVF signature and ascending segment numbers).
//
// When crossSegment is true the layout is EnCase 1 style (tables only, no
// sectors sections) in BOTH segments, so the parser's EnCase 1 synthesis sees
// one logical image. Chunk 0 lives in segment 1 and chunks 1..n-1 in segment 2.
// Real EWF writers never split a chunk's stored bytes across segment files, so
// no chunk straddles the boundary here; ReadAt's cross-segment span read (head
// from segment 1 + tail from segment 2 concatenated) is exercised directly by
// TestReadAt_CrossSegmentSpan.
//
// When crossSegment is false the layout is EnCase 2-5 style: segment 1 holds
// chunk 0 in its own sectors/table pair and segment 2 holds the remaining
// chunks, each chunk entirely within one segment.
//
// The disk must contain at least two chunks.
func WrapDiskSegments(disk []byte, opts Options, crossSegment bool) [][]byte {
	if opts.ChunkSectors == 0 {
		opts.ChunkSectors = defaultChunkSectors
	}
	if len(disk)%sectorSize != 0 {
		panic("ewffixture: disk not sector-aligned")
	}
	chunkBytes := int(opts.ChunkSectors) * sectorSize
	diskSectors := uint64(len(disk) / sectorSize)
	nChunks := (len(disk) + chunkBytes - 1) / chunkBytes
	if nChunks < 2 {
		panic("ewffixture: WrapDiskSegments requires at least 2 chunks")
	}
	mode := opts.Compress
	if crossSegment {
		mode = CompressNone
	}
	chunkStored := make([][]byte, nChunks)
	for i := 0; i < nChunks; i++ {
		cd := make([]byte, chunkBytes)
		copy(cd, disk[i*chunkBytes:])
		chunkStored[i] = chunkPayload(cd, mode)
	}

	fileHeader := func(b *builder, segNum uint16) {
		h := make([]byte, fileHeaderLen)
		copy(h[0:8], []byte{'E', 'V', 'F', 0x09, 0x0d, 0x0a, 0xff, 0x00})
		h[8] = 0x01
		binary.LittleEndian.PutUint16(h[9:], segNum)
		b.buf = append(b.buf, h...)
	}
	hz := zlibBytes([]byte(headerText))
	vol := diskSmart(uint32(nChunks), opts.ChunkSectors, sectorSize, diskSectors)
	// tableSectionDesc appends a bare "table" descriptor (76 bytes) and returns
	// its address; the caller writes the table payload and patches the
	// SectionSize / NextOffset / checksum.
	tableSectionDesc := func(b *builder) (addr int64) {
		addr = b.offset()
		desc := make([]byte, sectionLen)
		copy(desc[0:16], "table")
		b.buf = append(b.buf, desc...)
		return addr
	}
	// patchTableDesc fixes up SectionSize (header+entries+footer only) and
	// recomputes the descriptor checksum.
	patchTableDesc := func(b *builder, addr int64, next uint64) {
		binary.LittleEndian.PutUint64(b.buf[addr+16:], next)
		binary.LittleEndian.PutUint64(b.buf[addr+24:], uint64(sectionLen+tableHeaderLen+4+4))
		binary.LittleEndian.PutUint32(b.buf[addr+72:], adler32.Checksum(b.buf[addr:addr+72]))
	}

	if crossSegment {
		// --- segment 1 (E01): chunk 0 in its own EnCase 1 table ---
		b1 := &builder{}
		fileHeader(b1, 1)
		b1.writeSection("header2", hz)
		b1.writeSection("header", hz)
		b1.writeSection("volume", vol)
		b1.writeSection("disk", vol)

		// Chunk 0's table: base_offset = the chunk data start inside segment 1
		// (entry 0 = 0 ⇒ chunkOffset = base_offset).
		tbl := tableSectionDesc(b1)
		base := tbl + sectionLen + tableHeaderLen + 4 + chunkFooterLen
		b1.buf = append(b1.buf, tablePayloadV1(1, []uint32{0}, uint64(base))...)
		b1.buf = append(b1.buf, chunkStored[0]...)
		doneDesc, _ := b1.writeSection("done", nil)
		b1.patchNextOffset(doneDesc, uint64(doneDesc))

		// Patch chunk 0's table descriptor: NextOffset → done, SectionSize →
		// header+entries+footer only.
		binary.LittleEndian.PutUint64(b1.buf[tbl+16:], uint64(doneDesc))
		binary.LittleEndian.PutUint64(b1.buf[tbl+24:], uint64(sectionLen+tableHeaderLen+4+4))
		binary.LittleEndian.PutUint32(b1.buf[tbl+72:], adler32.Checksum(b1.buf[tbl:tbl+72]))

		// --- segment 2 (E02): chunks 1..n-1, each in its own EnCase 1 table ---
		b2 := &builder{}
		fileHeader(b2, 2)
		for ci := 1; ci < nChunks; ci++ {
			tbl2 := tableSectionDesc(b2)
			base2 := tbl2 + sectionLen + tableHeaderLen + 4 + chunkFooterLen
			b2.buf = append(b2.buf, tablePayloadV1(1, []uint32{0}, uint64(base2))...)
			b2.buf = append(b2.buf, chunkStored[ci]...)
			patchTableDesc(b2, tbl2, uint64(b2.offset()))
		}
		doneDesc2, _ := b2.writeSection("done", nil)
		b2.patchNextOffset(doneDesc2, uint64(doneDesc2))
		return [][]byte{b1.buf, b2.buf}
	}

	// --- EnCase 2-5 style, chunks aligned within one segment ---
	// segment 1 (E01): header + volume/disk + chunk 0's sectors/table pair.
	b1 := &builder{}
	fileHeader(b1, 1)
	b1.writeSection("header2", hz)
	b1.writeSection("header", hz)
	b1.writeSection("volume", vol)
	b1.writeSection("disk", vol)

	s1 := b1.offset()
	off1 := s1 + sectionLen
	entries1 := make([]uint32, 1)
	entries1[0] = uint32(off1)
	if mode == CompressZlib {
		entries1[0] |= 0x80000000
	}
	b1.writeSection("sectors", chunkStored[0])
	b1.writeSection("table", tablePayload(1, entries1, 0))
	b1.writeSection("table2", tablePayload(1, entries1, 0))
	doneDesc1, _ := b1.writeSection("done", nil)
	b1.patchNextOffset(doneDesc1, uint64(doneDesc1))

	// segment 2 (E02): chunks 1..n-1 in one sectors/table pair.
	b2 := &builder{}
	fileHeader(b2, 2)
	s2 := b2.offset()
	off2 := s2 + sectionLen
	entries2 := make([]uint32, nChunks-1)
	payload2 := make([]byte, 0, (nChunks-1)*chunkBytes)
	for ci := 1; ci < nChunks; ci++ {
		entries2[ci-1] = uint32(off2)
		if mode == CompressZlib {
			entries2[ci-1] |= 0x80000000
		}
		payload2 = append(payload2, chunkStored[ci]...)
		off2 += int64(len(chunkStored[ci]))
	}
	b2.writeSection("sectors", payload2)
	b2.writeSection("table", tablePayload(uint32(nChunks-1), entries2, 0))
	doneDesc2, _ := b2.writeSection("done", nil)
	b2.patchNextOffset(doneDesc2, uint64(doneDesc2))
	return [][]byte{b1.buf, b2.buf}
}

// TableEntryOffsetFor returns the file offset of the idx-th table entry in the
// first "table" section of the E01 produced by WrapDisk. Returns -1 if not
// found.
func TableEntryOffsetFor(e01 []byte, idx int) int64 {
	addr := int64(13)
	for {
		if int(addr)+sectionLen > len(e01) {
			return -1
		}
		name := string(bytes.TrimRight(e01[addr:addr+16], "\x00"))
		next := int64(binary.LittleEndian.Uint64(e01[addr+16:]))
		if name == "table" {
			return addr + sectionLen + tableHeaderLen + int64(4*idx)
		}
		if name == "done" || next <= addr {
			return -1
		}
		addr = next
	}
}
