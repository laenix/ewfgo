package carving

import (
	"encoding/binary"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

// memory wraps bytes as the hermetic in-memory byte source.
func memory(data []byte) *source.MemorySource {
	return source.NewMemorySource(1, data)
}

// filler returns bytes that cannot themselves match a carving magic.
func filler(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = '.'
	}
	return out
}

// makeBMP is a 2x2, 24-bit, bottom-up BMP: a 54-byte header and two 8-byte rows.
func makeBMP() []byte {
	out := make([]byte, 0, 70)
	out = append(out, 'B', 'M')
	out = binary.LittleEndian.AppendUint32(out, 70) // file size
	out = binary.LittleEndian.AppendUint16(out, 0)  // reserved
	out = binary.LittleEndian.AppendUint16(out, 0)  // reserved
	out = binary.LittleEndian.AppendUint32(out, 54) // pixel-data offset
	out = binary.LittleEndian.AppendUint32(out, 40) // DIB size
	out = binary.LittleEndian.AppendUint32(out, 2)  // width
	out = binary.LittleEndian.AppendUint32(out, 2)  // height
	out = binary.LittleEndian.AppendUint16(out, 1)  // planes
	out = binary.LittleEndian.AppendUint16(out, 24) // bits per pixel
	out = binary.LittleEndian.AppendUint32(out, 0)  // BI_RGB
	out = binary.LittleEndian.AppendUint32(out, 16) // image size
	out = binary.LittleEndian.AppendUint32(out, 0)  // x pixels/meter
	out = binary.LittleEndian.AppendUint32(out, 0)  // y pixels/meter
	out = binary.LittleEndian.AppendUint32(out, 0)  // colors used
	out = binary.LittleEndian.AppendUint32(out, 0)  // important colors
	out = append(out, make([]byte, 16)...)          // pixel data
	return out
}

// makeGIF is a 2x2 GIF89a with a global color table, one image with an LZW
// sub-block chain and a comment extension.
func makeGIF() []byte {
	out := []byte("GIF89a")
	out = binary.LittleEndian.AppendUint16(out, 2)           // width
	out = binary.LittleEndian.AppendUint16(out, 2)           // height
	out = append(out, 0x80, 0, 0)                            // global table, 2 entries
	out = append(out, 0, 0, 0, 255, 255, 255)                // 2-entry color table
	out = append(out, 0x21, 0xFE, 0x03, 'h', 'i', '!', 0x00) // comment
	out = append(out, 0x2C, 0, 0, 0, 0, 2, 0, 2, 0, 0x00)    // image descriptor
	out = append(out, 2)                                     // LZW minimum code size
	out = append(out, 0x02, 0x44, 0x01, 0x00)                // LZW sub-blocks
	out = append(out, 0x3B)                                  // trailer
	return out
}

// makeTIFF is a little-endian TIFF with one IFD: inline geometry, out-of-line
// StripOffsets/StripByteCounts arrays and the 4 bytes of strip data.
func makeTIFF() []byte {
	out := []byte("II*\x00")
	out = binary.LittleEndian.AppendUint32(out, 8) // first IFD
	out = binary.LittleEndian.AppendUint16(out, 4) // entry count
	out = binary.LittleEndian.AppendUint16(out, 256)
	out = binary.LittleEndian.AppendUint16(out, 4)
	out = binary.LittleEndian.AppendUint32(out, 1)
	out = binary.LittleEndian.AppendUint32(out, 2)
	out = binary.LittleEndian.AppendUint16(out, 257)
	out = binary.LittleEndian.AppendUint16(out, 4)
	out = binary.LittleEndian.AppendUint32(out, 1)
	out = binary.LittleEndian.AppendUint32(out, 2)
	out = binary.LittleEndian.AppendUint16(out, 273) // StripOffsets
	out = binary.LittleEndian.AppendUint16(out, 4)
	out = binary.LittleEndian.AppendUint32(out, 2)
	out = binary.LittleEndian.AppendUint32(out, 62)
	out = binary.LittleEndian.AppendUint16(out, 279) // StripByteCounts
	out = binary.LittleEndian.AppendUint16(out, 4)
	out = binary.LittleEndian.AppendUint32(out, 2)
	out = binary.LittleEndian.AppendUint32(out, 70)
	out = binary.LittleEndian.AppendUint32(out, 0) // next IFD
	out = binary.LittleEndian.AppendUint32(out, 78)
	out = binary.LittleEndian.AppendUint32(out, 78)
	out = binary.LittleEndian.AppendUint32(out, 4)
	out = binary.LittleEndian.AppendUint32(out, 4)
	out = append(out, 1, 2, 3, 4)
	return out
}

func webpChunk(kind string, payload []byte) []byte {
	out := append([]byte(kind), 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(out[4:8], uint32(len(payload)))
	out = append(out, payload...)
	if len(payload)%2 == 1 {
		out = append(out, 0)
	}
	return out
}

// makeWebP is a RIFF/WebP container with a VP8X header and a VP8L image chunk.
func makeWebP() []byte {
	var chunks []byte
	chunks = append(chunks, webpChunk("VP8X", make([]byte, 10))...)
	lossless := []byte{0x2F, 0, 0, 0, 0, 1, 2, 3}
	chunks = append(chunks, webpChunk("VP8L", lossless)...)
	out := []byte("RIFF")
	out = binary.LittleEndian.AppendUint32(out, uint32(4+len(chunks)))
	out = append(out, []byte("WEBP")...)
	out = append(out, chunks...)
	return out
}

const (
	testEVTXFileHeaderLen  = 0x1000
	testEVTXChunkHeaderLen = 0x200
	testEVTXChunkLen       = 0x10000
)

// makeEVTXChunk is a 64 KiB EVTX chunk whose header and records checksums both
// verify.
func makeEVTXChunk() []byte {
	chunk := make([]byte, testEVTXChunkLen)
	copy(chunk[0:8], []byte("ElfChnk\x00"))
	binary.LittleEndian.PutUint64(chunk[0x08:0x10], 1)
	binary.LittleEndian.PutUint64(chunk[0x10:0x18], 1)
	binary.LittleEndian.PutUint32(chunk[0x28:0x2C], 0x80)
	recordsEnd := uint32(testEVTXChunkHeaderLen + 16)
	binary.LittleEndian.PutUint32(chunk[0x30:0x34], recordsEnd)
	for i := uint32(0); i < 16; i++ {
		chunk[testEVTXChunkHeaderLen+int(i)] = byte(i)
	}
	records := foundation.CRC32(chunk[testEVTXChunkHeaderLen:recordsEnd])
	binary.LittleEndian.PutUint32(chunk[0x34:0x38], records)
	state := foundation.CRC32Seeded(0xFFFFFFFF, chunk[0:0x78])
	state = foundation.CRC32Seeded(state, chunk[0x80:0x200])
	binary.LittleEndian.PutUint32(chunk[0x7C:0x80], ^state)
	return chunk
}

// makeEVTXFile is a 4 KiB file header followed by chunks, with the header's
// own checksum computed and the declared chunk count stored.
func makeEVTXFile(chunks [][]byte, declared uint16) []byte {
	file := make([]byte, testEVTXFileHeaderLen)
	copy(file[0:8], []byte("ElfFile\x00"))
	binary.LittleEndian.PutUint32(file[0x20:0x24], 0x80)
	binary.LittleEndian.PutUint16(file[0x28:0x2A], 0x1000)
	binary.LittleEndian.PutUint16(file[0x2A:0x2C], declared)
	binary.LittleEndian.PutUint32(file[0x7C:0x80], foundation.CRC32(file[0:0x78]))
	for _, chunk := range chunks {
		file = append(file, chunk...)
	}
	return file
}

const testSQLitePage = 512

func sqliteHeaderPage(pageCount uint32) []byte {
	page := make([]byte, testSQLitePage)
	copy(page[0:16], []byte("SQLite format 3\x00"))
	binary.BigEndian.PutUint16(page[16:18], testSQLitePage)
	page[18] = 1
	page[19] = 1
	copy(page[21:24], []byte{64, 32, 32})
	binary.BigEndian.PutUint32(page[28:32], pageCount)
	binary.BigEndian.PutUint32(page[44:48], 1)
	binary.BigEndian.PutUint32(page[56:60], 1)
	return page
}

func sqliteLeafPage(payload []byte) []byte {
	page := make([]byte, testSQLitePage)
	page[0] = 13
	binary.BigEndian.PutUint16(page[3:5], 1)
	const cellAt = 400
	binary.BigEndian.PutUint16(page[5:7], cellAt)
	binary.BigEndian.PutUint16(page[8:10], cellAt)
	page[cellAt] = byte(len(payload))
	page[cellAt+1] = 1
	copy(page[cellAt+2:], payload)
	return page
}

// makeSQLiteDB is a two-page database: a schema leaf page holding one row and a
// second leaf page holding the caller's payload.
func makeSQLiteDB(payload []byte) []byte {
	out := sqliteHeaderPage(2)
	out[100] = 13
	binary.BigEndian.PutUint16(out[103:105], 1)
	binary.BigEndian.PutUint16(out[105:107], 400)
	binary.BigEndian.PutUint16(out[108:110], 400)
	out[400] = 5
	out[401] = 1
	copy(out[402:407], []byte("hello"))
	out = append(out, sqliteLeafPage(payload)...)
	return out
}

// makePrefetchRaw is a valid version-17 raw SCCA record with a terminated
// executable name and self-consistent section spans.
func makePrefetchRaw() []byte {
	body := make([]byte, 200)
	binary.LittleEndian.PutUint32(body[0:4], 17)
	copy(body[4:8], []byte("SCCA"))
	binary.LittleEndian.PutUint32(body[12:16], 200)
	off := 16
	for _, r := range "cmd.exe" {
		binary.LittleEndian.PutUint16(body[off:off+2], uint16(r))
		off += 2
	}
	// The NUL terminator and the rest of the 60-byte field are zero.
	binary.LittleEndian.PutUint32(body[84:88], 152)   // metrics offset
	binary.LittleEndian.PutUint32(body[100:104], 152) // strings offset
	binary.LittleEndian.PutUint32(body[108:112], 152) // volumes offset
	binary.LittleEndian.PutUint32(body[144:148], 3)   // run count (v17)
	return body
}

// makePrefetchMAM wraps makePrefetchRaw in a MAM\x04 container whose Xpress
// Huffman stream encodes the record as literal bytes.
func makePrefetchMAM() []byte {
	record := makePrefetchRaw()
	codes := make([]lzxCode, len(record))
	for i, b := range record {
		codes[i] = lzxCode{code: uint32(b), length: 9}
	}
	stream := append(lzxFlatTable(), lzxPack(codes)...)
	out := []byte("MAM\x04")
	out = binary.LittleEndian.AppendUint32(out, uint32(len(record)))
	out = append(out, stream...)
	return out
}

// damagedSource wraps an in-memory source and makes [badFrom, badTo) unreadable.
// ReadAtLossy zero-fills and counts the damaged bytes, like a real image adapter.
type damagedSource struct {
	*source.MemorySource
	badFrom uint64
	badTo   uint64
	corrupt uint64
}

func (d *damagedSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if offset < d.badTo && offset+uint64(len(buf)) > d.badFrom {
		return 0, source.NewCorrupt(offset, "damaged")
	}
	return d.MemorySource.ReadAt(offset, buf)
}

func (d *damagedSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	n, err := d.MemorySource.ReadAt(offset, buf)
	if err != nil && n == 0 {
		clear(buf)
		return len(buf), nil
	}
	for i := n; i < len(buf); i++ {
		buf[i] = 0
	}
	lo, hi := d.badFrom, d.badTo
	if lo < offset {
		lo = offset
	}
	if end := offset + uint64(len(buf)); hi > end {
		hi = end
	}
	if lo < hi {
		clear(buf[lo-offset : hi-offset])
		d.corrupt += hi - lo
	}
	return len(buf), nil
}

func (d *damagedSource) Stats() source.Stats {
	stats := d.MemorySource.Stats()
	stats.CorruptBytes = d.corrupt
	return stats
}
