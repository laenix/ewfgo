package xz

// The .xz container: stream header, blocks, index and stream footer.
//
// Every checksum the container stores is verified: the stream-header CRC32,
// each block-header CRC32, the per-block check (CRC32 or none), the index
// CRC32, and the stream-footer CRC32. Index records are compared in order
// against the blocks that were actually parsed, and the footer's backward
// size and stream flags must agree with the index and the header.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

const (
	streamHeaderSize = 12
	streamFooterSize = 12
)

var (
	streamMagic = []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}
	footerMagic = []byte("YZ")
)

// checkSizes maps an integrity-check ID to its Check field size. Only the
// supported IDs are ever looked up; unsupported ones are refused first.
var checkSizes = [...]int{0, 4}

// indexRecord is one Index entry: the block's unpadded size and the number of
// bytes it decoded to. Unpadded size excludes block padding and includes the
// block header and Check field.
type indexRecord struct {
	unpadded     uint64
	uncompressed uint64
}

type parser struct {
	data []byte
	pos  int
}

// decodeStreams parses every stream in data, joining their decoded output.
func decodeStreams(data []byte, limits Limits) ([]byte, Meta, error) {
	p := &parser{data: data}
	var out []byte
	meta := Meta{CompressedLen: uint64(len(data))}

	for {
		paddingStart := p.pos
		for p.pos < len(p.data) && p.data[p.pos] == 0x00 {
			p.pos++
		}
		padding := p.pos - paddingStart
		if padding > 0 {
			if padding%4 != 0 {
				return nil, Meta{}, corrupt(uint64(paddingStart),
					"xz stream padding is %d bytes, not a multiple of four", padding)
			}
			meta.PaddingBytes += uint64(padding)
		}
		if p.pos == len(p.data) {
			break
		}
		if !hasStreamMagic(p.data, p.pos) {
			return nil, Meta{}, corrupt(uint64(p.pos), "trailing bytes are not an xz stream")
		}
		if uint64(len(out)) >= limits.MaxDecodedBytes {
			return nil, Meta{}, unsupported(
				"decompressed xz output exceeds the %d-byte limit", limits.MaxDecodedBytes)
		}
		if err := p.parseStream(&out, limits); err != nil {
			return nil, Meta{}, err
		}
		meta.Streams++
	}

	if meta.Streams == 0 {
		return nil, Meta{}, corrupt(0, "the file holds no xz stream")
	}
	meta.DecompressedLen = uint64(len(out))
	return out, meta, nil
}

// hasStreamMagic reports whether data[at:] begins with the stream magic.
func hasStreamMagic(data []byte, at int) bool {
	return at >= 0 && len(data)-at >= len(streamMagic) &&
		bytes.Equal(data[at:at+len(streamMagic)], streamMagic)
}

// parseStream parses one stream starting at p.pos, appending decoded bytes to
// out, and leaves p.pos just after the stream footer.
func (p *parser) parseStream(out *[]byte, limits Limits) error {
	streamStart := p.pos
	if err := p.need(streamHeaderSize); err != nil {
		return err
	}
	header := p.data[p.pos : p.pos+streamHeaderSize]
	if !bytes.Equal(header[:6], streamMagic) {
		return corrupt(uint64(streamStart), "not an xz stream header")
	}

	var flags [2]byte
	copy(flags[:], header[6:8])
	if flags[0] != 0 || flags[1]&0xF0 != 0 {
		return corrupt(uint64(streamStart+6), "xz stream header reserved flags are nonzero")
	}
	checkID := flags[1] & 0x0F
	checkSize, err := supportedCheckSize(checkID)
	if err != nil {
		return err
	}
	if want, got := binary.LittleEndian.Uint32(header[8:12]), crc32.ChecksumIEEE(header[6:8]); want != got {
		return corrupt(uint64(streamStart+8),
			"xz stream header CRC32 mismatch: stored %#08x, computed %#08x", want, got)
	}
	p.pos += streamHeaderSize

	var records []indexRecord
	for {
		if p.pos >= len(p.data) {
			return corrupt(uint64(p.pos), "xz stream is truncated before its index")
		}
		if p.data[p.pos] == 0x00 {
			break // Index Indicator
		}
		record, err := p.parseBlock(out, checkID, checkSize, limits)
		if err != nil {
			return err
		}
		records = append(records, record)
	}

	indexStart := p.pos
	indexSize, err := p.parseIndex(indexStart, records)
	if err != nil {
		return err
	}

	footerStart := p.pos
	if err := p.need(streamFooterSize); err != nil {
		return err
	}
	footer := p.data[p.pos : p.pos+streamFooterSize]
	if !bytes.Equal(footer[10:12], footerMagic) {
		return corrupt(uint64(footerStart+10), "xz stream footer magic is missing")
	}
	if want, got := binary.LittleEndian.Uint32(footer[0:4]), crc32.ChecksumIEEE(footer[4:10]); want != got {
		return corrupt(uint64(footerStart),
			"xz stream footer CRC32 mismatch: stored %#08x, computed %#08x", want, got)
	}
	backward := binary.LittleEndian.Uint32(footer[4:8])
	if uint64(backward)+1 != indexSize/4 {
		return corrupt(uint64(footerStart+4),
			"xz stream footer backward size %d does not match the %d-byte index", backward, indexSize)
	}
	if footer[8] != flags[0] || footer[9] != flags[1] {
		return corrupt(uint64(footerStart+8), "xz stream footer flags differ from the stream header")
	}
	p.pos += streamFooterSize
	return nil
}

// supportedCheckSize returns the Check field size for a supported check ID and
// refuses every other integrity check.
func supportedCheckSize(id byte) (int, error) {
	switch id {
	case 0x00: // None
		return 0, nil
	case 0x01: // CRC32
		return checkSizes[id], nil
	case 0x04:
		return 0, unsupported("xz integrity check CRC64 is not supported")
	case 0x0A:
		return 0, unsupported("xz integrity check SHA-256 is not supported")
	default:
		return 0, unsupported("xz integrity check ID %#02x is not supported", id)
	}
}

// parseBlock parses and decodes one block, appending its output to out and
// returning its index record.
func (p *parser) parseBlock(out *[]byte, checkID byte, checkSize int, limits Limits) (indexRecord, error) {
	headerStart := p.pos
	headerSize := (int(p.data[p.pos]) + 1) * 4
	if p.pos+headerSize > len(p.data) {
		return indexRecord{}, corrupt(uint64(headerStart), "xz block header is truncated")
	}
	headerEnd := p.pos + headerSize
	storedCRC := binary.LittleEndian.Uint32(p.data[headerEnd-4 : headerEnd])
	if computed := crc32.ChecksumIEEE(p.data[headerStart : headerEnd-4]); storedCRC != computed {
		return indexRecord{}, corrupt(uint64(headerStart),
			"xz block header CRC32 mismatch: stored %#08x, computed %#08x", storedCRC, computed)
	}

	flags := p.data[headerStart+1]
	if flags&0x3C != 0 {
		return indexRecord{}, corrupt(uint64(headerStart+1), "xz block flags set reserved bits")
	}
	c := &cursor{buf: p.data[headerStart+2 : headerEnd-4]}

	hasCompressed := flags&0x40 != 0
	hasUncompressed := flags&0x80 != 0
	var declaredCompressed uint64
	var declaredUncompressed uint64
	if hasCompressed {
		v, err := c.vli()
		if err != nil {
			return indexRecord{}, corrupt(uint64(headerStart), "xz block header: %v", err)
		}
		if v == 0 {
			return indexRecord{}, corrupt(uint64(headerStart), "xz block declares a zero compressed size")
		}
		if v >= 1<<63-8 {
			return indexRecord{}, corrupt(uint64(headerStart), "xz block compressed size is too large")
		}
		declaredCompressed = v
	}
	if hasUncompressed {
		v, err := c.vli()
		if err != nil {
			return indexRecord{}, corrupt(uint64(headerStart), "xz block header: %v", err)
		}
		declaredUncompressed = v
	}

	numFilters := int(flags&0x03) + 1
	if numFilters != 1 {
		return indexRecord{}, unsupported(
			"xz block uses %d filters; only a single LZMA2 filter is supported", numFilters)
	}

	id, err := c.vli()
	if err != nil {
		return indexRecord{}, corrupt(uint64(headerStart), "xz block header: %v", err)
	}
	propsSize, err := c.vli()
	if err != nil {
		return indexRecord{}, corrupt(uint64(headerStart), "xz block header: %v", err)
	}
	if propsSize > uint64(len(c.buf)-c.pos) {
		return indexRecord{}, corrupt(uint64(headerStart), "xz block filter properties are truncated")
	}
	props := c.buf[c.pos : c.pos+int(propsSize)]
	c.pos += int(propsSize)

	if id != 0x21 {
		return indexRecord{}, unsupported("xz filter ID %#02x is not supported", id)
	}
	if propsSize != 1 {
		return indexRecord{}, corrupt(uint64(headerStart),
			"LZMA2 filter properties must be one byte (got %d)", propsSize)
	}
	if props[0] > 40 {
		return indexRecord{}, corrupt(uint64(headerStart),
			"invalid LZMA2 dictionary size property %d", props[0])
	}

	// The rest of the header up to the CRC is zero padding.
	for ; c.pos < len(c.buf); c.pos++ {
		if c.buf[c.pos] != 0 {
			return indexRecord{}, corrupt(uint64(headerStart), "xz block header padding is not zero")
		}
	}

	p.pos = headerEnd
	blockStart := len(*out)
	dataStart := p.pos

	var observedCompressed uint64
	if hasCompressed {
		if declaredCompressed > uint64(len(p.data)-p.pos) {
			return indexRecord{}, corrupt(uint64(p.pos), "xz block compressed data is truncated")
		}
		if hasUncompressed && exceedsLimit(uint64(len(*out)), declaredUncompressed, limits.MaxDecodedBytes) {
			return indexRecord{}, unsupported(
				"decompressed xz output exceeds the %d-byte limit", limits.MaxDecodedBytes)
		}
		chunk := p.data[p.pos : p.pos+int(declaredCompressed)]
		consumed, _, err := decodeLZMA2(chunk, lzma2DictSize(props[0]), limits.MaxDecodedBytes,
			out, uint64(dataStart), declaredUncompressed, hasUncompressed)
		if err != nil {
			return indexRecord{}, err
		}
		if consumed != len(chunk) {
			return indexRecord{}, corrupt(uint64(dataStart+consumed),
				"xz LZMA2 stream ended before the declared %d compressed bytes", declaredCompressed)
		}
		observedCompressed = declaredCompressed
		p.pos += len(chunk)
	} else {
		if hasUncompressed && exceedsLimit(uint64(len(*out)), declaredUncompressed, limits.MaxDecodedBytes) {
			return indexRecord{}, unsupported(
				"decompressed xz output exceeds the %d-byte limit", limits.MaxDecodedBytes)
		}
		consumed, _, err := decodeLZMA2(p.data[p.pos:], lzma2DictSize(props[0]), limits.MaxDecodedBytes,
			out, uint64(dataStart), declaredUncompressed, hasUncompressed)
		if err != nil {
			return indexRecord{}, err
		}
		observedCompressed = uint64(consumed)
		p.pos += consumed
	}

	produced := uint64(len(*out) - blockStart)

	// Block Padding pads the compressed data to a multiple of four bytes.
	// It is based on the observed compressed length, which is either the
	// declared size or the length the LZMA2 end mark revealed.
	padding := (4 - int(observedCompressed%4)) % 4
	if p.pos+padding > len(p.data) {
		return indexRecord{}, corrupt(uint64(p.pos), "xz block padding is truncated")
	}
	for i := 0; i < padding; i++ {
		if p.data[p.pos+i] != 0 {
			return indexRecord{}, corrupt(uint64(p.pos+i), "xz block padding is not zero")
		}
	}
	p.pos += padding

	// Check field.
	if checkSize > 0 {
		if p.pos+checkSize > len(p.data) {
			return indexRecord{}, corrupt(uint64(p.pos), "xz block check field is truncated")
		}
		stored := binary.LittleEndian.Uint32(p.data[p.pos : p.pos+checkSize])
		computed := crc32.ChecksumIEEE((*out)[blockStart:])
		if stored != computed {
			return indexRecord{}, corrupt(uint64(p.pos),
				"xz block CRC32 mismatch: stored %#08x, computed %#08x", stored, computed)
		}
		p.pos += checkSize
	}

	return indexRecord{
		unpadded:     uint64(headerSize) + observedCompressed + uint64(checkSize),
		uncompressed: produced,
	}, nil
}

// parseIndex parses the Index field starting at start (the Index Indicator)
// and returns its size including the trailing CRC32.
func (p *parser) parseIndex(start int, records []indexRecord) (uint64, error) {
	if p.pos >= len(p.data) || p.data[p.pos] != 0x00 {
		return 0, corrupt(uint64(p.pos), "xz index indicator is missing")
	}
	p.pos++

	count, err := p.vli()
	if err != nil {
		return 0, err
	}
	if count != uint64(len(records)) {
		return 0, corrupt(uint64(start),
			"xz index declares %d records but the stream has %d blocks", count, len(records))
	}
	for i := range records {
		unpadded, err := p.vli()
		if err != nil {
			return 0, err
		}
		uncompressed, err := p.vli()
		if err != nil {
			return 0, err
		}
		if unpadded != records[i].unpadded || uncompressed != records[i].uncompressed {
			return 0, corrupt(uint64(start),
				"xz index record %d (%d, %d) does not match block (%d, %d)",
				i, unpadded, uncompressed, records[i].unpadded, records[i].uncompressed)
		}
	}

	for (p.pos-start)%4 != 0 {
		if p.pos >= len(p.data) {
			return 0, corrupt(uint64(p.pos), "xz index is truncated")
		}
		if p.data[p.pos] != 0 {
			return 0, corrupt(uint64(p.pos), "xz index padding is not zero")
		}
		p.pos++
	}

	if err := p.need(4); err != nil {
		return 0, err
	}
	stored := binary.LittleEndian.Uint32(p.data[p.pos : p.pos+4])
	if computed := crc32.ChecksumIEEE(p.data[start:p.pos]); stored != computed {
		return 0, corrupt(uint64(p.pos),
			"xz index CRC32 mismatch: stored %#08x, computed %#08x", stored, computed)
	}
	p.pos += 4
	return uint64(p.pos - start), nil
}

// exceedsLimit reports whether current+add exceeds max without overflowing.
func exceedsLimit(current, add, limit uint64) bool {
	return current > limit || add > limit-current
}

func (p *parser) need(n int) error {
	if n < 0 || p.pos > len(p.data)-n {
		return corrupt(uint64(p.pos), "xz stream is truncated at offset %d", p.pos)
	}
	return nil
}

func (p *parser) vli() (uint64, error) {
	var value uint64
	for i := 0; i < 9; i++ {
		if p.pos >= len(p.data) {
			return 0, corrupt(uint64(p.pos), "xz variable-length integer is truncated")
		}
		b := p.data[p.pos]
		p.pos++
		value |= uint64(b&0x7F) << (7 * i)
		if b&0x80 == 0 {
			if b == 0 && i != 0 {
				return 0, corrupt(uint64(p.pos-1), "xz variable-length integer is not minimally encoded")
			}
			return value, nil
		}
	}
	return 0, corrupt(uint64(p.pos-1), "xz variable-length integer is too long")
}

// cursor is a bounded VLI reader over the block-header body.
type cursor struct {
	buf []byte
	pos int
}

func (c *cursor) vli() (uint64, error) {
	var value uint64
	for i := 0; i < 9; i++ {
		if c.pos >= len(c.buf) {
			return 0, fmt.Errorf("variable-length integer is truncated")
		}
		b := c.buf[c.pos]
		c.pos++
		value |= uint64(b&0x7F) << (7 * i)
		if b&0x80 == 0 {
			if b == 0 && i != 0 {
				return 0, fmt.Errorf("variable-length integer is not minimally encoded")
			}
			return value, nil
		}
	}
	return 0, fmt.Errorf("variable-length integer is too long")
}
