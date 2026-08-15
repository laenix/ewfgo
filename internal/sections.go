package internal

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

// readSectionAt reads the 76-byte section descriptor at address. A nil buffer
// or an unreadable descriptor is an explicit error.
func (e *EWFImage) readSectionAt(address int64) (*Section, error) {
	section := &Section{}
	buf := e.ReadAt(address, SectionLength)
	if buf == nil {
		return nil, fmt.Errorf("failed to read section at 0x%x", address)
	}
	err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, section)
	return section, err
}

// ReadSections walks the section chain of every segment file. Each segment's
// NextOffset is relative to the start of that segment's file, so the walk adds
// the segment's cumulative offset to recover the logical image offset.
func (e *EWFImage) ReadSections() error {
	for segIdx, seg := range e.segments {
		address := seg.start + EWFFileHeaderLength

		for {
			section, err := e.readSectionAt(address)
			if err != nil {
				return err
			}
			e.Sections = append(e.Sections, SectionWithAddress{
				Address: address,
				Section: *section,
				Segment: segIdx,
			})
			if string(bytes.TrimRight(section.SectionTypeDefinition[:], "\x00")) == "done" {
				break
			}
			if section.NextOffset == 0 {
				break
			}
			next := seg.start + int64(section.NextOffset)
			// NextOffset is relative to the segment file start and must move
			// forward; a crafted backward/cyclic pointer must not loop forever.
			if next <= address {
				break
			}
			address = next
		}
	}
	return nil
}

func (e *EWFImage) ParseSections() error {
	for _, v := range e.Sections {
		switch string(bytes.TrimRight(v.SectionTypeDefinition[:], "\x00")) {
		case "header2":
			if err := e.ParseHeader(v); err != nil {
				return err
			}
		case "header":
			if err := e.ParseHeader(v); err != nil {
				return err
			}
		case "volume", "disk":
			e.ParseVolume(v)
		case "sectors":
			e.AddSectorsAddress(v)
		case "table":
			e.AddTableAddress(v)
		case "digest":
			e.ParsesDigest(v)
		case "hash":
			e.ParsesHash(v)
		}
	}

	// EnCase 1 layout: chunk data lives inside the table section and there is no
	// separate "sectors" section. Detect it by the absence of sectors sections:
	// every other supported layout (EnCase 2-7, FTK) pairs a sectors section with
	// each table. Synthesize the sectors list directly from the table sections so
	// the existing read path handles the layout unchanged. BaseOffset is read
	// from the table header bytes [8:16]; a chunk's file offset is
	// segmentStart + BaseOffset + (entry & 0x7fffffff), matching the unified
	// offset model used by readChunkForSection.
	if len(e.TableAddress) > 0 && len(e.SectorsAddress) == 0 {
		for _, t := range e.TableAddress {
			tableEntry, baseOffset, err := e.ParseTable(t)
			if err != nil {
				return err
			}
			e.Sectors = append(e.Sectors, SectorAndTableWithAddress{
				Address:    t.Address,
				TableEntry: tableEntry,
				BaseOffset: baseOffset,
				Segment:    t.Segment,
			})
		}
		return nil
	}

	for k, v := range e.SectorsAddress {
		if k >= len(e.TableAddress) {
			return fmt.Errorf("sectors section %d has no matching table section (%d sectors sections, %d table sections)",
				k, len(e.SectorsAddress), len(e.TableAddress))
		}
		tableEntry, baseOffset, err := e.ParseTable(e.TableAddress[k])
		if err != nil {
			return err
		}
		// Chunk offsets and base offsets are relative to the segment file that
		// holds the TABLE section, so the pairing must carry the table's
		// segment index — not the sectors section's (they can differ in a
		// crafted/cross-segment chain; the EnCase 1 synthesis path already uses
		// t.Segment).
		e.Sectors = append(e.Sectors, SectorAndTableWithAddress{
			Address:    v.Address,
			TableEntry: tableEntry,
			BaseOffset: baseOffset,
			Segment:    e.TableAddress[k].Segment,
		})
	}
	return nil
}

// 3.3 3.4
func (e *EWFImage) ParseHeader(s SectionWithAddress) error {
	// The header payload is the section minus its 76-byte descriptor. Bound it
	// against the actual image so a crafted SectionSize near 2^63 cannot drive
	// make([]byte, ~2^63) inside ReadAt (OOM panic) — the same guard class
	// ParseTable uses. A section with SectionSize < 76 would also yield a
	// negative length; reject it explicitly rather than letting ReadAt silently
	// return nil.
	payloadBytes := int64(s.SectionSize) - SectionLength
	if payloadBytes < 0 {
		return fmt.Errorf("header section at 0x%x too small (%d bytes)", s.Address, s.SectionSize)
	}
	if total := e.totalSize(); total > 0 {
		payloadStart := s.Address + SectionLength
		// payloadStart+payloadBytes must fit inside the image; compare against
		// the remainder to avoid an overflowing sum.
		if payloadStart < 0 || payloadStart >= total || payloadBytes > total-payloadStart {
			return fmt.Errorf("header section at 0x%x extends beyond image size %d", s.Address, total)
		}
	}
	buf := e.ReadAt(s.Address+SectionLength, payloadBytes)
	r, err := zlib.NewReader(bytes.NewReader(buf))
	if err != nil {
		return err
	}
	var header bytes.Buffer
	io.Copy(&header, r)
	defer r.Close()
	var linesdata string
	// BOM
	// A crafted header section can decompress to fewer than 2 bytes; never
	// index header.Bytes() before checking its length (forensics golden rule).
	if header.Len() >= 2 {
		// UTF-16 BE
		if header.Bytes()[0] == 0xfe && header.Bytes()[1] == 0xff {
			utf16be := unicode.UTF16(unicode.BigEndian, unicode.ExpectBOM)
			decoder := utf16be.NewDecoder()
			utf8Data, _, err := transform.Bytes(decoder, header.Bytes())
			if err == nil {
				linesdata = string(utf8Data)
			}
		}
		// UTF-16 LE
		if header.Bytes()[0] == 0xff && header.Bytes()[1] == 0xfe {
			utf16le := unicode.UTF16(unicode.LittleEndian, unicode.ExpectBOM)
			decoder := utf16le.NewDecoder()
			utf8Data, _, err := transform.Bytes(decoder, header.Bytes())
			if err == nil {
				linesdata = string(utf8Data)
			}
		}
	}
	// UTF-8
	if linesdata == "" {
		linesdata = header.String()
	}
	lines := strings.Split(linesdata, "\n")
	// The parser needs line 3 (identifiers) and line 4 (values); a crafted
	// header with fewer lines would panic on lines[2]/lines[3].
	if len(lines) < 4 {
		return fmt.Errorf("malformed header section at 0x%x: got %d lines, need at least 4", s.Address, len(lines))
	}
	var flags []string
	var values []string
	flags = append(flags, strings.Split(lines[2], "\t")...)
	values = append(values, strings.Split(lines[3], "\t")...)

	if len(flags) == len(values) {
		headerSectionString := HeaderSectionString{}
		for k, flag := range flags {
			switch flag {
			case "a":
				headerSectionString.L3_a = values[k]
			case "c":
				headerSectionString.L3_c = values[k]
			case "n":
				headerSectionString.L3_n = values[k]
			case "e":
				headerSectionString.L3_e = values[k]
			case "t":
				headerSectionString.L3_t = values[k]
			case "av":
				headerSectionString.L3_av = values[k]
			case "ov":
				headerSectionString.L3_ov = values[k]
			case "m":
				headerSectionString.L3_m = values[k]
			case "u":
				headerSectionString.L3_u = values[k]
			case "p":
				headerSectionString.L3_p = values[k]
			case "md":
				headerSectionString.L3_md = values[k]
			case "sn":
				headerSectionString.L3_sn = values[k]
			case "l":
				headerSectionString.L3_l = values[k]
			case "pid":
				headerSectionString.L3_pid = values[k]
			case "dc":
				headerSectionString.L3_dc = values[k]
			case "ext":
				headerSectionString.L3_ext = values[k]
			}
		}
		e.Headers = append(e.Headers, headerSectionString)
	}
	return nil
}

// 3.5 Volume
func (e *EWFImage) ParseVolume(s SectionWithAddress) error {
	var err error
	// EWFSpecification 94 bytes
	if s.SectionSize > uint64(SectionLength)+uint64(DiskSMARTLength) {
		var ewfSpecification EWFSpecification
		buf := e.ReadAt(s.Address+SectionLength, EWFSpecificationLength)
		if buf != nil {
			err = binary.Read(bytes.NewReader(buf), binary.LittleEndian, &ewfSpecification)
		}
		if err != nil {
			return err
		}
	}
	// SMART 1052 bytes
	if s.SectionSize == uint64(SectionLength)+uint64(DiskSMARTLength) {
		var diskSMART DiskSMART
		buf := e.ReadAt(s.Address+SectionLength, DiskSMARTLength)
		if buf != nil {
			err = binary.Read(bytes.NewReader(buf), binary.LittleEndian, &diskSMART)
		}
		if err != nil {
			return err
		}
		e.DiskSMART = append(e.DiskSMART, diskSMART)
	}
	return err
}

// 3.8 Sector
func (e *EWFImage) AddSectorsAddress(s SectionWithAddress) error {
	e.SectorsAddress = append(e.SectorsAddress, s)
	return nil
}

// 3.9 Table
func (e *EWFImage) AddTableAddress(s SectionWithAddress) error {
	e.TableAddress = append(e.TableAddress, s)
	return nil
}

// ParseTable parses the table section at s, returning the chunk offset entries
// and the EnCase 6+ table base offset (0 for EnCase 1-5 / FTK / EnCase 2-5).
func (e *EWFImage) ParseTable(s SectionWithAddress) ([]uint32, uint64, error) {
	if s.SectionSize < uint64(SectionLength+TableSectionLength) {
		return nil, 0, fmt.Errorf("table section at 0x%x too small (%d bytes)", s.Address, s.SectionSize)
	}
	tableHeaderBuf := e.ReadAt(s.Address+SectionLength, TableSectionLength)
	if len(tableHeaderBuf) < int(TableSectionLength) {
		return nil, 0, fmt.Errorf("table section at 0x%x truncated", s.Address)
	}
	// EnCase 6-7 store the table base offset at header offset 8..16.
	baseOffset := binary.LittleEndian.Uint64(tableHeaderBuf[8:16])

	payloadBytes := int64(s.SectionSize) - SectionLength - TableSectionLength
	// At least one 4-byte entry + the 4-byte Adler-32 footer (payloadBytes >= 8).
	if payloadBytes < 2*chunkFooterLen {
		return nil, 0, fmt.Errorf("table section at 0x%x has no entries", s.Address)
	}
	// Bound the payload read to the actual image so a crafted SectionSize cannot
	// force a huge allocation (OOM) against a small image (kept from the
	// existing parser). The bound is against the logical image size across all
	// segments, so a table section in segment 2 is validated against segment 2's
	// extent.
	if total := e.totalSize(); total > 0 {
		payloadStart := s.Address + SectionLength + TableSectionLength
		// The payload must start inside the image and fit entirely within it.
		// A crafted table whose descriptor sits in the last 100 bytes has
		// payloadStart >= total, which previously skipped this guard entirely
		// (the old `payloadStart < total` precondition) and let a SectionSize
		// near 2^63 slip through to make([]byte, ~2^63) in ReadAt (panic).
		// Never panic — error. Also avoid the overflowing sum
		// payloadStart+payloadBytes: compare against the remainder instead.
		if payloadStart < 0 || payloadStart >= total || payloadBytes > total-payloadStart {
			return nil, 0, fmt.Errorf("table section at 0x%x extends beyond image size %d", s.Address, total)
		}
	}
	entryCount := (payloadBytes - chunkFooterLen) / 4
	buf := e.ReadAt(s.Address+SectionLength+TableSectionLength, payloadBytes)
	if int64(len(buf)) < payloadBytes {
		return nil, 0, fmt.Errorf("table section at 0x%x truncated", s.Address)
	}
	tableEntry := make([]uint32, entryCount)
	err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, &tableEntry)
	// DO NOT mask off bit 31 - it contains the compression flag!
	return tableEntry, baseOffset, err
}

// digestHashPayload returns the bytes of a digest/hash section payload, or nil
// if the section is too small or would extend beyond the image. Mirror the
// bounds guard ParseHeader uses so a crafted SectionSize cannot drive a huge
// allocation in ReadAt.
func (e *EWFImage) digestHashPayload(s SectionWithAddress, minBytes int64) []byte {
	if int64(s.SectionSize) < SectionLength+minBytes {
		return nil
	}
	payloadBytes := int64(s.SectionSize) - SectionLength
	if total := e.totalSize(); total > 0 {
		payloadStart := s.Address + SectionLength
		if payloadStart < 0 || payloadStart >= total || payloadBytes > total-payloadStart {
			return nil
		}
	}
	buf := e.ReadAt(s.Address+SectionLength, payloadBytes)
	if int64(len(buf)) < minBytes {
		return nil
	}
	return buf
}

// 3.17 Digest
// The digest section stores the MD5 and SHA1 hashes of the acquired data at the
// start of its payload: bytes [0:16] MD5, [16:36] SHA1 (an SHA1-only digest has
// a 20-byte payload and contributes only StoredSHA1).
func (e *EWFImage) ParsesDigest(s SectionWithAddress) {
	buf := e.digestHashPayload(s, 16)
	if buf == nil {
		return
	}
	e.StoredMD5 = append(e.StoredMD5[:0], buf[:16]...)
	if len(buf) >= 36 {
		e.StoredSHA1 = append(e.StoredSHA1[:0], buf[16:36]...)
	}
}

// 3.18 Hash
// The hash section stores the MD5 hash at the start of its payload ([0:16]).
func (e *EWFImage) ParsesHash(s SectionWithAddress) {
	buf := e.digestHashPayload(s, 16)
	if buf == nil {
		return
	}
	e.StoredMD5 = append(e.StoredMD5[:0], buf[:16]...)
}
