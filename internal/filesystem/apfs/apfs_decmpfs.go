package apfs

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
)

// APFS transparent compression (decmpfs).
//
// macOS stores most system binaries as transparently compressed files: the
// inode is dataless (no data-fork extents) and carries a com.apple.decmpfs
// xattr whose payload is a 16-byte header
//
//	{ magic u32 = 'fpmc', compression_type u32, uncompressed_size u64 }
//
// followed (for inline algorithms) by the compressed data. Algorithms with a
// "resource fork" storage keep the payload in the com.apple.ResourceFork xattr,
// which is a separate data stream split into 64 KiB chunks indexed by a u32
// offset table. Type/algorithm mapping (apfs-fuse Decmpfs.cpp):
//
//	3  Zlib      inline   7  LZVN       inline    9  raw inline
//	11 LZFSE     inline   13 LZBitmap   inline
//	4  Zlib      rsrc     8  LZVN       rsrc     10 raw rsrc
//	12 LZFSE     rsrc     14 LZBitmap   rsrc
//
// Zlib chunks start with 0x78 (zlib header) or 0xFF (raw copy). Raw-copy and
// "uncompressed" chunks (and LZVN chunks whose first byte is 0x06) carry the
// data verbatim. LZFSE and LZBitmap are not implemented; they return an
// explicit error rather than fabricated data (EWF 红线).

const (
	apfsDecmpfsMagic = 0x636d7066 // 'fpmc'
	apfsCmpfChunk    = 0x10000    // 64 KiB per compressed chunk
)

// apfsDecmpfsSize returns the uncompressed size declared by an inode's
// com.apple.decmpfs xattr header, or 0 when the inode is not compressed (no
// xattr, bad magic, or a stream-stored xattr that would need a read). Compressed
// files are dataless: the dstream xfield's size is unreliable (0 for some files,
// the uncompressed size for others, verified on mac.E01), so the decmpfs header
// is the authoritative size and the index reports it as the file size.
func apfsDecmpfsSize(xas []apfsXattr) uint64 {
	for _, xa := range xas {
		if xa.name != "com.apple.decmpfs" {
			continue
		}
		if xa.dataOID != 0 || len(xa.value) < 4+16 {
			return 0
		}
		payload := xa.value[4:] // strip {flags u16, xdata_len u16}
		if binary.LittleEndian.Uint32(payload[0:4]) != apfsDecmpfsMagic {
			return 0
		}
		return binary.LittleEndian.Uint64(payload[8:16])
	}
	return 0
}

// apfsReadDecmpfs returns the decompressed content of a compressed inode, or
// (nil, nil) when the inode carries no com.apple.decmpfs xattr (not compressed).
// A present but malformed xattr is an explicit error, never silent zeros.
func (apfs *APFS) apfsReadDecmpfs(ino uint64) ([]byte, error) {
	var payload []byte
	found := false
	for _, xa := range apfs.index.xattrs[ino] {
		if xa.name != "com.apple.decmpfs" {
			continue
		}
		found = true
		if xa.dataOID != 0 { // dataless decmpfs xattr stored as a stream
			p, err := apfs.apfsReadStream(xa.dataOID, xa.dataSize)
			if err != nil {
				return nil, err
			}
			payload = p
		} else if len(xa.value) >= 4 {
			payload = xa.value[4:] // strip {flags u16, xdata_len u16}
		}
		break
	}
	if !found {
		return nil, nil
	}
	if len(payload) < 16 {
		return nil, fmt.Errorf("APFS: inode %d com.apple.decmpfs xattr too short (%d bytes)", ino, len(payload))
	}
	if binary.LittleEndian.Uint32(payload[0:4]) != apfsDecmpfsMagic {
		return nil, fmt.Errorf("APFS: inode %d has an invalid com.apple.decmpfs magic", ino)
	}
	typ := binary.LittleEndian.Uint32(payload[4:8])
	size := binary.LittleEndian.Uint64(payload[8:16])
	var out []byte
	var err error
	switch {
	case typ == 3 || typ == 7 || typ == 9 || typ == 11 || typ == 13:
		out, err = apfs.decmpfsInline(typ, size, payload[16:])
	case typ == 4 || typ == 8 || typ == 10 || typ == 12 || typ == 14:
		out, err = apfs.decmpfsRsrc(ino, typ, size)
	default:
		return nil, fmt.Errorf("APFS: inode %d uses unsupported decmpfs type %d", ino, typ)
	}
	if err != nil {
		return nil, err
	}
	if uint64(len(out)) != size {
		return nil, fmt.Errorf("APFS: inode %d decmpfs produced %d bytes, want %d", ino, len(out), size)
	}
	return out, nil
}

// decmpfsInline decompresses an inline (odd-type) payload to size bytes.
func (apfs *APFS) decmpfsInline(typ uint32, size uint64, cdata []byte) ([]byte, error) {
	if len(cdata) == 0 {
		return nil, fmt.Errorf("APFS: inline decmpfs payload empty")
	}
	switch typ {
	case 3: // Zlib
		switch cdata[0] {
		case 0x78:
			return inflateZlib(cdata, size)
		case 0xFF:
			return cdata[1:], nil
		}
		return nil, fmt.Errorf("APFS: inline decmpfs type 3 chunk has bad zlib marker 0x%02x", cdata[0])
	case 7: // LZVN
		if cdata[0] == 0x06 {
			return cdata[1:], nil
		}
		return lzvnDecompress(cdata, uint32(size))
	case 9: // uncompressed
		return cdata[1:], nil
	case 11: // LZFSE
		return nil, fmt.Errorf("APFS: LZFSE decompression not implemented (decmpfs type 11)")
	case 13: // LZBitmap
		if cdata[0] == 0xFF {
			return cdata[1:], nil
		}
		return nil, fmt.Errorf("APFS: LZBitmap decompression not implemented (decmpfs type 13)")
	}
	return nil, fmt.Errorf("APFS: unsupported inline decmpfs type %d", typ)
}

// decmpfsRsrc decompresses a resource-fork (even-type) payload. The resource
// fork is read through the com.apple.ResourceFork xattr's external stream.
func (apfs *APFS) decmpfsRsrc(ino uint64, typ uint32, size uint64) ([]byte, error) {
	var rsrc []byte
	for _, xa := range apfs.index.xattrs[ino] {
		if xa.name != "com.apple.ResourceFork" {
			continue
		}
		if xa.dataOID != 0 {
			p, err := apfs.apfsReadStream(xa.dataOID, xa.dataSize)
			if err != nil {
				return nil, err
			}
			rsrc = p
		} else if len(xa.value) >= 4 {
			rsrc = xa.value[4:]
		}
		break
	}
	if rsrc == nil {
		return nil, fmt.Errorf("APFS: inode %d decmpfs type %d has no com.apple.ResourceFork", ino, typ)
	}
	if typ == 4 {
		return apfs.decmpfsRsrcZlib(rsrc, size)
	}
	return decmpfsRsrcChunks(typ, rsrc, size)
}

// decmpfsRsrcZlib handles the zlib resource fork: a big-endian RsrcForkHeader,
// then a CmpfRsrc table of {off, size} entries pointing at each chunk.
func (apfs *APFS) decmpfsRsrcZlib(rsrc []byte, size uint64) ([]byte, error) {
	if len(rsrc) < 16 {
		return nil, fmt.Errorf("APFS: zlib resource fork shorter than RsrcForkHeader")
	}
	dataOffset := binary.BigEndian.Uint32(rsrc[0:4]) // be_uint32_t
	if dataOffset > uint32(len(rsrc)) {
		return nil, fmt.Errorf("APFS: zlib resource fork has invalid data offset %d", dataOffset)
	}
	base := int(dataOffset) + 4 // skip the 4-byte data length after the offset
	if base+4 > len(rsrc) {
		return nil, fmt.Errorf("APFS: zlib resource fork CmpfRsrc out of range")
	}
	entries := binary.LittleEndian.Uint32(rsrc[base:])
	if entries > 64 { // a file decompressing to >4 GiB is not plausible here
		return nil, fmt.Errorf("APFS: zlib resource fork has implausible %d chunks", entries)
	}
	out := make([]byte, 0, size)
	for k := uint32(0); k < entries; k++ {
		pos := base + 4 + 8*int(k)
		if pos+8 > len(rsrc) {
			return nil, fmt.Errorf("APFS: zlib resource fork chunk table truncated")
		}
		off := binary.LittleEndian.Uint32(rsrc[pos:])
		chunkLen := binary.LittleEndian.Uint32(rsrc[pos+4:])
		s := base + int(off)
		if s < 0 || s+int(chunkLen) > len(rsrc) {
			return nil, fmt.Errorf("APFS: zlib resource fork chunk %d out of range", k)
		}
		src := rsrc[s : s+int(chunkLen)]
		want := uint64(apfsCmpfChunk)
		if size-uint64(k)*apfsCmpfChunk < want {
			want = size - uint64(k)*apfsCmpfChunk
		}
		var chunk []byte
		var err error
		switch {
		case src[0] == 0x78:
			chunk, err = inflateZlib(src, want)
		case src[0]&0x0f == 0x0f:
			chunk = src[1:]
		default:
			err = fmt.Errorf("APFS: zlib resource fork chunk %d has bad marker 0x%02x", k, src[0])
		}
		if err != nil {
			return nil, err
		}
		if uint64(len(chunk)) != want {
			return nil, fmt.Errorf("APFS: zlib chunk %d produced %d bytes, want %d", k, len(chunk), want)
		}
		out = append(out, chunk...)
	}
	return out, nil
}

// decmpfsRsrcChunks handles the offset-table resource forks (LZVN, raw,
// LZBitmap): a u32 LE array of chunk start offsets; chunk k spans
// [off_list[k], off_list[k+1]) and decompresses to min(64 KiB, remaining).
func decmpfsRsrcChunks(typ uint32, rsrc []byte, size uint64) ([]byte, error) {
	numChunks := int((size + apfsCmpfChunk - 1) / apfsCmpfChunk)
	if numChunks == 0 {
		return []byte{}, nil
	}
	if len(rsrc) < 4*(numChunks+1) {
		return nil, fmt.Errorf("APFS: resource fork offset table too short (%d bytes, need %d)", len(rsrc), 4*(numChunks+1))
	}
	out := make([]byte, 0, size)
	for k := 0; k < numChunks; k++ {
		start := binary.LittleEndian.Uint32(rsrc[4*k:])
		end := binary.LittleEndian.Uint32(rsrc[4*(k+1):])
		if int(end) > len(rsrc) || start >= end {
			return nil, fmt.Errorf("APFS: resource fork chunk %d has bad range %d..%d", k, start, end)
		}
		src := rsrc[start:end]
		want := uint64(apfsCmpfChunk)
		if size-uint64(k)*apfsCmpfChunk < want {
			want = size - uint64(k)*apfsCmpfChunk
		}
		var chunk []byte
		var err error
		switch typ {
		case 8: // LZVN
			if src[0] == 0x06 {
				chunk = src[1:] // raw copy marker
			} else {
				chunk, err = lzvnDecompress(src, uint32(want))
			}
		case 10: // uncompressed
			chunk = src[1:]
		case 12: // LZFSE
			return nil, fmt.Errorf("APFS: LZFSE decompression not implemented (decmpfs type 12)")
		case 14: // LZBitmap
			if src[0] == 0xFF {
				chunk = src[1:]
			} else {
				return nil, fmt.Errorf("APFS: LZBitmap decompression not implemented (decmpfs type 14)")
			}
		}
		if err != nil {
			return nil, err
		}
		if uint64(len(chunk)) != want {
			return nil, fmt.Errorf("APFS: resource fork chunk %d produced %d bytes, want %d", k, len(chunk), want)
		}
		out = append(out, chunk...)
	}
	return out, nil
}

// inflateZlib inflates src (a zlib stream) to exactly want bytes, rejecting
// both under- and over-long output so a corrupt chunk is an explicit error.
func inflateZlib(src []byte, want uint64) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(src))
	if err != nil {
		return nil, fmt.Errorf("APFS: invalid zlib stream: %w", err)
	}
	defer zr.Close()
	out := make([]byte, int(want))
	if _, err := io.ReadFull(zr, out); err != nil {
		return nil, fmt.Errorf("APFS: zlib stream shorter than %d bytes: %w", want, err)
	}
	var extra [1]byte
	if n, _ := zr.Read(extra[:]); n > 0 {
		return nil, fmt.Errorf("APFS: zlib stream inflates beyond %d bytes", want)
	}
	return out, nil
}
