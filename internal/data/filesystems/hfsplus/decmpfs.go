package hfsplus

// macOS transparent compression (`decmpfs`) on HFS+.
//
// A compressed file is dataless: its data fork holds no content and, usually,
// no allocated blocks.  The real content is described by the
// `com.apple.decmpfs` extended attribute (one record in the attributes B-tree):
//
//	header: [magic "fpmc"][compression type u32 LE][uncompressed size u64 LE]
//
// The bytes after the header are the compressed stream for the inline methods.
// The resource-fork methods keep the stream in the file's resource fork instead.
// For those, the classic HFS+ resource fork starts with a big-endian data
// offset; the four bytes at that offset are the stream's big-endian length and
// the stream follows.  This is the layout implemented here and in the Rust
// reference (filesystems/decmpfs.rs).  (The APFS reader in this repository
// additionally understands APFS's little-endian chunk offset table; HFS+
// decmpfs writes the classic big-endian single-stream layout, so that table is
// not consulted here.)
//
// Methods (the numbers on disk):
//
//	1  uncompressed inline      3  zlib inline       4  zlib resource fork
//	7  LZVN inline              8  LZVN resource     9  raw inline
//	11 LZFSE inline            12  LZFSE resource   10  raw resource fork
//	13 LZBitmap inline         14  LZBitmap resource fork
//
// Types 13/14 are refused by name unless the stored stream is the one-byte
// 0xFF raw-copy marker, which is served verbatim.  Every decoded stream is
// checked against the header's declared size; a short, long, truncated, or
// otherwise malformed stream is an explicit error, never zeros and never the
// compressed bytes.

import (
	"bytes"
	"compress/zlib"
	"io"

	"github.com/laenix/ewfgo/internal/data/compression/lzfse"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// DecmpfsAttribute is the extended attribute that carries the header and,
	// for inline methods, the compressed stream.
	DecmpfsAttribute = "com.apple.decmpfs"
	// ResourceForkAttribute names the attribute some volumes use for the
	// resource-fork stream; when absent the catalog's resource fork is read.
	ResourceForkAttribute = "com.apple.ResourceFork"

	// decmpfsMagic is "fpmc" as stored on disk (the letters of "cmpf" in
	// little-endian order).
	decmpfsMagic = "fpmc"
	// decmpfsHeaderLen is the header before any inline stream.
	decmpfsHeaderLen = 16
	// maxDecmpfsDecoded bounds one decoded file, matching the Rust reference.
	maxDecmpfsDecoded uint64 = 256 << 20
	// maxDecmpfsResource bounds the compressed resource fork this reader
	// materialises.
	maxDecmpfsResource uint64 = 256 << 20
)

// decmpfsCompressionType is the method number stored in the header.
type decmpfsCompressionType uint32

const (
	decmpfsUncompressedInline decmpfsCompressionType = 1
	decmpfsZlibInline         decmpfsCompressionType = 3
	decmpfsZlibResource       decmpfsCompressionType = 4
	decmpfsLZVNInline         decmpfsCompressionType = 7
	decmpfsLZVNResource       decmpfsCompressionType = 8
	decmpfsRawInline          decmpfsCompressionType = 9
	decmpfsRawResource        decmpfsCompressionType = 10
	decmpfsLZFSEInline        decmpfsCompressionType = 11
	decmpfsLZFSEEResource     decmpfsCompressionType = 12
	decmpfsLZBitmapInline     decmpfsCompressionType = 13
	decmpfsLZBitmapResource   decmpfsCompressionType = 14
)

// needsResourceFork reports whether the stream lives in the resource fork.
func (t decmpfsCompressionType) needsResourceFork() bool {
	switch t {
	case decmpfsZlibResource, decmpfsLZVNResource, decmpfsRawResource, decmpfsLZFSEEResource, decmpfsLZBitmapResource:
		return true
	default:
		return false
	}
}

// decmpfsHeader is the parsed 16-byte com.apple.decmpfs header.
type decmpfsHeader struct {
	Method decmpfsCompressionType
	Size   uint64
}

// parseDecmpfsHeader parses the attribute value.  The returned header
// describes the bytes after decmpfsHeaderLen.
func parseDecmpfsHeader(value []byte) (decmpfsHeader, error) {
	if len(value) < decmpfsHeaderLen {
		return decmpfsHeader{}, invalidf("decmpfs attribute is %d bytes, shorter than its %d byte header",
			len(value), decmpfsHeaderLen)
	}
	if string(value[:4]) != decmpfsMagic {
		return decmpfsHeader{}, invalidf("decmpfs attribute starts with % X, expected the %q magic",
			value[:4], decmpfsMagic)
	}
	raw := le32(value, 4)
	size := le64(value, 8)
	if size > maxDecmpfsDecoded {
		return decmpfsHeader{}, unsupportedf("decmpfs declares %d uncompressed bytes, above the %d byte limit",
			size, maxDecmpfsDecoded)
	}
	switch decmpfsCompressionType(raw) {
	case decmpfsUncompressedInline, decmpfsZlibInline, decmpfsZlibResource,
		decmpfsLZVNInline, decmpfsLZVNResource, decmpfsRawInline, decmpfsRawResource,
		decmpfsLZFSEInline, decmpfsLZFSEEResource, decmpfsLZBitmapInline, decmpfsLZBitmapResource:
		return decmpfsHeader{Method: decmpfsCompressionType(raw), Size: size}, nil
	default:
		return decmpfsHeader{}, unsupportedf("decmpfs compression type %d is not a documented method", raw)
	}
}

// decode decodes the content.  inline is the attribute value after its header;
// resource is the resource fork, required by the resource-fork methods.
func (h decmpfsHeader) decode(inline, resource []byte) ([]byte, error) {
	switch h.Method {
	case decmpfsUncompressedInline:
		// The Rust reference serves the first declared bytes, even when the
		// attribute stores more.
		if uint64(len(inline)) < h.Size {
			return nil, invalidf("decmpfs inline value holds %d bytes, short of its declared %d",
				len(inline), h.Size)
		}
		return append([]byte(nil), inline[:h.Size]...), nil

	case decmpfsZlibInline:
		return decodeZlibInline(inline, h.Size, "the decmpfs attribute")
	case decmpfsZlibResource:
		stream, err := decmpfsResourceStream(resource)
		if err != nil {
			return nil, err
		}
		return decodeZlibInline(stream, h.Size, "the resource fork")

	case decmpfsLZVNInline:
		return decodeLZVNInline(inline, h.Size, "the decmpfs attribute")
	case decmpfsLZVNResource:
		stream, err := decmpfsResourceStream(resource)
		if err != nil {
			return nil, err
		}
		return decodeLZVNInline(stream, h.Size, "the resource fork")

	case decmpfsRawInline:
		return decodeRawPayload(inline, h.Size)
	case decmpfsRawResource:
		stream, err := decmpfsResourceStream(resource)
		if err != nil {
			return nil, err
		}
		return decodeRawPayload(stream, h.Size)

	case decmpfsLZFSEInline:
		return decodeLZFSEInline(inline, h.Size, "the decmpfs attribute")
	case decmpfsLZFSEEResource:
		stream, err := decmpfsResourceStream(resource)
		if err != nil {
			return nil, err
		}
		return decodeLZFSEInline(stream, h.Size, "the resource fork")

	case decmpfsLZBitmapInline:
		if len(inline) > 0 && inline[0] == 0xFF {
			return decodeRawInline(inline[1:], h.Size)
		}
		return nil, unsupportedf("LZBitmap decompression is not implemented (decmpfs type 13)")
	case decmpfsLZBitmapResource:
		stream, err := decmpfsResourceStream(resource)
		if err != nil {
			return nil, err
		}
		if len(stream) > 0 && stream[0] == 0xFF {
			return decodeRawInline(stream[1:], h.Size)
		}
		return nil, unsupportedf("LZBitmap decompression is not implemented (decmpfs type 14)")
	}
	return nil, unsupportedf("decmpfs compression type %d is not decodable", h.Method)
}

// decmpfsResourceStream extracts the stream from a classic resource fork: a
// big-endian offset at byte 0, then a big-endian length at that offset, then
// the stream itself.
func decmpfsResourceStream(resource []byte) ([]byte, error) {
	if resource == nil {
		return nil, invalidf("decmpfs names its stream in the resource fork, but no resource fork is present")
	}
	if len(resource) < 16 {
		return nil, invalidf("resource fork is %d bytes, too short for its header", len(resource))
	}
	offset := uint64(be32(resource, 0))
	if offset < 16 || offset+4 > uint64(len(resource)) {
		return nil, invalidf("resource fork's data offset %d does not point at a chunk inside its %d bytes",
			offset, len(resource))
	}
	length := uint64(be32(resource, int(offset)))
	start := offset + 4
	if length > uint64(len(resource))-start {
		return nil, invalidf("resource fork chunk declares %d bytes at %d, past its %d bytes",
			length, start, len(resource))
	}
	return resource[start : start+length], nil
}

// decodeZlibInline inflates stored to exactly size bytes.  A leading 0xFF is
// the decmpfs raw-copy marker; it is served verbatim, as in the APFS reader.
//
// All stored bytes must belong to the zlib stream: trailing bytes mean the
// declared size or the stream boundaries are wrong, and are refused.
func decodeZlibInline(stored []byte, size uint64, what string) ([]byte, error) {
	if len(stored) > 0 && stored[0] == 0xFF && uint64(len(stored)-1) == size {
		return decodeRawInline(stored[1:], size)
	}
	reader := bytes.NewReader(stored)
	zr, err := zlib.NewReader(reader)
	if err != nil {
		return nil, invalidf("%s holds a broken zlib stream: %v", what, err)
	}
	defer zr.Close()

	// Read one byte past the target so an oversized stream is detected without
	// letting a corrupt length inflate without bound.  bytes.Reader implements
	// io.ByteReader, so flate does not read ahead and the remaining count is
	// exact.
	out, err := io.ReadAll(io.LimitReader(zr, int64(size)+1))
	if err != nil {
		return nil, invalidf("%s holds a broken zlib stream: %v", what, err)
	}
	if uint64(len(out)) != size {
		return nil, invalidf("%s produces %d bytes, not its declared %d", what, len(out), size)
	}
	if reader.Len() != 0 {
		return nil, invalidf("%s has %d stored bytes after its zlib stream", what, reader.Len())
	}
	return out, nil
}

// decodeLZVNInline decodes an LZVN stream to exactly size bytes.  A leading
// 0x06 byte is the decmpfs raw-copy marker.
func decodeLZVNInline(stored []byte, size uint64, what string) ([]byte, error) {
	if len(stored) > 0 && stored[0] == 0x06 && uint64(len(stored)-1) == size {
		return decodeRawInline(stored[1:], size)
	}
	out, err := decodeLZVN(stored, uint32(size))
	if err != nil {
		return nil, invalidf("%s holds a broken LZVN stream: %v", what, err)
	}
	if uint64(len(out)) != size {
		return nil, invalidf("%s produces %d bytes, not its declared %d", what, len(out), size)
	}
	return out, nil
}

// decodeLZFSEInline decodes an LZFSE stream to exactly size bytes.
func decodeLZFSEInline(stored []byte, size uint64, what string) ([]byte, error) {
	limit := size
	if limit == 0 {
		// The decoder treats zero as "use the default limit"; one byte is
		// enough to prove an empty file is empty.
		limit = 1
	}
	out, err := lzfse.Decode(stored, lzfse.Limits{MaxOutputBytes: limit})
	if err != nil {
		return nil, invalidf("%s holds a broken LZFSE stream: %v", what, err)
	}
	if uint64(len(out)) != size {
		return nil, invalidf("%s produces %d bytes, not its declared %d", what, len(out), size)
	}
	return out, nil
}

// decodeRawPayload serves a raw decmpfs stream.  Some writers prefix a raw
// chunk with the 0xFF raw-copy marker; when the stored bytes are exactly one
// longer than the declared size that marker is stripped.
func decodeRawPayload(stored []byte, size uint64) ([]byte, error) {
	if len(stored) > 0 && uint64(len(stored)-1) == size && stored[0] == 0xFF {
		stored = stored[1:]
	}
	return decodeRawInline(stored, size)
}

// decodeRawInline serves an uncompressed stream of exactly size bytes.  Raw
// decmpfs methods carry no marker; the 0xFF raw-copy marker is stripped by the
// caller before this check.
func decodeRawInline(stored []byte, size uint64) ([]byte, error) {
	if uint64(len(stored)) != size {
		return nil, invalidf("decmpfs raw stream holds %d bytes, not its declared %d", len(stored), size)
	}
	return append([]byte(nil), stored...), nil
}

// decmpfsContent reads and decodes one file's com.apple.decmpfs attribute.  A
// file with no attribute is (nil, false, nil); a present but undecodable
// attribute is an explicit error.
func (v *Volume) decmpfsContent(fileID uint32) ([]byte, bool, error) {
	value, err := v.Attribute(fileID, DecmpfsAttribute)
	if err != nil {
		return nil, false, err
	}
	if value == nil {
		return nil, false, nil
	}
	header, err := parseDecmpfsHeader(value)
	if err != nil {
		return nil, true, err
	}
	var resource []byte
	if header.Method.needsResourceFork() {
		resource, err = v.decmpfsResource(fileID)
		if err != nil {
			return nil, true, err
		}
	}
	out, err := header.decode(value[decmpfsHeaderLen:], resource)
	if err != nil {
		return nil, true, err
	}
	if uint64(len(out)) != header.Size {
		return nil, true, invalidf("decmpfs of CNID %d produced %d bytes, want %d", fileID, len(out), header.Size)
	}
	return out, true, nil
}

// decmpfsHeaderFor reads just the decmpfs header, for size reporting.  A file
// with no attribute is (nil, nil).
func (v *Volume) decmpfsHeaderFor(fileID uint32) (*decmpfsHeader, error) {
	value, err := v.Attribute(fileID, DecmpfsAttribute)
	if err != nil {
		return nil, err
	}
	if value == nil {
		return nil, nil
	}
	header, err := parseDecmpfsHeader(value)
	if err != nil {
		return nil, err
	}
	return &header, nil
}

// decmpfsResource materialises the resource fork a decmpfs method names.  It
// prefers an explicit com.apple.ResourceFork attribute and otherwise reads the
// file's catalog resource fork, which is where HFS+ keeps it.
func (v *Volume) decmpfsResource(fileID uint32) ([]byte, error) {
	if v.attributes != nil {
		value, err := readAttribute(v.attributes, v.src, v.header.BlockSize, v.CaseSensitive(), fileID, ResourceForkAttribute)
		if err != nil {
			return nil, err
		}
		if value != nil {
			if uint64(len(value)) > maxDecmpfsResource {
				return nil, unsupportedf("com.apple.ResourceFork of CNID %d is %d bytes, above the %d byte limit",
					fileID, len(value), maxDecmpfsResource)
			}
			return value, nil
		}
	}

	owner, file, ok, err := v.fileWithOwner(fileID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	fork := file.ResourceFork
	if fork.LogicalSize == 0 && fork.TotalBlocks == 0 {
		return nil, nil
	}
	if fork.LogicalSize > maxDecmpfsResource {
		return nil, unsupportedf("resource fork of CNID %d declares %d bytes, above the %d byte limit",
			owner, fork.LogicalSize, maxDecmpfsResource)
	}
	extents, err := v.extentsFor(ForkResource, owner, fork)
	if err != nil {
		return nil, err
	}
	covered := extents.CoveredBytes(v.header.BlockSize)
	if fork.LogicalSize > covered {
		return nil, unsupportedf("resource fork of CNID %d declares %d bytes but its extents cover %d",
			owner, fork.LogicalSize, covered)
	}
	value := make([]byte, int(fork.LogicalSize))
	if err := extents.ReadExact(v.src, v.header.BlockSize, 0, value); err != nil {
		return nil, err
	}
	return value, nil
}

// decmpfsSource wraps decoded content as a byte source.  The decoded bytes are
// materialised when the file is opened, so every read serves real content.
func (v *Volume) decmpfsSource(owner uint32, content []byte) source.ByteSource {
	id := source.ID(uint64(owner)<<8 | 0x01)
	memory := source.NewMemorySourceWithImage(id, v.src.ImageID(), content).WithSectorSize(v.src.SectorSize())
	return memory
}

// le32/le64 read little-endian integers, the order decmpfs headers use.
func le32(b []byte, off int) uint32 {
	return uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16 | uint32(b[off+3])<<24
}

func le64(b []byte, off int) uint64 {
	return uint64(le32(b, off)) | uint64(le32(b, off+4))<<32
}
