package rar

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

// ---------------------------------------------------------------------------
// In-memory RAR 5 builders.  These mirror the format writer used by the Rust
// reference tests: a block is CRC-32(vint(header_size) || fields) followed by
// the header fields and the optional data area.
// ---------------------------------------------------------------------------

func putVint(out []byte, value uint64) []byte {
	for {
		octet := byte(value & 0x7f)
		value >>= 7
		if value == 0 {
			return append(out, octet)
		}
		out = append(out, octet|0x80)
	}
}

func le32(out []byte, value uint32) []byte {
	return binary.LittleEndian.AppendUint32(out, value)
}

func le64(out []byte, value uint64) []byte {
	return binary.LittleEndian.AppendUint64(out, value)
}

func u32ptr(value uint32) *uint32 { return &value }

// assemble wraps header fields (which already start with the vint header size
// slot's contents, i.e. everything after that size) in the size vint and the
// CRC-32 and appends the data area.
func assemble(header, data []byte) []byte {
	body := putVint(nil, uint64(len(header)))
	body = append(body, header...)
	out := binary.LittleEndian.AppendUint32(nil, foundation.CRC32(body))
	out = append(out, body...)
	out = append(out, data...)
	return out
}

// buildBlock writes a structurally valid block.
func buildBlock(kind, flags uint64, headerData, extra, data []byte) []byte {
	if len(extra) > 0 {
		flags |= flagExtra
	}
	if len(data) > 0 {
		flags |= flagData
	}
	header := putVint(nil, kind)
	header = putVint(header, flags)
	if len(extra) > 0 {
		header = putVint(header, uint64(len(extra)))
	}
	if len(data) > 0 {
		header = putVint(header, uint64(len(data)))
	}
	header = append(header, headerData...)
	header = append(header, extra...)
	return assemble(header, data)
}

// rawBlock builds a block whose post-flags fields are supplied verbatim, for
// malformed-header tests.
func rawBlock(kind, flags uint64, fields, data []byte) []byte {
	header := putVint(nil, kind)
	header = putVint(header, flags)
	header = append(header, fields...)
	return assemble(header, data)
}

func archiveBytes(blocks ...[]byte) []byte {
	out := append([]byte(nil), []byte(MagicRAR5)...)
	for _, block := range blocks {
		out = append(out, block...)
	}
	return out
}

func mainBlock(flags uint64) []byte {
	header := putVint(nil, flags)
	if flags&archiveVolume != 0 && flags&archiveVolumeNumber != 0 {
		header = putVint(header, 7) // volume number
	}
	return buildBlock(typeMain, 0, header, nil, nil)
}

func endBlock() []byte {
	return buildBlock(typeEnd, 0, []byte{0}, nil, nil)
}

type fileSpec struct {
	name       string
	size       uint64
	attributes uint64
	fileFlags  uint64
	mtime      *uint32
	crc        *uint32
	method     uint32
	hostOS     uint64
	extra      []byte
	blockFlags uint64
	data       []byte
}

func (s fileSpec) headerBytes() []byte {
	out := putVint(nil, s.fileFlags)
	out = putVint(out, s.size)
	out = putVint(out, s.attributes)
	if s.fileFlags&fileMtime != 0 {
		out = le32(out, derefU32(s.mtime))
	}
	if s.fileFlags&fileCRC != 0 {
		out = le32(out, derefU32(s.crc))
	}
	out = putVint(out, uint64(s.method)<<7)
	out = putVint(out, s.hostOS)
	out = putVint(out, uint64(len(s.name)))
	return append(out, []byte(s.name)...)
}

func (s fileSpec) block() []byte {
	return buildBlock(typeFile, s.blockFlags, s.headerBytes(), s.extra, s.data)
}

func storedSpec(name string, payload []byte) fileSpec {
	crc := foundation.CRC32(payload)
	return fileSpec{
		name:       name,
		size:       uint64(len(payload)),
		attributes: 0x20,
		fileFlags:  fileCRC,
		crc:        &crc,
		hostOS:     1,
		data:       payload,
	}
}

func withMtime(spec fileSpec, value uint32) fileSpec {
	spec.fileFlags |= fileMtime
	spec.mtime = &value
	return spec
}

func withExtra(spec fileSpec, extra []byte) fileSpec {
	spec.extra = extra
	return spec
}

func withBlockFlags(spec fileSpec, flags uint64) fileSpec {
	spec.blockFlags |= flags
	return spec
}

func directorySpec(name string) fileSpec {
	return fileSpec{
		name:       name,
		attributes: 0x10,
		fileFlags:  fileDirectory | fileCRC,
		crc:        u32ptr(0),
		hostOS:     1,
	}
}

func extraRecord(recordType uint64, body []byte) []byte {
	out := putVint(nil, uint64(1+len(body)))
	out = putVint(out, recordType)
	return append(out, body...)
}

func htimeFiletimeExtra(unixSeconds int64) []byte {
	ticks := uint64(unixSeconds+filetimeUnixOffset) * 10_000_000
	body := putVint(nil, htimeMtime)
	body = le64(body, ticks)
	return extraRecord(extraHTime, body)
}

func htimeUnixExtra(unixSeconds uint32) []byte {
	body := putVint(nil, htimeMtime|htimeUnix)
	body = le32(body, unixSeconds)
	return extraRecord(extraHTime, body)
}

func derefU32(value *uint32) uint32 {
	if value == nil {
		return 0
	}
	return *value
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func memory(data []byte) source.ByteSource {
	return source.NewMemorySource(1, data)
}

func openReader(t *testing.T, data []byte) *Reader {
	t.Helper()
	reader, err := Open(memory(data), archive.DefaultLimits())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return reader
}

func readAll(t *testing.T, src source.ByteSource) []byte {
	t.Helper()
	out := make([]byte, 0, src.Len())
	buf := make([]byte, 64)
	offset := uint64(0)
	for offset < src.Len() {
		n, err := src.ReadAt(offset, buf)
		if err != nil {
			t.Fatalf("ReadAt(%d): %v", offset, err)
		}
		if n == 0 {
			t.Fatalf("ReadAt(%d): no progress", offset)
		}
		out = append(out, buf[:n]...)
		offset += uint64(n)
	}
	return out
}

func requireErrorIs(t *testing.T, err, target error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: got nil error, want %v", what, target)
	}
	if !errors.Is(err, target) {
		t.Fatalf("%s: error %v is not %v", what, err, target)
	}
}

func requireContains(t *testing.T, err error, substring string) {
	t.Helper()
	if err == nil {
		t.Fatalf("got nil error, want one containing %q", substring)
	}
	if !strings.Contains(err.Error(), substring) {
		t.Fatalf("error %q does not contain %q", err.Error(), substring)
	}
}

// ---------------------------------------------------------------------------
// Signature handling
// ---------------------------------------------------------------------------

func TestSignatureClassification(t *testing.T) {
	t.Run("rar4", func(t *testing.T) {
		_, err := Open(memory([]byte(MagicRAR4)), archive.DefaultLimits())
		requireErrorIs(t, err, source.ErrUnsupported, "RAR 4")
		requireContains(t, err, "RAR 4")
	})
	t.Run("rar4 with trailing bytes", func(t *testing.T) {
		_, err := Open(memory(append([]byte(MagicRAR4), 'x')), archive.DefaultLimits())
		requireErrorIs(t, err, source.ErrUnsupported, "RAR 4")
	})
	t.Run("not a rar", func(t *testing.T) {
		_, err := Open(memory([]byte("not a rar")), archive.DefaultLimits())
		requireErrorIs(t, err, source.ErrCorrupt, "foreign signature")
	})
	t.Run("shorter than rar4 signature", func(t *testing.T) {
		_, err := Open(memory([]byte("Rar!")), archive.DefaultLimits())
		requireErrorIs(t, err, source.ErrCorrupt, "short source")
	})
	t.Run("signature with no blocks", func(t *testing.T) {
		_, err := Open(memory([]byte(MagicRAR5)), archive.DefaultLimits())
		requireErrorIs(t, err, source.ErrCorrupt, "empty block chain")
		requireContains(t, err, "no block")
	})
}

// ---------------------------------------------------------------------------
// Listing and stored extraction
// ---------------------------------------------------------------------------

func TestStoredMemberRoundTrip(t *testing.T) {
	payload := []byte("rar stored member\n")
	spec := withMtime(storedSpec("docs/stored.txt", payload), 1_793_016_000)
	reader := openReader(t, archiveBytes(mainBlock(0), spec.block(), endBlock()))

	if reader.FormatID() != "rar" {
		t.Fatalf("FormatID = %q, want rar", reader.FormatID())
	}
	entries, err := reader.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	entry := entries[0]
	if entry.Path != "docs/stored.txt" || entry.RawPath != "docs/stored.txt" {
		t.Fatalf("path = %q raw = %q", entry.Path, entry.RawPath)
	}
	if entry.Kind != archive.KindFile {
		t.Fatalf("kind = %v, want file", entry.Kind)
	}
	if entry.Size != uint64(len(payload)) {
		t.Fatalf("size = %d, want %d", entry.Size, len(payload))
	}
	if entry.CompressedSize == nil || *entry.CompressedSize != uint64(len(payload)) {
		t.Fatalf("compressed size = %v", entry.CompressedSize)
	}
	if entry.Modified == nil || *entry.Modified != 1_793_016_000 {
		t.Fatalf("modified = %v", entry.Modified)
	}
	if entry.CRC32 == nil || *entry.CRC32 != foundation.CRC32(payload) {
		t.Fatalf("crc = %v", entry.CRC32)
	}
	if entry.Encrypted {
		t.Fatal("entry unexpectedly encrypted")
	}

	details := reader.Details()
	if len(details) != 1 {
		t.Fatalf("details = %d, want 1", len(details))
	}
	detail := details[0]
	if detail.Method != 0 || !detail.IsStored() {
		t.Fatalf("detail method = %d, stored = %v", detail.Method, detail.IsStored())
	}
	if detail.HostOS != 1 {
		t.Fatalf("host OS = %d, want 1", detail.HostOS)
	}
	if detail.Attributes != 0x20 {
		t.Fatalf("attributes = %#x, want 0x20", detail.Attributes)
	}
	if detail.CompressionInfo != 0 {
		t.Fatalf("compression info = %#x, want 0", detail.CompressionInfo)
	}
	if detail.DataSize != uint64(len(payload)) || detail.Size != uint64(len(payload)) {
		t.Fatalf("data size = %d size = %d", detail.DataSize, detail.Size)
	}
	if detail.HeaderOffset == 0 || detail.DataOffset <= detail.HeaderOffset {
		t.Fatalf("offsets header=%d data=%d", detail.HeaderOffset, detail.DataOffset)
	}

	src, err := reader.OpenEntry("docs/stored.txt", 9)
	if err != nil {
		t.Fatalf("OpenEntry: %v", err)
	}
	if got := readAll(t, src); !equalBytes(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
	if src.Stats().CorruptBytes != 0 {
		t.Fatalf("corrupt bytes = %d, want 0", src.Stats().CorruptBytes)
	}
	if stats := reader.Stats(); stats.Blocks != 3 || stats.FileHeaders != 1 {
		t.Fatalf("stats = %+v, want 3 blocks and 1 file header", stats)
	}
}

func TestStoredMemberAccessorsAndMapping(t *testing.T) {
	payload := []byte("0123456789")
	reader := openReader(t, archiveBytes(mainBlock(0), storedSpec("digits.bin", payload).block(), endBlock()))
	detail := reader.Details()[0]

	src, err := reader.OpenEntrySource("digits.bin", 9)
	if err != nil {
		t.Fatalf("OpenEntrySource: %v", err)
	}
	if src.DataOffset() != detail.DataOffset {
		t.Fatalf("DataOffset = %d, want %d", src.DataOffset(), detail.DataOffset)
	}
	if src.CompressedSize() != uint64(len(payload)) {
		t.Fatalf("CompressedSize = %d", src.CompressedSize())
	}
	if src.Entry().Path != "digits.bin" || src.Len() != uint64(len(payload)) {
		t.Fatalf("entry = %+v len = %d", src.Entry(), src.Len())
	}
	if src.SourceID() != 9 {
		t.Fatalf("SourceID = %d, want 9", src.SourceID())
	}
	if src.ImageID() != reader.source.ImageID() || src.SectorSize() != reader.source.SectorSize() {
		t.Fatal("parent image/sector hints not propagated")
	}
	if reader.Limits() != archive.DefaultLimits() {
		t.Fatalf("limits = %+v", reader.Limits())
	}
	if src.IsEmpty() {
		t.Fatal("non-empty member reported empty")
	}

	buf := make([]byte, 4)
	n, err := src.ReadAt(2, buf)
	if err != nil || n != 4 || !equalBytes(buf, payload[2:6]) {
		t.Fatalf("ReadAt(2) = (%d, %v) %q", n, err, buf[:n])
	}
	lossy := make([]byte, 4)
	if n, err := src.ReadAtLossy(1, lossy); err != nil || n != 4 || !equalBytes(lossy, payload[1:5]) {
		t.Fatalf("ReadAtLossy(1) = (%d, %v) %q", n, err, lossy[:n])
	}
	if _, err := src.ReadAtLossy(src.Len(), make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("lossy read at EOF = %v, want ErrOutOfRange", err)
	}
	if n, err := src.ReadAt(0, nil); err != nil || n != 0 {
		t.Fatalf("empty ReadAt = (%d, %v)", n, err)
	}
	if _, err := src.ReadAt(src.Len(), make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("read at EOF = %v, want ErrOutOfRange", err)
	}
	if ranges, err := src.Extents(0, 0); err != nil || len(ranges) != 0 {
		t.Fatalf("empty Extents = (%v, %v)", ranges, err)
	}
	if images, err := src.MapToImage(0, 0); err != nil || images != nil {
		t.Fatalf("empty MapToImage = (%v, %v)", images, err)
	}

	extents, err := src.Extents(2, 3)
	if err != nil {
		t.Fatalf("Extents: %v", err)
	}
	if len(extents) != 1 {
		t.Fatalf("extents = %d, want 1", len(extents))
	}
	if extents[0].Parent != reader.source.SourceID() || extents[0].ParentOffset != detail.DataOffset+2 ||
		extents[0].Len != 3 || extents[0].Kind != source.RangeData {
		t.Fatalf("extent = %+v", extents[0])
	}
	images, err := src.MapToImage(2, 3)
	if err != nil {
		t.Fatalf("MapToImage: %v", err)
	}
	if len(images) != 1 || images[0].Len != 3 || images[0].Kind != source.RangeData {
		t.Fatalf("image ranges = %+v", images)
	}
	if _, err := src.Extents(detail.Size, 1); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("extent past end = %v, want ErrOutOfRange", err)
	}
	if src.Stats().CacheMisses == 0 {
		t.Fatal("expected at least one cache miss")
	}
}

func TestCRCMismatchIsCountedButBytesSurvive(t *testing.T) {
	payload := []byte("evidence")
	spec := storedSpec("corrupt.bin", payload)
	bad := foundation.CRC32([]byte("other"))
	spec.crc = &bad
	reader := openReader(t, archiveBytes(mainBlock(0), spec.block(), endBlock()))

	src, err := reader.OpenEntry("corrupt.bin", 9)
	if err != nil {
		t.Fatalf("OpenEntry: %v", err)
	}
	if got := readAll(t, src); !equalBytes(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
	if src.Stats().CorruptBytes == 0 {
		t.Fatal("CRC mismatch was not counted as corrupt bytes")
	}
}

func TestHeaderCRCFailureIsRefused(t *testing.T) {
	payload := []byte("x")
	data := archiveBytes(mainBlock(0), storedSpec("x.bin", payload).block(), endBlock())
	// The final byte belongs to the end header's body; flipping it leaves the
	// block sizes intact and only invalidates that header's CRC.
	data[len(data)-1] ^= 0xFF
	_, err := Open(memory(data), archive.DefaultLimits())
	requireErrorIs(t, err, source.ErrCorrupt, "header CRC")
	requireContains(t, err, "CRC")
}

// ---------------------------------------------------------------------------
// Explicit refusals
// ---------------------------------------------------------------------------

func TestEncryptionHeaderRefused(t *testing.T) {
	data := archiveBytes(buildBlock(typeEncryption, 0, []byte{0}, nil, nil))
	_, err := Open(memory(data), archive.DefaultLimits())
	requireErrorIs(t, err, source.ErrDecrypt, "encrypted headers")
	requireErrorIs(t, err, archive.ErrEncrypted, "encrypted headers archive sentinel")
	requireContains(t, err, "encrypted")
}

func TestCompressedMemberListedButNotOpened(t *testing.T) {
	spec := fileSpec{
		name:       "packed.bin",
		size:       100,
		attributes: 0x20,
		fileFlags:  fileCRC,
		crc:        u32ptr(0),
		method:     1,
		hostOS:     1,
		data:       []byte{1, 2, 3},
	}
	reader := openReader(t, archiveBytes(mainBlock(0), spec.block(), endBlock()))

	entries, err := reader.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 1 || entries[0].Size != 100 {
		t.Fatalf("entries = %+v", entries)
	}
	if detail := reader.Details()[0]; detail.IsStored() {
		t.Fatal("compressed member reported as stored")
	}
	_, err = reader.OpenEntry("packed.bin", 9)
	requireErrorIs(t, err, source.ErrUnsupported, "compressed member")
	requireErrorIs(t, err, archive.ErrUnsupported, "compressed member archive sentinel")
	requireContains(t, err, "compression method 1")
	requireContains(t, err, "packed.bin")
}

func TestDirectoryHasNoStream(t *testing.T) {
	reader := openReader(t, archiveBytes(mainBlock(0), directorySpec("docs").block(), endBlock()))
	entries, err := reader.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 1 || entries[0].Kind != archive.KindDirectory {
		t.Fatalf("entries = %+v", entries)
	}
	_, err = reader.OpenEntry("docs", 9)
	requireErrorIs(t, err, archive.ErrInvalid, "directory entry")
	requireContains(t, err, "directory")
}

func TestSplitMemberRefused(t *testing.T) {
	for _, flags := range []uint64{flagSplitBefore, flagSplitAfter} {
		payload := []byte("abc")
		spec := withBlockFlags(storedSpec("part.bin", payload), flags)
		reader := openReader(t, archiveBytes(mainBlock(0), spec.block(), endBlock()))
		if detail := reader.Details()[0]; !detail.Split {
			t.Fatalf("flags %#x: detail.Split = false", flags)
		}
		_, err := reader.OpenEntry("part.bin", 9)
		requireErrorIs(t, err, source.ErrUnsupported, "split member")
		requireContains(t, err, "another volume")
	}
}

func TestEncryptionExtraRefused(t *testing.T) {
	spec := withExtra(storedSpec("secret.bin", []byte("abc")), extraRecord(extraCrypt, nil))
	reader := openReader(t, archiveBytes(mainBlock(0), spec.block(), endBlock()))
	if detail := reader.Details()[0]; !detail.Encrypted {
		t.Fatal("encryption extra was not recorded")
	}
	_, err := reader.OpenEntry("secret.bin", 9)
	requireErrorIs(t, err, source.ErrDecrypt, "encrypted member")
	requireContains(t, err, "secret.bin")
}

func TestUnknownUnpackedSizeRefused(t *testing.T) {
	spec := storedSpec("stream.bin", []byte("abc"))
	spec.fileFlags |= fileUnknownSize
	_, err := Open(memory(archiveBytes(mainBlock(0), spec.block(), endBlock())), archive.DefaultLimits())
	requireErrorIs(t, err, source.ErrUnsupported, "unknown unpacked size")
	requireContains(t, err, "unpacked size")
}

func TestUnknownHeaderTypeRefusals(t *testing.T) {
	t.Run("not skippable", func(t *testing.T) {
		data := archiveBytes(mainBlock(0), buildBlock(99, 0, []byte{0}, nil, nil), endBlock())
		_, err := Open(memory(data), archive.DefaultLimits())
		requireErrorIs(t, err, source.ErrUnsupported, "unknown block")
		requireContains(t, err, "99")
		requireContains(t, err, "not marked skippable")
	})
	t.Run("skippable", func(t *testing.T) {
		payload := []byte("after")
		data := archiveBytes(
			mainBlock(0),
			buildBlock(99, flagSkipIfUnknown, []byte{0}, nil, nil),
			storedSpec("after.bin", payload).block(),
			endBlock(),
		)
		reader := openReader(t, data)
		if stats := reader.Stats(); stats.SkippedUnknown != 1 || stats.Blocks != 4 {
			t.Fatalf("stats = %+v", stats)
		}
		if entries, _ := reader.Entries(); len(entries) != 1 || entries[0].Path != "after.bin" {
			t.Fatalf("entries = %+v", entries)
		}
	})
}

// ---------------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------------

func TestHTIMEExtraWinsOverInlineTime(t *testing.T) {
	payload := []byte("time")
	t.Run("windows filetime", func(t *testing.T) {
		spec := withMtime(storedSpec("t.txt", payload), 1_000)
		spec = withExtra(spec, htimeFiletimeExtra(1_700_000_000))
		reader := openReader(t, archiveBytes(mainBlock(0), spec.block(), endBlock()))
		modified := singleEntry(t, reader).Modified
		if modified == nil || *modified != 1_700_000_000 {
			t.Fatalf("modified = %v, want 1700000000", modified)
		}
	})
	t.Run("unix seconds", func(t *testing.T) {
		spec := withMtime(storedSpec("t.txt", payload), 1_000)
		spec = withExtra(spec, htimeUnixExtra(1_700_000_001))
		reader := openReader(t, archiveBytes(mainBlock(0), spec.block(), endBlock()))
		modified := singleEntry(t, reader).Modified
		if modified == nil || *modified != 1_700_000_001 {
			t.Fatalf("modified = %v, want 1700000001", modified)
		}
	})
	t.Run("unknown extra record does not desynchronize", func(t *testing.T) {
		extra := extraRecord(99, []byte{0xAA, 0xBB})
		extra = append(extra, htimeUnixExtra(1_234_567_890)...)
		spec := withMtime(storedSpec("t.txt", payload), 1_000)
		spec = withExtra(spec, extra)
		reader := openReader(t, archiveBytes(mainBlock(0), spec.block(), endBlock()))
		modified := singleEntry(t, reader).Modified
		if modified == nil || *modified != 1_234_567_890 {
			t.Fatalf("modified = %v, want 1234567890", modified)
		}
	})
}

func TestMalformedExtraRecordRefused(t *testing.T) {
	t.Run("truncated HTIME flags", func(t *testing.T) {
		// A record that declares one byte (just the type) but then claims HTIME.
		extra := putVint(nil, 1)
		extra = putVint(extra, extraHTime)
		spec := withExtra(storedSpec("t.txt", []byte("x")), extra)
		_, err := Open(memory(archiveBytes(mainBlock(0), spec.block(), endBlock())), archive.DefaultLimits())
		requireErrorIs(t, err, source.ErrCorrupt, "truncated HTIME")
	})
	t.Run("record runs past extra area", func(t *testing.T) {
		spec := withExtra(storedSpec("t.txt", []byte("x")), putVint(nil, 100))
		_, err := Open(memory(archiveBytes(mainBlock(0), spec.block(), endBlock())), archive.DefaultLimits())
		requireErrorIs(t, err, source.ErrCorrupt, "record past extra")
		requireContains(t, err, "extra area")
	})
	t.Run("truncated HTIME filetime", func(t *testing.T) {
		extra := extraRecord(extraHTime, putVint(nil, htimeMtime))
		spec := withExtra(storedSpec("t.txt", []byte("x")), extra)
		_, err := Open(memory(archiveBytes(mainBlock(0), spec.block(), endBlock())), archive.DefaultLimits())
		requireErrorIs(t, err, source.ErrCorrupt, "truncated filetime")
	})
}

func TestTruncatedFixedWidthFileFields(t *testing.T) {
	header := putVint(nil, fileMtime)
	header = putVint(header, 1) // size
	header = putVint(header, 0) // attributes
	// The declared inline mtime is missing.
	data := archiveBytes(mainBlock(0), buildBlock(typeFile, 0, header, nil, nil), endBlock())
	_, err := Open(memory(data), archive.DefaultLimits())
	requireErrorIs(t, err, source.ErrCorrupt, "truncated mtime")
	requireContains(t, err, "fixed-width")
}

func TestVolumeNumberMissingIsRefused(t *testing.T) {
	header := putVint(nil, archiveVolume|archiveVolumeNumber)
	data := archiveBytes(buildBlock(typeMain, 0, header, nil, nil), endBlock())
	_, err := Open(memory(data), archive.DefaultLimits())
	requireErrorIs(t, err, source.ErrCorrupt, "missing volume number")
	requireContains(t, err, "variable-length integer")
}

func TestNameRunsPastHeader(t *testing.T) {
	header := putVint(nil, 0)   // file flags
	header = putVint(header, 0) // size
	header = putVint(header, 0) // attributes
	header = putVint(header, 0) // compression info
	header = putVint(header, 1) // host OS
	header = putVint(header, 100)
	header = append(header, []byte("abc")...)
	data := archiveBytes(mainBlock(0), buildBlock(typeFile, 0, header, nil, nil), endBlock())
	_, err := Open(memory(data), archive.DefaultLimits())
	requireErrorIs(t, err, source.ErrCorrupt, "name past header")
	requireContains(t, err, "name runs past")
}

func TestEndHeaderWithoutBody(t *testing.T) {
	data := archiveBytes(mainBlock(0), buildBlock(typeEnd, 0, nil, nil, nil))
	reader := openReader(t, data)
	if stats := reader.Stats(); stats.Blocks != 2 || stats.TrailingBytes != 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestEntrySourceLossyZeroFillsReadErrors(t *testing.T) {
	parent := source.NewMemorySource(1, []byte("ab"))
	entry := archive.Entry{Path: "gone.bin", Kind: archive.KindFile, Size: 5}
	src := newEntrySource(9, parent, entry, 10, 5) // data offset is past the parent
	buf := []byte{1, 2, 3, 4}
	n, err := src.ReadAtLossy(0, buf)
	if err != nil || n != 4 {
		t.Fatalf("ReadAtLossy = (%d, %v), want (4, nil)", n, err)
	}
	for index, value := range buf {
		if value != 0 {
			t.Fatalf("byte %d = %d, want zero", index, value)
		}
	}
	if src.Stats().CorruptBytes != 4 {
		t.Fatalf("corrupt bytes = %d, want 4", src.Stats().CorruptBytes)
	}
}

func TestEntrySourceShortData(t *testing.T) {
	parent := source.NewMemorySource(1, []byte("abc"))
	entry := archive.Entry{Path: "short.bin", Kind: archive.KindFile, Size: 10}
	src := newEntrySource(9, parent, entry, 0, 3)
	if _, err := src.ReadAt(4, make([]byte, 3)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("read past decoded bytes = %v, want ErrCorrupt", err)
	}
	if _, err := src.ReadAt(0, make([]byte, 5)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("short decoded range = %v, want ErrCorrupt", err)
	}
	if src.Stats().CorruptBytes == 0 {
		t.Fatal("short member was not counted as corrupt")
	}
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

func TestBackslashAndInvalidUTF8Names(t *testing.T) {
	invalid := "x" + string([]byte{0xFF}) + ".txt"
	data := archiveBytes(
		mainBlock(0),
		storedSpec(`docs\sub\file.txt`, []byte("a")).block(),
		storedSpec(invalid, []byte("b")).block(),
		endBlock(),
	)
	reader := openReader(t, data)
	entries, err := reader.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	if entries[0].Path != "docs/sub/file.txt" {
		t.Fatalf("normalized path = %q", entries[0].Path)
	}
	if entries[0].RawPath != `docs\sub\file.txt` {
		t.Fatalf("raw path = %q", entries[0].RawPath)
	}
	if !strings.Contains(entries[1].Path, "\uFFFD") {
		t.Fatalf("lossy path = %q, want a replacement character", entries[1].Path)
	}
	if stats := reader.Stats(); stats.InvalidNames != 1 {
		t.Fatalf("invalid names = %d, want 1", stats.InvalidNames)
	}
}

func TestUnsafeNamesAreSkipped(t *testing.T) {
	names := []string{
		"../evil.txt",
		"/etc/passwd",
		`C:\Windows\system32\evil.dll`,
		"",
		"a\x00b",
	}
	blocks := [][]byte{mainBlock(0)}
	for _, name := range names {
		blocks = append(blocks, storedSpec(name, []byte("x")).block())
	}
	blocks = append(blocks, endBlock())

	reader := openReader(t, archiveBytes(blocks...))
	entries, err := reader.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("unsafe entries were listed: %+v", entries)
	}
	stats := reader.Stats()
	if stats.FileHeaders != uint64(len(names)) || stats.SkippedUnsafe != uint64(len(names)) {
		t.Fatalf("stats = %+v", stats)
	}
}

// ---------------------------------------------------------------------------
// Variable-length integers
// ---------------------------------------------------------------------------

func TestVintRoundTrip(t *testing.T) {
	values := []uint64{0, 1, 127, 128, 0x3FFF, 1 << 20, 0xFFFFFFFF, 1 << 63, ^uint64(0)}
	for _, value := range values {
		encoded := putVint(nil, value)
		pos := 0
		got, err := readVint(encoded, &pos)
		if err != nil {
			t.Fatalf("readVint(%d): %v", value, err)
		}
		if got != value || pos != len(encoded) {
			t.Fatalf("readVint(%d) = %d at %d/%d", value, got, pos, len(encoded))
		}
	}
}

func TestVintMalformed(t *testing.T) {
	t.Run("truncated", func(t *testing.T) {
		pos := 0
		_, err := readVint([]byte{0x80}, &pos)
		requireErrorIs(t, err, source.ErrCorrupt, "truncated vint")
	})
	t.Run("overflows 64 bits", func(t *testing.T) {
		buf := make([]byte, 0, 10)
		for i := 0; i < 9; i++ {
			buf = append(buf, 0x80)
		}
		buf = append(buf, 0x02)
		pos := 0
		_, err := readVint(buf, &pos)
		requireErrorIs(t, err, source.ErrCorrupt, "overflowing vint")
		requireContains(t, err, "overflow")
	})
	t.Run("in a block header", func(t *testing.T) {
		data := append([]byte(MagicRAR5), 0, 0, 0, 0)
		for i := 0; i < 9; i++ {
			data = append(data, 0x80)
		}
		data = append(data, 0x02)
		_, err := Open(memory(data), archive.DefaultLimits())
		requireErrorIs(t, err, source.ErrCorrupt, "overflowing header size")
	})
}

// ---------------------------------------------------------------------------
// Structural limits and truncation
// ---------------------------------------------------------------------------

func TestMalformedBlocks(t *testing.T) {
	t.Run("zero header size", func(t *testing.T) {
		data := append([]byte(MagicRAR5), 0, 0, 0, 0, 0x00)
		_, err := Open(memory(data), archive.DefaultLimits())
		requireErrorIs(t, err, source.ErrCorrupt, "zero header")
		requireContains(t, err, "zero bytes")
	})
	t.Run("header runs past archive", func(t *testing.T) {
		data := append([]byte(MagicRAR5), 0, 0, 0, 0)
		data = putVint(data, 1000)
		_, err := Open(memory(data), archive.DefaultLimits())
		requireErrorIs(t, err, source.ErrCorrupt, "header past end")
		requireContains(t, err, "runs past")
	})
	t.Run("header beyond the cap", func(t *testing.T) {
		data := append([]byte(MagicRAR5), 0, 0, 0, 0)
		data = putVint(data, MaxHeaderBytes+1)
		_, err := Open(memory(data), archive.DefaultLimits())
		requireErrorIs(t, err, archive.ErrLimit, "oversized header")
	})
	t.Run("data area runs past archive", func(t *testing.T) {
		payload := []byte("payload")
		block := storedSpec("p.bin", payload).block()
		data := archiveBytes(mainBlock(0), block[:len(block)-len(payload)])
		_, err := Open(memory(data), archive.DefaultLimits())
		requireErrorIs(t, err, source.ErrCorrupt, "data past end")
		requireContains(t, err, "data area")
	})
	t.Run("extra area longer than header", func(t *testing.T) {
		data := archiveBytes(rawBlock(typeMain, flagExtra, putVint(nil, 100), nil))
		_, err := Open(memory(data), archive.DefaultLimits())
		requireErrorIs(t, err, source.ErrCorrupt, "extra underflow")
		requireContains(t, err, "extra area")
	})
	t.Run("extra overlaps fixed fields", func(t *testing.T) {
		data := archiveBytes(rawBlock(typeMain, flagExtra, putVint(nil, 1), nil))
		_, err := Open(memory(data), archive.DefaultLimits())
		requireErrorIs(t, err, source.ErrCorrupt, "extra overlap")
		requireContains(t, err, "overlaps")
	})
	t.Run("trailing bytes too short for a header", func(t *testing.T) {
		data := archiveBytes(mainBlock(0))
		data = append(data, 1, 2, 3)
		_, err := Open(memory(data), archive.DefaultLimits())
		requireErrorIs(t, err, source.ErrCorrupt, "trailing junk")
		requireContains(t, err, "cannot hold a block header")
	})
}

func TestDeclaredSizeMismatchRefused(t *testing.T) {
	spec := storedSpec("lying.bin", []byte("abc"))
	spec.size = 10
	reader := openReader(t, archiveBytes(mainBlock(0), spec.block(), endBlock()))
	_, err := reader.OpenEntry("lying.bin", 9)
	requireErrorIs(t, err, source.ErrCorrupt, "declared size mismatch")
	requireContains(t, err, "declares")
	requireContains(t, err, "lying.bin")
}

// ---------------------------------------------------------------------------
// Archive-level metadata
// ---------------------------------------------------------------------------

func TestServiceHeadersAndTrailingBytes(t *testing.T) {
	payload := []byte("x")
	trailer := []byte("trailing junk")
	data := archiveBytes(
		mainBlock(0),
		buildBlock(typeService, 0, []byte{0, 1, 2}, nil, []byte("QO")),
		storedSpec("x.bin", payload).block(),
		endBlock(),
	)
	data = append(data, trailer...)
	reader := openReader(t, data)
	if stats := reader.Stats(); stats.ServiceHeaders != 1 || stats.TrailingBytes != uint64(len(trailer)) {
		t.Fatalf("stats = %+v", stats)
	}
	if entries, _ := reader.Entries(); len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
}

func TestArchiveFlags(t *testing.T) {
	flags := archiveVolume | archiveVolumeNumber | archiveSolid | archiveLocked
	reader := openReader(t, archiveBytes(mainBlock(flags), endBlock()))
	if reader.ArchiveFlags() != flags {
		t.Fatalf("archive flags = %#x, want %#x", reader.ArchiveFlags(), flags)
	}
	if !reader.IsSolid() || !reader.IsVolume() || !reader.IsLocked() {
		t.Fatalf("solid=%v volume=%v locked=%v", reader.IsSolid(), reader.IsVolume(), reader.IsLocked())
	}

	plain := openReader(t, archiveBytes(mainBlock(0), endBlock()))
	if plain.IsSolid() || plain.IsVolume() || plain.IsLocked() {
		t.Fatal("plain archive reported volume flags")
	}
}

// ---------------------------------------------------------------------------
// Framework integration
// ---------------------------------------------------------------------------

func TestAdapterRegistration(t *testing.T) {
	registry := archive.NewRegistry()
	if err := Register(registry); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if ids := registry.FormatIDs(); len(ids) != 1 || ids[0] != "rar" {
		t.Fatalf("format ids = %v", ids)
	}
	adapter, ok := registry.Adapter("rar")
	if !ok || adapter.FormatID() != "rar" {
		t.Fatalf("adapter = %v, ok = %v", adapter, ok)
	}
	if err := Register(registry); !errors.Is(err, archive.ErrInvalid) {
		t.Fatalf("duplicate Register = %v, want ErrInvalid", err)
	}

	payload := []byte("adapter")
	data := archiveBytes(mainBlock(0), storedSpec("a.bin", payload).block(), endBlock())
	reader, err := registry.Open("rar", memory(data), archive.DefaultLimits())
	if err != nil {
		t.Fatalf("registry.Open: %v", err)
	}
	if reader.FormatID() != "rar" {
		t.Fatalf("FormatID = %q", reader.FormatID())
	}
	src, err := reader.OpenEntry("a.bin", 3)
	if err != nil {
		t.Fatalf("OpenEntry: %v", err)
	}
	if got := readAll(t, src); !equalBytes(got, payload) {
		t.Fatalf("payload = %q", got)
	}
}

func TestLimitsAreEnforced(t *testing.T) {
	payload := []byte("payload")
	data := archiveBytes(mainBlock(0), storedSpec("p.bin", payload).block(), endBlock())

	limits := archive.DefaultLimits()
	limits.MaxEntries = 0
	if _, err := Open(memory(data), limits); !errors.Is(err, archive.ErrLimit) {
		t.Fatalf("MaxEntries = %v, want ErrLimit", err)
	}

	limits = archive.DefaultLimits()
	limits.MaxEntrySize = 1
	if _, err := Open(memory(data), limits); !errors.Is(err, archive.ErrLimit) {
		t.Fatalf("MaxEntrySize = %v, want ErrLimit", err)
	}
}

func TestFindAndOpenEntryPathHandling(t *testing.T) {
	payload := []byte("find me")
	reader := openReader(t, archiveBytes(mainBlock(0), storedSpec("docs/file.txt", payload).block(), endBlock()))

	entry, ok, err := reader.FindEntry("docs/file.txt")
	if err != nil || !ok || entry.Path != "docs/file.txt" {
		t.Fatalf("FindEntry exact = (%+v, %v, %v)", entry, ok, err)
	}
	entry, ok, err = reader.FindEntry(`docs\file.txt`)
	if err != nil || !ok || entry.Path != "docs/file.txt" {
		t.Fatalf("FindEntry backslash = (%+v, %v, %v)", entry, ok, err)
	}
	if _, ok, err := reader.FindEntry("missing"); err != nil || ok {
		t.Fatalf("FindEntry missing = (ok=%v, err=%v)", ok, err)
	}
	if _, _, err := reader.FindEntry("../escape"); !errors.Is(err, archive.ErrInvalid) {
		t.Fatalf("FindEntry unsafe = %v, want ErrInvalid", err)
	}

	src, err := reader.OpenEntry(`docs\file.txt`, 3)
	if err != nil {
		t.Fatalf("OpenEntry backslash: %v", err)
	}
	if got := readAll(t, src); !equalBytes(got, payload) {
		t.Fatalf("payload = %q", got)
	}
	if _, err := reader.OpenEntry("missing", 4); !errors.Is(err, archive.ErrInvalid) {
		t.Fatalf("OpenEntry missing = %v, want ErrInvalid", err)
	}
	if _, err := reader.OpenEntry("../escape", 5); !errors.Is(err, archive.ErrInvalid) {
		t.Fatalf("OpenEntry unsafe = %v, want ErrInvalid", err)
	}
}

// singleEntry lists entries and returns the only one.
func singleEntry(t *testing.T, reader *Reader) archive.Entry {
	t.Helper()
	entries, err := reader.Entries()
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	return entries[0]
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
