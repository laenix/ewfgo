package sevenz

import (
	"bytes"
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/source"
)

func TestEntrySourceAccessorsAndLossyRead(t *testing.T) {
	text := []byte("accessor payload")
	payload := append([]byte(nil), text...)
	wrong := fixtureCRC([]byte("different"))
	folder := &testFolder{
		coders:      []testCoder{{id: idCopy}},
		unpackSizes: []uint64{uint64(len(text))},
		packed:      payload,
		subSizes:    []uint64{uint64(len(text))},
		subCRCs:     []*uint32{&wrong},
		folderCRC:   &wrong,
	}
	fixture := buildArchive([]*testFolder{folder},
		[]*testFile{{name: "a.bin", data: text, folder: 0, sub: 0}})
	reader := openBytes(t, fixture.bytes, archive.DefaultLimits())
	if reader.FormatID() != "7z" {
		t.Errorf("FormatID = %q", reader.FormatID())
	}
	if reader.Limits().MaxEntries != archive.DefaultLimits().MaxEntries {
		t.Error("Limits does not return the opening limits")
	}
	entry, err := reader.OpenEntrySource("a.bin", 7)
	if err != nil {
		t.Fatalf("OpenEntrySource: %v", err)
	}
	if entry.SourceID() != 7 || entry.ImageID() != reader.source.ImageID() ||
		entry.SectorSize() != reader.source.SectorSize() {
		t.Error("source identity forwarding is wrong")
	}
	if entry.IsEmpty() || entry.Entry().Path != "a.bin" {
		t.Error("entry accessors are wrong")
	}
	if folderIndex, ok := entry.Folder(); !ok || folderIndex != 0 || entry.Substream() != 0 {
		t.Error("folder/substream accessors are wrong")
	}
	// A CRC mismatch must not stop a lossy read; it is counted as corrupt.
	buffer := make([]byte, len(text))
	n, err := entry.ReadAtLossy(0, buffer)
	if err != nil || n != len(text) || !bytes.Equal(buffer, text) {
		t.Fatalf("lossy read = %d, %v, %q", n, err, buffer)
	}
	if entry.Stats().CorruptBytes == 0 {
		t.Error("lossy read of a corrupt entry must count corrupt bytes")
	}
	if _, err := entry.ReadAtLossy(entry.Len(), make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Errorf("lossy out-of-range err = %v", err)
	}

	// An entry whose folder cannot decode zero-fills under the lossy contract.
	// A supported coder with malformed properties fails while decoding rather
	// than at open, leaving ReadAtLossy's fallback reachable.
	bad := singleCoderArchive(idDelta, []byte{1, 2}, text, text, "bad.bin")
	badReader := openBytes(t, bad.bytes, archive.DefaultLimits())
	badEntry, err := badReader.OpenEntrySource("bad.bin", 8)
	if err != nil {
		t.Fatalf("OpenEntrySource: %v", err)
	}
	zeros := make([]byte, len(text))
	zeros[0] = 0xFF
	n, err = badEntry.ReadAtLossy(0, zeros)
	if err != nil || n != len(text) || !bytes.Equal(zeros, make([]byte, len(text))) {
		t.Fatalf("lossy read of an undecodable entry = %d, %v, %v", n, err, zeros)
	}
	if badEntry.Stats().CorruptBytes == 0 {
		t.Error("zero-filled lossy bytes must be counted as corrupt")
	}
}

func TestCoderPropertyErrors(t *testing.T) {
	payload := []byte("payload bytes")
	cases := map[string]*testFolder{
		"lzma props": {
			coders:      []testCoder{{id: idLZMA, props: []byte{0x5D}}},
			unpackSizes: []uint64{uint64(len(payload))},
			packed:      payload,
		},
		"lzma2 props": {
			coders:      []testCoder{{id: idLZMA2, props: []byte{1, 2}}},
			unpackSizes: []uint64{uint64(len(payload))},
			packed:      payload,
		},
		"delta props": {
			coders:      []testCoder{{id: idDelta, props: []byte{1, 2}}},
			unpackSizes: []uint64{uint64(len(payload))},
			packed:      payload,
		},
		"bcj props": {
			coders:      []testCoder{{id: idBCJX86, props: []byte{0}}},
			unpackSizes: []uint64{uint64(len(payload))},
			packed:      payload,
		},
		"bcj size": {
			coders:      []testCoder{{id: idBCJX86}},
			unpackSizes: []uint64{uint64(len(payload) + 1)},
			packed:      payload,
		},
		"copy size": {
			coders:      []testCoder{{id: idCopy}},
			unpackSizes: []uint64{uint64(len(payload) + 1)},
			packed:      payload,
		},
		"deflate stream": {
			coders:      []testCoder{{id: idDeflate}},
			unpackSizes: []uint64{128},
			packed:      []byte("not a deflate stream"),
		},
		"bzip2 stream": {
			coders:      []testCoder{{id: idBzip2}},
			unpackSizes: []uint64{128},
			packed:      []byte("not a bzip2 stream"),
		},
		"ppmd props": {
			coders:      []testCoder{{id: idPPMd, props: []byte{6, 0, 0, 0}}},
			unpackSizes: []uint64{64},
			packed:      payload,
		},
		"ppmd order": {
			coders:      []testCoder{{id: idPPMd, props: []byte{1, 0, 8, 0, 0}}},
			unpackSizes: []uint64{64},
			packed:      payload,
		},
		"ppmd model": {
			coders:      []testCoder{{id: idPPMd, props: []byte{6, 0, 0, 0, 0x60}}},
			unpackSizes: []uint64{64},
			packed:      payload,
		},
		"ppmd stream": {
			coders:      []testCoder{{id: idPPMd, props: []byte{6, 0, 8, 0, 0}}},
			unpackSizes: []uint64{64},
			packed:      payload,
		},
		"lzma2 stream": {
			coders:      []testCoder{{id: idLZMA2, props: []byte{16}}},
			unpackSizes: []uint64{64},
			packed:      []byte{0xE0, 0xFF, 0xFF},
		},
		"lzma2 oversize chunk": {
			coders:      []testCoder{{id: idLZMA2, props: []byte{16}}},
			unpackSizes: []uint64{3},
			packed:      []byte{0x01, 0x00, 0x04, 'a', 'b', 'c', 'd', 'e', 0x00},
		},
	}
	for label, folder := range cases {
		folder := folder
		t.Run(label, func(t *testing.T) {
			folder.subSizes = []uint64{folder.unpackSizes[0]}
			fixture := buildArchive([]*testFolder{folder},
				[]*testFile{{name: "x.bin", data: payload, folder: 0, sub: 0}})
			reader := openBytes(t, fixture.bytes, archive.DefaultLimits())
			entry, err := reader.OpenEntrySource("x.bin", 2)
			if err != nil {
				t.Fatalf("OpenEntrySource: %v", err)
			}
			if _, err := source.ReadVecAt(entry, 0, entry.Len()); err == nil {
				t.Fatal("a malformed coder must be refused")
			}
		})
	}
}

func TestEncodedHeaderErrors(t *testing.T) {
	payload := []byte("main payload")
	folder := copyFolder(payload, nil, nil, crcPtr(payload))
	plain := buildHeader([]*testFolder{folder},
		[]*testFile{{name: "p", data: payload, folder: 0, sub: 0}})

	t.Run("corrupt compressed header", func(t *testing.T) {
		fixture := buildEncodedArchive(plain, payload, deflateCompress)
		data := append([]byte(nil), fixture.bytes...)
		// Flip a byte in the compressed header, which sits after the payload
		// and before the next header.
		data[signatureHeaderLen+len(payload)+2] ^= 0xFF
		if _, err := Open(memorySource(data), archive.DefaultLimits()); err == nil {
			t.Fatal("a corrupt compressed header must be refused")
		}
	})

	t.Run("folder CRC mismatch", func(t *testing.T) {
		stored := deflateCompress(plain)
		wrong := fixtureCRC([]byte("wrong"))
		encodedFolder := &testFolder{
			coders:      []testCoder{{id: idDeflate}},
			unpackSizes: []uint64{uint64(len(plain))},
			packed:      stored,
			subSizes:    []uint64{uint64(len(plain))},
		}
		encodedFolder.folderCRC = &wrong
		next := appendNumber(nil, kEncodedHeader)
		next = append(next, buildStreamsInfo([]*testFolder{encodedFolder}, 0)...)
		data := wrapNextHeader(next, stored)
		_, err := Open(memorySource(data), archive.DefaultLimits())
		if err == nil || !errors.Is(err, archive.ErrInvalid) {
			t.Fatalf("err = %v, want ErrInvalid", err)
		}
	})

	t.Run("no folder", func(t *testing.T) {
		next := appendNumber(nil, kEncodedHeader)
		next = appendNumber(next, kEnd)
		data := wrapNextHeader(next, nil)
		_, err := Open(memorySource(data), archive.DefaultLimits())
		if err == nil || !errors.Is(err, archive.ErrUnsupported) {
			t.Fatalf("err = %v, want ErrUnsupported", err)
		}
	})

	t.Run("two substreams", func(t *testing.T) {
		stored := deflateCompress(plain)
		encodedFolder := &testFolder{
			coders:      []testCoder{{id: idDeflate}},
			unpackSizes: []uint64{uint64(len(plain))},
			packed:      stored,
			subSizes:    []uint64{uint64(len(plain) / 2), uint64(len(plain) - len(plain)/2)},
		}
		next := appendNumber(nil, kEncodedHeader)
		next = append(next, buildStreamsInfo([]*testFolder{encodedFolder}, 0)...)
		data := wrapNextHeader(next, stored)
		_, err := Open(memorySource(data), archive.DefaultLimits())
		if err == nil || !errors.Is(err, archive.ErrUnsupported) {
			t.Fatalf("err = %v, want ErrUnsupported", err)
		}
	})

	t.Run("past expanded budget", func(t *testing.T) {
		fixture := buildEncodedArchive(plain, payload, deflateCompress)
		limits := archive.DefaultLimits()
		limits.MaxTotalExpanded = uint64(len(plain) - 1)
		_, err := Open(memorySource(fixture.bytes), limits)
		if err == nil || !errors.Is(err, archive.ErrLimit) {
			t.Fatalf("err = %v, want ErrLimit", err)
		}
	})
}

func TestHeaderGrammarEdges(t *testing.T) {
	t.Run("archive properties are skipped", func(t *testing.T) {
		next := appendNumber(nil, kHeader)
		next = appendNumber(next, kArchiveProperties)
		next = appendNumber(next, 1)
		next = appendNumber(next, 3)
		next = append(next, 1, 2, 3)
		next = appendNumber(next, kEnd) // end of the archive-properties list
		next = appendNumber(next, kEnd) // end of the header
		header, err := parsePlainHeader(next)
		if err != nil || len(header.files) != 0 || len(header.streams.folders) != 0 {
			t.Fatalf("header = %+v, %v", header, err)
		}
	})
	t.Run("duplicate main streams", func(t *testing.T) {
		next := appendNumber(nil, kHeader)
		next = appendNumber(next, kMainStreamsInfo)
		next = appendNumber(next, kEnd)
		next = appendNumber(next, kMainStreamsInfo)
		next = appendNumber(next, kEnd)
		next = appendNumber(next, kEnd)
		if _, err := parsePlainHeader(next); err == nil {
			t.Fatal("a repeated main streams property must fail")
		}
	})
	t.Run("unknown streams property", func(t *testing.T) {
		next := appendNumber(nil, kHeader)
		next = appendNumber(next, kMainStreamsInfo)
		next = appendNumber(next, 0x99)
		next = appendNumber(next, kEnd)
		next = appendNumber(next, kEnd)
		if _, err := parsePlainHeader(next); err == nil {
			t.Fatal("an unknown streams property must fail")
		}
	})
	t.Run("substreams before folders", func(t *testing.T) {
		next := appendNumber(nil, kHeader)
		next = appendNumber(next, kMainStreamsInfo)
		next = appendNumber(next, kSubstreamsInfo)
		next = appendNumber(next, kEnd)
		next = appendNumber(next, kEnd)
		next = appendNumber(next, kEnd)
		if _, err := parsePlainHeader(next); err == nil {
			t.Fatal("substreams before a folder must fail")
		}
	})
	t.Run("missing name table", func(t *testing.T) {
		next := appendNumber(nil, kHeader)
		next = appendNumber(next, kFilesInfo)
		next = appendNumber(next, 1)
		next = appendNumber(next, kEnd)
		next = appendNumber(next, kEnd)
		if _, err := parsePlainHeader(next); err == nil {
			t.Fatal("a files info without names must fail")
		}
	})
	t.Run("unpaired surrogate", func(t *testing.T) {
		next := appendNumber(nil, kHeader)
		next = appendNumber(next, kFilesInfo)
		next = appendNumber(next, 1)
		body := []byte{0, 0x00, 0xD8, 0, 0} // external flag, lone high surrogate, NUL
		next = appendNumber(next, kName)
		next = appendNumber(next, uint64(len(body)))
		next = append(next, body...)
		next = appendNumber(next, kEnd)
		next = appendNumber(next, kEnd)
		if _, err := parsePlainHeader(next); err == nil {
			t.Fatal("an unpaired surrogate must fail")
		}
	})
}

func TestBindPairCycleIsExplicit(t *testing.T) {
	payload := []byte("eight888")
	folder := &testFolder{
		coders:      []testCoder{{id: idCopy}, {id: idCopy}},
		bindPairs:   []bindPair{{input: 0, output: 0}},
		unpackSizes: []uint64{uint64(len(payload)), uint64(len(payload))},
		packed:      payload,
		subSizes:    []uint64{uint64(len(payload))},
	}
	fixture := buildArchive([]*testFolder{folder},
		[]*testFile{{name: "cycle.bin", data: payload, folder: 0, sub: 0}})
	reader := openBytes(t, fixture.bytes, archive.DefaultLimits())
	entry, err := reader.OpenEntrySource("cycle.bin", 2)
	if err != nil {
		t.Fatalf("OpenEntrySource: %v", err)
	}
	_, err = source.ReadVecAt(entry, 0, entry.Len())
	if err == nil || !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("err = %v, want ErrCorrupt", err)
	}
}

func TestAntiFileIsListedButNotOpened(t *testing.T) {
	payload := []byte("data")
	fixture := buildArchive(
		[]*testFolder{copyFolder(payload, nil, nil, crcPtr(payload))},
		[]*testFile{
			{name: "data.bin", data: payload, folder: 0, sub: 0},
			{name: "removed.bin", anti: true},
		})
	reader := openBytes(t, fixture.bytes, archive.DefaultLimits())
	entries, err := reader.Entries()
	if err != nil || len(entries) != 2 {
		t.Fatalf("entries = %+v, %v", entries, err)
	}
	if entries[1].Kind != archive.KindOther {
		t.Errorf("anti-file kind = %v, want KindOther", entries[1].Kind)
	}
	if _, err := reader.OpenEntrySource("removed.bin", 2); err == nil {
		t.Fatal("an anti-file must not open as data")
	}
}

func TestCoderLabels(t *testing.T) {
	labels := map[string][]byte{
		"Copy": idCopy, "LZMA": idLZMA, "LZMA2": idLZMA2, "Deflate": idDeflate,
		"Deflate64": idDeflate64, "BZip2": idBzip2, "AES-256": idAES,
		"Delta": idDelta, "BCJ x86": idBCJX86, "BCJ2": idBCJ2, "PPMd": idPPMd,
		"BCJ Alpha": idBCJAlpha, "BCJ PPC": idBCJPPC, "BCJ IA-64": idBCJIA64,
		"BCJ ARM": idBCJARM, "BCJ ARM-Thumb": idBCJARMT, "BCJ SPARC": idBCJSPARC,
		"BCJ ARM64": idBCJARM64, "BCJ RISC-V": idBCJRISCV,
		"Swap2": idSwap2, "Swap4": idSwap4,
	}
	for want, id := range labels {
		if got := coderLabel(id); got != want {
			t.Errorf("coderLabel(%x) = %q, want %q", id, got, want)
		}
	}
	if got := coderLabel([]byte{0x06, 0x99}); got != "0x0699" {
		t.Errorf("unknown coder label = %q", got)
	}
}

func TestEmptyEntryExtentsAndBounds(t *testing.T) {
	payload := []byte("data")
	fixture := buildArchive(
		[]*testFolder{copyFolder(payload, nil, nil, crcPtr(payload))},
		[]*testFile{
			{name: "data.bin", data: payload, folder: 0, sub: 0},
			{name: "empty.bin", empty: true},
		})
	reader := openBytes(t, fixture.bytes, archive.DefaultLimits())

	empty, err := reader.OpenEntrySource("empty.bin", 2)
	if err != nil {
		t.Fatalf("OpenEntrySource(empty): %v", err)
	}
	if !empty.IsEmpty() || empty.Len() != 0 {
		t.Error("the empty entry must have length zero")
	}
	if _, ok := empty.Folder(); ok {
		t.Error("an empty entry has no folder")
	}
	if ranges, err := empty.Extents(0, 0); err != nil || len(ranges) != 0 {
		t.Errorf("empty Extents = %v, %v", ranges, err)
	}
	if ranges, err := empty.MapToImage(0, 0); err != nil || len(ranges) != 0 {
		t.Errorf("empty MapToImage = %v, %v", ranges, err)
	}
	if _, err := empty.ReadAt(0, make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Errorf("empty read err = %v", err)
	}

	data, err := reader.OpenEntrySource("data.bin", 3)
	if err != nil {
		t.Fatalf("OpenEntrySource(data): %v", err)
	}
	if _, err := data.Extents(0, data.Len()+1); !errors.Is(err, source.ErrOutOfRange) {
		t.Errorf("Extents out of range err = %v", err)
	}
	if _, err := data.MapToImage(0, data.Len()+1); !errors.Is(err, source.ErrOutOfRange) {
		t.Errorf("MapToImage out of range err = %v", err)
	}
	if imageRanges, err := data.MapToImage(0, 0); err != nil || imageRanges != nil {
		t.Errorf("zero-length MapToImage = %v, %v", imageRanges, err)
	}
}
