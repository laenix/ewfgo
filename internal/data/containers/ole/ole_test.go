package ole

import (
	"encoding/binary"
	"errors"
	"testing"
	"unicode/utf16"

	"github.com/laenix/ewfgo/internal/data/source"
)

const testSector = 512

// testEntry is one directory record for the synthetic compound file builder.
// Zero links mean NO_ENTRY; the builder turns them into the sentinel.
type testEntry struct {
	name          string
	kind          Kind
	data          []byte
	left          uint32
	right         uint32
	child         uint32
	startOverride *uint32
	sizeOverride  *uint64
	clsid         CLSID
	state         uint32
	created       uint64
	modified      uint64
	color         uint8
}

type builtCFB struct {
	data            []byte
	fatOffset       int
	miniFATOffset   int
	directoryOffset int
	starts          map[string]uint32
}

func put16(b []byte, off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }
func put32(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }
func put64(b []byte, off int, v uint64) { binary.LittleEndian.PutUint64(b[off:], v) }

// buildCompound writes a version-3 compound file: one FAT sector, a directory
// chain, one mini FAT sector, regular stream sectors and a mini stream.  It is
// deliberately small but exercises both the FAT and mini FAT.
func buildCompound(t *testing.T, entries []testEntry) builtCFB {
	t.Helper()
	if len(entries) == 0 {
		t.Fatal("compound file needs at least the root entry")
	}
	if entries[0].kind == 0 {
		entries[0].kind = kindRoot
	}
	if entries[0].name == "" {
		entries[0].name = "Root Entry"
	}

	dirSectors := uint32((len(entries)*directoryEntryBytes + testSector - 1) / testSector)
	const fatSector = uint32(0)
	dirStart := uint32(1)
	miniFATSector := dirStart + dirSectors
	next := miniFATSector + 1

	type placement struct {
		start uint32
		size  uint64
	}
	places := make([]placement, len(entries))

	var mini []byte
	var miniFAT []uint32
	type regular struct {
		data  []byte
		first uint32
	}
	var regulars []regular

	for i := 1; i < len(entries); i++ {
		e := &entries[i]
		if e.kind != kindStream {
			continue
		}
		switch {
		case len(e.data) == 0:
			places[i] = placement{start: endOfChain}
		case len(e.data) < 4096:
			for len(mini)%64 != 0 {
				mini = append(mini, 0)
			}
			first := uint32(len(mini) / 64)
			mini = append(mini, e.data...)
			for len(mini)%64 != 0 {
				mini = append(mini, 0)
			}
			count := (len(e.data) + 63) / 64
			for len(miniFAT) < len(mini)/64 {
				miniFAT = append(miniFAT, freeSector)
			}
			for j := 0; j < count; j++ {
				index := int(first) + j
				if j+1 == count {
					miniFAT[index] = endOfChain
				} else {
					miniFAT[index] = uint32(index + 1)
				}
			}
			places[i] = placement{start: first, size: uint64(len(e.data))}
		default:
			count := uint32((len(e.data) + testSector - 1) / testSector)
			first := next
			next += count
			regulars = append(regulars, regular{data: e.data, first: first})
			places[i] = placement{start: first, size: uint64(len(e.data))}
		}
	}

	miniStreamStart := next
	miniSectors := uint32((len(mini) + testSector - 1) / testSector)
	next += miniSectors
	if miniSectors == 0 {
		miniStreamStart = endOfChain
	}
	places[0] = placement{start: miniStreamStart, size: uint64(len(mini))}

	for i := 0; i < len(entries); i++ {
		if entries[i].startOverride != nil {
			places[i].start = *entries[i].startOverride
		}
		if entries[i].sizeOverride != nil {
			places[i].size = *entries[i].sizeOverride
		}
	}

	const fatEntries = testSector / 4
	if next > fatEntries {
		t.Fatalf("fixture needs %d sectors, the one FAT sector holds %d", next, fatEntries)
	}
	if len(miniFAT) > testSector/4 {
		t.Fatalf("fixture mini FAT needs %d entries, one sector holds %d", len(miniFAT), testSector/4)
	}
	fat := make([]uint32, fatEntries)
	for i := range fat {
		fat[i] = freeSector
	}
	fat[fatSector] = fatSectorMark
	for i := uint32(0); i < dirSectors; i++ {
		sector := dirStart + i
		if i+1 == dirSectors {
			fat[sector] = endOfChain
		} else {
			fat[sector] = sector + 1
		}
	}
	fat[miniFATSector] = endOfChain
	for _, r := range regulars {
		count := uint32((len(r.data) + testSector - 1) / testSector)
		for j := uint32(0); j < count; j++ {
			sector := r.first + j
			if j+1 == count {
				fat[sector] = endOfChain
			} else {
				fat[sector] = sector + 1
			}
		}
	}
	for i := uint32(0); i < miniSectors; i++ {
		sector := miniStreamStart + i
		if i+1 == miniSectors {
			fat[sector] = endOfChain
		} else {
			fat[sector] = sector + 1
		}
	}

	header := make([]byte, testSector)
	copy(header[0:8], signature[:])
	put16(header, 24, 0x003E) // minor version
	put16(header, 26, 3)      // major version
	put16(header, 28, 0xFFFE) // byte order
	put16(header, 30, 9)      // sector shift (512)
	put16(header, 32, 6)      // mini sector shift (64)
	put32(header, 40, dirSectors)
	put32(header, 44, 1) // one FAT sector
	put32(header, 48, dirStart)
	put32(header, 56, 4096) // mini stream cutoff
	put32(header, 60, miniFATSector)
	put32(header, 64, 1) // one mini FAT sector
	put32(header, 68, endOfChain)
	put32(header, 72, 0) // no extra DIFAT sectors
	put32(header, 76, fatSector)
	for i := 1; i < 109; i++ {
		put32(header, 76+i*4, freeSector)
	}

	out := append([]byte(nil), header...)
	fatBytes := make([]byte, testSector)
	for i, value := range fat {
		put32(fatBytes, i*4, value)
	}
	out = append(out, fatBytes...)

	directory := make([]byte, int(dirSectors)*testSector)
	for i := range entries {
		e := &entries[i]
		raw := directory[i*directoryEntryBytes : (i+1)*directoryEntryBytes]
		units := append(utf16.Encode([]rune(e.name)), 0)
		if len(units)*2 > 64 {
			t.Fatalf("entry name %q is longer than 31 UTF-16 units", e.name)
		}
		for j, unit := range units {
			put16(raw, j*2, unit)
		}
		put16(raw, 64, uint16(len(units)*2))
		raw[66] = uint8(e.kind)
		raw[67] = e.color
		left, right, child := e.left, e.right, e.child
		if left == 0 {
			left = noEntry
		}
		if right == 0 {
			right = noEntry
		}
		if child == 0 {
			child = noEntry
		}
		put32(raw, 68, left)
		put32(raw, 72, right)
		put32(raw, 76, child)
		copy(raw[80:96], e.clsid[:])
		put32(raw, 96, e.state)
		put64(raw, 100, e.created)
		put64(raw, 108, e.modified)
		put32(raw, 116, places[i].start)
		put32(raw, 120, uint32(places[i].size))
	}
	out = append(out, directory...)

	miniFATBytes := make([]byte, testSector)
	for i, value := range miniFAT {
		put32(miniFATBytes, i*4, value)
	}
	out = append(out, miniFATBytes...)

	for _, r := range regulars {
		padded := append([]byte(nil), r.data...)
		for len(padded)%testSector != 0 {
			padded = append(padded, 0)
		}
		out = append(out, padded...)
	}

	miniPadded := append([]byte(nil), mini...)
	for len(miniPadded)%testSector != 0 {
		miniPadded = append(miniPadded, 0)
	}
	out = append(out, miniPadded...)

	if len(out) != int(next+1)*testSector {
		t.Fatalf("fixture length %d, sectors imply %d", len(out), int(next+1)*testSector)
	}

	starts := make(map[string]uint32)
	for i := range entries {
		if entries[i].kind == kindStream {
			starts[entries[i].name] = places[i].start
		}
	}
	return builtCFB{
		data:            out,
		fatOffset:       testSector,
		miniFATOffset:   int(miniFATSector+1) * testSector,
		directoryOffset: int(dirStart+1) * testSector,
		starts:          starts,
	}
}

func (b builtCFB) patchFAT(t *testing.T, sector, value uint32) {
	t.Helper()
	off := b.fatOffset + int(sector)*4
	if off+4 > len(b.data) {
		t.Fatalf("FAT patch for sector %d is outside the fixture", sector)
	}
	put32(b.data, off, value)
}

func (b builtCFB) patchMiniFAT(t *testing.T, index, value uint32) {
	t.Helper()
	off := b.miniFATOffset + int(index)*4
	if off+4 > len(b.data) {
		t.Fatalf("mini FAT patch for index %d is outside the fixture", index)
	}
	put32(b.data, off, value)
}

func (b builtCFB) patchDirEntry(t *testing.T, index, offset int, value uint16) {
	t.Helper()
	off := b.directoryOffset + index*directoryEntryBytes + offset
	if off+2 > len(b.data) {
		t.Fatalf("directory patch for entry %d is outside the fixture", index)
	}
	put16(b.data, off, value)
}

func readAll(t *testing.T, src source.ByteSource) []byte {
	t.Helper()
	data, err := source.ReadVecAt(src, 0, src.Len())
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	return data
}

func entryNames(entries []Entry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name)
	}
	return out
}

func TestValidListingAndStreams(t *testing.T) {
	small := []byte("hello mini stream")
	large := make([]byte, 5000)
	for i := range large {
		large[i] = byte(i)
	}
	inner := []byte("inner bytes")
	var clsid CLSID
	for i := range clsid {
		clsid[i] = byte(0x10 + i)
	}

	entries := []testEntry{
		{name: "Root Entry", kind: kindRoot, child: 1, clsid: clsid, state: 0x1234,
			created: 0x1122334455667788, modified: 0x99AABBCCDDEEFF00, color: 1},
		{name: "large.bin", kind: kindStream, data: large, right: 2, color: 1},
		{name: "small.txt", kind: kindStream, data: small, right: 3, color: 1},
		{name: "Sub", kind: kindStorage, child: 4, color: 1},
		{name: "inner.txt", kind: kindStream, data: inner, color: 1},
	}
	built := buildCompound(t, entries)
	file, err := Open(source.NewMemorySourceWithImage(1, 9, built.data))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	h := file.Header()
	if h.MajorVersion != 3 || h.MinorVersion != 0x3E || h.SectorSize != 512 || h.MiniSectorSize != 64 {
		t.Fatalf("header = %+v", h)
	}
	if h.MiniCutoff != 4096 || h.FATSectors != 1 || h.DirectorySectors != 2 {
		t.Fatalf("header geometry = %+v", h)
	}
	root := file.Root()
	if root == nil || root.Kind != kindRoot || root.Name != "Root Entry" {
		t.Fatalf("root = %+v", root)
	}
	if root.CLSID.String() != "13121110-1514-1716-1819-1A1B1C1D1E1F" {
		t.Fatalf("root CLSID = %q", root.CLSID.String())
	}
	if root.State != 0x1234 || root.Created != 0x1122334455667788 || root.Modified != 0x99AABBCCDDEEFF00 {
		t.Fatalf("root metadata = %+v", root)
	}
	if root.Kind.Label() != "root" || root.Type != kindRoot {
		t.Fatalf("root labels = %q %v", root.Kind.Label(), root.Type)
	}

	rootChildren, err := file.ListStorage("")
	if err != nil {
		t.Fatalf("ListStorage(root): %v", err)
	}
	if got, want := entryNames(rootChildren), []string{"large.bin", "small.txt", "Sub"}; !equalStrings(got, want) {
		t.Fatalf("root children = %v, want %v", got, want)
	}
	if rootChildren[2].Kind != kindStorage {
		t.Fatalf("Sub kind = %v", rootChildren[2].Kind)
	}

	subChildren, err := file.ListStorage("Sub")
	if err != nil {
		t.Fatalf("ListStorage(Sub): %v", err)
	}
	if got, want := entryNames(subChildren), []string{"inner.txt"}; !equalStrings(got, want) {
		t.Fatalf("Sub children = %v, want %v", got, want)
	}

	smallEntry, err := file.FindStream("small.txt")
	if err != nil {
		t.Fatalf("FindStream(small.txt): %v", err)
	}
	if smallEntry.Size != uint64(len(small)) || !smallEntry.IsStream() {
		t.Fatalf("small entry = %+v", smallEntry)
	}
	if _, err := file.FindStream("Sub/inner.txt"); err != nil {
		t.Fatalf("FindStream(Sub/inner.txt): %v", err)
	}
	if _, err := file.FindStream("SMALL.TXT"); err != nil {
		t.Fatalf("FindStream is case-insensitive: %v", err)
	}

	stream, err := file.OpenStream("small.txt", 7)
	if err != nil {
		t.Fatalf("OpenStream(small.txt): %v", err)
	}
	if stream.SourceID() != 7 {
		t.Fatalf("stream id = %d", stream.SourceID())
	}
	if got := readAll(t, stream); string(got) != string(small) {
		t.Fatalf("small stream = %q", got)
	}

	largeStream, err := file.OpenStream("large.bin", 8)
	if err != nil {
		t.Fatalf("OpenStream(large.bin): %v", err)
	}
	if got := readAll(t, largeStream); !equalBytes(got, large) {
		t.Fatalf("large stream differs: %d bytes", len(got))
	}

	innerStream, err := file.OpenStream("Sub\\inner.txt", 9)
	if err != nil {
		t.Fatalf("OpenStream(Sub\\inner.txt): %v", err)
	}
	if got := readAll(t, innerStream); string(got) != string(inner) {
		t.Fatalf("inner stream = %q", got)
	}
}

// buildCompoundV4 writes a minimal version-4 file with one regular stream.
func buildCompoundV4(t *testing.T, stream []byte) []byte {
	t.Helper()
	const sector = 4096
	const streamStart = 2
	streamSectors := (len(stream) + sector - 1) / sector

	header := make([]byte, sector)
	copy(header[0:8], Signature[:])
	put16(header, 24, 0x003E)
	put16(header, 26, 4)
	put16(header, 28, 0xFFFE)
	put16(header, 30, 12) // 4096-byte sectors
	put16(header, 32, 6)
	put32(header, 40, 1) // one directory sector
	put32(header, 44, 1) // one FAT sector
	put32(header, 48, 1)
	put32(header, 56, 4096)
	put32(header, 60, endOfChain)
	put32(header, 64, 0)
	put32(header, 68, endOfChain)
	put32(header, 72, 0)
	put32(header, 76, 0)
	for i := 1; i < 109; i++ {
		put32(header, 76+i*4, freeSector)
	}

	fat := make([]uint32, sector/4)
	for i := range fat {
		fat[i] = freeSector
	}
	fat[0] = fatSectorMark
	fat[1] = endOfChain
	for i := 0; i < streamSectors; i++ {
		value := endOfChain
		if i+1 < streamSectors {
			value = uint32(streamStart + i + 1)
		}
		fat[streamStart+i] = value
	}
	fatBytes := make([]byte, sector)
	for i, value := range fat {
		put32(fatBytes, i*4, value)
	}

	directory := make([]byte, sector)
	write := func(index int, name string, kind Kind, child uint32, start uint32, size uint64) {
		raw := directory[index*directoryEntryBytes : (index+1)*directoryEntryBytes]
		units := append(utf16.Encode([]rune(name)), 0)
		for j, unit := range units {
			put16(raw, j*2, unit)
		}
		put16(raw, 64, uint16(len(units)*2))
		raw[66] = uint8(kind)
		raw[67] = 1
		put32(raw, 68, noEntry)
		put32(raw, 72, noEntry)
		put32(raw, 76, child)
		put32(raw, 116, start)
		put64(raw, 120, size) // version 4 uses the full 64-bit size
	}
	write(0, "Root Entry", kindRoot, 1, endOfChain, 0)
	write(1, "big.bin", kindStream, noEntry, streamStart, uint64(len(stream)))

	out := append([]byte(nil), header...)
	out = append(out, fatBytes...)
	out = append(out, directory...)
	payload := append([]byte(nil), stream...)
	for len(payload)%sector != 0 {
		payload = append(payload, 0)
	}
	out = append(out, payload...)
	return out
}

func TestVersion4Sectors(t *testing.T) {
	stream := make([]byte, 5000)
	for i := range stream {
		stream[i] = byte(i)
	}
	file, err := Open(source.NewMemorySource(1, buildCompoundV4(t, stream)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if h := file.Header(); h.MajorVersion != 4 || h.SectorSize != 4096 || h.Sectors != 4 {
		t.Fatalf("v4 header = %+v", h)
	}
	entry, err := file.FindStream("big.bin")
	if err != nil {
		t.Fatalf("FindStream: %v", err)
	}
	if entry.Size != uint64(len(stream)) {
		t.Fatalf("v4 stream size = %d", entry.Size)
	}
	got, err := file.OpenStream("big.bin", 2)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if data := readAll(t, got); !equalBytes(data, stream) {
		t.Fatalf("v4 stream differs: %d bytes", len(data))
	}
}

func TestRedBlackSiblingOrder(t *testing.T) {
	// Root's child tree is B with left A and right C; in-order is A, B, C.
	entries := []testEntry{
		{name: "Root Entry", kind: kindRoot, child: 2, color: 1},
		{name: "A", kind: kindStream, data: []byte("a"), color: 0},
		{name: "B", kind: kindStream, data: []byte("b"), left: 1, right: 3, color: 1},
		{name: "C", kind: kindStream, data: []byte("c"), color: 0},
	}
	built := buildCompound(t, entries)
	file, err := Open(source.NewMemorySource(1, built.data))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	children, err := file.ListStorage("/")
	if err != nil {
		t.Fatalf("ListStorage: %v", err)
	}
	if got, want := entryNames(children), []string{"A", "B", "C"}; !equalStrings(got, want) {
		t.Fatalf("children = %v, want %v", got, want)
	}
}

func TestPathErrors(t *testing.T) {
	entries := []testEntry{
		{name: "Root Entry", kind: kindRoot, child: 1, color: 1},
		{name: "dir", kind: kindStorage, child: 2, color: 1},
		{name: "file.txt", kind: kindStream, data: []byte("data"), color: 1},
	}
	built := buildCompound(t, entries)
	file, err := Open(source.NewMemorySource(1, built.data))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	for _, path := range []string{"missing", "dir/missing", "../file.txt"} {
		if _, err := file.FindStream(path); !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrInvalidPath) {
			t.Fatalf("FindStream(%q) error = %v, want not found or invalid path", path, err)
		}
	}
	if _, err := file.ListStorage("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ListStorage(missing) error = %v", err)
	}
	if _, err := file.FindStream("dir"); !errors.Is(err, ErrNotStream) {
		t.Fatalf("FindStream(storage) error = %v", err)
	}
	if _, err := file.ListStorage("dir/file.txt"); !errors.Is(err, ErrNotStorage) {
		t.Fatalf("ListStorage(stream) error = %v", err)
	}
	if _, err := file.OpenStream("dir", 1); !errors.Is(err, ErrNotStream) {
		t.Fatalf("OpenStream(storage) error = %v", err)
	}
	if _, err := file.OpenStream("missing", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("OpenStream(missing) error = %v", err)
	}
}

func TestTruncatedAndInvalidHeaders(t *testing.T) {
	entries := []testEntry{
		{name: "Root Entry", kind: kindRoot, child: 1, color: 1},
		{name: "a", kind: kindStream, data: []byte("a"), color: 1},
	}
	valid := buildCompound(t, entries)

	cases := []struct {
		name   string
		mutate func(*builtCFB)
		empty  bool
		len    int
		kind   error
	}{
		{name: "empty", empty: true, kind: source.ErrCorrupt},
		{name: "short header", len: 100, kind: source.ErrCorrupt},
		{name: "bad signature", mutate: func(b *builtCFB) { b.data[0] = 0 }, kind: source.ErrCorrupt},
		{name: "bad byte order", mutate: func(b *builtCFB) { put16(b.data, 28, 0x1234) }, kind: source.ErrCorrupt},
		{name: "unsupported version", mutate: func(b *builtCFB) { put16(b.data, 26, 5) }, kind: source.ErrUnsupported},
		{name: "bad sector shift", mutate: func(b *builtCFB) { put16(b.data, 30, 10) }, kind: source.ErrCorrupt},
		{name: "bad mini shift", mutate: func(b *builtCFB) { put16(b.data, 32, 7) }, kind: source.ErrCorrupt},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			built := builtCFB{data: append([]byte(nil), valid.data...)}
			if tc.mutate != nil {
				tc.mutate(&built)
			}
			data := built.data
			if tc.empty {
				data = nil
			} else if tc.len > 0 {
				data = data[:tc.len]
			}
			_, err := Open(source.NewMemorySource(1, data))
			if !errors.Is(err, tc.kind) {
				t.Fatalf("Open error = %v, want %v", err, tc.kind)
			}
		})
	}
}

func TestFATChainFailures(t *testing.T) {
	large := make([]byte, 5000)
	entries := []testEntry{
		{name: "Root Entry", kind: kindRoot, child: 1, color: 1},
		{name: "big", kind: kindStream, data: large, color: 1},
	}
	valid := buildCompound(t, entries)
	start := valid.starts["big"]

	t.Run("loop", func(t *testing.T) {
		built := builtCFB{data: append([]byte(nil), valid.data...), fatOffset: valid.fatOffset}
		built.patchFAT(t, start, start)
		file, err := Open(source.NewMemorySource(1, built.data))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if _, err := file.OpenStream("big", 1); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("OpenStream error = %v, want corrupt", err)
		}
	})

	t.Run("free link", func(t *testing.T) {
		built := builtCFB{data: append([]byte(nil), valid.data...), fatOffset: valid.fatOffset}
		built.patchFAT(t, start, freeSector)
		file, err := Open(source.NewMemorySource(1, built.data))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if _, err := file.OpenStream("big", 1); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("OpenStream error = %v, want corrupt", err)
		}
	})

	t.Run("sector out of range", func(t *testing.T) {
		built := builtCFB{data: append([]byte(nil), valid.data...), fatOffset: valid.fatOffset}
		built.patchFAT(t, start, 1000)
		file, err := Open(source.NewMemorySource(1, built.data))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if _, err := file.OpenStream("big", 1); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("OpenStream error = %v, want corrupt", err)
		}
	})

	t.Run("chain shorter than declared size", func(t *testing.T) {
		built := builtCFB{data: append([]byte(nil), valid.data...), fatOffset: valid.fatOffset}
		built.patchFAT(t, start, endOfChain)
		file, err := Open(source.NewMemorySource(1, built.data))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if _, err := file.OpenStream("big", 1); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("OpenStream error = %v, want corrupt", err)
		}
	})

	t.Run("directory chain loop is refused at open", func(t *testing.T) {
		built := builtCFB{data: append([]byte(nil), valid.data...), fatOffset: valid.fatOffset}
		dirStart := binary.LittleEndian.Uint32(built.data[48:])
		built.patchFAT(t, dirStart, dirStart)
		if _, err := Open(source.NewMemorySource(1, built.data)); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("Open error = %v, want corrupt", err)
		}
	})
}

func TestMiniFATChainFailures(t *testing.T) {
	payload := make([]byte, 200)
	for i := range payload {
		payload[i] = byte(i)
	}
	entries := []testEntry{
		{name: "Root Entry", kind: kindRoot, child: 1, color: 1},
		{name: "small", kind: kindStream, data: payload, color: 1},
	}
	valid := buildCompound(t, entries)
	start := valid.starts["small"]

	t.Run("loop", func(t *testing.T) {
		built := builtCFB{data: append([]byte(nil), valid.data...), miniFATOffset: valid.miniFATOffset}
		built.patchMiniFAT(t, start, start)
		file, err := Open(source.NewMemorySource(1, built.data))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if _, err := file.OpenStream("small", 1); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("OpenStream error = %v, want corrupt", err)
		}
	})

	t.Run("chain shorter than declared size", func(t *testing.T) {
		built := builtCFB{data: append([]byte(nil), valid.data...), miniFATOffset: valid.miniFATOffset}
		built.patchMiniFAT(t, start, endOfChain)
		file, err := Open(source.NewMemorySource(1, built.data))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if _, err := file.OpenStream("small", 1); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("OpenStream error = %v, want corrupt", err)
		}
	})

	t.Run("mini sector outside mini stream", func(t *testing.T) {
		built := builtCFB{data: append([]byte(nil), valid.data...), miniFATOffset: valid.miniFATOffset}
		built.patchMiniFAT(t, start, 4)
		built.patchMiniFAT(t, 4, endOfChain)
		file, err := Open(source.NewMemorySource(1, built.data))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if _, err := file.OpenStream("small", 1); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("OpenStream error = %v, want corrupt", err)
		}
	})
}

func TestDirectoryTreeFailures(t *testing.T) {
	t.Run("sibling cycle", func(t *testing.T) {
		entries := []testEntry{
			{name: "Root Entry", kind: kindRoot, child: 1, color: 1},
			{name: "a", kind: kindStream, data: []byte("a"), right: 1, color: 1},
		}
		built := buildCompound(t, entries)
		file, err := Open(source.NewMemorySource(1, built.data))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if _, err := file.ListStorage(""); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("ListStorage error = %v, want corrupt", err)
		}
	})

	t.Run("child link past the table", func(t *testing.T) {
		entries := []testEntry{
			{name: "Root Entry", kind: kindRoot, child: 1, color: 1},
			{name: "sub", kind: kindStorage, child: 999, color: 1},
		}
		built := buildCompound(t, entries)
		file, err := Open(source.NewMemorySource(1, built.data))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if _, err := file.ListStorage("sub"); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("ListStorage error = %v, want corrupt", err)
		}
	})

	t.Run("first directory entry is not root", func(t *testing.T) {
		entries := []testEntry{
			{name: "Root Entry", kind: kindRoot, child: 1, color: 1},
			{name: "a", kind: kindStream, data: []byte("a"), color: 1},
		}
		built := buildCompound(t, entries)
		built.patchDirEntry(t, 0, 66, uint16(kindStream))
		if _, err := Open(source.NewMemorySource(1, built.data)); !errors.Is(err, source.ErrCorrupt) {
			t.Fatalf("Open error = %v, want corrupt", err)
		}
	})
}

func TestStreamSizeLimitAndEmptyStream(t *testing.T) {
	large := make([]byte, 5000)
	entries := []testEntry{
		{name: "Root Entry", kind: kindRoot, child: 1, color: 1},
		{name: "big", kind: kindStream, data: large, right: 2, color: 1},
		{name: "empty", kind: kindStream, data: nil, color: 1},
	}
	built := buildCompound(t, entries)
	file, err := OpenWithLimits(source.NewMemorySource(1, built.data), Limits{MaxStreamBytes: 1024})
	if err != nil {
		t.Fatalf("OpenWithLimits: %v", err)
	}
	if _, err := file.OpenStream("big", 1); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("OpenStream(big) error = %v, want corrupt", err)
	}
	empty, err := file.OpenStream("empty", 2)
	if err != nil {
		t.Fatalf("OpenStream(empty): %v", err)
	}
	if empty.Len() != 0 {
		t.Fatalf("empty stream length = %d", empty.Len())
	}

	smallEntries := []testEntry{
		{name: "Root Entry", kind: kindRoot, child: 1, color: 1},
		{name: "small", kind: kindStream, data: []byte("twenty bytes or so"), color: 1},
	}
	smallBuilt := buildCompound(t, smallEntries)
	if _, err := OpenWithLimits(source.NewMemorySource(1, smallBuilt.data), Limits{MaxStreamBytes: 10}); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("OpenWithLimits error = %v, want corrupt (root mini stream cap)", err)
	}
}

func TestEntriesAndStats(t *testing.T) {
	entries := []testEntry{
		{name: "Root Entry", kind: kindRoot, child: 1, color: 1},
		{name: "a", kind: kindStream, data: []byte("a"), color: 1},
	}
	built := buildCompound(t, entries)
	file, err := Open(source.NewMemorySource(1, built.data))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// One 512-byte directory sector holds four 128-byte entries; the two
	// unused slots are parsed as empty entries, as the format defines them.
	if len(file.Entries()) != 4 {
		t.Fatalf("entries = %d", len(file.Entries()))
	}
	stats := file.Stats()
	if stats.Streams != 1 || stats.Storages != 1 || stats.DirectoryEntries != 4 || stats.FATEntries != 128 {
		t.Fatalf("stats = %+v", stats)
	}
}

func equalStrings(a, b []string) bool {
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
