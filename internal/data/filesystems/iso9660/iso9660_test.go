package iso9660

import (
	"bytes"
	"compress/zlib"
	"errors"
	"testing"
	"time"

	"github.com/laenix/ewfgo/internal/data/source"
)

// ---- synthetic image builders -------------------------------------------

const (
	isoBlockSize = 2048
	isoVRSSector = 16
	isoBlocks    = 128
)

func le16(v uint16) []byte { return []byte{byte(v), byte(v >> 8)} }
func be16(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }
func le32(v uint32) []byte { return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)} }
func be32(v uint32) []byte { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }

func putBytes(b []byte, at int, v []byte)  { copy(b[at:], v) }
func putLE16(b []byte, at int, v uint16)   { putBytes(b, at, le16(v)) }
func putBE16(b []byte, at int, v uint16)   { putBytes(b, at, be16(v)) }
func putLE32(b []byte, at int, v uint32)   { putBytes(b, at, le32(v)) }
func putBE32(b []byte, at int, v uint32)   { putBytes(b, at, be32(v)) }
func putBoth16(b []byte, at int, v uint16) { putLE16(b, at, v); putBE16(b, at+2, v) }
func putBoth32(b []byte, at int, v uint32) { putLE32(b, at, v); putBE32(b, at+4, v) }

func putASCII(b []byte, at int, text string) { putBytes(b, at, []byte(text)) }

func padASCII(b []byte, at, width int, text string) {
	for i := 0; i < width; i++ {
		if i < len(text) {
			b[at+i] = text[i]
		} else {
			b[at+i] = ' '
		}
	}
}

// isoRecord builds one directory record. The record length includes the
// identifier padding byte and the system-use area.
func isoRecord(identifier []byte, extent, dataLen uint32, flags uint8, systemUse []byte, unitSize, gap uint8) []byte {
	body := make([]byte, 33+len(identifier))
	if len(identifier)%2 == 0 {
		body = append(body, 0)
	}
	body = append(body, systemUse...)
	if len(body) > 255 {
		panic("directory record too large for the test builder")
	}
	body[0] = byte(len(body))
	body[1] = 0
	putBoth32(body, 2, extent)
	putBoth32(body, 10, dataLen)
	copy(body[18:25], []byte{124, 1, 2, 3, 4, 5, 0})
	body[25] = flags
	body[26] = unitSize
	body[27] = gap
	putBoth16(body, 28, 1)
	body[32] = byte(len(identifier))
	copy(body[33:], identifier)
	return body
}

const (
	testFlagDir   = 0x02
	testFlagMulti = 0x80
)

func pathRecord(identifier []byte, extent uint32, parent uint16, bigEndian bool) []byte {
	record := make([]byte, 8+len(identifier))
	if len(identifier)%2 == 1 {
		record = append(record, 0)
	}
	record[0] = byte(len(identifier))
	record[1] = 0
	if bigEndian {
		putBE32(record, 2, extent)
		putBE16(record, 6, parent)
	} else {
		putLE32(record, 2, extent)
		putLE16(record, 6, parent)
	}
	copy(record[8:], identifier)
	return record
}

func suspEntry(signature string, data []byte) []byte {
	out := make([]byte, 4+len(data))
	copy(out, signature)
	out[2] = byte(len(out))
	out[3] = 1
	copy(out[4:], data)
	return out
}

func suspNM(name string) []byte {
	data := append([]byte{0}, []byte(name)...)
	return suspEntry("NM", data)
}

func suspPX(mode, links, uid, gid uint32) []byte {
	data := make([]byte, 16)
	putBE32(data, 0, mode)
	putBE32(data, 4, links)
	putBE32(data, 8, uid)
	putBE32(data, 12, gid)
	return suspEntry("PX", data)
}

func suspTF(recording []byte) []byte {
	data := append([]byte{0x02}, recording...)
	return suspEntry("TF", data)
}

func suspSL(components ...string) []byte {
	data := []byte{0}
	// First component is the root marker, then the named components.
	data = append(data, 0x08, 0)
	for _, component := range components {
		data = append(data, 0, byte(len(component)))
		data = append(data, []byte(component)...)
	}
	return suspEntry("SL", data)
}

func suspLoc(entry string, block uint32) []byte {
	data := make([]byte, 8)
	putLE32(data, 0, block)
	putBE32(data, 4, block)
	return suspEntry(entry, data)
}

func suspZisofs(plainLen uint32, blockShift uint8) []byte {
	data := make([]byte, 12)
	copy(data, "pz")
	data[2] = 4
	data[3] = blockShift
	putLE32(data, 4, plainLen)
	putBE32(data, 8, plainLen)
	return suspEntry("ZF", data)
}

func zlibBytes(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(plain); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

func zisofsPayload(t *testing.T, plain []byte, blockShift uint8) []byte {
	t.Helper()
	blockSize := 1 << blockShift
	blocks := (len(plain) + blockSize - 1) / blockSize
	tableEnd := 16 + 4*(blocks+1)
	var stream []byte
	pointers := make([]uint32, 0, blocks+1)
	position := tableEnd
	for start := 0; start < len(plain); start += blockSize {
		stop := start + blockSize
		if stop > len(plain) {
			stop = len(plain)
		}
		pointers = append(pointers, uint32(position))
		compressed := zlibBytes(t, plain[start:stop])
		position += len(compressed)
		stream = append(stream, compressed...)
	}
	pointers = append(pointers, uint32(position))

	out := make([]byte, tableEnd, position)
	copy(out, []byte{0x37, 0xE4, 0x53, 0x96, 0xC9, 0xDB, 0xD6, 0x07})
	putLE32(out, 8, uint32(len(plain)))
	out[12] = 4
	out[13] = blockShift
	for i, pointer := range pointers {
		putLE32(out, 16+4*i, pointer)
	}
	out = append(out, stream...)
	return out
}

// validationEntry builds an El Torito validation entry whose 16-bit checksum
// sums to zero.
func validationEntry(id string, platform uint8) []byte {
	entry := make([]byte, 32)
	entry[0] = 0x01
	entry[1] = platform
	padASCII(entry, 4, 24, id)
	entry[30] = 0x55
	entry[31] = 0xAA
	var sum uint16
	for i := 0; i < 32; i += 2 {
		sum += uint16(entry[i]) | uint16(entry[i+1])<<8
	}
	putLE16(entry, 28, -sum)
	return entry
}

func bootImageEntry(indicator, media uint8, loadSegment uint16, sectors uint16, rba uint32) []byte {
	entry := make([]byte, 32)
	entry[0] = indicator
	entry[1] = media
	putLE16(entry, 2, loadSegment)
	putLE16(entry, 6, sectors)
	putLE32(entry, 8, rba)
	return entry
}

func descriptor(kind uint8, blockSize, spaceSize uint32, pathL, pathM, pathSize uint32, root []byte, volumeID, systemID, escape string) []byte {
	d := make([]byte, isoBlockSize)
	d[0] = kind
	copy(d[1:6], "CD001")
	d[6] = 1
	padASCII(d, 8, 32, systemID)
	padASCII(d, 40, 32, volumeID)
	putBoth32(d, 80, spaceSize)
	if escape != "" {
		copy(d[88:91], escape)
	}
	putBoth16(d, 120, 1)
	putBoth16(d, 124, 1)
	putBoth16(d, 128, uint16(blockSize))
	putBoth32(d, 132, pathSize)
	putLE32(d, 140, pathL)
	putBE32(d, 148, pathM)
	copy(d[156:190], root)
	padASCII(d, 190, 128, "")
	padASCII(d, 318, 128, "")
	padASCII(d, 446, 128, "")
	padASCII(d, 574, 128, "")
	copy(d[813:], []byte("2024010203040500\x00"))
	copy(d[830:], []byte("2024010203040500\x00"))
	copy(d[847:], []byte("0000000000000000\x00"))
	copy(d[864:], []byte("0000000000000000\x00"))
	return d
}

func bootDescriptor(catalogLBA uint32) []byte {
	d := make([]byte, isoBlockSize)
	d[0] = 0
	copy(d[1:6], "CD001")
	d[6] = 1
	copy(d[7:39], "EL TORITO SPECIFICATION")
	putLE32(d, 71, catalogLBA)
	return d
}

type isoOptions struct {
	boot        bool
	rockRidge   bool
	joliet      bool
	multi       bool
	interleaved bool
	zisofs      bool
	relocate    bool
	badBlock    bool
}

var (
	isoHello       = []byte("iso hello payload\n")
	isoInner       = []byte("inner\n")
	isoMultiOne    = []byte("0123456789")
	isoMultiTwo    = []byte("abcdefghij")
	isoZisofsPlain = []byte("zisofs compressed payload, long enough to cross a block boundary when repeated: " + string(bytes.Repeat([]byte("xyz"), 200)))
	isoRecording   = []byte{124, 1, 2, 3, 4, 5, 0} // 2024-01-02 03:04:05 UTC
	isoRRRecording = []byte{124, 2, 3, 4, 5, 6, 0}
)

func buildISO(t *testing.T, opts isoOptions) []byte {
	t.Helper()

	const (
		pathLBlock  = 20
		pathMBlock  = 22
		rootBlock   = 24
		subBlock    = 26
		helloBlock  = 28
		multi1Block = 29
		multi2Block = 30
		inter1Block = 31
		gapBlock    = 32
		inter2Block = 33
		jolietRoot  = 34
		innerBlock  = 35
		zisofsBlock = 36
		catalogBlk  = 40
		movedBlock  = 44
	)

	blockSize := uint32(isoBlockSize)
	if opts.badBlock {
		blockSize = 4096
	}

	// Root and subdirectory records. Dot records first carry a zero length;
	// the record sizes do not depend on that value, so a second pass fills it.
	buildRoot := func(rootLen uint32, withOptions bool) []byte {
		var out []byte
		out = append(out, isoRecord([]byte{0}, rootBlock, rootLen, testFlagDir, nil, 0, 0)...)
		out = append(out, isoRecord([]byte{1}, rootBlock, rootLen, testFlagDir, nil, 0, 0)...)
		out = append(out, isoRecord([]byte("SUBDIR"), subBlock, 0, testFlagDir, nil, 0, 0)...)
		out = append(out, isoRecord([]byte("HELLO.TXT;1"), helloBlock, uint32(len(isoHello)), 0, nil, 0, 0)...)
		if withOptions && opts.multi {
			out = append(out, isoRecord([]byte("MULTI.BIN;1"), multi1Block, uint32(len(isoMultiOne)), testFlagMulti, nil, 0, 0)...)
			out = append(out, isoRecord([]byte("MULTI.BIN;1"), multi2Block, uint32(len(isoMultiTwo)), 0, nil, 0, 0)...)
		}
		if withOptions && opts.interleaved {
			out = append(out, isoRecord([]byte("INTER.BIN;1"), inter1Block, 2*isoBlockSize, 0, nil, 1, 1)...)
		}
		return out
	}
	rootLen := uint32(len(buildRoot(0, true)))

	buildSub := func(innerLen uint32) []byte {
		var out []byte
		out = append(out, isoRecord([]byte{0}, subBlock, innerLen, testFlagDir, nil, 0, 0)...)
		out = append(out, isoRecord([]byte{1}, rootBlock, rootLen, testFlagDir, nil, 0, 0)...)
		out = append(out, isoRecord([]byte("INNER.TXT;1"), innerBlock, uint32(len(isoInner)), 0, nil, 0, 0)...)
		return out
	}
	subLen := uint32(len(buildSub(0)))

	rootRecords := buildRoot(rootLen, true)
	patchRecordDataLen(rootRecords, []byte("SUBDIR"), subLen)

	// Rock Ridge entries are appended to the records that need them. Rebuild
	// the listing with system-use areas and measure it again.
	if opts.rockRidge {
		var out []byte
		out = append(out, isoRecord([]byte{0}, rootBlock, rootLen, testFlagDir,
			append(suspEntry("SP", []byte{0xBE, 0xEF, 0}), suspEntry("ST", nil)...), 0, 0)...)
		out = append(out, isoRecord([]byte{1}, rootBlock, rootLen, testFlagDir, nil, 0, 0)...)
		out = append(out, isoRecord([]byte("SUBDIR"), subBlock, subLen, testFlagDir,
			suspNM("subdir"), 0, 0)...)
		out = append(out, isoRecord([]byte("HELLO.TXT;1"), helloBlock, uint32(len(isoHello)), 0,
			joinSUSP(suspNM("hello.txt"), suspPX(0o100644, 1, 1000, 1000), suspTF(isoRRRecording)), 0, 0)...)
		out = append(out, isoRecord([]byte("LINK;1"), 0, 0, 0,
			joinSUSP(suspNM("link"), suspPX(0o120777, 1, 0, 0), suspSL("usr", "share")), 0, 0)...)
		if opts.multi {
			out = append(out, isoRecord([]byte("MULTI.BIN;1"), multi1Block, uint32(len(isoMultiOne)), testFlagMulti, nil, 0, 0)...)
			out = append(out, isoRecord([]byte("MULTI.BIN;1"), multi2Block, uint32(len(isoMultiTwo)), 0, nil, 0, 0)...)
		}
		if opts.interleaved {
			out = append(out, isoRecord([]byte("INTER.BIN;1"), inter1Block, 2*isoBlockSize, 0, nil, 1, 1)...)
		}
		if opts.zisofs {
			out = append(out, isoRecord([]byte("PACKED.BIN;1"), zisofsBlock, 0, 0,
				joinSUSP(suspNM("packed.bin"), suspPX(0o100644, 1, 0, 0), suspZisofs(uint32(len(isoZisofsPlain)), 12)), 0, 0)...)
		}
		if opts.relocate {
			out = append(out, isoRecord([]byte("MOVED"), movedBlock, 0, testFlagDir,
				joinSUSP(suspNM("moved"), suspPX(0o040755, 2, 0, 0), suspLoc("CL", movedBlock)), 0, 0)...)
		}
		rootRecords = out
		rootLen = uint32(len(out))
	}

	// The directory a CL entry relocates: its own "." carries RE, and its
	// ".." carries the logical parent's PL.
	var relocatedRecords []byte
	if opts.rockRidge && opts.relocate {
		buildRelocated := func(selfLen uint32) []byte {
			var out []byte
			out = append(out, isoRecord([]byte{0}, movedBlock, selfLen, testFlagDir, suspEntry("RE", nil), 0, 0)...)
			out = append(out, isoRecord([]byte{1}, rootBlock, rootLen, testFlagDir, suspLoc("PL", rootBlock), 0, 0)...)
			out = append(out, isoRecord([]byte("INNER.TXT;1"), innerBlock, uint32(len(isoInner)), 0, nil, 0, 0)...)
			return out
		}
		relocatedRecords = buildRelocated(uint32(len(buildRelocated(0))))
	}

	// The zisofs record's data length is the stored payload length.
	zisofsData := zisofsPayload(t, isoZisofsPlain, 12)
	if opts.rockRidge && opts.zisofs {
		// Patch the record field after the listing is built: easier than
		// threading the payload length through the builder.
		patchRecordDataLen(rootRecords, []byte("PACKED.BIN;1"), uint32(len(zisofsData)))
	}
	// Re-measure after patching (sizes unchanged).

	subRecords := buildSub(subLen)

	pathTable := append(pathRecord([]byte{0}, rootBlock, 1, false), pathRecord([]byte("SUBDIR"), subBlock, 1, false)...)
	pathTableBig := append(pathRecord([]byte{0}, rootBlock, 1, true), pathRecord([]byte("SUBDIR"), subBlock, 1, true)...)

	rootRecord34 := isoRecord([]byte{0}, rootBlock, rootLen, testFlagDir, nil, 0, 0)

	// Joliet tree: primary names are replaced with UCS-2.
	jolietRecords := jolietListing(t, jolietRoot, helloBlock, uint32(len(isoHello)))
	jolietRootRecord := isoRecord([]byte{0}, jolietRoot, uint32(len(jolietRecords)), testFlagDir, nil, 0, 0)

	image := make([]byte, isoBlocks*isoBlockSize)
	sector := func(n int) int { return n * isoBlockSize }

	descriptorIndex := isoVRSSector
	if opts.boot {
		copy(image[sector(descriptorIndex):], bootDescriptor(catalogBlk))
		descriptorIndex++
	}
	pvd := descriptor(1, blockSize, isoBlocks, pathLBlock, pathMBlock, uint32(len(pathTable)),
		rootRecord34, "TESTVOL", "SYSTEM", "")
	copy(image[sector(descriptorIndex):], pvd)
	descriptorIndex++
	if opts.joliet {
		svd := descriptor(2, blockSize, isoBlocks, 0, 0, 0, jolietRootRecord, "JOLIET", "SYSTEM", "%/E")
		copy(image[sector(descriptorIndex):], svd)
		descriptorIndex++
	}
	terminator := make([]byte, isoBlockSize)
	terminator[0] = 255
	copy(terminator[1:6], "CD001")
	copy(image[sector(descriptorIndex):], terminator)

	copy(image[sector(pathLBlock):], pathTable)
	copy(image[sector(pathMBlock):], pathTableBig)
	copy(image[sector(rootBlock):], rootRecords)
	copy(image[sector(subBlock):], subRecords)
	copy(image[sector(helloBlock):], isoHello)
	copy(image[sector(multi1Block):], isoMultiOne)
	copy(image[sector(multi2Block):], isoMultiTwo)
	for i := 0; i < isoBlockSize; i++ {
		image[sector(inter1Block)+i] = 'A'
		image[sector(gapBlock)+i] = 'X'
		image[sector(inter2Block)+i] = 'B'
	}
	copy(image[sector(jolietRoot):], jolietRecords)
	copy(image[sector(innerBlock):], isoInner)
	if len(relocatedRecords) > 0 {
		copy(image[sector(movedBlock):], relocatedRecords)
	}
	if opts.zisofs {
		copy(image[sector(zisofsBlock):], zisofsData)
	}
	if opts.boot {
		catalog := append(validationEntry("FORENSIC TEST", 0), bootImageEntry(0x88, 0, 0x7C0, 4, 28)...)
		copy(image[sector(catalogBlk):], catalog)
	}

	return image
}

func joinSUSP(entries ...[]byte) []byte {
	var out []byte
	for _, entry := range entries {
		out = append(out, entry...)
	}
	return out
}

func patchRecordDataLen(records []byte, identifier []byte, dataLen uint32) {
	for at := 0; at < len(records); {
		length := int(records[at])
		if length == 0 {
			break
		}
		idLen := int(records[at+32])
		id := records[at+33 : at+33+idLen]
		if bytes.Equal(id, identifier) {
			putBoth32(records, at+10, dataLen)
		}
		at += length
	}
}

func jolietListing(t *testing.T, rootBlock, helloBlock int, helloLen uint32) []byte {
	t.Helper()
	ucs2 := func(text string) []byte {
		var out []byte
		for _, unit := range []rune(text) {
			out = append(out, byte(unit>>8), byte(unit))
		}
		return out
	}
	var out []byte
	out = append(out, isoRecord([]byte{0}, uint32(rootBlock), 0, testFlagDir, nil, 0, 0)...)
	out = append(out, isoRecord([]byte{1}, uint32(rootBlock), 0, testFlagDir, nil, 0, 0)...)
	out = append(out, isoRecord(ucs2("hello.txt;1"), uint32(helloBlock), helloLen, 0, nil, 0, 0)...)
	return out
}

func openISO(t *testing.T, image []byte) *Volume {
	t.Helper()
	vol, err := Open(source.NewMemorySource(1, image))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return vol
}

// ---- tests ---------------------------------------------------------------

func TestPrimaryVolume(t *testing.T) {
	vol := openISO(t, buildISO(t, isoOptions{boot: true, multi: true, interleaved: true}))

	info := vol.Info()
	if info.Type != "ISO9660" || info.Label != "TESTVOL" || info.SystemID != "SYSTEM" {
		t.Errorf("info = %+v", info)
	}
	if info.BlockSize != isoBlockSize || info.VolumeSpaceSize != isoBlocks {
		t.Errorf("geometry = %+v", info)
	}
	if info.NameTree != "primary" || info.RockRidge {
		t.Errorf("tree = %+v", info)
	}
	if !info.HasBootCatalog || info.BootCatalogLBA != 40 || info.BootRecords != 1 {
		t.Errorf("boot info = %+v", info)
	}
	if info.PathTableRecords != 2 || info.PathTableError != "" {
		t.Errorf("path table = %+v", info)
	}

	root, err := vol.Stat("/")
	if err != nil {
		t.Fatalf("stat root: %v", err)
	}
	if !root.IsDir || root.Name != "/" {
		t.Errorf("root = %+v", root)
	}

	hello, err := vol.Stat("/HELLO.TXT")
	if err != nil {
		t.Fatalf("stat hello: %v", err)
	}
	if hello.Size != uint64(len(isoHello)) || !hello.IsFile {
		t.Errorf("hello = %+v", hello)
	}
	if !hello.Modified.Equal(time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Errorf("hello modified = %v", hello.Modified)
	}
	if !hello.HasVersion || hello.Version != 1 {
		t.Errorf("hello version = %d set=%v", hello.Version, hello.HasVersion)
	}
	if hello.HasXattr {
		t.Errorf("ISO reader has no xattrs; HasXattr should be false")
	}

	entries, err := vol.ListDir("/")
	if err != nil {
		t.Fatalf("list root: %v", err)
	}
	names := make([]string, len(entries))
	for i, entry := range entries {
		names[i] = entry.Name
	}
	for _, want := range []string{"SUBDIR", "HELLO.TXT", "MULTI.BIN", "INTER.BIN"} {
		found := false
		for _, name := range names {
			if name == want {
				found = true
			}
		}
		if !found {
			t.Errorf("root listing %v missing %q", names, want)
		}
	}

	inner, err := vol.Stat("/SUBDIR/INNER.TXT")
	if err != nil {
		t.Fatalf("stat inner: %v", err)
	}
	if inner.Size != uint64(len(isoInner)) {
		t.Errorf("inner = %+v", inner)
	}

	if _, err := vol.Stat("/NOPE"); !errors.Is(err, ErrPathNotFound) {
		t.Errorf("missing stat error = %v", err)
	}
	if _, err := vol.ListDir("/HELLO.TXT"); err == nil {
		t.Errorf("listing a file should fail")
	}
}

func TestPrimaryOpenFile(t *testing.T) {
	vol := openISO(t, buildISO(t, isoOptions{multi: true, interleaved: true}))

	file, err := vol.OpenFile("/HELLO.TXT")
	if err != nil {
		t.Fatalf("open hello: %v", err)
	}
	buf := make([]byte, len(isoHello))
	if err := source.ReadExactAt(file, 0, buf); err != nil {
		t.Fatalf("read hello: %v", err)
	}
	if !bytes.Equal(buf, isoHello) {
		t.Errorf("hello = %q", buf)
	}

	multi, err := vol.OpenFile("/MULTI.BIN")
	if err != nil {
		t.Fatalf("open multi: %v", err)
	}
	if multi.Len() != uint64(len(isoMultiOne)+len(isoMultiTwo)) {
		t.Fatalf("multi length = %d", multi.Len())
	}
	mbuf := make([]byte, multi.Len())
	if err := source.ReadExactAt(multi, 0, mbuf); err != nil {
		t.Fatalf("read multi: %v", err)
	}
	if !bytes.Equal(mbuf, append(append([]byte{}, isoMultiOne...), isoMultiTwo...)) {
		t.Errorf("multi = %q", mbuf)
	}

	inter, err := vol.OpenFile("/INTER.BIN")
	if err != nil {
		t.Fatalf("open interleaved: %v", err)
	}
	ibuf := make([]byte, 2*isoBlockSize)
	if err := source.ReadExactAt(inter, 0, ibuf); err != nil {
		t.Fatalf("read interleaved: %v", err)
	}
	if !bytes.Equal(ibuf[:isoBlockSize], bytes.Repeat([]byte{'A'}, isoBlockSize)) {
		t.Errorf("first interleaved unit wrong")
	}
	if !bytes.Equal(ibuf[isoBlockSize:], bytes.Repeat([]byte{'B'}, isoBlockSize)) {
		t.Errorf("second interleaved unit wrong; gap leaked")
	}
	entry, err := vol.Stat("/INTER.BIN")
	if err != nil {
		t.Fatalf("stat interleaved: %v", err)
	}
	if !entry.Interleaved {
		t.Errorf("entry should be marked interleaved: %+v", entry)
	}
	if _, err := vol.OpenFile("/SUBDIR"); err == nil {
		t.Errorf("opening a directory should fail")
	}
}

func TestRockRidgeAndZisofs(t *testing.T) {
	vol := openISO(t, buildISO(t, isoOptions{rockRidge: true, zisofs: true, relocate: true}))

	info := vol.Info()
	if !info.RockRidge || info.NameTree != "rock-ridge" {
		t.Errorf("info = %+v", info)
	}

	hello, err := vol.Stat("/hello.txt")
	if err != nil {
		t.Fatalf("stat hello: %v", err)
	}
	if hello.Name != "hello.txt" || !hello.IsFile {
		t.Errorf("hello = %+v", hello)
	}
	if !hello.HasMode || hello.Mode != 0o100644 {
		t.Errorf("mode = %#o set=%v", hello.Mode, hello.HasMode)
	}
	if !hello.HasOwner || hello.UID != 1000 || hello.GID != 1000 {
		t.Errorf("owner = %+v", hello)
	}
	if !hello.Modified.Equal(time.Date(2024, 2, 3, 4, 5, 6, 0, time.UTC)) {
		t.Errorf("modified = %v", hello.Modified)
	}

	link, err := vol.Stat("/link")
	if err != nil {
		t.Fatalf("stat link: %v", err)
	}
	if !link.IsSymlink || link.SymlinkTarget != "/usr/share" {
		t.Errorf("link = %+v", link)
	}
	if _, err := vol.OpenFile("/link"); err == nil {
		t.Errorf("opening a symlink should fail")
	}

	packed, err := vol.Stat("/packed.bin")
	if err != nil {
		t.Fatalf("stat packed: %v", err)
	}
	if packed.Zisofs == nil || packed.Size != uint64(len(isoZisofsPlain)) {
		t.Errorf("packed = %+v", packed)
	}
	file, err := vol.OpenFile("/packed.bin")
	if err != nil {
		t.Fatalf("open packed: %v", err)
	}
	plain := make([]byte, len(isoZisofsPlain))
	if err := source.ReadExactAt(file, 0, plain); err != nil {
		t.Fatalf("read packed: %v", err)
	}
	if !bytes.Equal(plain, isoZisofsPlain) {
		t.Errorf("zisofs payload mismatch")
	}
	if stats := vol.ZisofsStats(); stats.Files != 1 || stats.Blocks == 0 {
		t.Errorf("zisofs stats = %+v", stats)
	}

	// The CL-relocated directory is presented at its placeholder's path.
	moved, err := vol.Stat("/moved")
	if err != nil {
		t.Fatalf("stat moved: %v", err)
	}
	if !moved.IsDir || !moved.Relocated {
		t.Errorf("moved = %+v", moved)
	}
	movedEntries, err := vol.ListDir("/moved")
	if err != nil {
		t.Fatalf("list moved: %v", err)
	}
	if len(movedEntries) != 1 || movedEntries[0].Name != "INNER.TXT" {
		t.Errorf("moved entries = %+v", movedEntries)
	}
	if relocations := vol.Relocations(); len(relocations) != 1 || relocations[0].Block != 44 {
		t.Errorf("relocations = %+v", relocations)
	}
	if info.RelocatedDirectories != 1 {
		t.Errorf("relocated directories = %d", info.RelocatedDirectories)
	}
}

func TestJoliet(t *testing.T) {
	vol := openISO(t, buildISO(t, isoOptions{joliet: true}))

	info := vol.Info()
	if info.NameTree != "joliet" || !info.HasJoliet || info.JolietLevel != 3 {
		t.Errorf("info = %+v", info)
	}
	entry, err := vol.Stat("/hello.txt")
	if err != nil {
		t.Fatalf("stat joliet hello: %v", err)
	}
	if !entry.IsFile || entry.Size != uint64(len(isoHello)) {
		t.Errorf("entry = %+v", entry)
	}
	entries, err := vol.ListDir("/")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) == 0 || entries[0].Name != "hello.txt" {
		t.Errorf("entries = %+v", entries)
	}
}

func TestBootCatalog(t *testing.T) {
	vol := openISO(t, buildISO(t, isoOptions{boot: true}))
	catalog, ok := vol.Boot()
	if !ok || catalog == nil {
		t.Fatalf("no boot catalog: %v", vol.BootError())
	}
	if !catalog.ChecksumOK || !catalog.KeyOK {
		t.Errorf("validation = %+v", catalog)
	}
	if catalog.PlatformLabel != "x86" || catalog.ID != "FORENSIC TEST" {
		t.Errorf("catalog = %+v", catalog)
	}
	if catalog.Initial == nil || !catalog.Initial.Bootable || catalog.Initial.LoadRBA != 28 {
		t.Errorf("initial = %+v", catalog.Initial)
	}
	if catalog.BootableEntries() != 1 {
		t.Errorf("bootable = %d", catalog.BootableEntries())
	}
	if err := vol.BootError(); err != nil {
		t.Errorf("boot error = %v", err)
	}
}

func TestPathTableComparison(t *testing.T) {
	image := buildISO(t, isoOptions{})
	vol := openISO(t, image)
	table, ok := vol.PathTable()
	if !ok || table == nil {
		t.Fatalf("no path table: %v", vol.PathTableError())
	}
	records := table.Records()
	if len(records) != 2 {
		t.Fatalf("records = %d", len(records))
	}
	if records[0].Name() != "/" || records[0].Depth != 0 || records[0].Parent != 1 {
		t.Errorf("root record = %+v", records[0])
	}
	if records[1].Name() != "SUBDIR" || records[1].Depth != 1 || records[1].Extent != 26 {
		t.Errorf("sub record = %+v", records[1])
	}
	if len(table.Disagreements()) != 0 || table.BigEndianError() != nil {
		t.Errorf("disagreements = %+v err=%v", table.Disagreements(), table.BigEndianError())
	}

	// Corrupt the big-endian copy's root extent; the reader reports the
	// disagreement rather than trusting either copy silently.
	mutated := append([]byte{}, image...)
	putBE32(mutated, 22*isoBlockSize+2, 99)
	vol2 := openISO(t, mutated)
	table2, ok := vol2.PathTable()
	if !ok {
		t.Fatalf("path table after mutation missing: %v", vol2.PathTableError())
	}
	found := false
	for _, disagreement := range table2.Disagreements() {
		if disagreement.Field == "extent" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an extent disagreement, got %+v", table2.Disagreements())
	}
}

func TestIsoTime(t *testing.T) {
	recording, ok := isoTimeFromRecording(isoRecording)
	if !ok {
		t.Fatalf("recording timestamp did not decode")
	}
	if got, want := recording.UnixNanos(), time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC).UnixNano(); got != want {
		t.Errorf("recording = %d, want %d", got, want)
	}
	if _, ok := isoTimeFromRecording([]byte{0, 0, 0, 0, 0, 0, 0}); ok {
		t.Errorf("all-zero recording should be absent")
	}

	ascii := append([]byte("20240102030405"), '2', '5', 0)
	decoded, ok := isoTimeFromASCII(ascii)
	if !ok {
		t.Fatalf("ascii timestamp did not decode")
	}
	if got, want := decoded.UnixNanos(), time.Date(2024, 1, 2, 3, 4, 5, 250_000_000, time.UTC).UnixNano(); got != want {
		t.Errorf("ascii = %d, want %d", got, want)
	}
	if _, ok := isoTimeFromASCII([]byte("0000000000000000\x00")); ok {
		t.Errorf("all-zero ascii should be absent")
	}
}

func TestCorruptAndTruncated(t *testing.T) {
	good := buildISO(t, isoOptions{})

	badSignature := append([]byte{}, good...)
	badSignature[isoVRSSector*isoBlockSize+1] = 'X'
	if _, err := Open(source.NewMemorySource(1, badSignature)); !errors.Is(err, ErrCorrupt) {
		t.Errorf("bad signature error = %v", err)
	}

	truncated := good[:isoVRSSector*isoBlockSize+100]
	if _, err := Open(source.NewMemorySource(1, truncated)); err == nil {
		t.Errorf("truncated image should fail")
	}

	// A PVD that declares an undefined logical block size is unsupported.
	badBlock := append([]byte{}, good...)
	putBoth16(badBlock, isoVRSSector*isoBlockSize+128, 4096)
	if _, err := Open(source.NewMemorySource(1, badBlock)); !errors.Is(err, ErrUnsupported) {
		t.Errorf("block size error = %v", err)
	}

	// A directory record whose length is shorter than its header.
	badRecord := append([]byte{}, good...)
	rootOffset := 24 * isoBlockSize
	badRecord[rootOffset] = 10
	if _, err := records(badRecord[rootOffset:rootOffset+isoBlockSize], isoBlockSize); !errors.Is(err, ErrCorrupt) {
		t.Errorf("short record error = %v", err)
	}

	// A path table whose record count runs past the table.
	if _, err := parsePathTable([]byte{10, 0, 1, 2}, false); !errors.Is(err, ErrCorrupt) {
		t.Errorf("truncated path table error = %v", err)
	}

	// zisofs data that does not begin with the magic.
	zisofsImage := buildISO(t, isoOptions{rockRidge: true, zisofs: true})
	zisofsImage[36*isoBlockSize] = 0
	vol := openISO(t, zisofsImage)
	if _, err := vol.OpenFile("/packed.bin"); !errors.Is(err, ErrCorrupt) {
		t.Errorf("zisofs magic error = %v", err)
	}

	if _, err := Open(source.NewMemorySource(1, []byte("too short"))); err == nil {
		t.Errorf("a source shorter than the volume recognition sequence should fail or detect no volume")
	}
}

func TestDetect(t *testing.T) {
	good := buildISO(t, isoOptions{})
	ok, err := Detect(source.NewMemorySource(1, good))
	if err != nil || !ok {
		t.Errorf("Detect(valid) = %v, %v", ok, err)
	}
	ok, err = Detect(source.NewMemorySource(1, make([]byte, isoVRSSector*isoBlockSize)))
	if err != nil || ok {
		t.Errorf("Detect(empty) = %v, %v", ok, err)
	}
}
