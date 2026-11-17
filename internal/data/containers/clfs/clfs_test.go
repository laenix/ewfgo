package clfs

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"math"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/laenix/ewfgo/internal/data/source"
)

// The test layout mirrors the Rust reference's synthetic base log: a control
// block at 0, a general metadata block at 0x800, the base record at its +0x70,
// and a symbol zone inside the record image.
const (
	testControlBlockBytes     = 0x400
	testBaseBlockOffset       = 0x800
	testBaseRecordOffset      = 0x70
	testSymbolZoneStart       = 0x1400
	testSymbolStride          = 0x180
	testNameOffsetInSymbol    = 0x30
	testContextOffsetInSymbol = 0xA0
)

func putU16(file []byte, at int, value uint16) {
	binary.LittleEndian.PutUint16(file[at:], value)
}

func putU32(file []byte, at int, value uint32) {
	binary.LittleEndian.PutUint32(file[at:], value)
}

func putI32(file []byte, at int, value int32) {
	binary.LittleEndian.PutUint32(file[at:], uint32(value))
}

func putU64(file []byte, at int, value uint64) {
	binary.LittleEndian.PutUint64(file[at:], value)
}

func stampBlockCRC(block []byte) {
	for i := 0x0C; i < 0x10; i++ {
		block[i] = 0
	}
	binary.LittleEndian.PutUint32(block[0x0C:], crc32.ChecksumIEEE(block))
}

func putName(file []byte, at int, name string) {
	units := utf16.Encode([]rune(name))
	units = append(units, 0)
	for index, unit := range units {
		putU16(file, at+index*2, unit)
	}
}

func writeSymbol(file []byte, record, symbol int, name string, contextType, contextSize uint32) {
	at := record + symbol
	putU32(file, at, NodeTypeSymbol)
	putU32(file, at+0x04, SymbolHeaderBytes)
	putU32(file, at+0x08, 0x12345678)
	putU32(file, at+0x0C, contextSize)
	putU64(file, at+0x10, 0)
	putU64(file, at+0x18, 0)
	putI32(file, at+0x20, int32(symbol+testNameOffsetInSymbol))
	putI32(file, at+0x24, int32(symbol+testContextOffsetInSymbol))
	file[at+0x28] = 0
	putU32(file, record+symbol+testContextOffsetInSymbol, contextType)
	putName(file, record+symbol+testNameOffsetInSymbol, name)
}

func writeClientContext(file []byte, record, symbol int, id uint32) {
	at := record + symbol + testContextOffsetInSymbol
	putU32(file, at, NodeTypeClientContext)
	putU32(file, at+0x04, ClientContextBytes)
	putU32(file, at+0x08, id)
	putU16(file, at+0x0C, 0x26)
	putU32(file, at+0x10, 0x00040000)
	putU32(file, at+0x14, 0)
	putU64(file, at+0x18, 0)
	putU64(file, at+0x20, 0x01D0000000000000+uint64(id))
	putU64(file, at+0x28, 0x01D0000000000001+uint64(id))
	putU64(file, at+0x30, 0x01D0000000000002+uint64(id))
	for _, offset := range []int{0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70} {
		putU64(file, at+offset, 0)
	}
	putU32(file, at+0x78, 0x04)
	putU64(file, at+0x80, 0)
}

func writeContainerContext(file []byte, record, symbol int, id uint32) {
	at := record + symbol + testContextOffsetInSymbol
	putU32(file, at, NodeTypeContainerContext)
	putU32(file, at+0x04, ContainerContextBytes)
	putU64(file, at+0x08, 0x00010000)
	putU32(file, at+0x10, id)
	putU32(file, at+0x14, id)
	putU64(file, at+0x18, 0)
	putU64(file, at+0x20, 1)
	putU32(file, at+0x28, 1)
	putU32(file, at+0x2C, 0)
	putU32(file, at+0x30, 0)
}

// buildBLF builds a synthetic base log file with the given client and
// container names. The control block is 0x400 bytes and declares two metadata
// blocks (control and general); both blocks carry a valid stored CRC.
func buildBLF(clientNames, containerNames []string) []byte {
	return buildBLFWithControl(clientNames, containerNames, testControlBlockBytes, 2)
}

// buildBLFWithControl allows a larger control block and a larger declared
// metadata-block count (used for the metadata-block cap test).
func buildBLFWithControl(clientNames, containerNames []string, controlBlockBytes, blocksDeclared int) []byte {
	symbolCount := len(clientNames) + len(containerNames)
	required := testSymbolZoneStart + symbolCount*testSymbolStride + 0x200
	baseBlockBytes := ((required + 0x1FF) / 0x200) * 0x200
	fileLen := testBaseBlockOffset + baseBlockBytes
	file := make([]byte, fileLen)

	// Control log block at 0.
	file[0] = MajorVersion
	file[1] = MinorVersion
	file[3] = 1
	putU16(file, 0x04, uint16(controlBlockBytes/0x200))
	putU16(file, 0x06, uint16(controlBlockBytes/0x200))
	putU32(file, 0x24, 0x70)
	control := 0x70
	putU64(file, control, 1)
	putU64(file, control+0x08, ControlRecordMagic)
	file[control+0x10] = 1
	putU16(file, control+0x48, uint16(blocksDeclared))
	entry := control + 0x50
	putU32(file, entry+0x08, uint32(controlBlockBytes))
	putU32(file, entry+0x0C, 0)
	putU32(file, entry+0x10, 0)
	entry += 0x18
	putU32(file, entry+0x08, uint32(baseBlockBytes))
	putU32(file, entry+0x0C, testBaseBlockOffset)
	putU32(file, entry+0x10, 2)
	stampBlockCRC(file[:controlBlockBytes])

	// General metadata block at 0x800.
	base := testBaseBlockOffset
	file[base] = MajorVersion
	file[base+1] = MinorVersion
	file[base+3] = 1
	putU16(file, base+0x04, uint16(baseBlockBytes/0x200))
	putU16(file, base+0x06, uint16(baseBlockBytes/0x200))
	putU32(file, base+0x24, testBaseRecordOffset)
	putU32(file, base+0x68, uint32(baseBlockBytes-0x10))
	record := base + testBaseRecordOffset
	putU64(file, record, 1)
	for index := 0; index < 16; index++ {
		file[record+0x08+index] = 0xA0 + byte(index)
	}

	previousClient := -1
	for index, name := range clientNames {
		symbol := testSymbolZoneStart + index*testSymbolStride
		writeSymbol(file, record, symbol, name, NodeTypeClientContext, ClientContextBytes)
		writeClientContext(file, record, symbol, uint32(index)+1)
		if previousClient >= 0 {
			putU64(file, record+previousClient+0x18, uint64(symbol))
		} else {
			putU64(file, record+ClientSymbolTableOffset, uint64(symbol))
		}
		previousClient = symbol
	}
	containerStart := testSymbolZoneStart + len(clientNames)*testSymbolStride
	previousContainer := -1
	for index, name := range containerNames {
		symbol := containerStart + index*testSymbolStride
		writeSymbol(file, record, symbol, name, NodeTypeContainerContext, ContainerContextBytes)
		writeContainerContext(file, record, symbol, uint32(index)+7)
		if previousContainer >= 0 {
			putU64(file, record+previousContainer+0x18, uint64(symbol))
		} else {
			putU64(file, record+ContainerSymbolTableOffset, uint64(symbol))
		}
		previousContainer = symbol
	}

	symbolZoneEnd := containerStart + len(containerNames)*testSymbolStride
	putU32(file, record+0x1328, uint32(symbolZoneEnd))
	putU32(file, record+0x132C, uint32(SectorSize))
	putU32(file, record+0x1332, 0x04)
	file[record+0x1336] = 1
	clientsDeclared := len(clientNames)
	if clientsDeclared > 255 {
		clientsDeclared = 255
	}
	file[record+0x1337] = byte(clientsDeclared)
	stampBlockCRC(file[base:])
	return file
}

func buildContainer(containerID uint32, blockOffset uint64, recordSequence uint16, fileLen int) []byte {
	index := ((blockOffset / SectorSize) << 9) | uint64(recordSequence)
	lsn := (uint64(containerID) << 32) | index
	file := make([]byte, fileLen)
	file[0] = MajorVersion
	file[1] = MinorVersion
	file[3] = 0
	putU16(file, 0x04, uint16(fileLen/0x200))
	putU16(file, 0x06, uint16(fileLen/0x200))
	putU64(file, 0x14, lsn)
	putU32(file, 0x24, 0x70)
	stampBlockCRC(file)
	return file
}

func openBase(t *testing.T, bytes []byte) *BaseLog {
	t.Helper()
	log, err := OpenBaseLog(source.NewMemorySource(1, bytes))
	if err != nil {
		t.Fatalf("OpenBaseLog: %v", err)
	}
	return log
}

func openContainer(t *testing.T, bytes []byte) *ContainerHeader {
	t.Helper()
	header, err := OpenContainer(source.NewMemorySource(1, bytes))
	if err != nil {
		t.Fatalf("OpenContainer: %v", err)
	}
	return header
}

func wantCorrupt(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a corrupt-data error containing %q, got nil", substr)
	}
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("expected source.ErrCorrupt, got %v", err)
	}
	if !strings.Contains(err.Error(), substr) {
		t.Fatalf("expected error containing %q, got %q", substr, err.Error())
	}
}

func wantUnsupported(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an unsupported error containing %q, got nil", substr)
	}
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("expected source.ErrUnsupported, got %v", err)
	}
	if !strings.Contains(err.Error(), substr) {
		t.Fatalf("expected error containing %q, got %q", substr, err.Error())
	}
}

func hasWarning(warnings []string, substr string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, substr) {
			return true
		}
	}
	return false
}

func checksumIs(ok *bool, want bool) bool {
	return ok != nil && *ok == want
}

// --- detection -------------------------------------------------------------

func TestDetectAndDetectContainer(t *testing.T) {
	base := buildBLF([]string{"Registry"}, []string{"%BLF%\\TEST.regtrans-ms"})
	if !Detect(base) {
		t.Fatal("Detect must accept a base log")
	}
	if DetectContainer(base) {
		t.Fatal("DetectContainer must reject a base log")
	}

	container := buildContainer(7, 0x2000, 3, 0x400)
	if Detect(container) {
		t.Fatal("Detect must reject a container")
	}
	if !DetectContainer(container) {
		t.Fatal("DetectContainer must accept a container log block")
	}

	if Detect(make([]byte, 0x7F)) || DetectContainer(make([]byte, 0x7F)) {
		t.Fatal("short heads must not match")
	}
	shortBase := base[:LogBlockHeaderBytes]
	if Detect(shortBase) {
		t.Fatal("base detection needs the control-record magic at 0x78")
	}
}

func TestOpenDispatchesOnKind(t *testing.T) {
	base := buildBLF([]string{"Registry"}, []string{"%BLF%\\TEST.regtrans-ms"})
	parsed, err := Open(source.NewMemorySource(1, base))
	if err != nil {
		t.Fatalf("Open base log: %v", err)
	}
	if parsed.Kind() != KindBaseLog {
		t.Fatalf("kind = %v, want KindBaseLog", parsed.Kind())
	}
	if parsed.BaseLog() == nil || parsed.Header() != nil {
		t.Fatal("a base-log container must expose BaseLog and no container header")
	}

	container := buildContainer(7, 0x2000, 3, 0x400)
	parsed, err = Open(source.NewMemorySource(1, container))
	if err != nil {
		t.Fatalf("Open container: %v", err)
	}
	if parsed.Kind() != KindContainer {
		t.Fatalf("kind = %v, want KindContainer", parsed.Kind())
	}
	if parsed.Header() == nil || parsed.BaseLog() != nil {
		t.Fatal("a container must expose a header and no base log")
	}
}

func TestOpenRefusesPayloadReconstruction(t *testing.T) {
	parsed, err := Open(source.NewMemorySource(1, buildBLF([]string{"Registry"}, nil)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := parsed.OpenStream("Registry"); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("OpenStream error = %v, want ErrUnsupported", err)
	}
	if _, err := parsed.OpenRecord(0x0000000700000200); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("OpenRecord error = %v, want ErrUnsupported", err)
	}
}

// --- base log happy path ---------------------------------------------------

func TestMinimalBaseLogYieldsOneClientAndOneContainer(t *testing.T) {
	bytes := buildBLF([]string{"Registry"}, []string{"%BLF%\\TEST.regtrans-ms"})
	if !Detect(bytes) {
		t.Fatal("built file must match the base-log detector")
	}
	log := openBase(t, bytes)

	if got := log.ControlHeader().Signature(); got != [2]byte{0x15, 0x00} {
		t.Fatalf("control signature = % X", got)
	}
	if !checksumIs(log.ControlHeader().ChecksumOK, true) {
		t.Fatalf("control checksum = %v, want true", log.ControlHeader().ChecksumOK)
	}
	if !checksumIs(log.BaseHeader().ChecksumOK, true) {
		t.Fatalf("base checksum = %v, want true", log.BaseHeader().ChecksumOK)
	}
	if log.Control().BlocksDeclared != 2 || len(log.MetadataBlocks()) != 2 {
		t.Fatalf("blocks declared = %d, decoded = %d", log.Control().BlocksDeclared, len(log.MetadataBlocks()))
	}
	if log.MetadataBlocks()[1].TypeName() != "general" {
		t.Fatalf("metadata block 1 type = %q", log.MetadataBlocks()[1].TypeName())
	}
	if got := log.BaseRecord().LogIDText(); got != "A0A1A2A3-A4A5-A6A7-A8A9-AAABACADAEAF" {
		t.Fatalf("log id = %q", got)
	}
	if log.BaseRecord().SectorSize != uint32(SectorSize) {
		t.Fatalf("sector size = %d", log.BaseRecord().SectorSize)
	}

	if len(log.Clients()) != 1 {
		t.Fatalf("clients = %d, want 1", len(log.Clients()))
	}
	client := log.Clients()[0]
	if name, ok := client.Name(); !ok || name != "Registry" {
		t.Fatalf("client name = %q, %v", name, ok)
	}
	if client.Context.ClientID != 1 {
		t.Fatalf("client id = %d", client.Context.ClientID)
	}
	if client.Context.Attributes != 0x26 {
		t.Fatalf("attributes = %#x", client.Context.Attributes)
	}
	if client.Context.FlushThreshold != 0x00040000 {
		t.Fatalf("flush threshold = %#x", client.Context.FlushThreshold)
	}
	if client.Context.CreateTime != 0x01D0000000000001 {
		t.Fatalf("create time = %#x", client.Context.CreateTime)
	}
	if client.Context.State != 0x04 {
		t.Fatalf("state = %#x", client.Context.State)
	}

	if len(log.Containers()) != 1 {
		t.Fatalf("containers = %d, want 1", len(log.Containers()))
	}
	container := log.Containers()[0]
	if name, ok := container.Name(); !ok || name != "%BLF%\\TEST.regtrans-ms" {
		t.Fatalf("container name = %q, %v", name, ok)
	}
	if container.Context.ContainerID != 7 || container.Context.QueueID != 7 {
		t.Fatalf("container ids = %d/%d", container.Context.ContainerID, container.Context.QueueID)
	}
	if container.Context.ContainerBytes != 0x00010000 {
		t.Fatalf("container bytes = %#x", container.Context.ContainerBytes)
	}
	if len(container.Context.Extents) != 0 {
		t.Fatalf("extents = %v", container.Context.Extents)
	}

	stats := log.Stats()
	if stats.Clients != 1 || stats.Containers != 1 || stats.ChecksumFailures != 0 {
		t.Fatalf("stats = %+v", stats)
	}
	if stats.ClientSymbols != 1 || stats.ContainerSymbols != 1 || stats.DeletedSymbols != 0 {
		t.Fatalf("symbol stats = %+v", stats)
	}
	if len(log.Warnings()) != 0 {
		t.Fatalf("warnings = %q", log.Warnings())
	}
}

func TestRecordOffsetAfterSentinelSlotIsFollowed(t *testing.T) {
	bytes := buildBLF([]string{"Registry"}, []string{"%BLF%\\TEST.regtrans-ms"})
	putU32(bytes, 0x24, math.MaxUint32)
	putU32(bytes, 0x28, 0x70)
	base := testBaseBlockOffset
	putU32(bytes, base+0x24, math.MaxUint32)
	putU32(bytes, base+0x28, testBaseRecordOffset)
	stampBlockCRC(bytes[:testControlBlockBytes])
	stampBlockCRC(bytes[base:])

	log := openBase(t, bytes)
	if len(log.Clients()) != 1 || len(log.Containers()) != 1 {
		t.Fatalf("clients/containers = %d/%d", len(log.Clients()), len(log.Containers()))
	}
}

func TestFirstRecordOffsetFindsFirstUsableSlot(t *testing.T) {
	header := LogBlockHeader{RecordOffsets: [16]uint32{0, math.MaxUint32, 0x70, 0x80}}
	offset, ok := header.FirstRecordOffset()
	if !ok || offset != 0x70 {
		t.Fatalf("first record offset = %d, %v", offset, ok)
	}
	// The reference stops at the first non-sentinel value and only then
	// rejects it, so a too-low value hides a later usable slot.
	header.RecordOffsets = [16]uint32{0, math.MaxUint32, 0x60, 0x80}
	if _, ok := header.FirstRecordOffset(); ok {
		t.Fatal("a first non-sentinel value below the header must yield no offset")
	}
}

func TestMetadataBlockNamesAndShadowFlags(t *testing.T) {
	want := []string{"control", "control-shadow", "general", "general-shadow", "scratch", "scratch-shadow", "unknown"}
	for blockType, name := range want {
		block := MetadataBlock{BlockType: uint32(blockType)}
		if got := block.TypeName(); got != name {
			t.Fatalf("type %d name = %q, want %q", blockType, got, name)
		}
		wantShadow := blockType == 1 || blockType == 3 || blockType == 5
		if block.IsShadow() != wantShadow {
			t.Fatalf("type %d shadow = %v, want %v", blockType, block.IsShadow(), wantShadow)
		}
	}
}

func TestLogIDSectorSizeAndLSNHelpers(t *testing.T) {
	record := BaseRecord{LogID: [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}}
	if got := record.LogIDText(); got != "00010203-0405-0607-0809-0A0B0C0D0E0F" {
		t.Fatalf("log id = %q", got)
	}
	for _, test := range []struct {
		size uint32
		want bool
	}{{0, true}, {512, true}, {4096, false}, {1024, false}} {
		record.SectorSize = test.size
		if got := record.SectorSizeIsCanonical(); got != test.want {
			t.Fatalf("sector size %d canonical = %v", test.size, got)
		}
	}

	lsn := DecodePhysicalLSN((uint64(7) << 32) | ((0x2000 / SectorSize) << 9) | 3)
	if lsn.ContainerID != 7 || lsn.BlockOffset != 0x2000 || lsn.RecordSequence != 3 {
		t.Fatalf("lsn = %+v", lsn)
	}
	if lsn.Raw != (uint64(7)<<32)|((0x2000/SectorSize)<<9)|3 {
		t.Fatalf("raw = %#x", lsn.Raw)
	}
}

// --- sector signatures -----------------------------------------------------

func TestSignatureStamps(t *testing.T) {
	if got := signatureStamps(100, 200, uint32(SectorSize)); len(got) != 0 {
		t.Fatalf("stamps = %v", got)
	}
	if got := signatureStamps(100, 600, uint32(SectorSize)); len(got) != 1 || got[0] != 510 {
		t.Fatalf("stamps = %v", got)
	}
	if got := signatureStamps(512, 1024, uint32(SectorSize)); len(got) != 1 || got[0] != 1022 {
		t.Fatalf("stamps = %v", got)
	}
	if got := signatureStamps(500, 522, uint32(SectorSize)); len(got) != 1 || got[0] != 510 {
		t.Fatalf("stamps = %v", got)
	}
	if got := signatureStamps(500, 500, uint32(SectorSize)); len(got) != 0 {
		t.Fatalf("empty range stamps = %v", got)
	}
	if got := signatureStamps(100, 200, 500); len(got) != 0 {
		t.Fatalf("non-power-of-two sector size stamps = %v", got)
	}
}

func TestEffectiveSectorSize(t *testing.T) {
	for _, test := range []struct {
		size uint32
		want uint64
		ok   bool
	}{
		{0, 512, true}, {512, 512, true}, {1024, 1024, true},
		{4096, 4096, true}, {256, 0, false}, {500, 0, false}, {8192, 0, false},
	} {
		got, ok := effectiveSectorSize(test.size)
		if got != test.want || ok != test.ok {
			t.Fatalf("effectiveSectorSize(%d) = %d, %v", test.size, got, ok)
		}
	}
}

func TestNameCrossingASectorBoundaryKeepsStoredSignature(t *testing.T) {
	image := make([]byte, 1024)
	units := utf16.Encode([]rune("ABCDEFGHIJ"))
	for index, unit := range units[:5] {
		putU16(image, 500+index*2, unit)
	}
	putU16(image, 510, 0xAF10)
	for index, unit := range units[5:] {
		putU16(image, 512+index*2, unit)
	}
	name, size, ok := decodeSymbolName(image, 500, -1)
	if want := "ABCDE" + string(rune(0xAF10)) + "FGHIJ"; !ok || name != want || size != 22 {
		t.Fatalf("decoded = %q, %d, %v", name, size, ok)
	}
}

func TestLinkOverwrittenBySignatureIsNotFollowed(t *testing.T) {
	image := make([]byte, 0x400)
	node := 0x1E0
	putU32(image, node, NodeTypeSymbol)
	putU32(image, node+0x04, SymbolHeaderBytes)
	putU16(image, 0x1FE, 0xAF10)
	table := [SymbolTableEntries]uint64{uint64(node)}
	var warnings []string
	walk := walkSymbols(image, table, 0, uint32(SectorSize), 8, "container", &warnings)
	if len(walk.symbols) != 1 {
		t.Fatalf("symbols = %d", len(walk.symbols))
	}
	if walk.symbols[0].Above != 0xAF10000000000000 {
		t.Fatalf("above = %#x", walk.symbols[0].Above)
	}
	if !hasWarning(warnings, "has its header crossed") || !hasWarning(warnings, "is not followed") {
		t.Fatalf("warnings = %q", warnings)
	}
	if hasWarning(warnings, "pointing at offset") {
		t.Fatalf("overwritten link must not be walked: %q", warnings)
	}
}

func TestUnstampedSectorEndLeavesLinkTrustworthy(t *testing.T) {
	image := make([]byte, 0x400)
	node := 0x1E0
	child := 0x100
	putU32(image, node, NodeTypeSymbol)
	putU32(image, node+0x04, SymbolHeaderBytes)
	putU64(image, node+0x18, uint64(child))
	putU32(image, child, NodeTypeSymbol)
	putU32(image, child+0x04, SymbolHeaderBytes)
	table := [SymbolTableEntries]uint64{uint64(node)}
	var warnings []string
	walk := walkSymbols(image, table, 0, uint32(SectorSize), 8, "container", &warnings)
	if len(walk.symbols) != 2 {
		t.Fatalf("symbols = %d", len(walk.symbols))
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %q", warnings)
	}
}

func TestSymbolWalkCycleTerminates(t *testing.T) {
	image := make([]byte, 0x200)
	node := 0x80
	putU32(image, node, NodeTypeSymbol)
	putU32(image, node+0x04, SymbolHeaderBytes)
	putU64(image, node+0x18, uint64(node)) // above -> itself
	table := [SymbolTableEntries]uint64{uint64(node)}
	var warnings []string
	walk := walkSymbols(image, table, 0, uint32(SectorSize), 8, "client", &warnings)
	if len(walk.symbols) != 1 {
		t.Fatalf("symbols = %d", len(walk.symbols))
	}
}

func TestSymbolWalkSymbolLimitStopsHostileChain(t *testing.T) {
	image := make([]byte, 0x4000)
	const count = 100
	for index := 0; index < count; index++ {
		at := 0x80 + index*0x40
		putU32(image, at, NodeTypeSymbol)
		putU32(image, at+0x04, SymbolHeaderBytes)
		if index+1 < count {
			// A valid `above` chain: wrong-type nodes never propagate links,
			// so this is the structure a hostile block would use.
			putU64(image, at+0x18, uint64(0x80+(index+1)*0x40))
		}
	}
	table := [SymbolTableEntries]uint64{0x80}
	var warnings []string
	walk := walkSymbols(image, table, 0, uint32(SectorSize), 8, "client", &warnings)
	if len(walk.symbols) != 8 {
		t.Fatalf("symbols = %d, want 8", len(walk.symbols))
	}
	if !walk.capped {
		t.Fatal("walk must report the symbol cap")
	}
	if !hasWarning(warnings, "symbol table holds more than 8 symbols") {
		t.Fatalf("warnings = %q", warnings)
	}
}

func TestSymbolWalkNodeBudgetIsADefensiveBound(t *testing.T) {
	// The node budget is 2*limit+16. Every valid node appends a symbol, and
	// only a valid node can push links, so at most about 2*limit+1 nodes can
	// be visited before the symbol limit fires; the budget is a hard-stop
	// guard rather than a reachable cap. A cycle (the real hostile case) is
	// stopped by the visited set instead.
	image := make([]byte, 0x200)
	node := 0x80
	putU32(image, node, NodeTypeSymbol)
	putU32(image, node+0x04, SymbolHeaderBytes)
	putU64(image, node+0x10, uint64(node)) // below -> itself
	putU64(image, node+0x18, uint64(node)) // above -> itself
	table := [SymbolTableEntries]uint64{uint64(node)}
	var warnings []string
	walk := walkSymbols(image, table, 0, uint32(SectorSize), 8, "client", &warnings)
	if len(walk.symbols) != 1 || walk.capped {
		t.Fatalf("symbols = %d, capped = %v", len(walk.symbols), walk.capped)
	}
}

func TestSymbolWalkNamesBadPointers(t *testing.T) {
	image := make([]byte, 0x200)
	table := [SymbolTableEntries]uint64{0x100000}
	var warnings []string
	walk := walkSymbols(image, table, 0, uint32(SectorSize), 8, "client", &warnings)
	if len(walk.symbols) != 0 || !hasWarning(warnings, "outside the") {
		t.Fatalf("symbols = %d, warnings = %q", len(walk.symbols), warnings)
	}

	table = [SymbolTableEntries]uint64{0x80}
	warnings = nil
	putU32(image, 0x80, 0xFFFFFFFF)
	walk = walkSymbols(image, table, 0, uint32(SectorSize), 8, "client", &warnings)
	if len(walk.symbols) != 0 || !hasWarning(warnings, "node type is FFFFFFFF") {
		t.Fatalf("symbols = %d, warnings = %q", len(walk.symbols), warnings)
	}
}

// --- base-log symbol semantics ---------------------------------------------

func TestDeletedContainerWithStaleLengthStillNamesItsContainer(t *testing.T) {
	bytes := buildBLF([]string{"Registry"}, []string{"%BLF%\\TEST.regtrans-ms"})
	record := testBaseBlockOffset + testBaseRecordOffset
	symbol := record + testSymbolZoneStart + testSymbolStride
	putU32(bytes, symbol+0x0C, 0xAF100060)
	bytes[symbol+0x28] = 1
	stampBlockCRC(bytes[testBaseBlockOffset:])

	log := openBase(t, bytes)
	if len(log.Containers()) != 1 {
		t.Fatalf("containers = %d", len(log.Containers()))
	}
	if name, ok := log.Containers()[0].Name(); !ok || name != "%BLF%\\TEST.regtrans-ms" {
		t.Fatalf("container name = %q, %v", name, ok)
	}
	if !hasWarning(log.Warnings(), "deleted container symbol") || !hasWarning(log.Warnings(), "2937061472") {
		t.Fatalf("warnings = %q", log.Warnings())
	}
}

func TestLiveContainerWithStaleLengthIsRefused(t *testing.T) {
	bytes := buildBLF([]string{"Registry"}, []string{"%BLF%\\TEST.regtrans-ms"})
	record := testBaseBlockOffset + testBaseRecordOffset
	symbol := record + testSymbolZoneStart + testSymbolStride
	putU32(bytes, symbol+0x0C, 0xAF100060)
	stampBlockCRC(bytes[testBaseBlockOffset:])

	_, err := OpenBaseLog(source.NewMemorySource(1, bytes))
	wantCorrupt(t, err, "container context")
}

func TestContextOffsetOverwrittenBySignatureIsSkipped(t *testing.T) {
	bytes := buildBLF([]string{"Registry"}, []string{"%BLF%\\TEST.regtrans-ms"})
	record := testBaseBlockOffset + testBaseRecordOffset
	crossed := 0x1768
	writeSymbol(bytes, record, crossed, "%BLF%\\CROSSED.regtrans-ms", NodeTypeContainerContext, ContainerContextBytes)
	writeContainerContext(bytes, record, crossed, 0x20)
	putU64(bytes, record+ContainerSymbolTableOffset, uint64(crossed))
	putU16(bytes, 0x1FFE, 0x3210)
	stampBlockCRC(bytes[testBaseBlockOffset:])

	log := openBase(t, bytes)
	if len(log.Clients()) != 1 {
		t.Fatalf("clients = %d", len(log.Clients()))
	}
	if len(log.Containers()) != 0 {
		t.Fatalf("crossed context must be skipped, containers = %d", len(log.Containers()))
	}
	if !hasWarning(log.Warnings(), "context offset the log sector signature overwrote") ||
		!hasWarning(log.Warnings(), "skipped and the stored offset") {
		t.Fatalf("warnings = %q", log.Warnings())
	}
}

func TestNegativeContextOffsetIsSkipped(t *testing.T) {
	bytes := buildBLF([]string{"Registry"}, nil)
	record := testBaseBlockOffset + testBaseRecordOffset
	symbol := record + testSymbolZoneStart
	putI32(bytes, symbol+0x24, -4)
	stampBlockCRC(bytes[testBaseBlockOffset:])

	log := openBase(t, bytes)
	if len(log.Clients()) != 0 {
		t.Fatalf("clients = %d", len(log.Clients()))
	}
	if !hasWarning(log.Warnings(), "negative context offset") {
		t.Fatalf("warnings = %q", log.Warnings())
	}
}

func TestZeroContextDataIsSkipped(t *testing.T) {
	bytes := buildBLF([]string{"Registry"}, nil)
	record := testBaseBlockOffset + testBaseRecordOffset
	symbol := record + testSymbolZoneStart
	putU32(bytes, symbol+0x0C, 0)
	stampBlockCRC(bytes[testBaseBlockOffset:])

	log := openBase(t, bytes)
	if len(log.Clients()) != 0 {
		t.Fatalf("clients = %d", len(log.Clients()))
	}
	if !hasWarning(log.Warnings(), "declares no context data") {
		t.Fatalf("warnings = %q", log.Warnings())
	}
}

func TestInvalidUTF16NameIsNotDecoded(t *testing.T) {
	bytes := buildBLF([]string{"Registry"}, nil)
	record := testBaseBlockOffset + testBaseRecordOffset
	nameAt := record + testSymbolZoneStart + testNameOffsetInSymbol
	putU16(bytes, nameAt, 0xD800) // unpaired high surrogate then NUL
	putU16(bytes, nameAt+2, 0)
	stampBlockCRC(bytes[testBaseBlockOffset:])

	log := openBase(t, bytes)
	if len(log.Clients()) != 1 {
		t.Fatalf("clients = %d", len(log.Clients()))
	}
	if _, ok := log.Clients()[0].Name(); ok {
		t.Fatal("invalid UTF-16 must not decode to a name")
	}
	if !hasWarning(log.Warnings(), "did not decode as UTF-16") {
		t.Fatalf("warnings = %q", log.Warnings())
	}
}

func TestWrongContextNodeTypeIsSkipped(t *testing.T) {
	bytes := buildBLF([]string{"Registry"}, nil)
	record := testBaseBlockOffset + testBaseRecordOffset
	putU32(bytes, record+testSymbolZoneStart+testContextOffsetInSymbol, 0xDEADBEEF)
	stampBlockCRC(bytes[testBaseBlockOffset:])

	log := openBase(t, bytes)
	if len(log.Clients()) != 0 {
		t.Fatalf("clients = %d", len(log.Clients()))
	}
	if !hasWarning(log.Warnings(), "context type DEADBEEF") {
		t.Fatalf("warnings = %q", log.Warnings())
	}
}

func TestClientLimitWarnsAndKeepsDecodedClients(t *testing.T) {
	names := make([]string, MaxClients+1)
	for index := range names {
		names[index] = "Client" + itoa(index)
	}
	log := openBase(t, buildBLF(names, nil))

	if len(log.Clients()) != MaxClients {
		t.Fatalf("clients = %d, want %d", len(log.Clients()), MaxClients)
	}
	if !log.Stats().ClientsCapped {
		t.Fatal("clients_capped must be set")
	}
	if !hasWarning(log.Warnings(), "client symbol table holds more than") {
		t.Fatalf("warnings = %q", log.Warnings())
	}
	if name, _ := log.Clients()[0].Name(); name != "Client0" {
		t.Fatalf("first = %q", name)
	}
	if name, _ := log.Clients()[MaxClients-1].Name(); name != "Client"+itoa(MaxClients-1) {
		t.Fatalf("last = %q", name)
	}
}

func TestContainerLimitWarnsAndKeepsDecodedContainers(t *testing.T) {
	names := make([]string, MaxContainers+1)
	for index := range names {
		names[index] = "Container" + itoa(index)
	}
	log := openBase(t, buildBLF(nil, names))

	if len(log.Containers()) != MaxContainers {
		t.Fatalf("containers = %d, want %d", len(log.Containers()), MaxContainers)
	}
	if !log.Stats().ContainersCapped {
		t.Fatal("containers_capped must be set")
	}
	if !hasWarning(log.Warnings(), "container symbol table holds more than") {
		t.Fatalf("warnings = %q", log.Warnings())
	}
	if name, _ := log.Containers()[0].Name(); name != "Container0" {
		t.Fatalf("first = %q", name)
	}
}

func TestMetadataBlockCapWarns(t *testing.T) {
	bytes := buildBLFWithControl([]string{"Registry"}, nil, 0x800, MaxMetadataBlocks+1)
	log := openBase(t, bytes)
	if len(log.MetadataBlocks()) != MaxMetadataBlocks {
		t.Fatalf("metadata blocks = %d, want %d", len(log.MetadataBlocks()), MaxMetadataBlocks)
	}
	if !log.Stats().MetadataBlocksCapped {
		t.Fatal("metadata_blocks_capped must be set")
	}
	if !hasWarning(log.Warnings(), "only the first 64 were decoded") {
		t.Fatalf("warnings = %q", log.Warnings())
	}
}

func TestDeclaredClientMismatchWarns(t *testing.T) {
	bytes := buildBLF([]string{"Registry"}, nil)
	record := testBaseBlockOffset + testBaseRecordOffset
	bytes[record+0x1337] = 5
	stampBlockCRC(bytes[testBaseBlockOffset:])

	log := openBase(t, bytes)
	if !hasWarning(log.Warnings(), "declares 5 client(s) but 1 context(s) decoded") {
		t.Fatalf("warnings = %q", log.Warnings())
	}
}

func TestNonCanonicalSectorSizeWarns(t *testing.T) {
	bytes := buildBLF([]string{"Registry"}, nil)
	record := testBaseBlockOffset + testBaseRecordOffset
	putU32(bytes, record+0x132C, 1024)
	stampBlockCRC(bytes[testBaseBlockOffset:])

	log := openBase(t, bytes)
	if log.BaseRecord().SectorSize != 1024 {
		t.Fatalf("sector size = %d", log.BaseRecord().SectorSize)
	}
	if !hasWarning(log.Warnings(), "sector size of 1024") {
		t.Fatalf("warnings = %q", log.Warnings())
	}
}

// --- base-log corruption ---------------------------------------------------

func TestBadLogBlockSignatureIsRefusedByName(t *testing.T) {
	bytes := buildBLF([]string{"Registry"}, nil)
	bytes[0] = 0x14
	_, err := OpenBaseLog(source.NewMemorySource(1, bytes))
	wantCorrupt(t, err, "signature")
}

func TestBadControlRecordMagicIsRefusedByName(t *testing.T) {
	bytes := buildBLF([]string{"Registry"}, nil)
	bytes[0x78] ^= 0xFF
	stampBlockCRC(bytes[:testControlBlockBytes])
	_, err := OpenBaseLog(source.NewMemorySource(1, bytes))
	wantCorrupt(t, err, "magic")
}

func TestTruncatedControlRecordIsRefusedByName(t *testing.T) {
	bytes := buildBLF([]string{"Registry"}, nil)
	putU16(bytes, 0x70+0x48, 64)
	stampBlockCRC(bytes[:testControlBlockBytes])
	_, err := OpenBaseLog(source.NewMemorySource(1, bytes))
	wantCorrupt(t, err, "truncated")
}

func TestTruncatedSymbolContextIsRefusedByName(t *testing.T) {
	bytes := buildBLF([]string{"Registry"}, nil)
	record := testBaseBlockOffset + testBaseRecordOffset
	symbol := record + testSymbolZoneStart
	putU32(bytes, symbol+0x0C, 0x00100000)
	stampBlockCRC(bytes[testBaseBlockOffset:])
	_, err := OpenBaseLog(source.NewMemorySource(1, bytes))
	wantCorrupt(t, err, "client context")
}

func TestShortFileIsRefused(t *testing.T) {
	for _, length := range []int{0, 1, LogBlockHeaderBytes - 1} {
		_, err := OpenBaseLog(source.NewMemorySource(1, make([]byte, length)))
		wantCorrupt(t, err, "at least")
	}
}

func TestControlBlockPastFileIsRefused(t *testing.T) {
	bytes := buildBLF([]string{"Registry"}, nil)
	putU16(bytes, 0x04, 0xFFFF)
	_, err := OpenBaseLog(source.NewMemorySource(1, bytes))
	wantCorrupt(t, err, "declares")
}

func TestNoUsableGeneralBlockIsUnsupported(t *testing.T) {
	bytes := buildBLF([]string{"Registry"}, nil)
	// Entry 1's type is at 0x70+0x50+0x18+0x10.
	putU32(bytes, 0x70+0x50+0x18+0x10, 5)
	stampBlockCRC(bytes[:testControlBlockBytes])
	_, err := OpenBaseLog(source.NewMemorySource(1, bytes))
	wantUnsupported(t, err, "no usable general/base metadata block")
}

func TestShadowGeneralBlockFallbackWarns(t *testing.T) {
	bytes := buildBLF([]string{"Registry"}, []string{"%BLF%\\TEST.regtrans-ms"})
	putU32(bytes, 0x70+0x50+0x18+0x10, 3)
	stampBlockCRC(bytes[:testControlBlockBytes])
	log := openBase(t, bytes)
	if len(log.Clients()) != 1 {
		t.Fatalf("clients = %d", len(log.Clients()))
	}
	if !hasWarning(log.Warnings(), "only the shadow copy") {
		t.Fatalf("warnings = %q", log.Warnings())
	}
}

func TestZeroSizeGeneralBlockIsRefused(t *testing.T) {
	bytes := buildBLF([]string{"Registry"}, nil)
	putU32(bytes, 0x70+0x50+0x18+0x08, 0)
	stampBlockCRC(bytes[:testControlBlockBytes])
	_, err := OpenBaseLog(source.NewMemorySource(1, bytes))
	wantCorrupt(t, err, "zero-size general metadata block")
}

func TestGeneralBlockPastFileIsNotUsable(t *testing.T) {
	// Block selection skips a truncated block, so the later "extends past"
	// guard in the reader is a defensive branch. The observable behavior is
	// that no usable general block remains.
	bytes := buildBLF([]string{"Registry"}, nil)
	putU32(bytes, 0x70+0x50+0x18+0x08, 0x10000)
	putU32(bytes, 0x70+0x50+0x18+0x0C, uint32(len(bytes)-0x10))
	stampBlockCRC(bytes[:testControlBlockBytes])
	_, err := OpenBaseLog(source.NewMemorySource(1, bytes))
	wantUnsupported(t, err, "no usable general/base metadata block")
}

func TestBaseRecordThatDoesNotFitIsRefused(t *testing.T) {
	bytes := buildBLF([]string{"Registry"}, nil)
	putU32(bytes, 0x70+0x50+0x18+0x08, 0x100)
	stampBlockCRC(bytes[:testControlBlockBytes])
	_, err := OpenBaseLog(source.NewMemorySource(1, bytes))
	wantCorrupt(t, err, "does not fit")
}

func TestCorruptBlockChecksumWarnsButParses(t *testing.T) {
	bytes := buildBLF([]string{"Registry"}, []string{"%BLF%\\TEST.regtrans-ms"})
	bytes[0x100] ^= 0xFF // inside the control block, outside the parsed entries
	log := openBase(t, bytes)
	if checksumIs(log.ControlHeader().ChecksumOK, true) {
		t.Fatal("a corrupt control block must not report a matching checksum")
	}
	if log.Stats().ChecksumFailures != 1 {
		t.Fatalf("checksum failures = %d", log.Stats().ChecksumFailures)
	}
	if !hasWarning(log.Warnings(), "CRC-32") {
		t.Fatalf("warnings = %q", log.Warnings())
	}
	if len(log.Clients()) != 1 {
		t.Fatalf("metadata must remain readable, clients = %d", len(log.Clients()))
	}
}

func TestZeroStoredChecksumIsNotAPass(t *testing.T) {
	bytes := buildBLF([]string{"Registry"}, nil)
	for i := 0x0C; i < 0x10; i++ {
		bytes[i] = 0
	}
	log := openBase(t, bytes)
	if log.ControlHeader().ChecksumOK != nil {
		t.Fatalf("checksum = %v, want nil (not recorded)", log.ControlHeader().ChecksumOK)
	}
}

func TestMetadataBlockZeroSizeAndTruncationWarn(t *testing.T) {
	bytes := buildBLF([]string{"Registry"}, nil)
	// Entry 0 is the control block; make it zero-size and past the file.
	putU32(bytes, 0x70+0x50+0x08, 0)
	putU32(bytes, 0x70+0x50+0x0C, 0xFFFF)
	stampBlockCRC(bytes[:testControlBlockBytes])
	log := openBase(t, bytes)
	if !log.MetadataBlocks()[0].Truncated {
		t.Fatal("metadata block 0 must be marked truncated")
	}
	if !hasWarning(log.Warnings(), "has a zero size") || !hasWarning(log.Warnings(), "extends past") {
		t.Fatalf("warnings = %q", log.Warnings())
	}
}

// --- container header ------------------------------------------------------

func TestContainerHeaderDecodesPhysicalLSN(t *testing.T) {
	bytes := buildContainer(7, 0x2000, 3, 0x400)
	header := openContainer(t, bytes)
	if !checksumIs(header.Header.ChecksumOK, true) {
		t.Fatalf("checksum = %v", header.Header.ChecksumOK)
	}
	if header.ContainerID == nil || *header.ContainerID != 7 {
		t.Fatalf("container id = %v", header.ContainerID)
	}
	if header.BlockOffset == nil || *header.BlockOffset != 0x2000 {
		t.Fatalf("block offset = %v", header.BlockOffset)
	}
	if header.RecordSequence == nil || *header.RecordSequence != 3 {
		t.Fatalf("record sequence = %v", header.RecordSequence)
	}
	if header.FileLen != 0x400 {
		t.Fatalf("file len = %d", header.FileLen)
	}
	if len(header.Warnings) != 0 {
		t.Fatalf("warnings = %q", header.Warnings)
	}
}

func TestBadContainerSignatureIsRefusedByName(t *testing.T) {
	bytes := make([]byte, 0x400)
	bytes[0] = 0x14
	_, err := OpenContainer(source.NewMemorySource(1, bytes))
	wantCorrupt(t, err, "signature")
}

func TestContainerZeroSectorsIsRefused(t *testing.T) {
	// The header parser rejects a sector count too small for the fixed header
	// before OpenContainer's own zero-sector guard, which mirrors the
	// reference and is defensive.
	bytes := make([]byte, 0x400)
	bytes[0] = MajorVersion
	_, err := OpenContainer(source.NewMemorySource(1, bytes))
	wantCorrupt(t, err, "too few")
}

func TestContainerNonZeroStreamNumberWarns(t *testing.T) {
	bytes := buildContainer(7, 0x2000, 3, 0x400)
	bytes[3] = 4
	stampBlockCRC(bytes)
	header := openContainer(t, bytes)
	if !hasWarning(header.Warnings, "stream number") {
		t.Fatalf("warnings = %q", header.Warnings)
	}
}

func TestContainerTruncatedBlockWarnsAndSkipsChecksum(t *testing.T) {
	bytes := make([]byte, 0x400)
	bytes[0] = MajorVersion
	bytes[1] = MinorVersion
	putU16(bytes, 0x04, 4) // 0x800 declared, only 0x400 present
	putU16(bytes, 0x06, 4)
	putU32(bytes, 0x24, 0x70)
	stampBlockCRC(bytes)

	header := openContainer(t, bytes)
	if !hasWarning(header.Warnings, "is truncated") {
		t.Fatalf("warnings = %q", header.Warnings)
	}
	if header.Header.ChecksumOK != nil {
		t.Fatalf("checksum = %v, want nil because only a prefix exists", header.Header.ChecksumOK)
	}
}

func TestContainerCorruptChecksumWarns(t *testing.T) {
	bytes := buildContainer(7, 0x2000, 3, 0x400)
	bytes[0x100] ^= 0xFF
	header := openContainer(t, bytes)
	if checksumIs(header.Header.ChecksumOK, true) {
		t.Fatal("corrupt block must not report a matching checksum")
	}
	if !hasWarning(header.Warnings, "CRC-32") {
		t.Fatalf("warnings = %q", header.Warnings)
	}
}

func TestContainerInvalidCurrentLSNWithholdsFields(t *testing.T) {
	bytes := buildContainer(7, 0x2000, 3, 0x400)
	putU64(bytes, 0x14, math.MaxUint64)
	stampBlockCRC(bytes)
	header := openContainer(t, bytes)
	if header.ContainerID != nil || header.BlockOffset != nil || header.RecordSequence != nil {
		t.Fatalf("fields = %v/%v/%v", header.ContainerID, header.BlockOffset, header.RecordSequence)
	}
	if !hasWarning(header.Warnings, "current LSN is invalid") {
		t.Fatalf("warnings = %q", header.Warnings)
	}
}

func TestContainerThatBeginsInsideABlockFindsItsFirstHeader(t *testing.T) {
	blockOffset := uint64(SectorSize)
	declared := 2 * uint64(SectorSize)
	bytes := make([]byte, 0x600)
	for i := range bytes {
		bytes[i] = 0xAA
	}
	block := bytes[blockOffset : blockOffset+declared]
	for i := range block {
		block[i] = 0
	}
	block[0] = MajorVersion
	block[1] = MinorVersion
	block[3] = 0
	putU16(block, 0x04, 2)
	putU16(block, 0x06, 2)
	putU32(block, 0x24, 0x70)
	putU32(block, 0x68, uint32(declared-16))
	blockIndex := (0x2000 / SectorSize) << 9
	putU64(block, 0x14, (uint64(7)<<32)|blockIndex)

	header := openContainer(t, bytes)
	if header.Header.BlockOffset != blockOffset {
		t.Fatalf("header offset = %d", header.Header.BlockOffset)
	}
	if header.ContainerID != nil || header.BlockOffset != nil {
		t.Fatalf("the mismatched LSN must withhold fields: %v/%v", header.ContainerID, header.BlockOffset)
	}
	if !hasWarning(header.Warnings, "the first complete log block header is at offset 512") {
		t.Fatalf("warnings = %q", header.Warnings)
	}
	if !hasWarning(header.Warnings, "no container id or block offset is claimed") {
		t.Fatalf("warnings = %q", header.Warnings)
	}
}

func TestContainerFirstHeaderAtScannedOffsetClaimsMatchingLSN(t *testing.T) {
	bytes := make([]byte, 0x600)
	for i := range bytes {
		bytes[i] = 0xAA
	}
	block := bytes[SectorSize : 2*SectorSize]
	for i := range block {
		block[i] = 0
	}
	block[0] = MajorVersion
	block[1] = MinorVersion
	block[3] = 0
	putU16(block, 0x04, 2)
	putU16(block, 0x06, 2)
	putU32(block, 0x24, 0x70)
	putU32(block, 0x68, uint32(SectorSize-16))
	// Physical LSN names block offset 512, the header's real file offset.
	putU64(block, 0x14, (uint64(7)<<32)|((uint64(SectorSize)/SectorSize)<<9)|1)

	header := openContainer(t, bytes)
	if header.Header.BlockOffset != uint64(SectorSize) {
		t.Fatalf("header offset = %d", header.Header.BlockOffset)
	}
	if header.ContainerID == nil || *header.ContainerID != 7 {
		t.Fatalf("container id = %v", header.ContainerID)
	}
	if header.BlockOffset == nil || *header.BlockOffset != uint64(SectorSize) {
		t.Fatalf("block offset = %v", header.BlockOffset)
	}
	if header.RecordSequence == nil || *header.RecordSequence != 1 {
		t.Fatalf("record sequence = %v", header.RecordSequence)
	}
}

func TestContainerWithoutBlockHeaderIsRefusedAtOffsetZero(t *testing.T) {
	bytes := make([]byte, 0x600)
	for i := range bytes {
		bytes[i] = 0xAA
	}
	_, err := OpenContainer(source.NewMemorySource(1, bytes))
	wantCorrupt(t, err, "signature")
}

func TestContainerScanSkipsImplausibleCandidates(t *testing.T) {
	bytes := make([]byte, 0x800)
	for i := range bytes {
		bytes[i] = 0xAA
	}
	// Offset 512: signature but zero sectors, so it is not a complete header.
	candidate := bytes[SectorSize : SectorSize+LogBlockHeaderBytes]
	for i := range candidate {
		candidate[i] = 0
	}
	candidate[0] = MajorVersion
	candidate[1] = MinorVersion
	putU16(candidate, 0x04, 0)
	// Offset 1024: a usable header.
	good := bytes[2*SectorSize : 2*SectorSize+SectorSize]
	for i := range good {
		good[i] = 0
	}
	good[0] = MajorVersion
	good[1] = MinorVersion
	putU16(good, 0x04, 1)
	putU16(good, 0x06, 1)
	putU32(good, 0x24, 0x70)
	putU32(good, 0x68, 0x70)

	header := openContainer(t, bytes)
	if header.Header.BlockOffset != 2*SectorSize {
		t.Fatalf("header offset = %d", header.Header.BlockOffset)
	}
}

func TestContainerContextExtentsAreAlwaysEmpty(t *testing.T) {
	bytes := buildBLF(nil, []string{"%BLF%\\TEST.regtrans-ms"})
	log := openBase(t, bytes)
	if got := log.Containers()[0].Context.Extents; len(got) != 0 {
		t.Fatalf("extents = %v", got)
	}
}

func TestControlRecordBaseRecordAndSymbolFields(t *testing.T) {
	bytes := buildBLF([]string{"Registry"}, []string{"%BLF%\\TEST.regtrans-ms"})
	putU64(bytes, 0x70, 42)
	putU32(bytes, 0x70+0x14, 0xAABBCCDD)
	putU16(bytes, 0x70+0x18, 3)
	putU16(bytes, 0x70+0x1A, 4)
	putU32(bytes, 0x70+0x1C, 5)
	putU32(bytes, 0x70+0x20, 6)
	putU32(bytes, 0x70+0x24, 7)
	putU32(bytes, 0x70+0x4C, 9)
	stampBlockCRC(bytes[:testControlBlockBytes])

	src := source.NewMemorySource(1, bytes)
	log, err := OpenBaseLog(src)
	if err != nil {
		t.Fatalf("OpenBaseLog: %v", err)
	}
	control := log.Control()
	if control.RecordOffset != 0x70 || control.DumpCount != 42 || control.Version != 1 {
		t.Fatalf("control = %+v", control)
	}
	if control.ExtendState != 0xAABBCCDD || control.ExtendBlock != 3 || control.FlushBlock != 4 {
		t.Fatalf("extend fields = %+v", control)
	}
	if control.NewBlockSectors != 5 || control.ExtendStartSectors != 6 || control.ExtendSectors != 7 {
		t.Fatalf("sector fields = %+v", control)
	}
	if control.BlocksDeclared != 2 || control.Reserved != 9 {
		t.Fatalf("blocks/reserved = %+v", control)
	}
	if !checksumIs(control.ChecksumOK, true) {
		t.Fatalf("control checksum = %v", control.ChecksumOK)
	}

	base := log.BaseRecord()
	if base.DumpCount != 1 || base.USN != 1 || base.DeclaredClients != 1 || base.LogState != 4 {
		t.Fatalf("base record = %+v", base)
	}
	if base.RecordOffset != testBaseBlockOffset+testBaseRecordOffset {
		t.Fatalf("base record offset = %d", base.RecordOffset)
	}
	if base.SymbolZoneBytes != uint32(testSymbolZoneStart+2*testSymbolStride) {
		t.Fatalf("symbol zone = %#x", base.SymbolZoneBytes)
	}
	if base.SecuritySymbolTable != [SymbolTableEntries]uint64{} {
		t.Fatalf("security table = %v", base.SecuritySymbolTable)
	}

	client := log.Clients()[0].Symbol
	if client.Offset != testSymbolZoneStart {
		t.Fatalf("client symbol offset = %d", client.Offset)
	}
	if client.NodeType != NodeTypeSymbol || client.NodeSize != SymbolHeaderBytes {
		t.Fatalf("client node = %+v", client)
	}
	if client.NameHash != 0x12345678 || client.DataSize != ClientContextBytes {
		t.Fatalf("client hash/size = %+v", client)
	}
	if client.NameOffset != testSymbolZoneStart+testNameOffsetInSymbol {
		t.Fatalf("client name offset = %d", client.NameOffset)
	}
	if client.ContextOffset != testSymbolZoneStart+testContextOffsetInSymbol {
		t.Fatalf("client context offset = %d", client.ContextOffset)
	}
	if client.ContextOffsetLost || client.Deleted {
		t.Fatalf("client flags = %+v", client)
	}

	container := log.Containers()[0].Symbol
	if container.Offset != testSymbolZoneStart+testSymbolStride {
		t.Fatalf("container symbol offset = %d", container.Offset)
	}
	if container.DataSize != ContainerContextBytes {
		t.Fatalf("container data size = %d", container.DataSize)
	}

	stats := log.Stats()
	if stats.FileLen != uint64(len(bytes)) || stats.MetadataBlocks != 2 {
		t.Fatalf("stats = %+v", stats)
	}
	if log.Source() != src {
		t.Fatal("Source must return the opened source")
	}
}

func TestOpenNilAndShortSource(t *testing.T) {
	if _, err := Open(nil); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open(nil) error = %v", err)
	}
	if _, err := OpenBaseLog(nil); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("OpenBaseLog(nil) error = %v", err)
	}
	if _, err := OpenContainer(nil); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("OpenContainer(nil) error = %v", err)
	}
	if _, err := Open(source.NewMemorySource(1, nil)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Open(empty) error = %v", err)
	}
}

func TestNameCrossingSectorBoundaryIsNamed(t *testing.T) {
	image := make([]byte, 0x400)
	node := 0x80
	putU32(image, node, NodeTypeSymbol)
	putU32(image, node+0x04, SymbolHeaderBytes)
	putI32(image, node+0x20, 500)
	putI32(image, node+0x24, 0)
	units := utf16.Encode([]rune("ABCDEFGHIJ"))
	for index, unit := range units[:5] {
		putU16(image, 500+index*2, unit)
	}
	putU16(image, 510, 0xAF10)
	for index, unit := range units[5:] {
		putU16(image, 512+index*2, unit)
	}
	table := [SymbolTableEntries]uint64{uint64(node)}
	var warnings []string
	walk := walkSymbols(image, table, 0, uint32(SectorSize), 8, "client", &warnings)
	if len(walk.symbols) != 1 || !walk.symbols[0].HasName {
		t.Fatalf("symbols = %+v", walk.symbols)
	}
	if !hasWarning(warnings, "crosses the log sector boundary") {
		t.Fatalf("warnings = %q", warnings)
	}
}

func TestKindLabelsSourceAndFieldHelpers(t *testing.T) {
	if KindBaseLog.Label() != "base-log" || KindContainer.Label() != "container" {
		t.Fatalf("labels = %q/%q", KindBaseLog.Label(), KindContainer.Label())
	}
	src := source.NewMemorySource(1, buildBLF([]string{"Registry"}, nil))
	parsed, err := Open(src)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if parsed.Source() != src {
		t.Fatal("Container.Source must return the opened source")
	}

	if _, err := u16At(make([]byte, 1), 0, 5); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("u16At error = %v", err)
	}
	if _, err := u32At(make([]byte, 3), 0, 5); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("u32At error = %v", err)
	}
	if _, err := u64At(make([]byte, 7), 0, 5); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("u64At error = %v", err)
	}
}

func TestDecodeUTF16RejectsUnpairedSurrogates(t *testing.T) {
	if _, ok := decodeUTF16([]uint16{0xDC00}); ok {
		t.Fatal("a lone low surrogate must not decode")
	}
	if _, ok := decodeUTF16([]uint16{0xD800}); ok {
		t.Fatal("a lone high surrogate must not decode")
	}
	if _, ok := decodeUTF16([]uint16{0xD800, 0x0041}); ok {
		t.Fatal("a high surrogate followed by a non-low unit must not decode")
	}
	got, ok := decodeUTF16([]uint16{0xD83D, 0xDE00})
	if !ok || got != "😀" {
		t.Fatalf("surrogate pair = %q, %v", got, ok)
	}
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	at := len(digits)
	for value > 0 {
		at--
		digits[at] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[at:])
}
