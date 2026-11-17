package carving

import (
	"strings"
	"testing"
)

func TestBMPEndsAtTheSizeItsHeaderDeclares(t *testing.T) {
	bytes := makeBMP()
	bounds, err := bmpBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("bmpBounds: %v", err)
	}
	if bounds == nil {
		t.Fatal("bmpBounds returned no object")
	}
	if !bounds.Terminated || bounds.End != uint64(len(bytes)) {
		t.Fatalf("bounds = (%d, terminated=%v), want (%d, true)", bounds.End, bounds.Terminated, len(bytes))
	}
	if !strings.Contains(bounds.Detail, "2x2 24-bit") {
		t.Fatalf("Detail = %q", bounds.Detail)
	}
}

func TestBMPFileSizeDisagreeingWithGeometryIsRefused(t *testing.T) {
	bytes := makeBMP()
	bytes[2] = 71
	bounds, err := bmpBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("bmpBounds: %v", err)
	}
	if bounds != nil {
		t.Fatalf("bounds = %+v, want refused", bounds)
	}
}

func TestBMPDeclaredSizePastTheSourceIsTruncated(t *testing.T) {
	bytes := makeBMP()[:60]
	bounds, err := bmpBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("bmpBounds: %v", err)
	}
	if bounds == nil || bounds.Terminated || bounds.End != uint64(len(bytes)) {
		t.Fatalf("bounds = %+v, want a truncated header", bounds)
	}
}

func TestBMPImpossibleDIBHeaderIsRefused(t *testing.T) {
	bytes := makeBMP()
	bytes[14] = 41
	bounds, err := bmpBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("bmpBounds: %v", err)
	}
	if bounds != nil {
		t.Fatalf("bounds = %+v, want refused", bounds)
	}
}

func TestGIFWalksToItsTrailer(t *testing.T) {
	bytes := makeGIF()
	bounds, err := gifBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("gifBounds: %v", err)
	}
	if bounds == nil || !bounds.Terminated || bounds.End != uint64(len(bytes)) {
		t.Fatalf("bounds = %+v, want the trailer", bounds)
	}
	if !strings.Contains(bounds.Detail, "trailer at") {
		t.Fatalf("Detail = %q", bounds.Detail)
	}
}

func TestGIFCutBeforeItsTrailerIsKeptAsTruncated(t *testing.T) {
	bytes := makeGIF()
	bytes = bytes[:len(bytes)-4]
	bounds, err := gifBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("gifBounds: %v", err)
	}
	if bounds == nil || bounds.Terminated || bounds.End != uint64(len(bytes)) {
		t.Fatalf("bounds = %+v, want a truncated GIF", bounds)
	}
}

func TestGIFUnknownBlockByteIsNotAGIF(t *testing.T) {
	bytes := makeGIF()
	bytes[len(bytes)-1] = 0x99
	bounds, err := gifBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("gifBounds: %v", err)
	}
	if bounds != nil {
		t.Fatalf("bounds = %+v, want refused", bounds)
	}
}

func TestTIFFWalksItsIFDAndOutOfLineValues(t *testing.T) {
	bytes := makeTIFF()
	bounds, err := tiffBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("tiffBounds: %v", err)
	}
	if bounds == nil || !bounds.Terminated || bounds.End != uint64(len(bytes)) {
		t.Fatalf("bounds = %+v, want the strip-data end", bounds)
	}
	if !strings.Contains(bounds.Detail, "1 IFD(s)") {
		t.Fatalf("Detail = %q", bounds.Detail)
	}
}

func TestTIFFEntryCapIsReportedAsALimit(t *testing.T) {
	bytes := []byte("II*\x00")
	bytes = append(bytes, 8, 0, 0, 0)
	bytes = append(bytes, 0x88, 0x13) // 5000 entries
	bounds, err := tiffBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("tiffBounds: %v", err)
	}
	if bounds == nil || bounds.Terminated {
		t.Fatalf("bounds = %+v, want a capped walk", bounds)
	}
	if !strings.Contains(bounds.Detail, "limit:") || !strings.Contains(bounds.Detail, "4096") {
		t.Fatalf("Detail = %q", bounds.Detail)
	}
}

func TestTIFFIFDLoopIsRefused(t *testing.T) {
	bytes := makeTIFF()
	const nextAt = 8 + 2 + 4*12
	bytes[nextAt], bytes[nextAt+1], bytes[nextAt+2], bytes[nextAt+3] = 8, 0, 0, 0
	bounds, err := tiffBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("tiffBounds: %v", err)
	}
	if bounds != nil {
		t.Fatalf("bounds = %+v, want refused", bounds)
	}
}

func TestTIFFIFDTablePastTheSourceIsTruncated(t *testing.T) {
	bytes := makeTIFF()[:60]
	bounds, err := tiffBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("tiffBounds: %v", err)
	}
	if bounds == nil || bounds.Terminated || bounds.End != uint64(len(bytes)) {
		t.Fatalf("bounds = %+v, want a truncated table", bounds)
	}
}

func TestTIFFIFDOffsetInsideTheHeaderIsRefused(t *testing.T) {
	bytes := makeTIFF()
	bytes[4], bytes[5], bytes[6], bytes[7] = 4, 0, 0, 0
	bounds, err := tiffBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("tiffBounds: %v", err)
	}
	if bounds != nil {
		t.Fatalf("bounds = %+v, want refused", bounds)
	}
}

func TestWebPWalksItsRIFFChunksToTheDeclaredEnd(t *testing.T) {
	bytes := makeWebP()
	bounds, err := webpBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("webpBounds: %v", err)
	}
	if bounds == nil || !bounds.Terminated || bounds.End != uint64(len(bytes)) {
		t.Fatalf("bounds = %+v, want the RIFF end", bounds)
	}
	if !strings.Contains(bounds.Detail, "2 RIFF chunk(s)") {
		t.Fatalf("Detail = %q", bounds.Detail)
	}
}

func TestWebPRIFFSizePastTheSourceIsTruncated(t *testing.T) {
	bytes := makeWebP()
	bytes[4], bytes[5], bytes[6], bytes[7] = 0, 0x10, 0, 0 // 4096
	bounds, err := webpBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("webpBounds: %v", err)
	}
	if bounds == nil || bounds.Terminated || bounds.End != uint64(len(bytes)) {
		t.Fatalf("bounds = %+v, want a truncated RIFF", bounds)
	}
}

func TestRIFFThatIsNotWebPIsRefused(t *testing.T) {
	bytes := []byte("RIFF")
	bytes = append(bytes, 4, 0, 0, 0)
	bytes = append(bytes, []byte("WAVE")...)
	bounds, err := webpBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("webpBounds: %v", err)
	}
	if bounds != nil {
		t.Fatalf("bounds = %+v, want refused", bounds)
	}
}

func TestWebPVP8ChunkWithoutItsKeyframeCodeIsRefused(t *testing.T) {
	chunks := webpChunk("VP8 ", make([]byte, 10))
	bytes := []byte("RIFF")
	bytes = append(bytes, 0, 0, 0, 0)
	bytes[4] = byte(4 + len(chunks))
	bytes = append(bytes, []byte("WEBP")...)
	bytes = append(bytes, chunks...)
	bounds, err := webpBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("webpBounds: %v", err)
	}
	if bounds != nil {
		t.Fatalf("bounds = %+v, want refused", bounds)
	}
}

func TestEVTXChunkVerifiesOnItsOwn(t *testing.T) {
	bytes := makeEVTXChunk()
	bounds, err := evtxChunkBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("evtxChunkBounds: %v", err)
	}
	if bounds == nil || !bounds.Terminated || bounds.End != testEVTXChunkLen {
		t.Fatalf("bounds = %+v, want one 64 KiB chunk", bounds)
	}
	if !strings.Contains(bounds.Detail, "records end at 0x210") {
		t.Fatalf("Detail = %q", bounds.Detail)
	}
}

func TestEVTXChunkWithBadRecordsChecksumIsNotAnObject(t *testing.T) {
	bytes := makeEVTXChunk()
	bytes[testEVTXChunkHeaderLen+3] ^= 0xFF
	bounds, err := evtxChunkBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("evtxChunkBounds: %v", err)
	}
	if bounds != nil {
		t.Fatalf("bounds = %+v, want refused", bounds)
	}
}

func TestEVTXLogIsCarvedToItsLastVerifiedChunk(t *testing.T) {
	bytes := makeEVTXFile([][]byte{makeEVTXChunk(), makeEVTXChunk()}, 2)
	bounds, err := evtxFileBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("evtxFileBounds: %v", err)
	}
	wantEnd := uint64(testEVTXFileHeaderLen + 2*testEVTXChunkLen)
	if bounds == nil || !bounds.Terminated || bounds.End != wantEnd {
		t.Fatalf("bounds = %+v, want end %d", bounds, wantEnd)
	}
	if bounds.Detail != "2 chunk(s) with both checksums verified" {
		t.Fatalf("Detail = %q", bounds.Detail)
	}
}

func TestEVTXEmptyChunkEndsTheLogTheHeaderDeclares(t *testing.T) {
	bytes := makeEVTXFile([][]byte{makeEVTXChunk(), makeEVTXChunk()}, 3)
	bytes = append(bytes, make([]byte, testEVTXChunkLen)...)
	bounds, err := evtxFileBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("evtxFileBounds: %v", err)
	}
	wantEnd := uint64(testEVTXFileHeaderLen + 2*testEVTXChunkLen)
	if bounds == nil || !bounds.Terminated || bounds.End != wantEnd {
		t.Fatalf("bounds = %+v, want end %d", bounds, wantEnd)
	}
	if !strings.Contains(bounds.Detail, "the header declares 3") || !strings.Contains(bounds.Detail, "chunk 2 is empty") {
		t.Fatalf("Detail = %q", bounds.Detail)
	}
}

func TestEVTXLogWithoutARecordedCountIsWalkedToItsEnd(t *testing.T) {
	bytes := makeEVTXFile([][]byte{makeEVTXChunk(), makeEVTXChunk()}, 0)
	bytes = append(bytes, make([]byte, testEVTXChunkLen)...)
	bounds, err := evtxFileBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("evtxFileBounds: %v", err)
	}
	wantEnd := uint64(testEVTXFileHeaderLen + 2*testEVTXChunkLen)
	if bounds == nil || !bounds.Terminated || bounds.End != wantEnd {
		t.Fatalf("bounds = %+v, want end %d", bounds, wantEnd)
	}
	if !strings.Contains(bounds.Detail, "chunk 2 is empty") {
		t.Fatalf("Detail = %q", bounds.Detail)
	}
}

func TestEVTXLogWhoseHeaderChecksumFailsIsNotAnObject(t *testing.T) {
	bytes := makeEVTXFile([][]byte{makeEVTXChunk()}, 1)
	bytes[0x10] ^= 0xFF
	bounds, err := evtxFileBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("evtxFileBounds: %v", err)
	}
	if bounds != nil {
		t.Fatalf("bounds = %+v, want refused", bounds)
	}
}

func TestSQLiteDatabaseWalksEveryDeclaredPage(t *testing.T) {
	bytes := makeSQLiteDB([]byte{1, 2, 3})
	bounds, err := sqliteBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("sqliteBounds: %v", err)
	}
	wantEnd := uint64(2 * testSQLitePage)
	if bounds == nil || !bounds.Terminated || bounds.End != wantEnd {
		t.Fatalf("bounds = %+v, want end %d", bounds, wantEnd)
	}
	if !strings.Contains(bounds.Detail, "2 page(s)") {
		t.Fatalf("Detail = %q", bounds.Detail)
	}
}

func TestSQLiteDamagedHeaderIsNotADatabase(t *testing.T) {
	bytes := makeSQLiteDB([]byte{1, 2, 3})
	bytes[16], bytes[17] = 0x04, 0xD2 // page size 1234
	bounds, err := sqliteBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("sqliteBounds: %v", err)
	}
	if bounds != nil {
		t.Fatalf("bounds = %+v, want refused", bounds)
	}
}

func TestSQLiteDeclaredPageCountPastTheSourceIsTruncated(t *testing.T) {
	bytes := makeSQLiteDB([]byte{1, 2, 3})[:testSQLitePage+100]
	bounds, err := sqliteBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("sqliteBounds: %v", err)
	}
	if bounds == nil || bounds.Terminated || bounds.End != uint64(len(bytes)) {
		t.Fatalf("bounds = %+v, want a truncated database", bounds)
	}
}

func TestSQLitePageWithAnImpossibleCellPointerIsRefused(t *testing.T) {
	bytes := makeSQLiteDB([]byte{1, 2, 3})
	second := testSQLitePage
	bytes[second+8], bytes[second+9] = 0, 10 // cell pointer below the content area
	bounds, err := sqliteBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("sqliteBounds: %v", err)
	}
	if bounds != nil {
		t.Fatalf("bounds = %+v, want refused", bounds)
	}
}

func TestPrefetchRecordSizedZeroIsRefused(t *testing.T) {
	bytes := make([]byte, 4096)
	bytes[0], bytes[1], bytes[2], bytes[3] = 30, 0, 0, 0
	copy(bytes[4:8], []byte("SCCA"))
	bounds, err := prefetchBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("prefetchBounds: %v", err)
	}
	if bounds != nil {
		t.Fatalf("bounds = %+v, want refused", bounds)
	}
}

func TestPrefetchUnknownVersionIsRefused(t *testing.T) {
	bytes := make([]byte, 4096)
	bytes[0] = 99
	copy(bytes[4:8], []byte("SCCA"))
	bytes[12], bytes[13], bytes[14], bytes[15] = 0x00, 0x10, 0, 0 // 4096
	bounds, err := prefetchBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("prefetchBounds: %v", err)
	}
	if bounds != nil {
		t.Fatalf("bounds = %+v, want refused", bounds)
	}
}

func TestPrefetchRecordDeclaringMoreThan32MiBIsRefused(t *testing.T) {
	bytes := make([]byte, 4096)
	bytes[0], bytes[1], bytes[2], bytes[3] = 30, 0, 0, 0
	copy(bytes[4:8], []byte("SCCA"))
	bytes[12], bytes[13], bytes[14], bytes[15] = 0x01, 0x00, 0x00, 0x02 // 32 MiB + 1
	bounds, err := prefetchBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("prefetchBounds: %v", err)
	}
	if bounds != nil {
		t.Fatalf("bounds = %+v, want refused", bounds)
	}
}

func TestPrefetchRawRecordValidates(t *testing.T) {
	bytes := makePrefetchRaw()
	bounds, err := prefetchBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("prefetchBounds: %v", err)
	}
	if bounds == nil || !bounds.Terminated || bounds.End != uint64(len(bytes)) {
		t.Fatalf("bounds = %+v, want the declared record", bounds)
	}
	if !strings.Contains(bounds.Detail, "version 17") || !strings.Contains(bounds.Detail, "executable cmd.exe") {
		t.Fatalf("Detail = %q", bounds.Detail)
	}
}

func TestPrefetchRecordPastTheScanBoundIsTruncated(t *testing.T) {
	bytes := makePrefetchRaw()[:160]
	bounds, err := prefetchBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("prefetchBounds: %v", err)
	}
	if bounds == nil || bounds.Terminated || bounds.End != uint64(len(bytes)) {
		t.Fatalf("bounds = %+v, want a truncated record", bounds)
	}
}

func TestPrefetchMAMContainerValidates(t *testing.T) {
	bytes := makePrefetchMAM()
	bounds, err := prefetchBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("prefetchBounds: %v", err)
	}
	if bounds == nil || !bounds.Terminated || bounds.End != uint64(len(bytes)) {
		t.Fatalf("bounds = %+v, want the end of the compressed stream", bounds)
	}
	if !strings.Contains(bounds.Detail, "MAM container") || !strings.Contains(bounds.Detail, "executable cmd.exe") {
		t.Fatalf("Detail = %q", bounds.Detail)
	}
}

func TestPrefetchMAMWithAZeroTableIsRefused(t *testing.T) {
	bytes := []byte("MAM\x04")
	bytes = append(bytes, 200, 0, 0, 0)
	bytes = append(bytes, make([]byte, 512)...)
	bounds, err := prefetchBounds(memory(bytes), 0, uint64(len(bytes)))
	if err != nil {
		t.Fatalf("prefetchBounds: %v", err)
	}
	if bounds != nil {
		t.Fatalf("bounds = %+v, want refused", bounds)
	}
}
