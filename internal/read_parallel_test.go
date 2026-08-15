package internal

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/laenix/ewfgo/internal/ewffixture"
)

// sectorBytes is the EWF sector size the fixture always emits.
const sectorBytes = 512

// openInternalE01 opens a synthetic E01 through the internal Open pipeline,
// which is what wires up the chunk cache and Sectors tables that
// ReadSectorData's parallel path relies on.
func openInternalE01(t *testing.T, e01 []byte) *EWFImage {
	t.Helper()
	path := filepath.Join(t.TempDir(), "f.E01")
	if err := os.WriteFile(path, e01, 0o644); err != nil {
		t.Fatal(err)
	}
	img, err := (&EWFImage{}).Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Mirror the public ewf.Open pipeline: parse every section chain (and the
	// chunk tables) so Sectors is populated for ReadSectorData.
	if err := img.ReadSections(); err != nil {
		img.Close()
		t.Fatal(err)
	}
	if err := img.ParseSections(); err != nil {
		img.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { img.Close() })
	return img
}

// readSectors reads a sector range through the parallel ReadSectorData path.
func readSectors(t *testing.T, img *EWFImage, start, n uint64) []byte {
	t.Helper()
	got, err := img.ReadSectorData(start, n)
	if err != nil {
		t.Fatalf("ReadSectorData(%d, %d): %v", start, n, err)
	}
	return got
}

// TestReadSectorData_ParallelIdentity is the byte-identity guarantee of the
// batched parallel decompression: the multi-core output must be byte-for-byte
// identical to the source disk for a full read, an off-chunk partial read, a
// read spanning section boundaries, and both compression modes. The disk is 64
// chunks so the parallel branch (len(batch) >= 2*GOMAXPROCS) is always taken.
func TestReadSectorData_ParallelIdentity(t *testing.T) {
	const totalSectors = 4096 // 64 chunks of 64 sectors
	const chunkSectors = 64
	disk := ewffixture.DiskPattern(totalSectors)

	for _, mode := range []ewffixture.CompressMode{ewffixture.CompressZlib, ewffixture.CompressNone} {
		name := "zlib"
		if mode == ewffixture.CompressNone {
			name = "none"
		}
		t.Run(name, func(t *testing.T) {
			e01 := ewffixture.WrapDisk(disk, ewffixture.Options{
				ChunkSectors: chunkSectors,
				Compress:     mode,
				Sections:     3, // three sectors/table pairs to force cross-section reads
			})
			img := openInternalE01(t, e01)

			// Full-image read.
			got := readSectors(t, img, 0, totalSectors)
			if !bytes.Equal(got, disk) {
				t.Fatal("full-image parallel read mismatch")
			}

			// Off-chunk, off-alignment partial read: sectors 100..350.
			mid := readSectors(t, img, 100, 250)
			if !bytes.Equal(mid, disk[100*sectorBytes:(100+250)*sectorBytes]) {
				t.Fatal("mid-chunk partial read mismatch")
			}

			// Range spanning a section boundary (3 sections -> ~21 chunks each;
			// the boundary between section 0 and 1 falls near sector 1372).
			got = readSectors(t, img, 1300, 300)
			if !bytes.Equal(got, disk[1300*sectorBytes:(1300+300)*sectorBytes]) {
				t.Fatal("cross-section read mismatch")
			}

			// Cache correctness: re-reading the same range returns identical bytes.
			again := readSectors(t, img, 100, 250)
			if !bytes.Equal(again, mid) {
				t.Fatal("repeat read (cache path) mismatch")
			}
		})
	}
}

// TestReadSectorData_ParallelTailPartialChunk pins the behavior at the end of a
// media whose size is not a multiple of the chunk size: the stored final chunk
// is zero-padded to full size, so a read covering it returns the real data
// followed by the stored padding, byte-identical to the sequential path.
func TestReadSectorData_ParallelTailPartialChunk(t *testing.T) {
	const totalSectors = 2000 // 32 chunks; the last (chunk 31) covers only 16 sectors
	disk := ewffixture.DiskPattern(totalSectors)
	e01 := ewffixture.WrapDisk(disk, ewffixture.Options{ChunkSectors: 64})
	img := openInternalE01(t, e01)

	// Full read: the padded tail must match what WrapDisk stored (real data +
	// zero padding to the chunk boundary).
	got := readSectors(t, img, 0, totalSectors)
	if !bytes.Equal(got, disk) {
		t.Fatal("full read of partial-final-chunk disk mismatch")
	}

	// Read that starts mid-chunk 30 and runs through the partial final chunk.
	got = readSectors(t, img, 1980, 40) // sectors 1980..2019, media ends at 2000
	want := make([]byte, 40*sectorBytes)
	copy(want, disk[1980*sectorBytes:]) // 20 sectors of real data + 20 of zeros
	if !bytes.Equal(got, want) {
		t.Fatal("read across partial final chunk mismatch")
	}
}

// TestReadSectorData_ParallelError pins error propagation through the parallel
// path: a failing chunk aborts the read with the failing sector's context and
// never returns partial container bytes. We corrupt one stored chunk in the
// middle of the image and confirm the read errors.
func TestReadSectorData_ParallelError(t *testing.T) {
	const totalSectors = 4096
	disk := ewffixture.DiskPattern(totalSectors)
	e01 := ewffixture.WrapDisk(disk, ewffixture.Options{ChunkSectors: 64})

	// Find the first table entry offset and corrupt the stored chunk at chunk 10
	// (sector 640). The entry holds its file offset (LayoutEnCase2_5: absolute,
	// base 0); flip the stream's first byte so the zlib header is invalid.
	entryOff := ewffixture.TableEntryOffsetFor(e01, 10)
	if entryOff < 0 {
		t.Fatal("could not locate table entry for chunk 10")
	}
	entry := binary.LittleEndian.Uint32(e01[entryOff : entryOff+4])
	chunkOff := int64(entry & 0x7FFFFFFF)
	e01[chunkOff] ^= 0xFF

	img := openInternalE01(t, e01)
	_, err := img.ReadSectorData(0, totalSectors)
	if err == nil {
		t.Fatal("corrupted chunk must produce an explicit error, not fabricated data")
	}
	// The error should mention the failing sector near chunk 10 (sector 640).
	if !bytes.Contains([]byte(err.Error()), []byte("sector")) {
		t.Fatalf("error lacks failing-sector context: %v", err)
	}
}
