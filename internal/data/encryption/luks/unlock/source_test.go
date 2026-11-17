package unlock

import (
	"bytes"
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

const testImageID source.ImageID = 77

func openedLUKS2(t *testing.T, options luks2Options) (*Source, []byte) {
	t.Helper()
	image := buildLUKS2(t, options)
	unlocked, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	parent := source.NewMemorySourceWithImage(1, testImageID, image)
	opened, err := unlocked.Open(2, parent)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	plain := make([]byte, 0, 1024)
	for _, segment := range options.segments {
		plain = append(plain, segment.plaintext...)
	}
	return opened, plain
}

func TestSourceReadsDecryptedPayload(t *testing.T) {
	options := defaultLUKS2Options(patternBytes(1024, 1))
	opened, plain := openedLUKS2(t, options)

	if opened.SourceID() != 2 || opened.Len() != 1024 || opened.SectorSize() != 512 {
		t.Fatalf("geometry = id %d len %d sector %d", opened.SourceID(), opened.Len(), opened.SectorSize())
	}
	if opened.ImageID() != testImageID || opened.IsEmpty() {
		t.Fatalf("provenance = image %d empty %v", opened.ImageID(), opened.IsEmpty())
	}
	if opened.PayloadOffset() != 32768 || opened.IVTweak() != 9 {
		t.Fatalf("payload = %d tweak %d", opened.PayloadOffset(), opened.IVTweak())
	}

	full := make([]byte, len(plain))
	if n, err := opened.ReadAt(0, full); err != nil || n != len(plain) {
		t.Fatalf("ReadAt(0) = %d, %v", n, err)
	}
	if !bytes.Equal(full, plain) {
		t.Fatal("full payload did not decrypt")
	}

	// An unaligned read crosses a sector boundary.
	part := make([]byte, 100)
	if n, err := opened.ReadAt(500, part); err != nil || n != 100 {
		t.Fatalf("ReadAt(500) = %d, %v", n, err)
	}
	if !bytes.Equal(part, plain[500:600]) {
		t.Fatal("cross-sector read did not decrypt")
	}

	lossy := make([]byte, 300)
	if n, err := opened.ReadAtLossy(3, lossy); err != nil || n != 300 {
		t.Fatalf("ReadAtLossy(3) = %d, %v", n, err)
	}
	if !bytes.Equal(lossy, plain[3:303]) {
		t.Fatal("lossy read did not decrypt")
	}

	if n, err := opened.ReadAt(0, nil); n != 0 || err != nil {
		t.Fatalf("empty read = %d, %v", n, err)
	}
	if n, err := opened.ReadAt(1000, make([]byte, 100)); n != 24 || err != nil {
		t.Fatalf("tail read = %d, %v", n, err)
	}
}

func TestSourceProvenance(t *testing.T) {
	options := defaultLUKS2Options(patternBytes(1024, 2))
	opened, _ := openedLUKS2(t, options)

	probe := make([]byte, 32)
	if _, err := opened.ReadAt(0, probe); err != nil {
		t.Fatalf("probe read: %v", err)
	}

	extents, err := opened.Extents(0, opened.Len())
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 1 || extents[0].Parent != 1 || extents[0].ParentOffset != 32768 ||
		extents[0].Len != 1024 || extents[0].Kind != source.RangeData {
		t.Fatalf("extents = %+v", extents)
	}
	ranges, err := opened.MapToImage(0, opened.Len())
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 1 || ranges[0].ImageID != testImageID || ranges[0].ImageOffset != 32768 ||
		ranges[0].Len != 1024 || ranges[0].Kind != source.RangeData {
		t.Fatalf("image ranges = %+v", ranges)
	}
	if _, err := opened.Extents(opened.Len(), 1); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("out-of-range extents error = %v", err)
	}
	if _, err := opened.ReadAt(opened.Len(), make([]byte, 1)); !errors.Is(err, source.ErrOutOfRange) {
		t.Fatalf("out-of-range read error = %v", err)
	}

	stats := opened.Stats()
	if stats.Reads == 0 || stats.BytesRead == 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestSourceMultiSegmentConcatention(t *testing.T) {
	options := defaultLUKS2Options(patternBytes(1024, 3))
	options.segments = []segmentSpec{
		{
			offset: 32768, size: 1024, ivTweak: 5, sectorSize: 512,
			encryption: "aes-xts-plain64", plaintext: patternBytes(1024, 4),
		},
		{
			offset: 33792, size: 1024, ivTweak: 11, sectorSize: 1024,
			encryption: "aes-xts-plain64", plaintext: patternBytes(1024, 5),
		},
	}
	opened, plain := openedLUKS2(t, options)
	if opened.Len() != 2048 || opened.SectorSize() != 1024 {
		t.Fatalf("geometry = len %d sector %d", opened.Len(), opened.SectorSize())
	}
	got := make([]byte, 2048)
	if _, err := opened.ReadAt(0, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("multi-segment payload did not decrypt")
	}
	// A read that starts in segment 0 and ends in segment 1.
	got = make([]byte, 200)
	if _, err := opened.ReadAt(950, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain[950:1150]) {
		t.Fatal("read across the segment boundary did not decrypt")
	}
	extents, err := opened.Extents(0, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 2 || extents[0].ParentOffset != 32768 ||
		extents[1].ParentOffset != 33792 || extents[1].Len != 1024 {
		t.Fatalf("extents = %+v", extents)
	}
	ranges, err := opened.MapToImage(1000, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 2 || ranges[0].ImageOffset != 33768 || ranges[1].ImageOffset != 33792 {
		t.Fatalf("image ranges = %+v", ranges)
	}
}

func TestSourceUsesTheSegmentSectorSize(t *testing.T) {
	options := defaultLUKS2Options(patternBytes(8192, 6))
	options.segments[0].sectorSize = 4096
	opened, plain := openedLUKS2(t, options)
	if opened.SectorSize() != 4096 {
		t.Fatalf("sector size = %d", opened.SectorSize())
	}
	got := make([]byte, 8192)
	if _, err := opened.ReadAt(0, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("4096-byte sector payload did not decrypt")
	}
	part := make([]byte, 500)
	if _, err := opened.ReadAt(3000, part); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(part, plain[3000:3500]) {
		t.Fatal("unaligned 4096-byte-sector read did not decrypt")
	}
}

func TestSourceLUKS1Provenance(t *testing.T) {
	options := defaultLUKS1Options(patternBytes(1024, 7))
	image := buildLUKS1(t, options)
	unlocked, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := unlocked.Open(2, source.NewMemorySourceWithImage(1, testImageID, image))
	if err != nil {
		t.Fatal(err)
	}
	if opened.PayloadOffset() != 40*512 || opened.IVTweak() != 0 || opened.SectorSize() != 512 {
		t.Fatalf("geometry = %+v", opened)
	}
	got := make([]byte, 1024)
	if _, err := opened.ReadAt(0, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, options.payload) {
		t.Fatal("LUKS1 payload did not decrypt")
	}
	extents, err := opened.Extents(0, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 1 || extents[0].ParentOffset != 40*512 || extents[0].Len != 1024 {
		t.Fatalf("LUKS1 extents = %+v", extents)
	}
}

// shortReadSource claims its parent's length but never delivers bytes. A
// source must report an error rather than invent zeros.
type shortReadSource struct{ source.ByteSource }

func (s shortReadSource) ReadAt(uint64, []byte) (int, error)      { return 0, nil }
func (s shortReadSource) ReadAtLossy(uint64, []byte) (int, error) { return 0, nil }

// corruptSource always reports a damaged backing range.
type corruptSource struct{ source.ByteSource }

func (s corruptSource) ReadAt(offset uint64, _ []byte) (int, error) {
	return 0, source.NewCorrupt(offset, "damaged backing store")
}

func (s corruptSource) ReadAtLossy(offset uint64, _ []byte) (int, error) {
	return 0, source.NewCorrupt(offset, "damaged backing store")
}

func TestSourceShortParentIsAnErrorNotZeros(t *testing.T) {
	options := defaultLUKS2Options(patternBytes(512, 8))
	image := buildLUKS2(t, options)
	unlocked, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
	if err != nil {
		t.Fatal(err)
	}
	parent := shortReadSource{ByteSource: source.NewMemorySource(1, image)}
	opened, err := unlocked.Open(2, parent)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	if _, err := opened.ReadAt(0, buf); !errors.Is(err, source.ErrUnexpectedEOF) {
		t.Fatalf("short parent error = %v, want ErrUnexpectedEOF", err)
	}
	for _, value := range buf {
		if value != 0 {
			t.Fatal("a failed read wrote bytes into the caller's buffer")
		}
	}
}

func TestSourceParentErrorPropagates(t *testing.T) {
	options := defaultLUKS2Options(patternBytes(512, 9))
	image := buildLUKS2(t, options)
	unlocked, err := Unlock(source.NewMemorySource(1, image), options.passphrase)
	if err != nil {
		t.Fatal(err)
	}
	parent := corruptSource{ByteSource: source.NewMemorySource(1, image)}
	opened, err := unlocked.Open(2, parent)
	if err != nil {
		t.Fatal(err)
	}
	_, err = opened.ReadAt(0, make([]byte, 64))
	if !errors.Is(err, ErrSource) || !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("parent error = %v, want ErrSource wrapping ErrCorrupt", err)
	}
}
