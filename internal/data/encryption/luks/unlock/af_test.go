package unlock

import (
	"bytes"
	"errors"
	"testing"
)

func counterFill() func([]byte) {
	state := uint32(0x12345678)
	return func(out []byte) {
		for index := range out {
			state = state*1103515245 + 12345
			out[index] = byte(state >> 16)
		}
	}
}

func keyBytes(count int) []byte {
	out := make([]byte, count)
	for index := range out {
		out[index] = byte(0x40 + index)
	}
	return out
}

func TestAFSplitThenMergeRestoresTheKey(t *testing.T) {
	for _, size := range []int{16, 32, 64} {
		for _, stripes := range []int{2, 3, 100, 4000} {
			original := keyBytes(size)
			area, err := afSplit(original, stripes, counterFill())
			if err != nil {
				t.Fatalf("%d stripes of %d bytes: %v", stripes, size, err)
			}
			if len(area) != size*stripes {
				t.Fatalf("area is %d bytes, want %d", len(area), size*stripes)
			}
			if bytes.Equal(area[:size], original) {
				t.Fatal("the first stripe is the key in the clear")
			}
			merged, err := afMerge(area, size)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(merged, original) {
				t.Fatalf("%d stripes of %d bytes did not merge back", stripes, size)
			}
		}
	}
}

func TestAFOneCorruptedStripeChangesTheWholeKey(t *testing.T) {
	original := keyBytes(32)
	area, _ := afSplit(original, 16, counterFill())
	area[5] ^= 0x80
	merged, err := afMerge(area, 32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(merged, original) || bytes.Equal(merged[:16], original[:16]) {
		t.Fatal("a corrupted stripe did not change the result")
	}
}

func TestAFDiffusePrefixesTheChunkIndex(t *testing.T) {
	block := make([]byte, 64)
	diffused := afDiffuse(block)
	if len(diffused) != 64 {
		t.Fatalf("diffuse returned %d bytes", len(diffused))
	}
	if bytes.Equal(diffused[:32], diffused[32:]) {
		t.Fatal("identical chunks at different positions must hash differently")
	}
	if !bytes.Equal(diffused[:32], afDiffuse(make([]byte, 32))[:32]) {
		t.Fatal("the first chunk's diffusion changed with the block length")
	}
}

func TestAFDiffuseTruncatesTheTailChunk(t *testing.T) {
	diffused := afDiffuse(make([]byte, 40))
	if len(diffused) != 40 {
		t.Fatalf("diffuse returned %d bytes", len(diffused))
	}
}

func TestAFRefusesBadShapes(t *testing.T) {
	if _, err := afMerge(make([]byte, 33), 32); !errors.Is(err, ErrAntiForensic) {
		t.Fatalf("unaligned area error = %v", err)
	}
	if _, err := afMerge(make([]byte, 32), 32); !errors.Is(err, ErrAntiForensic) {
		t.Fatalf("single stripe error = %v", err)
	}
	if _, err := afMerge(nil, 32); !errors.Is(err, ErrAntiForensic) {
		t.Fatalf("empty area error = %v", err)
	}
	if _, err := afMerge(make([]byte, 64), 0); !errors.Is(err, ErrAntiForensic) {
		t.Fatalf("zero key size error = %v", err)
	}
	if _, err := afSplit(nil, 2, func([]byte) {}); !errors.Is(err, ErrAntiForensic) {
		t.Fatalf("empty key split error = %v", err)
	}
	if _, err := afSplit([]byte{1, 2, 3, 4}, 1, func([]byte) {}); !errors.Is(err, ErrAntiForensic) {
		t.Fatalf("one stripe split error = %v", err)
	}
}
