package filesystem_test

// Shared E01 fixture helper for the handler tests. It opens the E01 through
// the data-layer EWF source (exact decompression) and resolves the first
// partition from the image's own partition table, so the reader-based handler
// tests no longer depend on the removed root-package convenience API.

import (
	"testing"

	ewfcontainer "github.com/laenix/ewfgo/internal/data/containers/ewf"
	"github.com/laenix/ewfgo/internal/data/partition"
)

// e01Partition opens the E01 and returns its media source and first partition.
func e01Partition(t *testing.T, name string) (*ewfcontainer.EWFSource, partition.Partition) {
	t.Helper()
	src, _, err := ewfcontainer.OpenFile(1, 1, name)
	if err != nil {
		t.Fatalf("ewf.OpenFile(%s): %v", name, err)
	}
	t.Cleanup(func() { src.Close() })

	table, err := partition.Detect(src)
	if err != nil {
		t.Fatalf("partition.Detect(%s): %v", name, err)
	}
	parts := table.Partitions()
	if len(parts) == 0 {
		t.Fatalf("partition.Detect(%s): no partitions", name)
	}
	return src, parts[0]
}
