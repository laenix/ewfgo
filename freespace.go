package forensic

import "context"

// FreeRun is one contiguous run of free bytes at a volume-relative offset.
type FreeRun struct {
	Offset uint64
	Length uint64
}

// FreeSpaceMap is a volume's free-space map, built from the filesystem's own
// allocation metadata. Runs never overlap and lie inside Covered. Bytes before
// the allocation area are metadata; bytes after Covered are unmapped.
type FreeSpaceMap struct {
	FreeBytes uint64
	Covered   uint64
	// AreaStart is where the allocation area begins, when the filesystem
	// reports it. Bytes before it are filesystem metadata.
	AreaStart uint64
	// Basis names the on-disk structure the map came from (for example
	// "jfs.dmap.working" or "reiserfs.bitmap").
	Basis string
	Runs  []FreeRun
	// Notes record caveats such as an unclean volume or a fallback map.
	Notes []string
}

// FreeSpaceProvider is implemented by filesystems that can enumerate free
// space. Query it with a type assertion:
//
//	if provider, ok := fsys.(forensic.FreeSpaceProvider); ok {
//		space, err := provider.FreeSpace(ctx)
//	}
type FreeSpaceProvider interface {
	FreeSpace(ctx context.Context) (*FreeSpaceMap, error)
}
