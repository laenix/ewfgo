package forensic

import (
	"errors"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/containers/cab"
	"github.com/laenix/ewfgo/internal/data/source"
)

// cabArchive adapts the Cabinet reader to the archive.Reader interface so CAB
// files use the same public Archive API as ZIP, TAR, CPIO and ar.
type cabArchive struct {
	cabinet *cab.Cabinet
}

func openCAB(src source.ByteSource) (archive.Reader, error) {
	cabinet, err := cab.Open(src)
	if err != nil {
		return nil, err
	}
	return &cabArchive{cabinet: cabinet}, nil
}

func (r *cabArchive) FormatID() string { return "cab" }

func (r *cabArchive) Entries() ([]archive.Entry, error) {
	raw := r.cabinet.Files()
	entries := make([]archive.Entry, 0, len(raw))
	for i := range raw {
		entry := &raw[i]
		kind := archive.KindFile
		if entry.Size == 0 && entry.Available == 0 && entry.Path == "" {
			kind = archive.KindOther
		}
		converted := archive.Entry{
			Path:     entry.Path,
			RawPath:  entry.RawPath,
			Kind:     kind,
			Size:     entry.Size,
			Modified: entry.Modified,
		}
		entries = append(entries, converted)
	}
	return entries, nil
}

func (r *cabArchive) FindEntry(path string) (archive.Entry, bool, error) {
	found, ok := r.cabinet.Find(path)
	if !ok {
		return archive.Entry{}, false, nil
	}
	return archive.Entry{
		Path:     found.Path,
		RawPath:  found.RawPath,
		Kind:     archive.KindFile,
		Size:     found.Size,
		Modified: found.Modified,
	}, true, nil
}

func (r *cabArchive) OpenEntry(path string, sourceID source.ID) (source.ByteSource, error) {
	src, err := r.cabinet.OpenFile(path, sourceID)
	if err != nil {
		switch {
		case errors.Is(err, cab.ErrNotFound), errors.Is(err, cab.ErrInvalidPath):
			return nil, archive.Invalidf("%v", err)
		case errors.Is(err, source.ErrUnsupported), errors.Is(err, cab.ErrEntryTooLarge):
			return nil, archive.Unsupportedf("%v", err)
		default:
			return nil, fmt.Errorf("%w: %v", archive.ErrInvalid, err)
		}
	}
	return src, nil
}
