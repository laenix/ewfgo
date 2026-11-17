package xar

import (
	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/source"
)

// Adapter registers XAR with the archive framework.  It is the Go counterpart
// of the reference reader's XarAdapter.
type Adapter struct{}

// FormatID implements archive.Adapter.
func (Adapter) FormatID() string { return "xar" }

// Open parses an archive and applies the framework's resource budget to every
// member before exposing it.
func (Adapter) Open(src source.ByteSource, limits archive.Limits) (archive.Reader, error) {
	reader, err := Open(src)
	if err != nil {
		return nil, err
	}
	budget := archive.NewBudget(limits)
	for index := range reader.entries {
		entry, err := archiveEntry(&reader.entries[index])
		if err != nil {
			return nil, err
		}
		if err := budget.Admit(entry); err != nil {
			return nil, err
		}
	}
	return &archiveView{reader: reader}, nil
}

// Register adds the XAR adapter to registry.
func Register(registry *archive.Registry) error { return registry.Register(Adapter{}) }

// archiveView adapts the package's Reader to archive.Reader.  The Go method
// set cannot hold both the native Entries and the framework Entries on one
// type, so the framework view lives on a thin wrapper.
type archiveView struct {
	reader *Reader
}

// FormatID implements archive.Reader.
func (v *archiveView) FormatID() string { return "xar" }

// Entries implements archive.Reader.
func (v *archiveView) Entries() ([]archive.Entry, error) {
	out := make([]archive.Entry, 0, len(v.reader.entries))
	for index := range v.reader.entries {
		entry, err := archiveEntry(&v.reader.entries[index])
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, nil
}

// OpenEntry implements archive.Reader.
func (v *archiveView) OpenEntry(path string, id source.ID) (source.ByteSource, error) {
	return v.reader.OpenEntry(path, id)
}

// FindEntry implements archive.Reader.
func (v *archiveView) FindEntry(path string) (archive.Entry, bool, error) {
	normalized, err := archive.SanitizeEntryPath(path)
	if err != nil {
		return archive.Entry{}, false, archive.Invalidf("%v", err)
	}
	entry, ok := v.reader.Entry(normalized)
	if !ok {
		return archive.Entry{}, false, nil
	}
	converted, err := archiveEntry(entry)
	if err != nil {
		return archive.Entry{}, false, err
	}
	return converted, true, nil
}

func archiveEntry(entry *Entry) (archive.Entry, error) {
	kind := archive.KindFile
	switch entry.Kind {
	case EntryKindDirectory:
		kind = archive.KindDirectory
	case EntryKindSymlink:
		kind = archive.KindSymlink
	}
	out, err := archive.NewEntry(entry.Path, kind, entry.Size)
	if err != nil {
		return archive.Entry{}, err
	}
	out.Modified = entry.Mtime
	if entry.Data != nil {
		stored := entry.Data.Length
		out.CompressedSize = &stored
	}
	return out, nil
}
