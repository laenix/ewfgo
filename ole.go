package forensic

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/laenix/ewfgo/internal/data/containers/ole"
	"github.com/laenix/ewfgo/internal/data/source"
)

// OLEFile is an opened OLE2/Compound File Binary document: a tree of storages
// (directories) and streams (files). Entry paths are '/'-separated, absolute
// and start at the root storage ("/WordDocument").
type OLEFile struct {
	path   string
	file   *ole.File
	limits Limits

	closeMu sync.Mutex
	closers []io.Closer
	closed  bool

	nextID atomic.Uint64
}

// OLEEntry is one storage or stream in an OLE document.
type OLEEntry struct {
	Path string
	Name string

	IsStorage bool
	Size      uint64
	CLSID     string

	Created     time.Time
	HasCreated  bool
	Modified    time.Time
	HasModified bool
}

// OpenOLE opens an OLE2/CFB document from a path.
func OpenOLE(ctx context.Context, imagePath string, opts Options) (*OLEFile, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	src, err := source.OpenRawFileWithSectorSize(imagePath, 1, 1, opts.sectorSize(nil, 512))
	if err != nil {
		return nil, fmt.Errorf("open OLE document %s: %w", imagePath, err)
	}
	doc, err := OpenOLESource(ctx, src, opts)
	if err != nil {
		src.Close()
		return nil, err
	}
	doc.path = imagePath
	doc.closers = []io.Closer{src}
	return doc, nil
}

// OpenOLESource opens an OLE2/CFB document over an existing byte source. The
// source is not closed by OLEFile.Close.
func OpenOLESource(ctx context.Context, src ByteSource, opts Options) (*OLEFile, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, fmt.Errorf("%w: nil OLE source", ErrInvalidArgument)
	}
	limits := ole.Limits{}
	if opts.Limits.MaxFileBytes != 0 {
		limits.MaxStreamBytes = opts.Limits.MaxFileBytes
	}
	file, err := ole.OpenWithLimits(src, limits)
	if err != nil {
		return nil, fmt.Errorf("open OLE document: %w", err)
	}
	return &OLEFile{file: file, limits: opts.Limits}, nil
}

// Path returns the document path, empty for OpenOLESource.
func (o *OLEFile) Path() string { return o.path }

// SectorSize returns the CFB sector size (512 for v3, 4096 for v4).
func (o *OLEFile) SectorSize() uint32 { return o.file.Header().SectorSize }

// Version returns "3" or "4" for the CFB major version.
func (o *OLEFile) Version() string { return fmt.Sprintf("%d", o.file.Header().MajorVersion) }

// Entries returns every storage and stream in document order, with absolute
// paths. The root storage itself is returned as path "/".
func (o *OLEFile) Entries(ctx context.Context) ([]OLEEntry, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw := o.file.Entries()
	if len(raw) == 0 {
		return nil, nil
	}
	byIndex := make(map[uint32]*ole.Entry, len(raw))
	for i := range raw {
		entry := raw[i]
		byIndex[entry.Index] = &entry
	}
	root := o.file.Root()
	if root == nil {
		return nil, fmt.Errorf("%w: OLE document has no root entry", ErrCorrupt)
	}

	entries := []OLEEntry{o.convert(root, "/")}
	visited := map[uint32]bool{}
	var walk func(storage *ole.Entry, prefix string, depth int) error
	walk = func(storage *ole.Entry, prefix string, depth int) error {
		if depth > 64 {
			return fmt.Errorf("%w: OLE storage tree is deeper than 64", ErrCorrupt)
		}
		if storage.Child == ole.NoEntry {
			return nil
		}
		// The child tree is a red-black tree: in-order traversal yields the
		// stored (name) order.
		var visit func(index uint32) error
		visit = func(index uint32) error {
			if index == ole.NoEntry {
				return nil
			}
			entry, ok := byIndex[index]
			if !ok {
				return fmt.Errorf("%w: OLE directory link %d is out of range", ErrCorrupt, index)
			}
			if visited[index] {
				return fmt.Errorf("%w: OLE directory tree revisits entry %d", ErrCorrupt, index)
			}
			visited[index] = true
			if err := visit(entry.Left); err != nil {
				return err
			}
			p := path.Join(prefix, entry.Name)
			entries = append(entries, o.convert(entry, p))
			if entry.IsStorage() {
				if err := walk(entry, p, depth+1); err != nil {
					return err
				}
			}
			return visit(entry.Right)
		}
		return visit(storage.Child)
	}
	if err := walk(root, "/", 0); err != nil {
		return nil, err
	}
	return entries, nil
}

// ListStorage returns the direct children of one storage. path may be "" for
// the root.
func (o *OLEFile) ListStorage(ctx context.Context, storagePath string) ([]OLEEntry, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw, err := o.file.ListStorage(storagePath)
	if err != nil {
		return nil, mapOLEError(err)
	}
	prefix := path.Join("/", strings.TrimLeft(normalizePath(storagePath), "/"))
	entries := make([]OLEEntry, 0, len(raw))
	for i := range raw {
		entries = append(entries, o.convert(&raw[i], path.Join(prefix, raw[i].Name)))
	}
	return entries, nil
}

// Open opens a stream by path for streaming reads.
func (o *OLEFile) Open(ctx context.Context, streamPath string) (*File, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	entry, err := o.file.FindStream(normalizePath(streamPath))
	if err != nil {
		return nil, mapOLEError(err)
	}
	if !entry.IsStream() {
		return nil, fmt.Errorf("%w: %q is a storage, not a stream", ErrInvalidArgument, streamPath)
	}
	id := source.ID(o.nextID.Add(1) + 1_000_000)
	src, err := o.file.OpenStream(normalizePath(streamPath), id)
	if err != nil {
		return nil, fmt.Errorf("open OLE stream %q: %w", streamPath, mapOLEError(err))
	}
	entryInfo := Entry{
		Name: entry.Name,
		Path: path.Join("/", strings.TrimLeft(normalizePath(streamPath), "/")),
		Size: src.Len(),
	}
	return &File{entry: entryInfo, size: src.Len(), max: o.limits.MaxFileBytes, src: src}, nil
}

// convert maps one OLE directory entry into the public shape.
func (o *OLEFile) convert(entry *ole.Entry, entryPath string) OLEEntry {
	out := OLEEntry{
		Path:      entryPath,
		Name:      entry.Name,
		IsStorage: entry.IsStorage(),
		Size:      entry.Size,
	}
	if entry.IsStream() {
		out.CLSID = ""
	} else if entry.CLSID.String() != "00000000-0000-0000-0000-000000000000" {
		out.CLSID = entry.CLSID.String()
	}
	if entry.Created != 0 {
		out.Created = filetime(entry.Created)
		out.HasCreated = true
	}
	if entry.Modified != 0 {
		out.Modified = filetime(entry.Modified)
		out.HasModified = true
	}
	return out
}

// filetime converts Windows FILETIME ticks (100 ns since 1601-01-01) to time.
func filetime(ticks uint64) time.Time {
	const epochDelta = 116444736000000000 // 1601 -> 1970 in 100 ns units
	if ticks < epochDelta {
		return time.Time{}
	}
	return time.Unix(0, int64(ticks-epochDelta)*100).UTC()
}

// mapOLEError translates the OLE package's lookup sentinels into public kinds.
func mapOLEError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ole.ErrNotFound):
		return fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	case errors.Is(err, ole.ErrInvalidPath):
		return fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	case errors.Is(err, ole.ErrNotStorage), errors.Is(err, ole.ErrNotStream):
		return fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	default:
		return err
	}
}

// Close releases the document's file handle. It is idempotent.
func (o *OLEFile) Close() error {
	o.closeMu.Lock()
	defer o.closeMu.Unlock()
	if o.closed {
		return nil
	}
	o.closed = true
	var firstErr error
	for _, closer := range o.closers {
		if err := closer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	o.closers = nil
	return firstErr
}
