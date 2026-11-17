package forensic

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/laenix/ewfgo/internal/data/containers/l01"
	"github.com/laenix/ewfgo/internal/data/source"
)

// LogicalImage is an opened EWF logical evidence image (EnCase L01/Lx01 v1).
// Unlike a disk image it is a catalog of acquired files, not a byte-addressable
// medium: use Entries and Open instead of Partitions.
type LogicalImage struct {
	path   string
	info   ImageInfo
	image  *l01.Image
	limits Limits

	closeMu sync.Mutex
	closers []io.Closer
	closed  bool

	nextID atomic.Uint64
}

// LogicalEntry is one catalog row of a logical evidence image. Metadata the
// catalog does not record is left zero (HasSize false, zero times, empty
// hashes); nothing is synthesized.
type LogicalEntry struct {
	Index int
	Name  string
	Path  string

	IsDir   bool
	Deleted bool

	Size    uint64
	HasSize bool

	MD5  string
	SHA1 string

	Created   time.Time
	Modified  time.Time
	Accessed  time.Time
	DeletedAt time.Time

	ID uint64
}

// OpenLogical opens an EnCase L01 logical evidence image, including sibling
// segments (L02, L03, ...).
func OpenLogical(ctx context.Context, imagePath string, opts Options) (*LogicalImage, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if imagePath == "" {
		return nil, fmt.Errorf("%w: empty image path", ErrInvalidArgument)
	}

	segments, closers, err := openL01Segments(imagePath)
	if err != nil {
		return nil, err
	}
	limits := l01.DefaultLimits()
	if opts.Limits.MaxEntries != 0 && opts.Limits.MaxEntries < uint64(limits.MaxEntries) {
		limits.MaxEntries = int(opts.Limits.MaxEntries)
	}
	if opts.Limits.MaxDepth != 0 && opts.Limits.MaxDepth < limits.MaxDepth {
		limits.MaxDepth = opts.Limits.MaxDepth
	}

	image, err := l01.OpenSegmentsWithLimits(segments, limits)
	if err != nil {
		for _, closer := range closers {
			closer.Close()
		}
		return nil, fmt.Errorf("open L01 %s: %w", imagePath, err)
	}
	return newLogicalImage(image, opts, imagePath, closers), nil
}

// OpenLogicalSource opens a single-segment L01 over an existing byte source
// (for example an archive entry or nested node). Multi-segment L01 sets need
// OpenLogical with paths so siblings can be discovered. The source is not
// closed by LogicalImage.Close.
func OpenLogicalSource(ctx context.Context, src ByteSource, opts Options) (*LogicalImage, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, fmt.Errorf("%w: nil L01 source", ErrInvalidArgument)
	}
	limits := l01.DefaultLimits()
	if opts.Limits.MaxEntries != 0 && opts.Limits.MaxEntries < uint64(limits.MaxEntries) {
		limits.MaxEntries = int(opts.Limits.MaxEntries)
	}
	if opts.Limits.MaxDepth != 0 && opts.Limits.MaxDepth < limits.MaxDepth {
		limits.MaxDepth = opts.Limits.MaxDepth
	}
	image, err := l01.OpenWithLimits(src, limits)
	if err != nil {
		return nil, err
	}
	return newLogicalImage(image, opts, "", nil), nil
}

func newLogicalImage(image *l01.Image, opts Options, imagePath string, closers []io.Closer) *LogicalImage {
	raw := image.Info()
	logical := &LogicalImage{
		path:    imagePath,
		image:   image,
		limits:  opts.Limits,
		closers: closers,
	}
	mediaSize := raw.LogicalSize
	if mediaSize == 0 {
		mediaSize = raw.LogicalDataSize
	}
	logical.info = ImageInfo{
		Path:           imagePath,
		Format:         "L01",
		Size:           mediaSize,
		SectorSize:     raw.BytesPerSector,
		CaseNumber:     raw.CaseNumber,
		EvidenceNumber: raw.EvidenceNumber,
	}
	if logical.info.SectorSize == 0 {
		logical.info.SectorSize = 512
	}
	return logical
}

// openL01Segments opens the first segment and every existing sibling segment.
func openL01Segments(imagePath string) ([]source.ByteSource, []io.Closer, error) {
	openOne := func(name string) (source.ByteSource, io.Closer, error) {
		src, err := source.OpenRawFileWithSectorSize(name, 0, 1, 512)
		if err != nil {
			return nil, nil, err
		}
		return src, src, nil
	}

	first, firstCloser, err := openOne(imagePath)
	if err != nil {
		return nil, nil, fmt.Errorf("open L01 segment %s: %w", imagePath, err)
	}
	segments := []source.ByteSource{first}
	closers := []io.Closer{firstCloser}
	for number := uint32(2); number <= 999; number++ {
		name, ok := l01.SiblingSegmentFileName(imagePath, number)
		if !ok {
			break
		}
		if filepath.Clean(name) == filepath.Clean(imagePath) {
			continue
		}
		if _, err := os.Stat(name); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				break
			}
			for _, closer := range closers {
				closer.Close()
			}
			return nil, nil, fmt.Errorf("stat L01 segment %s: %w", name, err)
		}
		src, closer, err := openOne(name)
		if err != nil {
			for _, c := range closers {
				c.Close()
			}
			return nil, nil, fmt.Errorf("open L01 segment %s: %w", name, err)
		}
		segments = append(segments, src)
		closers = append(closers, closer)
	}
	return segments, closers, nil
}

// Info returns the logical image metadata.
func (l *LogicalImage) Info() ImageInfo { return l.info }

// Path returns the first segment's path.
func (l *LogicalImage) Path() string { return l.path }

// Entries returns the full catalog in catalog order.
func (l *LogicalImage) Entries(ctx context.Context) ([]LogicalEntry, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw, err := l.image.Entries()
	if err != nil {
		return nil, err
	}
	entries := make([]LogicalEntry, 0, len(raw))
	for _, e := range raw {
		entries = append(entries, convertLogicalEntry(e))
	}
	return entries, nil
}

func convertLogicalEntry(e l01.Entry) LogicalEntry {
	out := LogicalEntry{
		Index:     e.Index,
		Name:      e.Name,
		Path:      e.Path,
		IsDir:     e.Kind == l01.KindDirectory,
		Deleted:   e.Deleted(),
		MD5:       e.MD5,
		SHA1:      e.SHA1,
		Created:   logicalTime(e.CreationTime),
		Modified:  logicalTime(e.ModificationTime),
		Accessed:  logicalTime(e.AccessTime),
		DeletedAt: logicalTime(e.DeletionTime),
	}
	if out.Path == "" {
		out.Path = "/"
	} else if !strings.HasPrefix(out.Path, "/") {
		out.Path = "/" + out.Path
	}
	if e.Size != nil {
		out.Size = *e.Size
		out.HasSize = true
	}
	if e.ID != nil {
		out.ID = *e.ID
	}
	return out
}

func logicalTime(value *int64) time.Time {
	if value == nil || *value == 0 {
		return time.Time{}
	}
	return time.Unix(*value, 0).UTC()
}

// Open opens a cataloged file for streaming reads by its recorded path.
func (l *LogicalImage) Open(ctx context.Context, filePath string) (*File, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	filePath = normalizePath(filePath)

	entries, err := l.Entries(ctx)
	if err != nil {
		return nil, err
	}
	var found *LogicalEntry
	for i := range entries {
		if strings.EqualFold(entries[i].Path, filePath) || entries[i].Path == filePath {
			found = &entries[i]
			break
		}
	}

	openPath := filePath
	if found != nil {
		openPath = found.Path
	}
	id := source.ID(l.nextID.Add(1) + 1_000_000)
	src, err := l.image.OpenFile(openPath, id)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", filePath, err)
	}
	size := src.Len()
	entry := Entry{Name: path.Base(filePath), Path: filePath, Size: size}
	if found != nil {
		entry.Name = found.Name
		entry.Path = found.Path
		entry.IsDir = found.IsDir
		entry.Deleted = found.Deleted
		entry.Modified = found.Modified
		entry.Accessed = found.Accessed
		entry.Created = found.Created
		if found.HasSize {
			size = found.Size
		}
	}
	return &File{entry: entry, size: size, max: l.limits.MaxFileBytes, src: src}, nil
}

// ReadAt reads the logical media stream at an offset. For a logical evidence
// image this is the acquired logical data stream, not a disk address space.
func (l *LogicalImage) ReadAt(offset uint64, buf []byte) (int, error) {
	return l.image.ReadMediaAt(offset, buf)
}

// Close releases the segment file handles. It is idempotent.
func (l *LogicalImage) Close() error {
	l.closeMu.Lock()
	defer l.closeMu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	var firstErr error
	for _, closer := range l.closers {
		if err := closer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	l.closers = nil
	return firstErr
}
