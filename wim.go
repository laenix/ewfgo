package forensic

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"
	"time"

	wimcontainer "github.com/laenix/ewfgo/internal/data/containers/wim"
	"github.com/laenix/ewfgo/internal/data/source"
)

// WIM is an opened Windows Imaging Format archive. A WIM holds one or more
// images; every image is a file tree whose entries can be read as streams.
// Solid/ESD (LZMS) WIMs are refused at open with an explicit error.
type WIM struct {
	path      string
	container *wimcontainer.Container
	limits    Limits

	closeMu sync.Mutex
	closers []io.Closer
	closed  bool
}

// WIMInfo describes the WIM container.
type WIMInfo struct {
	Version     uint32
	Flags       uint32
	ChunkSize   uint32
	Compression string
	GUID        string
	PartNumber  uint16
	TotalParts  uint16
	Images      int
}

// WIMImage describes one image inside a WIM.
type WIMImage struct {
	Index       uint32
	Name        string
	Description string
	Files       int
	Directories int
	// Declared counters are the writer's claims, present when the WIM records
	// them.
	DeclaredFiles      *uint64
	DeclaredTotalBytes *uint64
}

// WIMStream is one stream of a WIM entry: the unnamed data stream or a named
// alternate data stream.
type WIMStream struct {
	Name     string
	Size     uint64
	SHA1     string
	Resolved bool
}

// WIMEntry is one file or directory in a WIM image. Times are zero when the
// writer recorded none.
type WIMEntry struct {
	Path string
	Name string

	IsDir     bool
	IsReparse bool
	Size      uint64

	Created  time.Time
	Modified time.Time
	Accessed time.Time

	SHA1    string
	Streams []WIMStream
	// Resolved is false when the entry's unnamed stream hash names no blob in
	// this WIM (split or damaged set); Open then returns an explicit error.
	Resolved bool
}

// OpenWIM opens a WIM archive from a path.
func OpenWIM(ctx context.Context, imagePath string, opts Options) (*WIM, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw, err := source.OpenRawFileWithSectorSize(imagePath, 1, 1, opts.sectorSize(nil, 512))
	if err != nil {
		return nil, fmt.Errorf("open WIM %s: %w", imagePath, err)
	}
	archive, err := OpenWIMSource(ctx, raw, opts)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("parse WIM %s: %w", imagePath, err)
	}
	archive.path = imagePath
	archive.closers = []io.Closer{raw}
	return archive, nil
}

// OpenWIMSource opens a WIM over an existing byte source (for example an
// archive entry or nested node). The source is not closed by WIM.Close.
func OpenWIMSource(ctx context.Context, src ByteSource, opts Options) (*WIM, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, fmt.Errorf("%w: nil WIM source", ErrInvalidArgument)
	}
	container, err := wimcontainer.Open(src)
	if err != nil {
		return nil, err
	}
	return &WIM{container: container, limits: opts.Limits}, nil
}

// Path returns the WIM file path.
func (w *WIM) Path() string { return w.path }

// Info returns the container metadata.
func (w *WIM) Info() WIMInfo {
	info := w.container.Info()
	return WIMInfo{
		Version:     info.Version,
		Flags:       info.Flags,
		ChunkSize:   info.ChunkSize,
		Compression: info.Compression.String(),
		GUID:        fmt.Sprintf("%X", info.GUID),
		PartNumber:  info.PartNumber,
		TotalParts:  info.TotalParts,
		Images:      len(w.container.Images()),
	}
}

// Images returns the images in index order with their declared metadata.
func (w *WIM) Images(ctx context.Context) ([]WIMImage, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw := w.container.Images()
	out := make([]WIMImage, 0, len(raw))
	for _, image := range raw {
		info := WIMImage{
			Index:              image.Index,
			DeclaredFiles:      image.DeclaredFiles,
			DeclaredTotalBytes: image.DeclaredTotalBytes,
		}
		if image.Name != nil {
			info.Name = *image.Name
		}
		if image.Description != nil {
			info.Description = *image.Description
		}
		for _, entry := range image.Entries {
			if entry.IsDirectory() {
				info.Directories++
			} else {
				info.Files++
			}
		}
		out = append(out, info)
	}
	return out, nil
}

func (w *WIM) image(index uint32) (*wimcontainer.Image, error) {
	images := w.container.Images()
	for i := range images {
		if images[i].Index == index {
			return &images[i], nil
		}
	}
	return nil, fmt.Errorf("%w: WIM image %d does not exist", ErrInvalidArgument, index)
}

// Entries returns every entry of one image, in metadata order.
func (w *WIM) Entries(ctx context.Context, imageIndex uint32) ([]WIMEntry, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	image, err := w.image(imageIndex)
	if err != nil {
		return nil, err
	}
	entries := make([]WIMEntry, 0, len(image.Entries))
	for i := range image.Entries {
		entries = append(entries, convertWIMEntry(&image.Entries[i]))
	}
	return entries, nil
}

func convertWIMEntry(entry *wimcontainer.Entry) WIMEntry {
	out := WIMEntry{
		Path:      entry.Path,
		Name:      entry.Name,
		IsDir:     entry.IsDirectory(),
		IsReparse: entry.IsReparsePoint(),
		Size:      entry.Size,
		SHA1:      hex.EncodeToString(entry.SHA1[:]),
		Resolved:  entry.Resolved,
	}
	if entry.Created != 0 {
		out.Created = filetime(entry.Created)
	}
	if entry.Written != 0 {
		out.Modified = filetime(entry.Written)
	}
	if entry.Accessed != 0 {
		out.Accessed = filetime(entry.Accessed)
	}
	for _, stream := range entry.Streams {
		out.Streams = append(out.Streams, WIMStream{
			Name:     stream.Name,
			Size:     stream.Size,
			SHA1:     hex.EncodeToString(stream.SHA1[:]),
			Resolved: stream.Resolved,
		})
	}
	return out
}

// Open opens an image entry's unnamed data stream.
func (w *WIM) Open(ctx context.Context, imageIndex uint32, entryPath string) (*File, error) {
	return w.open(ctx, imageIndex, entryPath, nil)
}

// OpenStream opens one named stream of an image entry.
func (w *WIM) OpenStream(ctx context.Context, imageIndex uint32, entryPath, streamName string) (*File, error) {
	return w.open(ctx, imageIndex, entryPath, &streamName)
}

func (w *WIM) open(ctx context.Context, imageIndex uint32, entryPath string, streamName *string) (*File, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	entryPath = strings.TrimLeft(strings.ReplaceAll(entryPath, "\\", "/"), "/")
	image, err := w.image(imageIndex)
	if err != nil {
		return nil, err
	}
	var found *wimcontainer.Entry
	for i := range image.Entries {
		if strings.EqualFold(image.Entries[i].Path, entryPath) {
			found = &image.Entries[i]
			break
		}
	}
	if found != nil && found.IsDirectory() {
		return nil, fmt.Errorf("%w: %q is a directory", ErrInvalidArgument, entryPath)
	}
	lookupPath := entryPath
	if found != nil {
		lookupPath = found.Path
	}

	var src *wimcontainer.EntrySource
	if streamName == nil {
		src, err = w.container.OpenEntry(imageIndex, lookupPath)
	} else {
		src, err = w.container.OpenStream(imageIndex, lookupPath, *streamName)
	}
	if err != nil {
		return nil, fmt.Errorf("open WIM entry %q: %w", entryPath, err)
	}
	if w.limits.MaxFileBytes != 0 && src.Len() > w.limits.MaxFileBytes {
		return nil, fmt.Errorf("%w: WIM stream is %d bytes, MaxFileBytes limit is %d",
			ErrUnsupported, src.Len(), w.limits.MaxFileBytes)
	}

	entry := Entry{Name: path.Base(entryPath), Path: "/" + entryPath, Size: src.Len()}
	if found != nil {
		entry.Name = found.Name
		entry.Path = "/" + strings.TrimLeft(found.Path, "/")
		entry.Size = src.Len()
		if found.Written != 0 {
			entry.Modified = filetime(found.Written)
		}
		if found.Created != 0 {
			entry.Created = filetime(found.Created)
		}
		if found.Accessed != 0 {
			entry.Accessed = filetime(found.Accessed)
		}
	}
	return &File{entry: entry, size: src.Len(), max: w.limits.MaxFileBytes, src: src}, nil
}

// Close releases the WIM file handle. It is idempotent.
func (w *WIM) Close() error {
	w.closeMu.Lock()
	defer w.closeMu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	var firstErr error
	for _, closer := range w.closers {
		if err := closer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	w.closers = nil
	return firstErr
}
