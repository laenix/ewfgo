package forensic

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/laenix/ewfgo/internal/data/containers/androidbackup"
	arc "github.com/laenix/ewfgo/internal/data/containers/archive"
	archar "github.com/laenix/ewfgo/internal/data/containers/archive/ar"
	archcpio "github.com/laenix/ewfgo/internal/data/containers/archive/cpio"
	archtar "github.com/laenix/ewfgo/internal/data/containers/archive/tar"
	archzip "github.com/laenix/ewfgo/internal/data/containers/archive/zip"
	"github.com/laenix/ewfgo/internal/data/containers/rar"
	"github.com/laenix/ewfgo/internal/data/containers/sevenz"
	"github.com/laenix/ewfgo/internal/data/containers/xar"
	"github.com/laenix/ewfgo/internal/data/source"
)

// Archive is a read-only archive-shaped evidence container (ZIP, TAR, CPIO,
// ar, CAB, XAR, RAR 5, 7-Zip or Android backup). Entry paths are normalized,
// '/'-separated and relative to the archive
// root; absolute paths and ".." components are rejected while opening.
type Archive struct {
	path   string
	format string
	reader arc.Reader
	limits Limits

	closeMu sync.Mutex
	closers []io.Closer
	closed  bool

	nextID atomic.Uint64
}

// ArchiveEntry is one archive member.
type ArchiveEntry struct {
	Path string
	// Kind is "file", "directory", "symlink" or "special".
	Kind string
	Size uint64
	// Encrypted reports a ciphertext payload.
	Encrypted bool

	Modified    time.Time
	HasModified bool
}

// ArchiveFormat names a supported archive format.
type ArchiveFormat string

const (
	ArchiveZIP     ArchiveFormat = "zip"
	ArchiveTAR     ArchiveFormat = "tar"
	ArchiveCPIO    ArchiveFormat = "cpio"
	ArchiveAR      ArchiveFormat = "ar"
	ArchiveCAB     ArchiveFormat = "cab"
	ArchiveAndroid ArchiveFormat = "android backup"
	ArchiveXAR     ArchiveFormat = "xar"
	ArchiveRAR     ArchiveFormat = "rar"
	Archive7z      ArchiveFormat = "7z"
)

// OpenArchive opens a supported archive from a path.
func OpenArchive(ctx context.Context, imagePath string, opts Options) (*Archive, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	src, err := source.OpenRawFileWithSectorSize(imagePath, 1, 1, opts.sectorSize(nil, 512))
	if err != nil {
		return nil, fmt.Errorf("open archive %s: %w", imagePath, err)
	}
	archive, err := OpenArchiveSource(ctx, src, opts)
	if err != nil {
		src.Close()
		return nil, err
	}
	archive.path = imagePath
	archive.closers = []io.Closer{src}
	return archive, nil
}

// OpenArchiveSource opens an archive over an already-opened byte source. The
// source is not closed by Archive.Close; the caller keeps ownership.
func OpenArchiveSource(ctx context.Context, src ByteSource, opts Options) (*Archive, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, fmt.Errorf("%w: nil archive source", ErrInvalidArgument)
	}
	format, err := sniffArchive(src)
	if err != nil {
		return nil, err
	}

	limits := arc.DefaultLimits()
	if opts.Limits.MaxEntries != 0 && int(opts.Limits.MaxEntries) < limits.MaxEntries {
		limits.MaxEntries = int(opts.Limits.MaxEntries)
	}
	if opts.Limits.MaxFileBytes != 0 && opts.Limits.MaxFileBytes < limits.MaxEntrySize {
		limits.MaxEntrySize = opts.Limits.MaxFileBytes
	}

	var reader arc.Reader
	switch format {
	case ArchiveZIP:
		reader, err = archzip.Open(src, limits)
	case ArchiveTAR:
		reader, err = archtar.Open(src, limits)
	case ArchiveCPIO:
		reader, err = archcpio.Open(src, limits)
	case ArchiveAR:
		reader, err = archar.Open(src, limits)
	case ArchiveCAB:
		reader, err = openCAB(src)
	case ArchiveAndroid:
		reader, err = openAndroidBackup(src, limits)
	case ArchiveXAR:
		reader, err = xar.Adapter{}.Open(src, limits)
	case ArchiveRAR:
		reader, err = rar.Open(src, limits)
	case Archive7z:
		reader, err = sevenz.Open(src, limits)
	default:
		err = fmt.Errorf("%w: no archive reader for %q", ErrUnsupported, format)
	}
	if err != nil {
		return nil, mapArchiveError(err)
	}
	return &Archive{
		format: string(format),
		reader: reader,
		limits: opts.Limits,
	}, nil
}

// sniffArchive identifies the archive format from the source's first bytes.
func sniffArchive(src ByteSource) (ArchiveFormat, error) {
	length := src.Len()
	if length > 512 {
		length = 512
	}
	head, err := source.ReadVecAt(src, 0, length)
	if err != nil {
		return "", err
	}
	switch {
	case bytes.HasPrefix(head, []byte("PK\x03\x04")),
		bytes.HasPrefix(head, []byte("PK\x05\x06")),
		bytes.HasPrefix(head, []byte("PK\x07\x08")):
		return ArchiveZIP, nil
	case bytes.HasPrefix(head, []byte("!<arch>\n")):
		return ArchiveAR, nil
	case bytes.HasPrefix(head, []byte("MSCF")):
		return ArchiveCAB, nil
	case bytes.HasPrefix(head, []byte("xar!")):
		return ArchiveXAR, nil
	case bytes.HasPrefix(head, []byte(rar.MagicRAR5)),
		bytes.HasPrefix(head, []byte(rar.MagicRAR4)):
		return ArchiveRAR, nil
	case bytes.HasPrefix(head, []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}):
		return Archive7z, nil
	case bytes.HasPrefix(head, []byte(androidbackup.Magic)),
		bytes.HasPrefix(head, []byte(androidbackup.MIUI)):
		return ArchiveAndroid, nil
	case bytes.HasPrefix(head, []byte("070701")),
		bytes.HasPrefix(head, []byte("070702")),
		bytes.HasPrefix(head, []byte("070707")),
		bytes.HasPrefix(head, []byte{0xc7, 0x71}),
		bytes.HasPrefix(head, []byte{0x71, 0xc7}):
		return ArchiveCPIO, nil
	case len(head) >= 262 && string(head[257:262]) == "ustar":
		return ArchiveTAR, nil
	}
	return "", fmt.Errorf("%w: source is not a recognised archive (ZIP/TAR/CPIO/ar/CAB/XAR/RAR/7z/Android backup)", ErrUnsupported)
}

// Format returns "zip", "tar", "cpio", "ar", "cab", "xar", "rar", "7z" or
// "android backup".
func (a *Archive) Format() string { return a.format }

// Path returns the archive path, empty for OpenArchiveSource.
func (a *Archive) Path() string { return a.path }

// Entries returns the archive members with limits applied.
func (a *Archive) Entries(ctx context.Context) ([]ArchiveEntry, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw, err := a.reader.Entries()
	if err != nil {
		return nil, mapArchiveError(err)
	}
	entries := make([]ArchiveEntry, 0, len(raw))
	for _, e := range raw {
		entry := ArchiveEntry{
			Path:      e.Path,
			Kind:      e.Kind.Label(),
			Size:      e.Size,
			Encrypted: e.Encrypted,
		}
		if e.Modified != nil {
			entry.Modified = time.Unix(*e.Modified, 0).UTC()
			entry.HasModified = true
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// OpenSource returns one entry's bytes as a ByteSource with archive-derived
// provenance. The path is archive-relative; a leading '/' is accepted.
func (a *Archive) OpenSource(ctx context.Context, entryPath string) (ByteSource, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	cleaned, err := arc.SanitizeEntryPath(strings.TrimLeft(normalizePath(entryPath), "/"))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	raw, found, err := a.reader.FindEntry(cleaned)
	if err != nil {
		return nil, mapArchiveError(err)
	}
	if !found {
		return nil, fmt.Errorf("%w: archive member %q", os.ErrNotExist, cleaned)
	}
	if raw.Kind == arc.KindDirectory {
		return nil, fmt.Errorf("%w: %q is a directory", ErrInvalidArgument, cleaned)
	}
	if raw.Encrypted {
		return nil, fmt.Errorf("%w: archive member %q is encrypted", ErrDecrypt, cleaned)
	}
	id := source.ID(a.nextID.Add(1) + 1_000_000)
	src, err := a.reader.OpenEntry(cleaned, id)
	if err != nil {
		return nil, fmt.Errorf("open archive member %q: %w", cleaned, mapArchiveError(err))
	}
	return src, nil
}

// Open opens one entry for streaming reads. The path is archive-relative; a
// leading '/' is accepted.
func (a *Archive) Open(ctx context.Context, entryPath string) (*File, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	cleaned, err := arc.SanitizeEntryPath(strings.TrimLeft(normalizePath(entryPath), "/"))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	entryPath = cleaned
	raw, found, err := a.reader.FindEntry(entryPath)
	if err != nil {
		return nil, mapArchiveError(err)
	}
	if !found {
		return nil, fmt.Errorf("%w: archive member %q", os.ErrNotExist, entryPath)
	}
	if raw.Kind == arc.KindDirectory {
		return nil, fmt.Errorf("%w: %q is a directory", ErrInvalidArgument, entryPath)
	}
	if raw.Encrypted {
		return nil, fmt.Errorf("%w: archive member %q is encrypted", ErrDecrypt, entryPath)
	}

	id := source.ID(a.nextID.Add(1) + 1_000_000)
	src, err := a.reader.OpenEntry(entryPath, id)
	if err != nil {
		return nil, fmt.Errorf("open archive member %q: %w", entryPath, mapArchiveError(err))
	}
	entry := Entry{
		Name: path.Base(raw.Path),
		Path: raw.Path,
		Size: src.Len(),
	}
	if raw.Modified != nil {
		entry.Modified = time.Unix(*raw.Modified, 0).UTC()
	}
	return &File{entry: entry, size: src.Len(), max: a.limits.MaxFileBytes, src: src}, nil
}

// mapArchiveError translates the archive framework's sentinels into the public
// error kinds.
func mapArchiveError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, arc.ErrInvalid):
		return fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	case errors.Is(err, arc.ErrEncrypted):
		return fmt.Errorf("%w: %v", ErrDecrypt, err)
	case errors.Is(err, arc.ErrLimit), errors.Is(err, arc.ErrUnsupported):
		return fmt.Errorf("%w: %v", ErrUnsupported, err)
	default:
		return err
	}
}

// Close releases the archive's file handle. It is idempotent. A source passed
// to OpenArchiveSource is not closed.
func (a *Archive) Close() error {
	a.closeMu.Lock()
	defer a.closeMu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	var firstErr error
	for _, closer := range a.closers {
		if err := closer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	a.closers = nil
	return firstErr
}
