// Package archive defines the shared model for archive-shaped evidence.
//
// A container that wraps other files (a ZIP backup, a tar source bundle, a
// CPIO initramfs, an ar library) is exposed through the same two abstractions:
// an Adapter opens a ByteSource as a Reader, and a Reader lists Entries and
// opens one entry as a new ByteSource.  This is the Go port of forensic-core's
// data/containers/archive.rs framework.
//
// # Path safety
//
// Archive entry names are attacker-controlled.  NewEntry normalizes separators
// and rejects absolute paths, drive prefixes, NUL bytes, and ".." components.
// The engine never extracts to disk, but normalizing now means a later export
// step cannot accidentally write outside its destination.
package archive

import (
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Error kinds. Callers test them with errors.Is, never by string matching.
var (
	// ErrInvalid means the archive is malformed or a request names a missing
	// entry.
	ErrInvalid = errors.New("archive: invalid archive")
	// ErrLimit means a configured resource budget was exceeded.
	ErrLimit = errors.New("archive: limit exceeded")
	// ErrEncrypted means the entry's payload is ciphertext and this layer has
	// no key provider.
	ErrEncrypted = errors.New("archive: encrypted entry")
	// ErrUnsupported means the format is recognized but this feature is not
	// readable.
	ErrUnsupported = errors.New("archive: unsupported feature")
)

// Invalidf builds an ErrInvalid error with a formatted detail.
func Invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Limitf builds an ErrLimit error with a formatted detail.
func Limitf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrLimit, fmt.Sprintf(format, args...))
}

// Unsupportedf builds an ErrUnsupported error with a formatted detail.
func Unsupportedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUnsupported, fmt.Sprintf(format, args...))
}

// Encryptedf builds an ErrEncrypted error with a formatted detail.
func Encryptedf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrEncrypted, fmt.Sprintf(format, args...))
}

// Kind is what an entry represents.
type Kind uint8

const (
	// KindFile is a regular file with a payload.
	KindFile Kind = iota
	// KindDirectory is a directory entry.
	KindDirectory
	// KindSymlink is a symbolic link.
	KindSymlink
	// KindOther is a device node, fifo, socket, or hard link: a member that is
	// neither a file, directory, nor symlink.
	KindOther
)

// Label returns the human-readable kind name.
func (k Kind) Label() string {
	switch k {
	case KindFile:
		return "file"
	case KindDirectory:
		return "directory"
	case KindSymlink:
		return "symlink"
	default:
		return "special"
	}
}

// Entry is one member as listed by an archive reader.
type Entry struct {
	// Path is the normalized, "/"-separated path relative to the archive root.
	Path string
	// RawPath is the original name exactly as stored, kept for reporting.
	RawPath string
	// Kind is what the member represents.
	Kind Kind
	// Size is the uncompressed size in bytes.
	Size uint64
	// CompressedSize is the size as stored in the container, when recorded.
	CompressedSize *uint64
	// Modified is the last-modified Unix time in seconds, when recorded.
	Modified *int64
	// CRC32 is the CRC-32 recorded by the container, when present.
	CRC32 *uint32
	// Encrypted reports whether the entry payload is ciphertext.
	Encrypted bool
}

// NewEntry builds an entry, normalizing and validating the stored name.
func NewEntry(rawPath string, kind Kind, size uint64) (Entry, error) {
	path, err := sanitizeEntryPath(rawPath)
	if err != nil {
		return Entry{}, err
	}
	return Entry{Path: path, RawPath: rawPath, Kind: kind, Size: size}, nil
}

// IsDir reports whether the entry is a directory.
func (e Entry) IsDir() bool { return e.Kind == KindDirectory }

// sanitizeEntryPath is the package-internal spelling of SanitizeEntryPath.
func sanitizeEntryPath(raw string) (string, error) { return SanitizeEntryPath(raw) }

// SanitizeEntryPath turns an archive-stored name into a safe relative path.
//
// Backslashes become "/", repeated and "." components are dropped, and the
// path must stay below the archive root.  Empty names and NUL bytes are
// rejected.
func SanitizeEntryPath(raw string) (string, error) {
	if raw == "" {
		return "", Invalidf("archive entry has an empty name")
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] == 0 {
			return "", Invalidf("archive entry name contains a NUL byte")
		}
	}

	normalized := make([]byte, len(raw))
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\\' {
			normalized[i] = '/'
		} else {
			normalized[i] = raw[i]
		}
	}
	if len(normalized) > 0 && normalized[0] == '/' {
		return "", Invalidf("archive entry has an absolute path: %q", raw)
	}
	if len(normalized) >= 2 && isASCIILetter(normalized[0]) && normalized[1] == ':' {
		return "", Invalidf("archive entry has an absolute path: %q", raw)
	}

	components := make([]string, 0, 4)
	start := 0
	for i := 0; i <= len(normalized); i++ {
		if i < len(normalized) && normalized[i] != '/' {
			continue
		}
		component := string(normalized[start:i])
		start = i + 1
		switch component {
		case "", ".":
			// Drop empty and current-directory components.
		case "..":
			return "", Invalidf("archive entry escapes the archive root: %q", raw)
		default:
			components = append(components, component)
		}
	}
	if len(components) == 0 {
		return "", Invalidf("archive entry has no path components: %q", raw)
	}

	out := components[0]
	for _, component := range components[1:] {
		out += "/" + component
	}
	return out, nil
}

func isASCIILetter(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// Limits are hard resource limits applied while listing or opening an archive.
//
// Defaults are generous for real evidence but stop decompression bombs and
// pathological entry counts.  A caller that needs more can raise a field
// explicitly, which leaves an auditable decision in the case record.
type Limits struct {
	MaxEntries       int
	MaxEntrySize     uint64
	MaxTotalExpanded uint64
	MaxDepth         uint32
	MaxPathLen       int
}

// DefaultLimits returns the framework defaults.
func DefaultLimits() Limits {
	return Limits{
		MaxEntries:       100_000,
		MaxEntrySize:     4 * 1024 * 1024 * 1024,
		MaxTotalExpanded: 64 * 1024 * 1024 * 1024,
		MaxDepth:         8,
		MaxPathLen:       4096,
	}
}

// Budget tracks consumption against Limits for one archive.
//
// Adapters call Admit for every entry before exposing it.  Expanded counts
// claimed uncompressed sizes, not bytes actually read, so the check happens
// before decompression.
type Budget struct {
	limits   Limits
	entries  int
	expanded uint64
}

// NewBudget creates a budget for one archive.
func NewBudget(limits Limits) *Budget { return &Budget{limits: limits} }

// Limits returns the configured limits.
func (b *Budget) Limits() Limits { return b.limits }

// Entries returns the number of admitted entries.
func (b *Budget) Entries() int { return b.entries }

// Expanded returns the admitted uncompressed byte total.
func (b *Budget) Expanded() uint64 { return b.expanded }

// CheckDepth rejects nesting deeper than the configured limit.
func (b *Budget) CheckDepth(depth uint32) error {
	if depth > b.limits.MaxDepth {
		return Limitf("archive nesting depth %d exceeds %d", depth, b.limits.MaxDepth)
	}
	return nil
}

// Admit accounts for one entry or fails with ErrLimit.
func (b *Budget) Admit(entry Entry) error {
	nextEntries := b.entries + 1
	if nextEntries > b.limits.MaxEntries {
		return Limitf("archive has more than %d entries", b.limits.MaxEntries)
	}
	if len(entry.Path) > b.limits.MaxPathLen {
		return Limitf("archive entry path is longer than %d bytes", b.limits.MaxPathLen)
	}
	if entry.Kind == KindFile && entry.Size > b.limits.MaxEntrySize {
		return Limitf("archive entry %s claims %d bytes, limit is %d", entry.Path, entry.Size, b.limits.MaxEntrySize)
	}

	// Directory entries often carry a bogus size; only file payloads count
	// toward the expanded budget.
	expanded := b.expanded
	if entry.Kind == KindFile {
		if entry.Size > math.MaxUint64-b.expanded {
			return Limitf("archive expanded size overflows u64")
		}
		expanded += entry.Size
	}
	if expanded > b.limits.MaxTotalExpanded {
		return Limitf("archive expands beyond %d bytes", b.limits.MaxTotalExpanded)
	}

	b.entries = nextEntries
	b.expanded = expanded
	return nil
}

// Reader is a read-only view of one archive.
type Reader interface {
	// FormatID is the format identifier, for example "zip".
	FormatID() string
	// Entries lists all entries with limits already applied.
	Entries() ([]Entry, error)
	// OpenEntry opens one entry as an independent byte source.  The caller
	// supplies the id so the new source can be registered in the case graph.
	OpenEntry(path string, sourceID source.ID) (source.ByteSource, error)
	// FindEntry looks up one entry by normalized path.
	FindEntry(path string) (Entry, bool, error)
}

// Find is the default FindEntry implementation for readers that store a plain
// entry list.
func Find(reader Reader, path string) (Entry, bool, error) {
	entries, err := reader.Entries()
	if err != nil {
		return Entry{}, false, err
	}
	for _, entry := range entries {
		if entry.Path == path {
			return entry, true, nil
		}
	}
	return Entry{}, false, nil
}

// Adapter opens a specific archive format.
type Adapter interface {
	// FormatID is the format id this adapter handles.
	FormatID() string
	// Open parses source and returns a reader.
	Open(source source.ByteSource, limits Limits) (Reader, error)
}

// Registry is a format-id to adapter routing table.  A new registry is empty
// by design: a caller decides which adapters are available.
type Registry struct {
	adapters map[string]Adapter
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{adapters: make(map[string]Adapter)} }

// Register adds an adapter.  A duplicate format id is rejected rather than
// silently replacing a parser.
func (r *Registry) Register(adapter Adapter) error {
	formatID := adapter.FormatID()
	if _, exists := r.adapters[formatID]; exists {
		return Invalidf("an archive adapter for %s is already registered", formatID)
	}
	r.adapters[formatID] = adapter
	return nil
}

// Adapter returns the adapter registered for formatID.
func (r *Registry) Adapter(formatID string) (Adapter, bool) {
	adapter, ok := r.adapters[formatID]
	return adapter, ok
}

// IsEmpty reports whether the registry has no adapters.
func (r *Registry) IsEmpty() bool { return len(r.adapters) == 0 }

// Len returns the number of registered adapters.
func (r *Registry) Len() int { return len(r.adapters) }

// FormatIDs returns the registered format ids in sorted order.
func (r *Registry) FormatIDs() []string {
	ids := make([]string, 0, len(r.adapters))
	for id := range r.adapters {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Open parses source with the adapter registered for formatID.
func (r *Registry) Open(formatID string, src source.ByteSource, limits Limits) (Reader, error) {
	adapter, ok := r.adapters[formatID]
	if !ok {
		return nil, Unsupportedf("no archive adapter is registered for %s", formatID)
	}
	return adapter.Open(src, limits)
}
