package forensic

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/laenix/ewfgo/internal/data/containers/mmkv"
	"github.com/laenix/ewfgo/internal/data/source"
)

// MMKVStore is a decoded Tencent MMKV key-value store or its CRC sidecar. MMKV
// stores are append-only record streams: the reader replays every set/delete
// and reports the final state of each key, including overwritten and deleted
// values.
type MMKVStore struct {
	path string
	kind string

	store *mmkv.Store
	meta  *mmkv.MetaSummary

	summary MMKVSummary
	keys    []MMKVKey
}

// MMKVSummary describes the record stream of one store.
type MMKVSummary struct {
	DeclaredSize    uint32
	PayloadBytes    uint64
	Boundary        string
	Records         uint64
	Sets            uint64
	Deletes         uint64
	LiveKeys        uint64
	DeletedKeys     uint64
	OverwrittenKeys uint64
	KeyBytes        uint64
	ValueBytes      uint64
	TrailingBytes   uint64
	Truncated       bool
	Warnings        []string
}

// MMKVKey is the final replayed state of one key. Values are represented by
// their length, SHA-256 and a bounded preview; the store indexes records rather
// than retaining every historical value in memory.
type MMKVKey struct {
	Key string

	Live        bool
	HasValue    bool
	ValueLen    uint64
	ValueSHA256 string

	Sets    uint32
	Deletes uint32

	// Shape is "text", "container" or "raw"; Preview/PreviewTruncated carry a
	// bounded decoded preview and RawHex a bounded hex dump for opaque values.
	Shape            string
	Preview          string
	PreviewTruncated bool
	ContainerEntries uint32
	RawHex           string
	RawTruncated     bool
}

// MMKVMeta is the decoded CRC sidecar of a store.
type MMKVMeta struct {
	CRC            uint32
	Version        uint32
	Sequence       uint32
	IVHex          string
	ActualSize     uint32
	LastActualSize uint32
	LastCRC        uint32
	Flags          uint64
	Short          bool
	Warnings       []string
}

// OpenMMKV decodes an MMKV store file or its ".crc" sidecar.
func OpenMMKV(ctx context.Context, imagePath string, opts Options) (*MMKVStore, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	info, err := os.Stat(imagePath)
	if err != nil {
		return nil, fmt.Errorf("open MMKV store %s: %w", imagePath, err)
	}
	if info.Size() < 0 || uint64(info.Size()) > mmkv.MaxStoreBytes {
		return nil, fmt.Errorf("%w: MMKV store is %d bytes, limit is %d",
			ErrUnsupported, info.Size(), mmkv.MaxStoreBytes)
	}
	data, err := os.ReadFile(imagePath)
	if err != nil {
		return nil, fmt.Errorf("read MMKV store %s: %w", imagePath, err)
	}

	store := &MMKVStore{path: imagePath, kind: "store"}
	if strings.HasSuffix(strings.ToLower(imagePath), ".crc") {
		meta, err := mmkv.ParseMeta(data)
		if err != nil {
			return nil, fmt.Errorf("parse MMKV sidecar: %w", err)
		}
		store.kind = "meta"
		store.meta = meta
		store.summary = MMKVSummary{
			DeclaredSize: meta.ActualSize,
			Warnings:     append([]string(nil), meta.Warnings...),
		}
		return store, nil
	}

	decoded, err := mmkv.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse MMKV store: %w", err)
	}
	applyMMKVStore(store, decoded)
	return store, nil
}

// OpenMMKVSource decodes an MMKV store over an existing byte source (for
// example an archive entry or nested node). A CRC sidecar has no path-based
// identity in this form, so the source is parsed as a store.
func OpenMMKVSource(ctx context.Context, src ByteSource, opts Options) (*MMKVStore, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, fmt.Errorf("%w: nil MMKV source", ErrInvalidArgument)
	}
	if src.Len() > mmkv.MaxStoreBytes {
		return nil, fmt.Errorf("%w: MMKV store is %d bytes, limit is %d",
			ErrUnsupported, src.Len(), mmkv.MaxStoreBytes)
	}
	data, err := source.ReadVecAt(src, 0, src.Len())
	if err != nil {
		return nil, err
	}
	decoded, err := mmkv.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse MMKV store: %w", err)
	}
	store := &MMKVStore{kind: "store", store: decoded}
	applyMMKVStore(store, decoded)
	return store, nil
}

func applyMMKVStore(store *MMKVStore, decoded *mmkv.Store) {
	store.store = decoded
	s := decoded.Summary
	store.summary = MMKVSummary{
		DeclaredSize:    s.DeclaredSize,
		PayloadBytes:    s.PayloadBytes,
		Boundary:        s.Boundary.Label(),
		Records:         s.Records,
		Sets:            s.Sets,
		Deletes:         s.Deletes,
		LiveKeys:        s.LiveKeys,
		DeletedKeys:     s.DeletedKeys,
		OverwrittenKeys: s.OverwrittenKeys,
		KeyBytes:        s.KeyBytes,
		ValueBytes:      s.ValueBytes,
		TrailingBytes:   s.TrailingBytes,
		Truncated:       s.Truncated,
		Warnings:        append([]string(nil), s.Warnings...),
	}
	store.keys = make([]MMKVKey, 0, len(decoded.Keys))
	for _, key := range decoded.Keys {
		store.keys = append(store.keys, convertMMKVKey(key))
	}
}

func convertMMKVKey(key mmkv.KeyFacts) MMKVKey {
	out := MMKVKey{
		Key:         key.Key,
		Live:        key.Live,
		HasValue:    key.HasValue,
		ValueLen:    key.ValueLen,
		ValueSHA256: key.ValueSHA256,
		Sets:        key.Sets,
		Deletes:     key.Deletes,
	}
	if key.View != nil {
		out.Shape = key.View.Shape.Label()
		out.Preview = key.View.Text
		out.PreviewTruncated = key.View.TextTruncated
		out.ContainerEntries = key.View.ContainerEntries
		out.RawHex = key.View.RawHex
		out.RawTruncated = key.View.RawTruncated
	}
	return out
}

// Path returns the store path.
func (m *MMKVStore) Path() string { return m.path }

// Kind returns "store" or "meta".
func (m *MMKVStore) Kind() string { return m.kind }

// Summary returns the record-stream statistics.
func (m *MMKVStore) Summary() MMKVSummary { return m.summary }

// Meta returns the CRC sidecar metadata, nil for a store file.
func (m *MMKVStore) Meta() *MMKVMeta {
	if m.meta == nil {
		return nil
	}
	meta := &MMKVMeta{
		CRC:            m.meta.CRC,
		Version:        m.meta.Version,
		Sequence:       m.meta.Sequence,
		IVHex:          m.meta.IVHex,
		ActualSize:     m.meta.ActualSize,
		LastActualSize: m.meta.LastActualSize,
		LastCRC:        m.meta.LastCRC,
		Flags:          m.meta.Flags,
		Short:          m.meta.Short,
		Warnings:       append([]string(nil), m.meta.Warnings...),
	}
	return meta
}

// Keys returns every key's final replayed state.
func (m *MMKVStore) Keys(ctx context.Context) ([]MMKVKey, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	return append([]MMKVKey(nil), m.keys...), nil
}

// Lookup returns one key's final state. An MMKV key is a byte string rendered
// by the reader; matching is exact and case-sensitive.
func (m *MMKVStore) Lookup(ctx context.Context, key string) (*MMKVKey, bool, error) {
	if err := checkContext(ctx); err != nil {
		return nil, false, err
	}
	for i := range m.keys {
		if m.keys[i].Key == key {
			found := m.keys[i]
			return &found, true, nil
		}
	}
	return nil, false, nil
}

// ModTime returns the store file's modification time.
func (m *MMKVStore) ModTime() (time.Time, error) {
	info, err := os.Stat(m.path)
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}
