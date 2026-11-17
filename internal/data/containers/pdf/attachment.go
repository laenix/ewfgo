// Byte-source access to embedded file streams.

package pdf

import (
	"errors"

	"github.com/laenix/ewfgo/internal/data/source"
)

// ErrNotFound is returned when an attachment name or index does not exist.
var ErrNotFound = errors.New("pdf: attachment not found")

// AttachmentSource serves the decoded content of one embedded file as a
// ByteSource. The stream's stored offset and length are validated against the
// document source when the attachment is opened; RawOffset and RawLength
// report the stored range. Decoded bytes are derived, so Extents and
// MapToImage mark their ranges RangeDerived rather than pretending a decoded
// offset is a stored offset.
type AttachmentSource struct {
	id           source.ID
	parent       source.ByteSource
	data         []byte
	rawOffset    uint64
	rawLength    uint64
	hasRawLength bool
	filters      []string
	name         string
	index        int
	counters     source.Counters
}

// OpenAttachment opens the embedded file named by name. A file's tree name or
// its /UF or /F filename may match. The stream is decoded here, bounded by
// Limits.MaxEmbeddedBytes, so a stream that fails decoding is an error and no
// partial bytes are ever labelled as the attachment's content.
func (d *Document) OpenAttachment(name string, id source.ID) (*AttachmentSource, error) {
	for index, file := range d.EmbeddedFiles {
		if file.Name == name {
			return d.OpenAttachmentIndex(index, id)
		}
		if file.Filename != nil && *file.Filename == name {
			return d.OpenAttachmentIndex(index, id)
		}
	}
	return nil, ErrNotFound
}

// OpenAttachmentIndex opens the embedded file at index.
func (d *Document) OpenAttachmentIndex(index int, id source.ID) (*AttachmentSource, error) {
	if index < 0 || index >= len(d.EmbeddedFiles) {
		return nil, ErrNotFound
	}
	file := d.EmbeddedFiles[index]
	if !file.hasStream {
		if file.Note != nil {
			return nil, unsupported("attachment %q: %s", file.Name, *file.Note)
		}
		return nil, unsupported("attachment %q has no embedded stream", file.Name)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	value, ok, err := d.loader.object(file.streamNumber)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, corrupt(0, "attachment %q names object %d, which is absent", file.Name, file.streamNumber)
	}
	dict, ok := value.AsDict()
	if !ok || !dict.Contains([]byte("Length")) {
		return nil, corrupt(0, "attachment %q object %d is not a stream", file.Name, file.streamNumber)
	}
	loaded, ok := d.loader.cache[file.streamNumber]
	if !ok || !loaded.hasStream {
		return nil, corrupt(0, "attachment %q object %d has no stream body", file.Name, file.streamNumber)
	}
	rawOffset := loaded.stream
	if rawOffset > d.src.Len() {
		return nil, corrupt(rawOffset, "attachment %q stream starts at byte %d, past the end of the %d byte file",
			file.Name, rawOffset, d.src.Len())
	}
	rawLength, hasRawLength, err := d.loader.lengthOf(dict)
	if err != nil {
		return nil, err
	}
	if hasRawLength {
		if rawLength > d.src.Len()-rawOffset {
			return nil, corrupt(rawOffset, "attachment %q stream declares %d bytes, past the end of the file", file.Name, rawLength)
		}
	}
	bytesValue, filters, err := d.loader.decodedStreamNumber(file.streamNumber, dict)
	if err != nil {
		var encrypted encryptedError
		if errors.As(err, &encrypted) {
			return nil, unsupported("%s; attachment %q was not decoded", encrypted.Error(), file.Name)
		}
		return nil, err
	}
	if len(bytesValue) > d.limits.MaxEmbeddedBytes {
		return nil, unsupported("attachment %q decodes to %d bytes, above the %d byte accessor limit",
			file.Name, len(bytesValue), d.limits.MaxEmbeddedBytes)
	}
	return &AttachmentSource{
		id: id, parent: d.src, data: bytesValue,
		rawOffset: rawOffset, rawLength: rawLength, hasRawLength: hasRawLength,
		filters: filters, name: file.Name, index: index,
	}, nil
}

// Name returns the name tree's name for the attachment.
func (s *AttachmentSource) Name() string { return s.name }

// Index returns the attachment's position in Document.EmbeddedFiles.
func (s *AttachmentSource) Index() int { return s.index }

// Bytes returns the decoded content.
func (s *AttachmentSource) Bytes() []byte { return s.data }

// Filters returns the filter chain applied, in order.
func (s *AttachmentSource) Filters() []string { return append([]string(nil), s.filters...) }

// RawOffset returns the validated offset of the stored stream body.
func (s *AttachmentSource) RawOffset() uint64 { return s.rawOffset }

// RawLength returns the stored stream length and whether the file gave a
// direct or resolvable /Length (false means the length came from endstream).
func (s *AttachmentSource) RawLength() (uint64, bool) { return s.rawLength, s.hasRawLength }

// SourceID implements source.ByteSource.
func (s *AttachmentSource) SourceID() source.ID { return s.id }

// Len implements source.ByteSource.
func (s *AttachmentSource) Len() uint64 { return uint64(len(s.data)) }

// ImageID implements source.ByteSource.
func (s *AttachmentSource) ImageID() source.ImageID { return s.parent.ImageID() }

// SectorSize implements source.ByteSource.
func (s *AttachmentSource) SectorSize() uint32 { return s.parent.SectorSize() }

// IsEmpty implements source.ByteSource.
func (s *AttachmentSource) IsEmpty() bool { return len(s.data) == 0 }

// Stats implements source.ByteSource.
func (s *AttachmentSource) Stats() source.Stats { return s.counters.Snapshot() }

// ReadAt implements source.ByteSource over the decoded bytes.
func (s *AttachmentSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= uint64(len(s.data)) {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), uint64(len(s.data)))
	}
	n := copy(buf, s.data[offset:])
	s.counters.AddRead(n)
	return n, nil
}

// ReadAtLossy implements source.ByteSource; every decoded byte is present, so
// it is the same as ReadAt.
func (s *AttachmentSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	return s.ReadAt(offset, buf)
}

// ExtentsInto reports the decoded range as derived from this source.
func (s *AttachmentSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > uint64(len(s.data)) || length > uint64(len(s.data))-offset {
		return out, source.NewOutOfRange(offset, length, uint64(len(s.data)))
	}
	if length > 0 {
		out = append(out, source.ParentRange{Parent: s.id, ParentOffset: 0, Len: length, Kind: source.RangeDerived})
	}
	return out, nil
}

// Extents implements source.ByteSource.
func (s *AttachmentSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

// MapToImage maps a decoded range to the stored stream's start. The kind is
// RangeDerived because the mapping is not positional.
func (s *AttachmentSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	if offset > uint64(len(s.data)) || length > uint64(len(s.data))-offset {
		return nil, source.NewOutOfRange(offset, length, uint64(len(s.data)))
	}
	if length == 0 {
		return nil, nil
	}
	return []source.ImageRange{{
		ImageID: s.parent.ImageID(), ImageOffset: s.rawOffset, Len: length, Kind: source.RangeDerived,
	}}, nil
}

var _ source.ByteSource = (*AttachmentSource)(nil)
