package internal

import (
	"fmt"
	"io"
)

// SegmentSource is one EWF segment held in a reader rather than a host file.
// It is used when an E01 is embedded in another container (a ZIP member, a
// carved range, a decoded stream) and no file path exists.
type SegmentSource struct {
	Name   string
	Reader io.ReaderAt
	Size   int64
}

// NewSegmentImage builds an EWF image over already-open segment readers. The
// caller is responsible for calling ReadSections and ParseSections before any
// sector read, exactly as Open's callers do.
func NewSegmentImage(sources []SegmentSource) (*EWFImage, error) {
	if len(sources) == 0 {
		return nil, fmt.Errorf("an EWF image needs at least one segment")
	}
	image := &EWFImage{chunkCache: newChunkCache(chunkCacheMaxBytes)}
	var start int64
	for index, segment := range sources {
		if segment.Reader == nil {
			return nil, fmt.Errorf("EWF segment %d has no reader", index+1)
		}
		if segment.Size < 0 {
			return nil, fmt.Errorf("EWF segment %d has a negative size", index+1)
		}
		image.segments = append(image.segments, &SegmentFile{
			filepath: segment.Name,
			reader:   segment.Reader,
			size:     segment.Size,
			start:    start,
		})
		start += segment.Size
	}
	if len(image.segments) > 0 {
		image.filepath = image.segments[0].filepath
	}
	return image, nil
}
