package ewf

import (
	"fmt"

	"github.com/laenix/ewfgo/internal"
	"github.com/laenix/ewfgo/internal/data/source"
)

// Info is the acquisition metadata parsed from an E01 image. Every field is
// copied from a real section; absent metadata stays empty rather than being
// invented.
type Info struct {
	Path string

	CaseNumber      string
	EvidenceNumber  string
	Examiner        string
	Description     string
	Notes           string
	Platform        string
	AcquisitionDate string
	SystemDate      string

	MediaModel   string
	SerialNumber string
	DeviceLabel  string

	SectorSize       uint32
	TotalSectors     uint64
	ChunkSectors     uint32
	CompressionLevel uint8

	// StoredMD5/StoredSHA1 are the acquisition hashes from the image's
	// "hash"/"digest" sections; nil when the image carries none.
	StoredMD5  []byte
	StoredSHA1 []byte
}

type imageReader struct {
	image *internal.EWFImage
}

func (r imageReader) TotalSectors() uint64 {
	if len(r.image.DiskSMART) > 0 {
		return r.image.DiskSMART[0].SectorsCount
	}
	return 0
}

func (r imageReader) SectorSize() uint32 {
	if len(r.image.DiskSMART) > 0 && r.image.DiskSMART[0].SectorBytes > 0 {
		return r.image.DiskSMART[0].SectorBytes
	}
	return 512
}

func (r imageReader) ReadSectors(lba, count uint64) ([]byte, error) {
	return r.image.ReadSectorData(lba, count)
}

// OpenFile opens an EWF/E01 image (discovering sibling E02, E03, ... segments),
// parses its sections, and returns its media as a ByteSource together with the
// acquisition metadata. Every read served by the source is exact decompressed
// media data or an explicit error; EWF container bytes are never exposed.
func OpenFile(id source.ID, imageID source.ImageID, path string) (*EWFSource, *Info, error) {
	image := &internal.EWFImage{}
	if _, err := image.Open(path); err != nil {
		return nil, nil, fmt.Errorf("open EWF %s: %w", path, err)
	}
	if err := image.ReadSections(); err != nil {
		image.Close()
		return nil, nil, fmt.Errorf("read EWF sections: %w", err)
	}
	if err := image.ParseSections(); err != nil {
		image.Close()
		return nil, nil, fmt.Errorf("parse EWF sections: %w", err)
	}

	reader := imageReader{image: image}
	src := NewEWFSource(id, imageID, reader)
	src.closer = image
	src.path = path
	src.totalSectors = reader.TotalSectors()
	src.info = buildInfo(path, image)
	return src, src.info, nil
}

func buildInfo(path string, image *internal.EWFImage) *Info {
	info := &Info{
		Path:       path,
		StoredMD5:  image.StoredMD5,
		StoredSHA1: image.StoredSHA1,
	}
	if len(image.Headers) > 0 {
		h := image.Headers[0]
		info.CaseNumber = h.L3_c
		info.EvidenceNumber = h.L3_n
		info.Examiner = h.L3_e
		info.Description = h.L3_a
		info.Notes = h.L3_t
		info.Platform = h.L3_ov
		info.AcquisitionDate = h.L3_m
		info.SystemDate = h.L3_u
		info.MediaModel = h.L3_md
		info.SerialNumber = h.L3_sn
		info.DeviceLabel = h.L3_l
	}
	if len(image.DiskSMART) > 0 {
		d := image.DiskSMART[0]
		info.SectorSize = d.SectorBytes
		info.TotalSectors = d.SectorsCount
		info.ChunkSectors = d.ChunkSectors
		info.CompressionLevel = d.CompressionLevel
	}
	if info.SectorSize == 0 {
		info.SectorSize = 512
	}
	return info
}

// OpenSources parses an EWF image whose segments are byte sources (for example
// entries inside an archive) rather than host files. Multi-segment images are
// supported when every segment source is supplied in order. The caller keeps
// ownership of the sources; the returned EWFSource does not close them.
func OpenSources(id source.ID, imageID source.ImageID, segments []source.ByteSource) (*EWFSource, *Info, error) {
	if len(segments) == 0 {
		return nil, nil, fmt.Errorf("open EWF: no segment sources")
	}
	converted := make([]internal.SegmentSource, 0, len(segments))
	for index, segment := range segments {
		if segment == nil {
			return nil, nil, fmt.Errorf("open EWF: segment %d is nil", index+1)
		}
		if segment.Len() > uint64(^uint64(0)>>1) {
			return nil, nil, fmt.Errorf("open EWF: segment %d is too large", index+1)
		}
		converted = append(converted, internal.SegmentSource{
			Name:   fmt.Sprintf("segment-%d", index+1),
			Reader: source.ReaderAt(segment),
			Size:   int64(segment.Len()),
		})
	}
	image, err := internal.NewSegmentImage(converted)
	if err != nil {
		return nil, nil, err
	}
	if err := image.ReadSections(); err != nil {
		return nil, nil, fmt.Errorf("read EWF sections: %w", err)
	}
	if err := image.ParseSections(); err != nil {
		return nil, nil, fmt.Errorf("parse EWF sections: %w", err)
	}
	reader := imageReader{image: image}
	src := NewEWFSource(id, imageID, reader)
	src.totalSectors = reader.TotalSectors()
	src.info = buildInfo("", image)
	return src, src.info, nil
}
