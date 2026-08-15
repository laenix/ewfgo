package ewf

import "fmt"

// CaseNumber returns the case number from the EWF metadata.
func (e *EWFImage) CaseNumber() string {
	for _, h := range e.ewf.Headers {
		return h.L3_c
	}
	return ""
}

// EvidenceNumber returns the evidence number from the EWF metadata.
func (e *EWFImage) EvidenceNumber() string {
	for _, h := range e.ewf.Headers {
		return h.L3_n
	}
	return ""
}

// Examiner returns the examiner name from the EWF metadata.
func (e *EWFImage) Examiner() string {
	for _, h := range e.ewf.Headers {
		return h.L3_e
	}
	return ""
}

// TotalSectors returns the total number of sectors in the image.
func (e *EWFImage) TotalSectors() uint64 {
	for _, v := range e.ewf.DiskSMART {
		return v.SectorsCount
	}
	return 0
}

// SectorSize returns the size of each sector in bytes (usually 512).
func (e *EWFImage) SectorSize() uint32 {
	for _, v := range e.ewf.DiskSMART {
		return v.SectorBytes
	}
	return 512
}

// GetDiskInfo returns the disk information from the EWF metadata.
func (e *EWFImage) GetDiskInfo() *DiskInfo {
	for _, v := range e.ewf.DiskSMART {
		return &DiskInfo{
			MediaType:        v.MediaType,
			TotalSectors:     v.SectorsCount,
			SectorBytes:      v.SectorBytes,
			CHS:              fmt.Sprintf("%d/%d/%d", v.CHScylinders, v.CHSheads, v.CHSsectors),
			CompressionLevel: v.CompressionLevel,
			SegmentFileSetID: fmt.Sprintf("%x", v.SegmentFileSetIdentifier),
		}
	}
	return nil
}

// DiskInfo contains disk metadata from the EWF image.
type DiskInfo struct {
	MediaType        byte
	TotalSectors     uint64
	SectorBytes      uint32
	CHS              string
	CompressionLevel byte
	SegmentFileSetID string
}
