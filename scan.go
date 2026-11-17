package forensic

import (
	"context"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/partition"
)

// ScanOptions configures a signature scan.
type ScanOptions = partition.ScanOptions

// ScanReport is the result of a signature scan.
type ScanReport = partition.ScanReport

// ScanCandidate is one volume-like structure found by a scan.
type ScanCandidate = partition.Candidate

// ScanCandidateStatus says how far a candidate's own metadata can be trusted.
type ScanCandidateStatus = partition.CandidateStatus

const (
	ScanVerified   = partition.CandidateStatusVerified
	ScanUnverified = partition.CandidateStatusUnverified
	ScanRejected   = partition.CandidateStatusRejected
)

// DefaultScanOptions returns the signature scan defaults.
func DefaultScanOptions() ScanOptions { return partition.DefaultScanOptions() }

// Scan searches a byte source for partition tables, boot sectors and
// filesystem superblocks, confirming each candidate's own metadata (and
// checksum where the format has one). It is the recovery path for a damaged or
// overwritten partition table.
func Scan(src ByteSource, options ScanOptions) (*ScanReport, error) {
	if src == nil {
		return nil, fmt.Errorf("%w: nil scan source", ErrInvalidArgument)
	}
	return partition.Scan(src, options)
}

// Scan searches this image's decoded media.
func (i *Image) Scan(ctx context.Context, options ScanOptions) (*ScanReport, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	return Scan(i.source, options)
}

// Scan searches this partition-relative byte range.
func (p *Partition) Scan(ctx context.Context, options ScanOptions) (*ScanReport, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	return Scan(p.src, options)
}

// Scan searches this assembled volume.
func (v *Volume) Scan(ctx context.Context, options ScanOptions) (*ScanReport, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if v.src == nil {
		return nil, fmt.Errorf("%w: volume %s cannot be assembled: %s", ErrUnsupported, v.name, v.issue)
	}
	return Scan(v.src, options)
}
