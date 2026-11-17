package forensic

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/laenix/ewfgo/internal/data/containers/certstore"
	"github.com/laenix/ewfgo/internal/data/source"
)

// CertificateStore is a decoded serialized Windows certificate store. DER
// certificate blobs are exposed as source-backed byte ranges; X.509 fields are
// not parsed here.
type CertificateStore struct {
	path   string
	store  *certstore.Store
	closer io.Closer

	nextID atomic.Uint64
}

// CertificateStoreInfo summarizes a store.
type CertificateStoreInfo struct {
	Records       int
	Certificates  int
	Names         int
	Opaque        int
	Terminated    bool
	TrailingBytes uint64
	Capped        bool
	Warnings      []string
}

// CertificateInfo describes one stored DER certificate.
type CertificateInfo struct {
	Index int
	Len   uint64
	SHA1  string
	// SHA256 is the lower-case hex digest.
	SHA256 string
	// StoredSHA1Matches/StoredSHA256Matches report the most recent stored
	// digest record, when one was seen.
	StoredSHA1Matches   *bool
	StoredSHA256Matches *bool
}

// OpenCertificateStore opens a serialized certificate store.
func OpenCertificateStore(ctx context.Context, imagePath string, opts Options) (*CertificateStore, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw, err := source.OpenRawFileWithSectorSize(imagePath, 1, 1, opts.sectorSize(nil, 512))
	if err != nil {
		return nil, fmt.Errorf("open certificate store %s: %w", imagePath, err)
	}
	store, err := OpenCertificateStoreSource(ctx, raw, opts)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("parse certificate store %s: %w", imagePath, err)
	}
	store.path = imagePath
	store.closer = raw
	return store, nil
}

// OpenCertificateStoreSource opens a serialized certificate store over an
// existing byte source. The source is not closed by CertificateStore.Close.
func OpenCertificateStoreSource(ctx context.Context, src ByteSource, opts Options) (*CertificateStore, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, fmt.Errorf("%w: nil certificate store source", ErrInvalidArgument)
	}
	limits := certstore.DefaultLimits()
	if opts.Limits.MaxFileBytes != 0 && opts.Limits.MaxFileBytes < limits.MaxBytes {
		limits.MaxBytes = opts.Limits.MaxFileBytes
	}
	store, err := certstore.Open(src, limits)
	if err != nil {
		return nil, err
	}
	return &CertificateStore{store: store}, nil
}

// Path returns the store path.
func (s *CertificateStore) Path() string { return s.path }

// Info returns the store summary.
func (s *CertificateStore) Info() CertificateStoreInfo {
	return CertificateStoreInfo{
		Records:       s.store.Records,
		Certificates:  len(s.store.Certificates),
		Names:         len(s.store.Names),
		Opaque:        len(s.store.Opaque),
		Terminated:    s.store.Terminated,
		TrailingBytes: s.store.TrailingBytes,
		Capped:        s.store.Capped,
		Warnings:      append([]string(nil), s.store.Warnings...),
	}
}

// Certificates returns the stored DER certificates' metadata.
func (s *CertificateStore) Certificates(ctx context.Context) ([]CertificateInfo, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	out := make([]CertificateInfo, 0, len(s.store.Certificates))
	for index := range s.store.Certificates {
		certificate := &s.store.Certificates[index]
		out = append(out, CertificateInfo{
			Index: index, Len: certificate.Len,
			SHA1: certificate.SHA1, SHA256: certificate.SHA256,
			StoredSHA1Matches:   certificate.StoredSHA1Matches,
			StoredSHA256Matches: certificate.StoredSHA256Matches,
		})
	}
	return out, nil
}

// Names returns the friendly names the store records.
func (s *CertificateStore) Names(ctx context.Context) ([]string, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	return append([]string(nil), s.store.Names...), nil
}

// OpenCertificate opens one DER certificate blob as a byte source.
func (s *CertificateStore) OpenCertificate(ctx context.Context, index int) (ByteSource, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	id := source.ID(s.nextID.Add(1) + 1_000_000)
	blob, err := s.store.CertificateSource(index, id)
	if err != nil {
		return nil, err
	}
	return blob, nil
}

// Close releases the store file.
func (s *CertificateStore) Close() error {
	if s.closer == nil {
		return nil
	}
	err := s.closer.Close()
	s.closer = nil
	return err
}
