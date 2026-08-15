package ewf

import (
	"fmt"

	"github.com/laenix/ewfgo/internal"
)

// Open opens an EWF image file and parses its metadata.
// It supports E01 format and automatically handles multi-volume files if present.
//
// Example:
//
//	img, err := ewf.Open("/path/to/disk.E01")
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer img.Close()
//
//	// Read metadata
//	fmt.Printf("Case: %s\n", img.CaseNumber())
//	fmt.Printf("Evidence: %s\n", img.EvidenceNumber())
//
//	// Scan filesystems
//	parts, _ := img.ScanFileSystems()
//	for _, p := range parts {
//		fmt.Printf("Partition %d: %s (%.2f GB)\n", p.Index, p.TypeName, float64(p.SizeBytes)/1024/1024/1024)
//	}
func Open(filepath string) (*EWFImage, error) {
	e := &internal.EWFImage{}
	_, err := e.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open EWF file: %w", err)
	}

	// Read and parse all sections. The per-segment section walk must fail
	// loudly: an unparseable sibling segment (or a broken chain) must make
	// Open return an error — never be dropped here so the image silently reads
	// with missing/zero-filled segment data.
	if err := e.ReadSections(); err != nil {
		e.Close()
		return nil, fmt.Errorf("failed to read sections: %w", err)
	}
	if err := e.ParseSections(); err != nil {
		// e.file is still open here (opened by e.Open above); close it so a
		// rejected image does not hold a lock on the file on Windows.
		e.Close()
		return nil, fmt.Errorf("failed to parse sections: %w", err)
	}

	// Create wrapper with exported methods
	return &EWFImage{
		ewf: e,
	}, nil
}

// EWFImage wraps the internal EWFImage and provides exported methods.
type EWFImage struct {
	ewf *internal.EWFImage
}

// Close closes the EWF image file.
func (e *EWFImage) Close() error {
	if e.ewf != nil {
		return e.ewf.Close()
	}
	return nil
}

// IsEWF checks if the given file is a valid EWF image.
func IsEWF(filepath string) bool {
	e := &internal.EWFImage{}
	defer e.Close()
	_, err := e.Open(filepath)
	return err == nil
}
