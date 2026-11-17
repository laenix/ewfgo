// Package hfsplus is a read-only reader for Apple HFS+ and HFSX volumes.
//
// It is a Go port of forensic-core's data::filesystems::hfsplus module.  A
// volume is opened from a source.ByteSource, its three B-trees (catalog,
// extents overflow, attributes) are parsed, and files are exposed as byte
// sources with the same read-only contract as every other data-layer adapter.
//
// On-disk layout (TN1150):
//
//	volume header (H+/HX, byte 1024)          header.go
//	  -> extents overflow B-tree              btree.go + fork.go
//	    -> catalog B-tree (names, records)    catalog.go
//	      -> data / resource fork byte source file.go
//
// Feature notes are recorded at the functions that implement them.  Branches
// this port does not implement are refused with ErrUnsupported naming the
// feature rather than fabricated.
package hfsplus

import (
	"encoding/binary"
	"unicode/utf16"
)

func be16(b []byte, off int) uint16 { return binary.BigEndian.Uint16(b[off:]) }
func be32(b []byte, off int) uint32 { return binary.BigEndian.Uint32(b[off:]) }
func be64(b []byte, off int) uint64 { return binary.BigEndian.Uint64(b[off:]) }

// decodeUnits renders UTF-16 code units, replacing unpaired surrogates with
// U+FFFD so a damaged name still appears in a listing.
func decodeUnits(units []uint16) string {
	return string(utf16.Decode(units))
}

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
