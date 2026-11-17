package iso9660

import (
	"encoding/binary"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// maxPathTableBytes bounds a declared path table.
const maxPathTableBytes = 16 * 1024 * 1024

// PathTableRecord is one directory in the path table.
type PathTableRecord struct {
	Number     uint32
	Parent     uint32
	Depth      uint32
	Extent     uint32
	ExtAttrLen uint8
	Identifier []byte
}

// Name returns the identifier as text, with "\0" standing for the root.
func (r *PathTableRecord) Name() string {
	if len(r.Identifier) == 1 && r.Identifier[0] == 0 {
		return "/"
	}
	return latin1String(r.Identifier)
}

// Disagreement is one field on which the two encodings disagree.
type Disagreement struct {
	Number uint32
	Field  string
}

// PathTable is one image's path tables as read from the primary descriptor.
type PathTable struct {
	size           uint32
	records        []PathTableRecord
	bigEndianError error
	disagreements  []Disagreement
}

// Records returns every record in table order.
func (t *PathTable) Records() []PathTableRecord { return t.records }

// Size returns the bytes the descriptor declares for the table.
func (t *PathTable) Size() uint32 { return t.size }

// BigEndianError reports why the big-endian copy could not be compared.
func (t *PathTable) BigEndianError() error { return t.bigEndianError }

// Disagreements returns fields the two encodings disagree on.
func (t *PathTable) Disagreements() []Disagreement { return t.disagreements }

// readPathTable reads the tables the descriptor names. A descriptor with a
// zero size names none and returns (nil, nil).
func readPathTable(src source.ByteSource, descriptor *VolumeDescriptor) (*PathTable, error) {
	size := descriptor.PathTableSize
	if size == 0 {
		return nil, nil
	}
	if descriptor.PathTableL == 0 {
		return nil, corruptf("the descriptor declares a %d-byte path table but names no little-endian location", size)
	}
	if size > maxPathTableBytes {
		return nil, corruptf("the path table claims %d bytes, more than %d", size, maxPathTableBytes)
	}
	if size%2 != 0 {
		return nil, corruptf("the path table length %d is odd; every record is an even number of bytes", size)
	}

	blockSize := uint64(descriptor.BlockSize)
	littleOffset := uint64(descriptor.PathTableL) * blockSize
	if littleOffset > src.Len() || uint64(size) > src.Len()-littleOffset {
		return nil, corruptf("the little-endian path table at byte %d runs past the %d bytes in the source",
			littleOffset, src.Len())
	}
	raw := make([]byte, int(size))
	if err := source.ReadExactAt(src, littleOffset, raw); err != nil {
		return nil, err
	}
	records, err := parsePathTable(raw, false)
	if err != nil {
		return nil, err
	}

	var bigEndianError error
	var disagreements []Disagreement
	if descriptor.PathTableM == 0 {
		bigEndianError = fmt.Errorf("the descriptor names no big-endian table")
	} else {
		bigOffset := uint64(descriptor.PathTableM) * blockSize
		if bigOffset > src.Len() || uint64(size) > src.Len()-bigOffset {
			bigEndianError = fmt.Errorf("the big-endian path table at byte %d runs past the %d bytes in the source",
				bigOffset, src.Len())
		} else {
			bigBytes := make([]byte, int(size))
			if err := source.ReadExactAt(src, bigOffset, bigBytes); err != nil {
				bigEndianError = err
			} else {
				bigRecords, err := parsePathTable(bigBytes, true)
				if err != nil {
					bigEndianError = err
				} else {
					disagreements = comparePathTables(records, bigRecords)
				}
			}
		}
	}
	return &PathTable{
		size:           size,
		records:        records,
		bigEndianError: bigEndianError,
		disagreements:  disagreements,
	}, nil
}

// parsePathTable parses one table. bigEndian selects the field order.
func parsePathTable(bytes []byte, bigEndian bool) ([]PathTableRecord, error) {
	var records []PathTableRecord
	at := 0
	for at < len(bytes) {
		if bytes[at] == 0 {
			allZero := true
			for _, b := range bytes[at:] {
				if b != 0 {
					allZero = false
					break
				}
			}
			if allZero {
				break
			}
			nonZero := 0
			for _, b := range bytes[at:] {
				if b != 0 {
					nonZero++
				}
			}
			return nil, corruptf("path table byte %d is zero, but %d non-zero byte(s) follow it", at, nonZero)
		}
		length := int(bytes[at])
		recordLen := 8 + length + length%2
		end := at + recordLen
		if end > len(bytes) {
			return nil, corruptf("path table record at byte %d needs %d bytes, past the %d-byte table",
				at, recordLen, len(bytes))
		}
		number := uint32(len(records) + 1)
		extAttrLen := bytes[at+1]
		extent := pathExtent(bytes[at+2:at+6], bigEndian)
		parent := pathParent(bytes[at+6:at+8], bigEndian)
		identifier := append([]byte(nil), bytes[at+8:at+8+length]...)

		if number == 1 {
			if !(len(identifier) == 1 && identifier[0] == 0) {
				return nil, corruptf("path table record 1 is not the root: its identifier is %X", identifier)
			}
			if parent != 1 {
				return nil, corruptf("the path table root names parent %d, not itself", parent)
			}
		} else {
			if len(identifier) == 1 && identifier[0] == 0 {
				return nil, corruptf("path table record %d repeats the root's identifier", number)
			}
			for position, b := range identifier {
				if b == 0 {
					return nil, corruptf("path table record %d has a zero byte at identifier position %d", number, position)
				}
			}
			if parent == 0 || parent >= number {
				return nil, corruptf("path table record %d names parent %d, which is not an earlier record", number, parent)
			}
		}
		var depth uint32
		if number != 1 {
			depth = records[parent-1].Depth + 1
		}
		records = append(records, PathTableRecord{
			Number:     number,
			Parent:     parent,
			Depth:      depth,
			Extent:     extent,
			ExtAttrLen: extAttrLen,
			Identifier: identifier,
		})
		at = end
	}
	if len(records) == 0 {
		return nil, corruptf("the path table holds no records")
	}
	return records, nil
}

func comparePathTables(little, big []PathTableRecord) []Disagreement {
	var disagreements []Disagreement
	if len(little) != len(big) {
		disagreements = append(disagreements, Disagreement{Number: 0, Field: "record count"})
	}
	for i := 0; i < len(little) && i < len(big); i++ {
		left, right := little[i], big[i]
		checks := []struct {
			field   string
			differs bool
		}{
			{"extent", left.Extent != right.Extent},
			{"parent", left.Parent != right.Parent},
			{"extended attribute length", left.ExtAttrLen != right.ExtAttrLen},
			{"identifier", string(left.Identifier) != string(right.Identifier)},
		}
		for _, check := range checks {
			if check.differs {
				disagreements = append(disagreements, Disagreement{Number: left.Number, Field: check.field})
			}
		}
	}
	return disagreements
}

func pathExtent(bytes []byte, bigEndian bool) uint32 {
	if bigEndian {
		return binary.BigEndian.Uint32(bytes)
	}
	return binary.LittleEndian.Uint32(bytes)
}

func pathParent(bytes []byte, bigEndian bool) uint32 {
	if bigEndian {
		return uint32(binary.BigEndian.Uint16(bytes))
	}
	return uint32(binary.LittleEndian.Uint16(bytes))
}
