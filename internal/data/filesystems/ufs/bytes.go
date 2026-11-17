package ufs

import "encoding/binary"

// Endian is the byte order a volume is stored in. UFS writers may use either
// order; the magic word is read both ways at each superblock offset to decide.
type Endian uint8

const (
	// LittleEndian is the byte order of the formats this reader was first
	// tested against.
	LittleEndian Endian = iota
	// BigEndian is the byte order of historical and cross-built volumes.
	BigEndian
)

// U16 decodes a 16-bit field. The caller has already bounded the buffer.
func (e Endian) U16(bytes []byte, at int) uint16 {
	if e == BigEndian {
		return binary.BigEndian.Uint16(bytes[at:])
	}
	return binary.LittleEndian.Uint16(bytes[at:])
}

// U32 decodes a 32-bit field.
func (e Endian) U32(bytes []byte, at int) uint32 {
	if e == BigEndian {
		return binary.BigEndian.Uint32(bytes[at:])
	}
	return binary.LittleEndian.Uint32(bytes[at:])
}

// I32 decodes a signed 32-bit field.
func (e Endian) I32(bytes []byte, at int) int32 { return int32(e.U32(bytes, at)) }

// U64 decodes a 64-bit field.
func (e Endian) U64(bytes []byte, at int) uint64 {
	if e == BigEndian {
		return binary.BigEndian.Uint64(bytes[at:])
	}
	return binary.LittleEndian.Uint64(bytes[at:])
}

// I64 decodes a signed 64-bit field.
func (e Endian) I64(bytes []byte, at int) int64 { return int64(e.U64(bytes, at)) }
