package zfs

import "fmt"

// blockPointerSize is the 128-byte on-disk block pointer (SPA_BLKPTRSHIFT 7).
const blockPointerSize = 128

// minBlockShift is the 512-byte unit every non-embedded size counts in.
const minBlockShift = 9

// embeddedPayloadSize is the bytes of payload an embedded pointer carries:
// the property word and the logical-birth word are not payload.
const embeddedPayloadSize = 112

// Dva is one of the three device-virtual addresses a pointer may carry.
type Dva struct {
	word0 uint64
	word1 uint64
}

func parseDva(word0, word1 uint64) Dva { return Dva{word0: word0, word1: word1} }

// asize is the allocated size in bytes, including RAID-Z parity.
func (d Dva) asize() uint64 { return (d.word0 & ((1 << 24) - 1)) << minBlockShift }

// vdev is the leaf vdev id the DVA names.
func (d Dva) vdev() uint64 { return (d.word0 >> 32) & ((1 << 24) - 1) }

// offset is the byte offset inside the leaf's allocatable area.
func (d Dva) offset() uint64 { return (d.word1 & ((1 << 63) - 1)) << minBlockShift }

// gang reports whether the DVA points at a gang block.
func (d Dva) gang() bool { return d.word1>>63 != 0 }

func (d Dva) isEmpty() bool { return d.word0 == 0 && d.word1 == 0 }

// Compression is the algorithm a block pointer names.
type Compression uint8

const (
	CompressionInherit Compression = iota
	CompressionOn
	CompressionOff
	CompressionLZJB
	CompressionEmpty
	// CompressionGzip is the base of the gzip levels; the on-disk ids 5..13
	// carry the level and are stored as this base plus level-1.
	CompressionGzip
	CompressionGzipLast = CompressionGzip + 8
	CompressionZLE      = 14
	CompressionLZ4      = 15
	CompressionZstd     = 16
	CompressionOther    = 255
)

func compressionFromID(id byte) Compression {
	switch {
	case id == 0:
		return CompressionInherit
	case id == 1:
		return CompressionOn
	case id == 2:
		return CompressionOff
	case id == 3:
		return CompressionLZJB
	case id == 4:
		return CompressionEmpty
	case id >= 5 && id <= 13:
		return CompressionGzip + Compression(id-5)
	case id == 14:
		return CompressionZLE
	case id == 15:
		return CompressionLZ4
	case id == 16:
		return CompressionZstd
	default:
		return CompressionOther
	}
}

func (c Compression) label() string {
	switch {
	case c == CompressionInherit:
		return "inherit"
	case c == CompressionOn:
		return "on"
	case c == CompressionOff:
		return "off"
	case c == CompressionLZJB:
		return "lzjb"
	case c == CompressionEmpty:
		return "empty"
	case c >= CompressionGzip && c <= CompressionGzipLast:
		return "gzip"
	case c == CompressionZLE:
		return "zle"
	case c == CompressionLZ4:
		return "lz4"
	case c == CompressionZstd:
		return "zstd"
	default:
		return "other"
	}
}

func (c Compression) isGzip() bool { return c >= CompressionGzip && c <= CompressionGzipLast }

// BlockPointer is a 128-byte description of one block: up to three DVAs, the
// sizes, the compression and checksum algorithms, the object type and the
// four checksum words.
type BlockPointer struct {
	words [16]uint64
}

func parseBlockPointer(bytes []byte) (BlockPointer, error) {
	if len(bytes) < blockPointerSize {
		return BlockPointer{}, corruptf("a block pointer is %d bytes, not %d", len(bytes), blockPointerSize)
	}
	var pointer BlockPointer
	for i := range pointer.words {
		pointer.words[i] = leUint64(bytes[i*8 : i*8+8])
	}
	return pointer, nil
}

func (b BlockPointer) prop() uint64 { return b.words[6] }

func (b BlockPointer) dva(index int) (Dva, bool) {
	if index < 0 || index >= 3 {
		return Dva{}, false
	}
	return parseDva(b.words[index*2], b.words[index*2+1]), true
}

func (b BlockPointer) embedded() bool { return (b.prop()>>39)&1 != 0 }

// byteOrderBit reports the on-disk byte-order flag. It is informational: this
// reader always reads the little-endian layout, and a big-endian pool's blocks
// fail their checksum rather than being quietly misread.
func (b BlockPointer) byteOrderBit() bool { return b.prop()>>63 != 0 }

func (b BlockPointer) dedup() bool { return (b.prop()>>62)&1 != 0 }

// crypt reports the encryption/authentication bit. The block reader refuses
// such a pointer because no key is available.
func (b BlockPointer) crypt() bool { return (b.prop()>>61)&1 != 0 }

func (b BlockPointer) level() uint8 { return uint8((b.prop() >> 56) & 0x1f) }

func (b BlockPointer) objectType() uint8 { return uint8((b.prop() >> 48) & 0xff) }

// checksumID is the raw algorithm id as the pointer stores it.
func (b BlockPointer) checksumID() byte { return byte((b.prop() >> 40) & 0xff) }

func (b BlockPointer) checksum() Checksum {
	if b.embedded() {
		return ChecksumOff
	}
	return checksumFromID(b.checksumID())
}

// compressionID is the raw algorithm id; bit 39 is the embedded flag, so the
// field is masked to seven bits.
func (b BlockPointer) compressionID() byte { return byte((b.prop() >> 32) & 0x7f) }

func (b BlockPointer) compression() Compression {
	return compressionFromID(b.compressionID())
}

// lsize is the logical size in bytes. The stored field is a sector count minus
// one (OpenZFS's BF64_GET_SB bias), and an embedded payload carries a byte
// count minus one.
func (b BlockPointer) lsize() uint64 {
	if b.embedded() {
		return (b.prop() & ((1 << 25) - 1)) + 1
	}
	return ((b.prop() & 0xffff) + 1) << minBlockShift
}

// psize is the stored (compressed) size in bytes, likewise biased.
func (b BlockPointer) psize() uint64 {
	if b.embedded() {
		return ((b.prop() >> 25) & 0x7f) + 1
	}
	return (((b.prop() >> 16) & 0xffff) + 1) << minBlockShift
}

// physicalBirth is the transaction group the block was written at; zero means
// "same as logical".
func (b BlockPointer) physicalBirth() uint64 {
	if b.embedded() {
		return 0
	}
	if b.words[9] != 0 {
		return b.words[9]
	}
	return b.words[10]
}

func (b BlockPointer) logicalBirth() uint64 { return b.words[10] }

func (b BlockPointer) fill() uint64 {
	if b.embedded() {
		return 1
	}
	return b.words[11]
}

// checksumBytes is the stored 32-byte checksum.
func (b BlockPointer) checksumBytes() []byte {
	out := make([]byte, 32)
	for i := 0; i < 4; i++ {
		putLEUint64(out[i*8:], b.words[12+i])
	}
	return out
}

func (b BlockPointer) raw() [blockPointerSize]byte {
	var out [blockPointerSize]byte
	for i, word := range b.words {
		putLEUint64(out[i*8:], word)
	}
	return out
}

// embeddedPayload returns the 112 payload bytes, still compressed. The payload
// skips the property word (bytes 48..56) and the logical-birth word (80..88).
func (b BlockPointer) embeddedPayload() ([]byte, error) {
	if !b.embedded() {
		return nil, corruptf("a block pointer without embedded data")
	}
	if b.psize() > embeddedPayloadSize {
		return nil, corruptf("an embedded pointer claims %d stored bytes; the payload area is %d",
			b.psize(), embeddedPayloadSize)
	}
	raw := b.raw()
	payload := make([]byte, 0, embeddedPayloadSize)
	payload = append(payload, raw[0:48]...)
	payload = append(payload, raw[56:80]...)
	payload = append(payload, raw[88:128]...)
	return payload[:b.psize()], nil
}

// isHole reports a pointer that names no location; reading it yields zeroes.
func (b BlockPointer) isHole() bool {
	if b.embedded() {
		return false
	}
	dva, ok := b.dva(0)
	return !ok || dva.isEmpty()
}

func (b BlockPointer) String() string {
	return fmt.Sprintf("bp(level=%d type=%d lsize=%d psize=%d %s/%s)",
		b.level(), b.objectType(), b.lsize(), b.psize(), b.compression().label(), b.checksum().label())
}

func putLEUint64(dst []byte, value uint64) {
	dst[0] = byte(value)
	dst[1] = byte(value >> 8)
	dst[2] = byte(value >> 16)
	dst[3] = byte(value >> 24)
	dst[4] = byte(value >> 32)
	dst[5] = byte(value >> 40)
	dst[6] = byte(value >> 48)
	dst[7] = byte(value >> 56)
}
