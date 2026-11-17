package sysv

import (
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/laenix/ewfgo/internal/data/source"
)

func utoa(value uint32) string { return strconv.FormatUint(uint64(value), 10) }

func utoa64(value uint64) string { return strconv.FormatUint(value, 10) }

func utoaHex(value uint32) string { return fmt.Sprintf("0x%x", value) }

const (
	// superblockOffset is the half-block where System V R2/R4 and Coherent
	// keep their superblock.
	superblockOffset = uint64(512)
	// xenixSuperblockOffset is where Xenix keeps its 1024-byte superblock.
	xenixSuperblockOffset = uint64(1024)

	// On-disk magics.
	xenixMagic = 0x002B5544
	sysvMagic  = 0xFD187E20

	// Unix seconds before this select System V Release 2.
	jan11980 = 3652 * 24 * 60 * 60

	// Clean-state markers.
	sysv4CleanBase = 0x7C269D38
	sysv2Clean     = 0xCB096F43

	// afsMarker is the s_nfree value SCO AFS uses.
	afsMarker = 0xFFFF

	firstInodeZone = uint32(2)
	rootInode      = uint32(2)

	// inodeSize is the on-disk inode record size in every verified variant.
	inodeSize = 32 + 32

	// directoryEntrySize and nameLength are fixed in every verified variant.
	directoryEntrySize = 16
	nameLength         = 14

	xenixNICFREE    = 100
	sysvNICFREE     = 50
	coherentNICFREE = 64
	nicinod         = 100

	maxBlockSize = 2048
)

// variant is one of the four verified layouts.
type variant uint8

const (
	variantXenix variant = iota
	variantSysV2
	variantSysV4
	variantCoherent
)

func (v variant) label() string {
	switch v {
	case variantXenix:
		return "Xenix"
	case variantSysV2:
		return "System V Release 2"
	case variantSysV4:
		return "System V Release 4"
	default:
		return "Coherent"
	}
}

func (v variant) nicfree() int {
	switch v {
	case variantXenix:
		return xenixNICFREE
	case variantCoherent:
		return coherentNICFREE
	default:
		return sysvNICFREE
	}
}

// chunkEntriesOffset is where a continuation chunk's entries begin: Release 4
// has a 16-bit count followed by a 16-bit pad.
func (v variant) chunkEntriesOffset() int {
	if v == variantSysV4 {
		return 4
	}
	return 2
}

// byteOrder is how a variant stores multi-byte fields.
type byteOrder uint8

const (
	orderLittle byteOrder = iota
	orderBig
	// orderPDP is PDP-11 order: 16-bit fields little-endian, 32-bit fields
	// with their 16-bit halves swapped.
	orderPDP
)

func (o byteOrder) label() string {
	switch o {
	case orderBig:
		return "big-endian"
	case orderPDP:
		return "PDP-endian"
	default:
		return "little-endian"
	}
}

func (o byteOrder) u16(bytes []byte, at int) uint16 {
	if o == orderBig {
		return binary.BigEndian.Uint16(bytes[at:])
	}
	return binary.LittleEndian.Uint16(bytes[at:])
}

func (o byteOrder) u32(bytes []byte, at int) uint32 {
	var value uint32
	if o == orderBig {
		value = binary.BigEndian.Uint32(bytes[at:])
	} else {
		value = binary.LittleEndian.Uint32(bytes[at:])
	}
	if o == orderPDP {
		value = value<<16 | value>>16
	}
	return value
}

// ptr24 decodes one of the thirteen three-byte inode pointers. The kernel
// builds a 32-bit field from the three bytes and then applies the variant's
// 32-bit byte order.
func (o byteOrder) ptr24(bytes []byte, at int) uint32 {
	switch o {
	case orderBig:
		return uint32(bytes[at])<<16 | uint32(bytes[at+1])<<8 | uint32(bytes[at+2])
	case orderPDP:
		return uint32(bytes[at])<<16 | uint32(bytes[at+1]) | uint32(bytes[at+2])<<8
	default:
		return uint32(bytes[at]) | uint32(bytes[at+1])<<8 | uint32(bytes[at+2])<<16
	}
}

// detection is what the on-disk signature says, before geometry is validated.
type detection struct {
	variant   variant
	byteOrder byteOrder
	offset    uint64
	afs       bool
}

// superblock is one image's geometry.
type superblock struct {
	variant   variant
	byteOrder byteOrder
	magic     uint32
	hasMagic  bool

	blockSize uint32
	// isize is s_isize: the first data zone, in filesystem blocks.
	isize uint32
	// fsize is s_fsize: the declared zone count.
	fsize uint32

	nfree  uint16
	free   []uint32
	ninode uint16
	inode  []uint32

	time   uint32
	tfree  uint32
	tinode uint16

	state    uint32
	hasState bool
	sType    uint32
	hasType  bool

	fname string
	fpack string
	afs   bool
}

func (sb *superblock) inodesPerBlock() uint32 { return sb.blockSize / inodeSize }

func (sb *superblock) inodeCount() uint32 {
	return saturatingMul32(sb.isize-firstInodeZone, sb.inodesPerBlock())
}

func (sb *superblock) firstDataZone() uint32 { return sb.isize }

func (sb *superblock) zones() uint32 { return sb.fsize }

func (sb *superblock) zoneSize() uint64 { return uint64(sb.blockSize) }

func (sb *superblock) inodeOffset(number uint32) (uint64, bool) {
	if number == 0 || number > sb.inodeCount() {
		return 0, false
	}
	index := uint64(number - 1)
	return uint64(firstInodeZone)*uint64(sb.blockSize) + index*inodeSize, true
}

func (sb *superblock) isDataZone(zone uint32) bool {
	return zone >= sb.isize && zone < sb.fsize
}

func (sb *superblock) zoneOffset(zone uint32) (uint64, bool) {
	offset := uint64(zone) * uint64(sb.blockSize)
	if zone != 0 && offset/uint64(sb.blockSize) != uint64(zone) {
		return 0, false
	}
	return offset, true
}

func (sb *superblock) nicfree() int { return sb.variant.nicfree() }

func (sb *superblock) chunkEntriesOffset() int { return sb.variant.chunkEntriesOffset() }

// clean reports the recorded clean marker, when the variant defines one.
func (sb *superblock) clean() (clean, known bool) {
	if !sb.hasState {
		return false, false
	}
	switch sb.variant {
	case variantSysV4:
		return sb.state == sysv4CleanBase-sb.time, true
	case variantSysV2:
		return sb.state == sysv2Clean, true
	default:
		return false, false
	}
}

func (sb *superblock) declaredBytes() uint64 {
	return uint64(sb.fsize) * uint64(sb.blockSize)
}

func saturatingMul32(a, b uint32) uint32 {
	product := uint64(a) * uint64(b)
	if product > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(product)
}

func le16(bytes []byte, at int) uint16 { return binary.LittleEndian.Uint16(bytes[at:]) }

// Detect reports whether the source carries a System V-family superblock this
// reader understands. Detection validates only the signature: an unusable
// s_type or geometry is reported by Open with the named refusal.
func Detect(src source.ByteSource) (bool, error) {
	found, err := detectSuperblock(src)
	if err != nil {
		return false, err
	}
	return found != nil, nil
}

func detectSuperblock(src source.ByteSource) (*detection, error) {
	if src.Len() >= xenixSuperblockOffset+1024 {
		var magic [4]byte
		if err := source.ReadExactAt(src, xenixSuperblockOffset+1016, magic[:]); err != nil {
			return nil, err
		}
		little := binary.LittleEndian.Uint32(magic[:])
		big := binary.BigEndian.Uint32(magic[:])
		if little == xenixMagic || big == xenixMagic {
			order := orderLittle
			if little != xenixMagic {
				order = orderBig
			}
			return &detection{variant: variantXenix, byteOrder: order, offset: xenixSuperblockOffset}, nil
		}
	}

	if src.Len() < superblockOffset+512 {
		return nil, nil
	}
	bytes := make([]byte, 512)
	if err := source.ReadExactAt(src, superblockOffset, bytes); err != nil {
		return nil, err
	}

	order := byteOrder(0xff)
	switch {
	case le32(bytes, 504) == sysvMagic:
		order = orderLittle
	case binary.BigEndian.Uint32(bytes[504:]) == sysvMagic:
		order = orderBig
	}
	if order != byteOrder(0xff) {
		// The driver checks AFS first, then the update time, both at their
		// Release 4 offsets even when the image is Release 2.
		afs := order.u16(bytes, 8) == afsMarker
		update := order.u32(bytes, 420)
		found := variantSysV4
		if !afs && update < jan11980 {
			found = variantSysV2
		}
		return &detection{variant: found, byteOrder: order, offset: superblockOffset, afs: afs}, nil
	}

	// Coherent has no magic: its volume and pack names are the signature.
	fname := bytes[484:490]
	fpack := bytes[490:496]
	if (string(fname) == "noname" || string(fname) == "xxxxx ") &&
		(string(fpack) == "nopack" || string(fpack) == "xxxxx\n") {
		return &detection{variant: variantCoherent, byteOrder: orderPDP, offset: superblockOffset}, nil
	}
	return nil, nil
}

func le32(bytes []byte, at int) uint32 { return binary.LittleEndian.Uint32(bytes[at:]) }

// readSuperblock reads and validates the superblock.
func readSuperblock(src source.ByteSource) (*superblock, error) {
	found, err := detectSuperblock(src)
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, badSuperblock("no System V-family superblock signature")
	}
	var sb *superblock
	switch found.variant {
	case variantXenix:
		sb, err = readXenix(src, found.byteOrder)
	case variantCoherent:
		sb, err = readCoherent(src)
	default:
		sb, err = readSysV(src, *found)
	}
	if err != nil {
		return nil, err
	}
	if err := validateSuperblock(sb); err != nil {
		return nil, err
	}
	return sb, nil
}

func readXenix(src source.ByteSource, order byteOrder) (*superblock, error) {
	bytes := make([]byte, 1024)
	if err := source.ReadExactAt(src, xenixSuperblockOffset, bytes); err != nil {
		return nil, err
	}
	magic := order.u32(bytes, 1016)
	sType := order.u32(bytes, 1020)
	var blockSize uint32
	switch sType {
	case 1:
		return nil, unverifiedInodeLayout(
			"Xenix with 512-byte blocks: the superblock structure at byte 1024 overlaps the block-2 inode table")
	case 2:
		blockSize = 1024
	default:
		return nil, unsupportedVariant(
			"Xenix s_type " + utoa(sType) + "; only 1 (512-byte blocks) and 2 (1024-byte blocks) are defined")
	}
	return &superblock{
		variant:   variantXenix,
		byteOrder: order,
		magic:     magic,
		hasMagic:  true,
		blockSize: blockSize,
		isize:     uint32(order.u16(bytes, 0)),
		fsize:     order.u32(bytes, 2),
		nfree:     order.u16(bytes, 6),
		free:      readU32Array(bytes, 8, order, xenixNICFREE),
		ninode:    order.u16(bytes, 408),
		inode:     readU16Array(bytes, 410, order, nicinod),
		time:      order.u32(bytes, 614),
		tfree:     order.u32(bytes, 618),
		tinode:    order.u16(bytes, 622),
		sType:     sType,
		hasType:   true,
		fname:     readName(bytes, 632),
		fpack:     readName(bytes, 638),
	}, nil
}

func readSysV(src source.ByteSource, found detection) (*superblock, error) {
	bytes := make([]byte, 512)
	if err := source.ReadExactAt(src, superblockOffset, bytes); err != nil {
		return nil, err
	}
	order := found.byteOrder
	sType := order.u32(bytes, 508)
	if sType >= 0x10 {
		return nil, unverifiedInodeLayout(
			"ISC Interactive Unix long-name variant (s_type " + utoaHex(sType) +
				"): the 14-byte directory entry this reader verifies does not apply")
	}
	var blockSize uint32
	switch sType {
	case 1:
		blockSize = 512
	case 2:
		blockSize = 1024
	case 3:
		blockSize = 2048
	default:
		return nil, unsupportedVariant("System V s_type " + utoa(sType) +
			"; the format defines only 1 (512-byte), 2 (1024-byte) and 3 (2048-byte) blocks")
	}
	sb := &superblock{
		byteOrder: order,
		blockSize: blockSize,
		magic:     order.u32(bytes, 504),
		hasMagic:  true,
		isize:     uint32(order.u16(bytes, 0)),
		state:     order.u32(bytes, 500),
		hasState:  true,
		sType:     sType,
		hasType:   true,
	}
	if found.variant == variantSysV4 {
		sb.variant = variantSysV4
		sb.fsize = order.u32(bytes, 4)
		sb.nfree = order.u16(bytes, 8)
		sb.free = readU32Array(bytes, 12, order, sysvNICFREE)
		sb.ninode = order.u16(bytes, 212)
		sb.inode = readU16Array(bytes, 216, order, nicinod)
		sb.time = order.u32(bytes, 420)
		sb.tfree = order.u32(bytes, 432)
		sb.tinode = order.u16(bytes, 436)
		sb.fname = readName(bytes, 440)
		sb.fpack = readName(bytes, 446)
		sb.afs = found.afs
		return sb, nil
	}
	sb.variant = variantSysV2
	sb.fsize = order.u32(bytes, 2)
	sb.nfree = order.u16(bytes, 6)
	sb.free = readU32Array(bytes, 8, order, sysvNICFREE)
	sb.ninode = order.u16(bytes, 208)
	sb.inode = readU16Array(bytes, 210, order, nicinod)
	sb.time = order.u32(bytes, 414)
	sb.tfree = order.u32(bytes, 426)
	sb.tinode = order.u16(bytes, 430)
	sb.fname = readName(bytes, 432)
	sb.fpack = readName(bytes, 438)
	return sb, nil
}

func readCoherent(src source.ByteSource) (*superblock, error) {
	bytes := make([]byte, 500)
	if err := source.ReadExactAt(src, superblockOffset, bytes); err != nil {
		return nil, err
	}
	order := orderPDP
	return &superblock{
		variant:   variantCoherent,
		byteOrder: order,
		blockSize: 512,
		isize:     uint32(order.u16(bytes, 0)),
		fsize:     order.u32(bytes, 2),
		nfree:     order.u16(bytes, 6),
		free:      readU32Array(bytes, 8, order, coherentNICFREE),
		ninode:    order.u16(bytes, 264),
		inode:     readU16Array(bytes, 266, order, nicinod),
		time:      order.u32(bytes, 470),
		tfree:     order.u32(bytes, 474),
		tinode:    order.u16(bytes, 478),
		fname:     readName(bytes, 484),
		fpack:     readName(bytes, 490),
	}, nil
}

func readU32Array(bytes []byte, at int, order byteOrder, count int) []uint32 {
	out := make([]uint32, count)
	for index := range out {
		out[index] = order.u32(bytes, at+index*4)
	}
	return out
}

func readU16Array(bytes []byte, at int, order byteOrder, count int) []uint32 {
	out := make([]uint32, count)
	for index := range out {
		out[index] = uint32(order.u16(bytes, at+index*2))
	}
	return out
}

// readName reads a fixed six-byte name field, trimming NUL and trailing space
// padding. An all-padding field is no name.
func readName(bytes []byte, at int) string {
	field := bytes[at : at+6]
	end := len(field)
	for index, value := range field {
		if value == 0 {
			end = index
			break
		}
	}
	name := field[:end]
	for len(name) > 0 && name[len(name)-1] == ' ' {
		name = name[:len(name)-1]
	}
	return strings.ToValidUTF8(string(name), "�")
}

func validateSuperblock(sb *superblock) error {
	label := sb.variant.label()
	if sb.isize <= firstInodeZone {
		return badSuperblock(label + ": s_isize " + utoa(sb.isize) +
			" leaves no inode table after block 2")
	}
	if sb.fsize <= sb.isize {
		return badSuperblock(label + ": s_fsize " + utoa(sb.fsize) +
			" does not extend past the first data zone " + utoa(sb.isize))
	}
	if sb.inodeCount() < rootInode {
		return badSuperblock(label + ": " + utoa(sb.blockSize) + "-byte blocks give room for only " +
			utoa(sb.inodeCount()) + " inodes, fewer than the root needs")
	}
	if sb.tfree > sb.fsize {
		return badSuperblock(label + ": s_tfree " + utoa(sb.tfree) +
			" exceeds the declared " + utoa(sb.fsize) + " zones")
	}
	return nil
}
