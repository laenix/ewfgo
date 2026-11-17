package qnx6

import (
	"fmt"
	"strings"

	"github.com/laenix/ewfgo/internal/data/source"
)

// The QNX6 magic, as a numeric value.
const Magic uint32 = 0x6819_1122

// Every superblock copy is 512 bytes.
const SuperblockSize = 0x200

// SuperblockArea is the area reserved for the superblock after the bootblock.
const SuperblockArea uint64 = 0x1000

// BootblockSize is the bootblock area that precedes the superblock on normal
// images.
const BootblockSize uint64 = 0x2000

// PrimaryOffset is the byte offset of the primary copy on a normal image.
const PrimaryOffset uint64 = BootblockSize

// AlternateOffset is the byte offset of the Audi MMI 3G copy when no normal
// primary exists.
const AlternateOffset uint64 = 0

// RootNodeSize is the bytes a qnx6_root_node occupies.
const RootNodeSize = 0x50

// SwappedMagic is the magic of a filesystem written with the opposite byte
// order.
const SwappedMagic uint32 = 0x2211_1968

// Smallest and largest block sizes this reader accepts.
const (
	MinBlockSize uint32 = 512
	MaxBlockSize uint32 = 4096
)

// MaxPtrLevels is the largest pointer-tree depth the format defines.
const MaxPtrLevels uint8 = 5

const (
	checksumAt     = 0x04
	serialAt       = 0x08
	ctimeAt        = 0x10
	atimeAt        = 0x14
	flagsAt        = 0x18
	version1At     = 0x1c
	version2At     = 0x1e
	volumeIDAt     = 0x20
	blockSizeAt    = 0x30
	numInodesAt    = 0x34
	freeInodesAt   = 0x38
	numBlocksAt    = 0x3c
	freeBlocksAt   = 0x40
	allocGroupAt   = 0x44
	inodeRootAt    = 0x48
	bitmapRootAt   = 0x98
	longfileRootAt = 0xe8
	unknownRootAt  = 0x138

	mmiBlockSizeAt    = 0x28
	mmiNumInodesAt    = 0x2c
	mmiFreeInodesAt   = 0x30
	mmiNumBlocksAt    = 0x34
	mmiFreeBlocksAt   = 0x38
	mmiInodeRootAt    = 0x40
	mmiBitmapRootAt   = 0x90
	mmiLongfileRootAt = 0xe0
	mmiUnknownRootAt  = 0x130
)

// Layout is which on-disk field layout a superblock copy uses.
type Layout uint8

const (
	// LayoutStandard is the normal 8 KiB bootblock image at byte 8192.
	LayoutStandard Layout = iota
	// LayoutMMI is the Audi MMI 3G image at byte zero.
	LayoutMMI
)

// Label returns the stable label for facts and warnings.
func (l Layout) Label() string {
	switch l {
	case LayoutMMI:
		return "mmi"
	default:
		return "standard"
	}
}

// ByteOrder is the byte order a superblock's multi-byte fields use.
type ByteOrder uint8

const (
	// Little is little-endian.
	Little ByteOrder = iota
	// Big is big-endian.
	Big
)

// Label returns the stable label for facts.
func (o ByteOrder) Label() string {
	if o == Big {
		return "big"
	}
	return "little"
}

func (o ByteOrder) u16(bytes []byte, offset int) uint16 {
	if o == Big {
		return uint16(bytes[offset])<<8 | uint16(bytes[offset+1])
	}
	return uint16(bytes[offset]) | uint16(bytes[offset+1])<<8
}

func (o ByteOrder) u32(bytes []byte, offset int) uint32 {
	if o == Big {
		return uint32(bytes[offset])<<24 | uint32(bytes[offset+1])<<16 |
			uint32(bytes[offset+2])<<8 | uint32(bytes[offset+3])
	}
	return uint32(bytes[offset]) | uint32(bytes[offset+1])<<8 |
		uint32(bytes[offset+2])<<16 | uint32(bytes[offset+3])<<24
}

func (o ByteOrder) u64(bytes []byte, offset int) uint64 {
	if o == Big {
		return uint64(o.u32(bytes, offset))<<32 | uint64(o.u32(bytes, offset+4))
	}
	return uint64(o.u32(bytes, offset)) | uint64(o.u32(bytes, offset+4))<<32
}

// RootNode is one of the four qnx6_root_node descriptors in the superblock.
type RootNode struct {
	// Size is the stream length in bytes.
	Size uint64
	// Ptr holds top-level filesystem block numbers; ^uint32(0) means unused.
	Ptr [16]uint32
	// Levels is the pointer-tree depth.
	Levels uint8
	// Mode is the recorded mode byte; the format does not document it.
	Mode uint8
}

func parseRootNode(bytes []byte, offset int, order ByteOrder, what string) (RootNode, error) {
	var node RootNode
	node.Size = order.u64(bytes, offset)
	for index := 0; index < 16; index++ {
		node.Ptr[index] = order.u32(bytes, offset+8+index*4)
	}
	node.Levels = bytes[offset+0x48]
	if node.Levels > MaxPtrLevels {
		return RootNode{}, unsupportedf("%s has pointer-tree depth %d, more than the %d-level cap",
			what, node.Levels, MaxPtrLevels)
	}
	node.Mode = bytes[offset+0x49]
	return node, nil
}

// CopyInfo is the state of one superblock position.
type CopyInfo struct {
	// Offset is the byte offset of this copy.
	Offset uint64
	// Label is "primary", "mmi" or "backup".
	Label string
	// Serial is sb_serial when the copy validated.
	Serial *uint64
	// Valid is true when magic, checksum and geometry all validated.
	Valid bool
	// Reason explains why the copy was not accepted.
	Reason string
}

// Superblock is a parsed QNX6 superblock plus the state of every copy that was
// inspected.
type Superblock struct {
	Order  ByteOrder
	Layout Layout

	Checksum uint32
	Serial   uint64
	// Ctime is filesystem creation time in Unix seconds; zero means unset.
	Ctime uint32
	// Atime is last access/mount time in Unix seconds; zero means unset.
	Atime uint32
	Flags uint32

	Version1 uint16
	Version2 uint16

	VolumeIDBytes [16]byte

	BlockSize  uint32
	NumInodes  uint32
	FreeInodes uint32
	NumBlocks  uint32
	FreeBlocks uint32
	AllocGroup uint32

	Inode    RootNode
	Bitmap   RootNode
	Longfile RootNode
	Unknown  RootNode

	// BootblockBytes is the bytes that precede the superblock area (0 or
	// 0x2000).
	BootblockBytes uint64
	// BlksOff is the device blocks before the data area (s_blks_off).
	BlksOff uint64
	// CopyOffset is the byte offset of the copy this reader selected.
	CopyOffset uint64
	// Copies lists every copy position inspected, in probe order.
	Copies []CopyInfo
}

// BlockShift returns log2(block_size).
func (s *Superblock) BlockShift() uint32 {
	return uint32(trailingZeros32(s.BlockSize))
}

// PtrBits returns the bits of a block-number index: log2(block_size / 4).
func (s *Superblock) PtrBits() uint32 {
	return uint32(trailingZeros32(s.BlockSize / 4))
}

// VolumeBytes returns the bytes in the data area.
func (s *Superblock) VolumeBytes() uint64 {
	return uint64(s.NumBlocks) * uint64(s.BlockSize)
}

// TotalDeviceBlocks returns the device blocks the whole filesystem spans,
// excluding the backup copy.
func (s *Superblock) TotalDeviceBlocks() uint64 {
	return s.BlksOff + uint64(s.NumBlocks)
}

// DeviceBlock returns the physical device block for a filesystem-relative
// block number.
func (s *Superblock) DeviceBlock(block uint64) (uint64, bool) {
	device := block + s.BlksOff
	if device < block || device >= s.TotalDeviceBlocks() {
		return 0, false
	}
	return device, true
}

// BlockOffset returns the physical byte offset for a filesystem-relative
// block number.
func (s *Superblock) BlockOffset(block uint64) (uint64, bool) {
	device, ok := s.DeviceBlock(block)
	if !ok {
		return 0, false
	}
	return device * uint64(s.BlockSize), true
}

// ValidateBlock validates one filesystem block number against the data area.
func (s *Superblock) ValidateBlock(block uint64, what string) error {
	if block >= uint64(s.NumBlocks) {
		return corruptf("%s names block %d, out of range for the volume's %d data blocks",
			what, block, s.NumBlocks)
	}
	return nil
}

// BackupOffset returns the byte offset of the backup copy.
func (s *Superblock) BackupOffset() uint64 {
	return s.TotalDeviceBlocks() * uint64(s.BlockSize)
}

// VolumeID returns the 16-byte volume identifier as text when it is printable
// ASCII, otherwise as hexadecimal. An empty identifier is the empty string.
func (s *Superblock) VolumeID() string {
	end := len(s.VolumeIDBytes)
	for index, value := range s.VolumeIDBytes {
		if value == 0 {
			end = index
			break
		}
	}
	field := s.VolumeIDBytes[:end]
	if len(field) == 0 {
		return ""
	}
	printable := true
	for _, value := range field {
		if !((value >= 0x21 && value <= 0x7e) || value == ' ') {
			printable = false
			break
		}
	}
	if printable {
		return string(field)
	}
	var builder strings.Builder
	builder.Grow(32)
	for _, value := range s.VolumeIDBytes {
		fmt.Fprintf(&builder, "%02x", value)
	}
	return builder.String()
}

func trailingZeros32(value uint32) int {
	if value == 0 {
		return 32
	}
	count := 0
	for value&1 == 0 {
		count++
		value >>= 1
	}
	return count
}

// CRC32BE is the zero-seeded, non-reflected CRC-32 polynomial 0x04C11DB7 with
// no final xor (Linux's crc32_be(0, ...)), the checksum QNX6 stores.
func CRC32BE(bytes []byte) uint32 {
	var crc uint32
	for _, value := range bytes {
		crc ^= uint32(value) << 24
		for bit := 0; bit < 8; bit++ {
			if crc&0x8000_0000 != 0 {
				crc = (crc << 1) ^ 0x04C1_1DB7
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// orderFromMagic returns the byte order a four-byte magic proves.
func orderFromMagic(magic []byte) (ByteOrder, bool) {
	le := uint32(magic[0]) | uint32(magic[1])<<8 | uint32(magic[2])<<16 | uint32(magic[3])<<24
	if le == Magic {
		return Little, true
	}
	be := uint32(magic[0])<<24 | uint32(magic[1])<<16 | uint32(magic[2])<<8 | uint32(magic[3])
	if be == Magic {
		return Big, true
	}
	return Little, false
}

func shortCopyError(offset, sourceLen uint64) error {
	return corruptf("a QNX6 magic is present at byte %d but the source is %d bytes, shorter than the %d-byte superblock",
		offset, sourceLen, SuperblockSize)
}

func parseAt(src source.ByteSource, offset, bootblockBytes uint64, layout Layout) (*Superblock, error) {
	if src.Len() < offset+4 {
		return nil, nil
	}
	var magic [4]byte
	if err := source.ReadExactAt(src, offset, magic[:]); err != nil {
		return nil, err
	}
	order, ok := orderFromMagic(magic[:])
	if !ok {
		return nil, nil
	}
	if src.Len() < offset+SuperblockSize {
		return nil, shortCopyError(offset, src.Len())
	}
	var bytes [SuperblockSize]byte
	if err := source.ReadExactAt(src, offset, bytes[:]); err != nil {
		return nil, err
	}

	checksum := order.u32(bytes[:], checksumAt)
	computed := CRC32BE(bytes[8:SuperblockSize])
	if checksum != computed {
		return nil, corruptf("the superblock at byte %d stores checksum 0x%08x but the zero-seeded CRC-32 over bytes 8..512 is 0x%08x",
			offset, checksum, computed)
	}

	blockSizeOffset := blockSizeAt
	numInodesOffset := numInodesAt
	freeInodesOffset := freeInodesAt
	numBlocksOffset := numBlocksAt
	freeBlocksOffset := freeBlocksAt
	inodeOffset := inodeRootAt
	bitmapOffset := bitmapRootAt
	longfileOffset := longfileRootAt
	unknownOffset := unknownRootAt
	if layout == LayoutMMI {
		blockSizeOffset = mmiBlockSizeAt
		numInodesOffset = mmiNumInodesAt
		freeInodesOffset = mmiFreeInodesAt
		numBlocksOffset = mmiNumBlocksAt
		freeBlocksOffset = mmiFreeBlocksAt
		inodeOffset = mmiInodeRootAt
		bitmapOffset = mmiBitmapRootAt
		longfileOffset = mmiLongfileRootAt
		unknownOffset = mmiUnknownRootAt
	}

	blockSize := order.u32(bytes[:], blockSizeOffset)
	if blockSize < MinBlockSize || blockSize > MaxBlockSize || blockSize&(blockSize-1) != 0 {
		return nil, unsupportedf("block size %d at byte %d; this reader accepts powers of two from %d through %d",
			blockSize, offset, MinBlockSize, MaxBlockSize)
	}
	if layout == LayoutMMI {
		bootblockBytes = 0
	}
	blockBytes := uint64(blockSize)
	if bootblockBytes%blockBytes != 0 || SuperblockArea%blockBytes != 0 {
		return nil, corruptf("the %d-byte block size does not divide the bootblock and superblock areas", blockSize)
	}
	blksOff := bootblockBytes/blockBytes + SuperblockArea/blockBytes

	numBlocks := order.u32(bytes[:], numBlocksOffset)
	if numBlocks == 0 {
		return nil, corruptf("the superblock at byte %d declares no data blocks", offset)
	}
	numInodes := order.u32(bytes[:], numInodesOffset)
	if numInodes == 0 {
		return nil, corruptf("the superblock at byte %d declares no inodes", offset)
	}

	inodeNode, err := parseRootNode(bytes[:], inodeOffset, order, "the Inode root node")
	if err != nil {
		return nil, err
	}
	bitmapNode, err := parseRootNode(bytes[:], bitmapOffset, order, "the Bitmap root node")
	if err != nil {
		return nil, err
	}
	longfileNode, err := parseRootNode(bytes[:], longfileOffset, order, "the Longfile root node")
	if err != nil {
		return nil, err
	}
	unknownNode, err := parseRootNode(bytes[:], unknownOffset, order, "the Unknown root node")
	if err != nil {
		return nil, err
	}

	dataBytes := uint64(numBlocks) * blockBytes
	tableBytes := uint64(numInodes) * InodeSize
	if inodeNode.Size < tableBytes {
		return nil, corruptf("the Inode root node covers %d bytes, fewer than the %d bytes its %d inodes need",
			inodeNode.Size, tableBytes, numInodes)
	}
	if inodeNode.Size > dataBytes {
		return nil, corruptf("the Inode root node covers %d bytes, more than the %d-byte data area",
			inodeNode.Size, dataBytes)
	}
	if longfileNode.Size > dataBytes {
		return nil, corruptf("the Longfile root node covers %d bytes, more than the %d-byte data area",
			longfileNode.Size, dataBytes)
	}

	totalDeviceBlocks := blksOff + uint64(numBlocks)
	if totalDeviceBlocks < blksOff {
		return nil, corruptf("the volume geometry overflows the byte address space")
	}
	neededBytes := totalDeviceBlocks * blockBytes
	if neededBytes/totalDeviceBlocks != blockBytes {
		return nil, corruptf("the volume geometry overflows the byte address space")
	}
	if neededBytes > src.Len() {
		return nil, corruptf("the superblock at byte %d describes %d device blocks (%d bytes) but the source is %d bytes",
			offset, totalDeviceBlocks, neededBytes, src.Len())
	}

	var (
		ctime      uint32
		atime      uint32
		flags      uint32
		version1   uint16
		version2   uint16
		volumeID   [16]byte
		allocGroup uint32
	)
	if layout == LayoutStandard {
		ctime = order.u32(bytes[:], ctimeAt)
		atime = order.u32(bytes[:], atimeAt)
		flags = order.u32(bytes[:], flagsAt)
		version1 = order.u16(bytes[:], version1At)
		version2 = order.u16(bytes[:], version2At)
		copy(volumeID[:], bytes[volumeIDAt:volumeIDAt+16])
		allocGroup = order.u32(bytes[:], allocGroupAt)
	}

	return &Superblock{
		Order:          order,
		Layout:         layout,
		Checksum:       checksum,
		Serial:         order.u64(bytes[:], serialAt),
		Ctime:          ctime,
		Atime:          atime,
		Flags:          flags,
		Version1:       version1,
		Version2:       version2,
		VolumeIDBytes:  volumeID,
		BlockSize:      blockSize,
		NumInodes:      numInodes,
		FreeInodes:     order.u32(bytes[:], freeInodesOffset),
		NumBlocks:      numBlocks,
		FreeBlocks:     order.u32(bytes[:], freeBlocksOffset),
		AllocGroup:     allocGroup,
		Inode:          inodeNode,
		Bitmap:         bitmapNode,
		Longfile:       longfileNode,
		Unknown:        unknownNode,
		BootblockBytes: bootblockBytes,
		BlksOff:        blksOff,
		CopyOffset:     offset,
	}, nil
}

type probeResult struct {
	info CopyInfo
	sb   *Superblock
	err  error
}

func probe(src source.ByteSource, offset, bootblockBytes uint64, layout Layout, label string) probeResult {
	sb, err := parseAt(src, offset, bootblockBytes, layout)
	if err != nil {
		return probeResult{
			info: CopyInfo{Offset: offset, Label: label, Valid: false, Reason: err.Error()},
			err:  err,
		}
	}
	if sb == nil {
		return probeResult{
			info: CopyInfo{Offset: offset, Label: label, Valid: false, Reason: "no QNX6 magic"},
		}
	}
	serial := sb.Serial
	return probeResult{
		info: CopyInfo{Offset: offset, Label: label, Serial: &serial, Valid: true},
		sb:   sb,
	}
}

// pickHighest returns the valid candidate with the highest serial. On a tie
// the later candidate wins, matching the reference reader's max_by_key.
func pickHighest(candidates []*Superblock) *Superblock {
	var best *Superblock
	for _, candidate := range candidates {
		if best == nil || candidate.Serial >= best.Serial {
			best = candidate
		}
	}
	return best
}

// ReadSuperblock reads and chooses the active superblock. The primary copy at
// byte 8192 and the Audi MMI copy at byte 0 are both tried; the valid copy
// with the highest serial, including the backup, is active.
func ReadSuperblock(src source.ByteSource) (*Superblock, error) {
	primary := probe(src, PrimaryOffset, BootblockSize, LayoutStandard, "primary")
	alternate := probe(src, AlternateOffset, 0, LayoutMMI, "mmi")

	copies := []CopyInfo{primary.info, alternate.info}
	var baseCandidates []*Superblock
	if primary.sb != nil {
		baseCandidates = append(baseCandidates, primary.sb)
	}
	if alternate.sb != nil {
		baseCandidates = append(baseCandidates, alternate.sb)
	}
	if len(baseCandidates) == 0 {
		if primary.err != nil {
			return nil, primary.err
		}
		if alternate.err != nil {
			return nil, alternate.err
		}
		return nil, corruptf("no QNX6 superblock magic at byte %d or byte %d",
			PrimaryOffset, AlternateOffset)
	}

	base := pickHighest(baseCandidates)
	backup := probe(src, base.BackupOffset(), base.BootblockBytes, base.Layout, "backup")
	copies = append(copies, backup.info)

	var valid []*Superblock
	if primary.sb != nil {
		valid = append(valid, primary.sb)
	}
	if alternate.sb != nil {
		valid = append(valid, alternate.sb)
	}
	if backup.sb != nil {
		if backup.sb.Layout == base.Layout &&
			backup.sb.BlockSize == base.BlockSize &&
			backup.sb.NumBlocks == base.NumBlocks &&
			backup.sb.BlksOff == base.BlksOff {
			valid = append(valid, backup.sb)
		} else {
			last := &copies[len(copies)-1]
			last.Valid = false
			last.Serial = nil
			last.Reason = fmt.Sprintf(
				"the backup's geometry (block size %d, %d blocks, offset %d) disagrees with the primary (block size %d, %d blocks, offset %d)",
				backup.sb.BlockSize, backup.sb.NumBlocks, backup.sb.BlksOff,
				base.BlockSize, base.NumBlocks, base.BlksOff)
		}
	}

	active := pickHighest(valid)
	if active == nil {
		return nil, corruptf("no QNX6 superblock copy validated its magic, checksum and geometry")
	}
	active.Copies = copies
	return active, nil
}

// detectSuperblock reports whether a QNX6 superblock this reader understands
// is present. A magic without a matching checksum is an error by name rather
// than a positive identification.
func detectSuperblock(src source.ByteSource) (bool, error) {
	found := false
	for _, offset := range []uint64{PrimaryOffset, AlternateOffset} {
		if src.Len() < offset+4 {
			continue
		}
		var magic [4]byte
		if err := source.ReadExactAt(src, offset, magic[:]); err != nil {
			return false, err
		}
		if _, ok := orderFromMagic(magic[:]); ok {
			found = true
		}
	}
	if !found {
		return false, nil
	}
	if _, err := ReadSuperblock(src); err != nil {
		return false, err
	}
	return true, nil
}
