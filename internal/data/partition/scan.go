package partition

import (
	"bytes"
	"math"
	"sort"

	"github.com/laenix/ewfgo/internal/data/source"
)

// This file is the Go port of forensic-core's data/partition/scan.rs: a
// conservative signature scan for volumes whose partition table was damaged,
// wiped, or never existed.  A candidate is evidence, not a decision; the table
// reader still decides what a disk's partitions are.

const (
	// scanHeadLen is how far into a candidate volume its signature may sit.
	// Btrfs puts its superblock at 64 KiB + 64, the deepest fixed magic here.
	scanHeadLen = 68 * 1024
	// scanChunk is the number of bytes read per pass.
	scanChunk = 8 * 1024 * 1024
	// scanOverlap lets a signature that straddles a chunk boundary be seen by
	// the chunk that starts before it.
	scanOverlap = scanHeadLen + 4096
	// defaultMaxCandidates bounds a list that would otherwise grow without
	// bound on an image that is not what it seems.
	defaultMaxCandidates = 4096
)

// ScanOptions are the knobs for Scan.  The zero value reads the whole source
// and uses defaultMaxCandidates; a nil Limit means "to the end of the source".
type ScanOptions struct {
	// Limit stops the scan after this many bytes, counted from the start of
	// the source.  nil reads the whole source.
	Limit *uint64
	// MaxCandidates gives up after this many confirmed candidates.  Zero (or
	// negative) selects defaultMaxCandidates.
	MaxCandidates int
}

// DefaultScanOptions returns the Rust defaults: no limit, 4096 candidates.
func DefaultScanOptions() ScanOptions {
	return ScanOptions{MaxCandidates: defaultMaxCandidates}
}

// CandidateStatus says how far a candidate's own metadata can be trusted.
type CandidateStatus uint8

const (
	// CandidateStatusVerified means a recorded checksum or redundant
	// structure matched.
	CandidateStatusVerified CandidateStatus = iota
	// CandidateStatusUnverified means the header parses and fits, but the
	// format records no checksum this reader can verify (or its parser is
	// not ported yet).
	CandidateStatusUnverified
	// CandidateStatusRejected means the header did not parse, did not fit, or
	// a recorded checksum failed.
	CandidateStatusRejected
)

// String returns the lower-case name used in reports and facts.
func (s CandidateStatus) String() string {
	switch s {
	case CandidateStatusVerified:
		return "verified"
	case CandidateStatusUnverified:
		return "unverified"
	case CandidateStatusRejected:
		return "rejected"
	default:
		return "unknown"
	}
}

// AsStr is the Rust as_str spelling for callers that prefer it.
func (s CandidateStatus) AsStr() string { return s.String() }

// Verification is the verdict on one candidate, with the check that produced
// it.  Reason is always populated.
type Verification struct {
	Status CandidateStatus
	Reason string
}

func verified(reason string) Verification {
	return Verification{Status: CandidateStatusVerified, Reason: reason}
}

func unverified(reason string) Verification {
	return Verification{Status: CandidateStatusUnverified, Reason: reason}
}

func rejected(reason string) Verification {
	return Verification{Status: CandidateStatusRejected, Reason: reason}
}

// Candidate is one volume the scan found, addressed by its offset in the
// source.
type Candidate struct {
	// Offset is the byte offset of the volume's first sector.
	Offset uint64
	// SignatureOffset is the offset of the magic inside the volume, counted
	// from Offset.
	SignatureOffset uint64
	// ID is the stable identifier VolumeSignature reports.
	ID string
	// Label is the human-readable format name.
	Label string
	// VolumeLen is the length the format reports, when a field states it.
	// Zero means no such field (the Rust Option's None).
	VolumeLen uint64
	// SizeBasis names the field VolumeLen came from, or is empty.
	SizeBasis string
	// Status says how far the candidate's metadata can be trusted.
	Status CandidateStatus
	// Reason is the check that produced Status, or what failed.
	Reason string
	// InsideOf is the offset of the candidate whose extent contains this one,
	// or nil.  A backup boot sector, a superblock mirror, or a volume written
	// inside another lands here: the hit is real, but it does not start a
	// volume.
	InsideOf *uint64
}

// ScanReport is what one scan pass found.
type ScanReport struct {
	SectorSize uint64
	// BytesScanned is the number of bytes actually read.
	BytesScanned uint64
	Candidates   []Candidate
	// RejectedHits counts positions where an anchor matched but the signature
	// did not confirm.
	RejectedHits int
	// Truncated is true when the candidate cap stopped the scan early.
	Truncated bool
}

// TopLevel returns the candidates that start a volume rather than sitting
// inside one.
func (r *ScanReport) TopLevel() []Candidate {
	if r == nil {
		return nil
	}
	out := make([]Candidate, 0, len(r.Candidates))
	for _, c := range r.Candidates {
		if c.InsideOf == nil {
			out = append(out, c)
		}
	}
	return out
}

// scanAnchor is a byte pattern and the offset from a volume's start where the
// format keeps it.  The format is confirmed afterwards with VolumeSignature,
// which is why these carry no names.
type scanAnchor struct {
	at    uint64
	magic []byte
}

var scanAnchors = []scanAnchor{
	// Boot sectors: the OEM/magic field sits three bytes in.
	{3, []byte("NTFS    ")},
	{3, []byte("ReFS    ")},
	{3, []byte("EXFAT   ")},
	{3, []byte("-FVE-FS-")},
	{54, []byte("FAT12   ")},
	{54, []byte("FAT16   ")},
	{82, []byte("FAT32   ")},
	// Volume headers with a magic at offset zero.
	{0, []byte("XFSB")},
	{0, []byte("hsqs")},
	{0, []byte("LUKS\xba\xbe")},
	{0, []byte{0x45, 0x3d, 0xcd, 0x28}},
	// A CramFS image behind a boot header starts 512 bytes in.
	{512, []byte{0x45, 0x3d, 0xcd, 0x28}},
	// Container and volume-manager signatures.
	{0x200, []byte("LABELONE")},
	{0x1000, []byte{0xFC, 0x4E, 0x2B, 0xA9}},
	// Superblocks at fixed offsets.
	{32, []byte("NXSB")},
	{1024, []byte("H+")},
	{1024, []byte("HX")},
	{1080, []byte{0x53, 0xEF}},
	{1024, []byte{0xF2, 0xF5, 0x20, 0x10}},
	{8192 + 1372, []byte{0x54, 0x19, 0x01, 0x00}},
	{8192 + 1372, []byte{0x00, 0x01, 0x19, 0x54}},
	{0x8001, []byte("CD001")},
	// UDF's volume recognition sequence starts with the same sector-16 byte
	// offset; the revision descriptor is checked by the signature reader.
	{0x8001, []byte("BEA01")},
	{65536 + 64, []byte("_BHRfS_M")},
	{65536 + 1372, []byte{0x19, 0x01, 0x54, 0x19}},
	{65536 + 1372, []byte{0x19, 0x54, 0x01, 0x19}},
	// EROFS: 32-bit magic in the superblock at byte 1024.
	{1024, []byte{0xE2, 0xE1, 0xF5, 0xE0}},
	// ReiserFS: the ten-byte magic is 52 bytes into the superblock at 8 KiB.
	{8*1024 + 52, []byte("ReIsErFs")},
	{8*1024 + 52, []byte("ReIsEr2Fs")},
	{8*1024 + 52, []byte("ReIsEr3Fs")},
	// JFS: aggregate superblock in the page at byte 0x8000.
	{0x8000, []byte("JFS1")},
	// Minix: the V1/V2 magics at superblock byte 16, the V3 magic at byte 24,
	// and each in the opposite byte order.
	{1024 + 16, []byte{0x7F, 0x13}},
	{1024 + 16, []byte{0x8F, 0x13}},
	{1024 + 16, []byte{0x68, 0x24}},
	{1024 + 16, []byte{0x78, 0x24}},
	{1024 + 16, []byte{0x13, 0x7F}},
	{1024 + 16, []byte{0x13, 0x8F}},
	{1024 + 16, []byte{0x24, 0x68}},
	{1024 + 16, []byte{0x24, 0x78}},
	{1024 + 24, []byte{0x5A, 0x4D}},
	{1024 + 24, []byte{0x4D, 0x5A}},
	// BeFS: magic 32 bytes into the superblock at byte 512, both byte orders.
	{512 + 32, []byte{0x31, 0x53, 0x46, 0x42}},
	{512 + 32, []byte{0x42, 0x46, 0x53, 0x31}},
	// OCFS2: the signature in filesystem block 2, for each permitted block
	// size, and the reversed form a byte-swapped image presents.
	{2 * 512, []byte("OCFSV2")},
	{2 * 512, []byte("2VSFCO")},
	{2 * 1024, []byte("OCFSV2")},
	{2 * 1024, []byte("2VSFCO")},
	{2 * 2048, []byte("OCFSV2")},
	{2 * 2048, []byte("2VSFCO")},
	{2 * 4096, []byte("OCFSV2")},
	{2 * 4096, []byte("2VSFCO")},
	// GFS2: big-endian magic at byte 65536, plus the swapped word.
	{65536, []byte{0x01, 0x16, 0x19, 0x70}},
	{65536, []byte{0x70, 0x19, 0x16, 0x01}},
	// QNX6: primary superblock at 8 KiB or the MMI copy at zero, both orders.
	{0, []byte{0x22, 0x11, 0x19, 0x68}},
	{0, []byte{0x68, 0x19, 0x11, 0x22}},
	{8192, []byte{0x22, 0x11, 0x19, 0x68}},
	{8192, []byte{0x68, 0x19, 0x11, 0x22}},
	// HPFS: the filesystem name in the boot sector.
	{0x36, []byte("HPFS")},
	// Classic HFS: the Master Directory Block's `BD` at byte 1024.
	{1024, []byte("BD")},
	// JFFS2: a node header at byte zero; the signature reader checks its CRC.
	{0, []byte{0x85, 0x19}},
	// System V: magic at the end of the 512-byte superblock, both orders.
	{512 + 504, []byte{0x20, 0x7E, 0x18, 0xFD}},
	{512 + 504, []byte{0xFD, 0x18, 0x7E, 0x20}},
	// Xenix: magic at the end of its 1024-byte superblock at byte 1024.
	{1024 + 1016, []byte{0x44, 0x55, 0x2B, 0x00}},
	{1024 + 1016, []byte{0x00, 0x2B, 0x55, 0x44}},
}

// Scan looks for volume signatures in sector steps, reading the source once.
func Scan(src source.ByteSource, options ScanOptions) (*ScanReport, error) {
	sectorSize, err := scanSectorSize(src)
	if err != nil {
		return nil, err
	}
	maxCandidates := options.MaxCandidates
	if maxCandidates <= 0 {
		maxCandidates = defaultMaxCandidates
	}

	total := src.Len()
	end := total
	if options.Limit != nil && *options.Limit < end {
		end = *options.Limit
	}

	type hit struct {
		offset          uint64
		signatureOffset uint64
	}
	hits := make([]hit, 0)
	var bytesScanned, coveredUntil uint64

	if end >= sectorSize {
		for base := uint64(0); ; {
			length := uint64(scanChunk)
			if remaining := end - base; remaining < length {
				length = remaining
			}
			buffer := make([]byte, int(length))
			if err := source.ReadExactAt(src, base, buffer); err != nil {
				return nil, err
			}

			// The overlap with the previous chunk is read twice but counted
			// once.
			var repeated uint64
			if coveredUntil > base {
				repeated = coveredUntil - base
				if repeated > length {
					repeated = length
				}
			}
			bytesScanned += length - repeated
			if base+length > coveredUntil {
				coveredUntil = base + length
			}

			position := ((base + sectorSize - 1) / sectorSize) * sectorSize
			chunkEnd := base + length
			for position < chunkEnd {
				index := position - base
				for _, anchor := range scanAnchors {
					at := index + anchor.at
					if at+uint64(len(anchor.magic)) > uint64(len(buffer)) {
						continue
					}
					if bytes.Equal(buffer[at:at+uint64(len(anchor.magic))], anchor.magic) {
						hits = append(hits, hit{offset: position, signatureOffset: anchor.at})
						break
					}
				}
				position += sectorSize
			}

			if chunkEnd >= end || length < uint64(scanChunk) {
				break
			}
			// Back up over the overlap; duplicate positions are removed below.
			base = chunkEnd - scanOverlap
		}
	}

	sort.Slice(hits, func(i, j int) bool {
		if hits[i].offset != hits[j].offset {
			return hits[i].offset < hits[j].offset
		}
		return hits[i].signatureOffset < hits[j].signatureOffset
	})
	deduped := hits[:0]
	for _, h := range hits {
		if len(deduped) == 0 || deduped[len(deduped)-1].offset != h.offset {
			deduped = append(deduped, h)
		}
	}
	hits = deduped

	candidates := make([]Candidate, 0, len(hits))
	rejectedHits := 0
	truncated := false
	for _, h := range hits {
		if len(candidates) >= maxCandidates {
			truncated = true
			break
		}
		remaining := total - h.offset
		headLen := remaining
		if headLen > scanHeadLen {
			headLen = scanHeadLen
		}
		head := make([]byte, int(headLen))
		if err := source.ReadExactAt(src, h.offset, head); err != nil {
			return nil, err
		}
		id, label, ok := VolumeSignature(head)
		if !ok {
			rejectedHits++
			continue
		}
		if !confirm(id, head) {
			rejectedHits++
			continue
		}
		volumeLen, sizeBasis, hasLen := volumeLength(id, head)
		verification := VerifyCandidate(src, h.offset, id, label, head, remaining)
		candidate := Candidate{
			Offset:          h.offset,
			SignatureOffset: h.signatureOffset,
			ID:              id,
			Label:           label,
			Status:          verification.Status,
			Reason:          verification.Reason,
		}
		if hasLen {
			candidate.VolumeLen = volumeLen
			candidate.SizeBasis = sizeBasis
		}
		candidates = append(candidates, candidate)
	}

	// Mark candidates that sit inside another candidate's extent.  The list is
	// in offset order, so a stack of open extents is enough.  A rejected
	// candidate's extent is not opened: a decoy that copied a superblock must
	// not make everything after it look like a child of a volume it is not.
	type extent struct {
		offset uint64
		end    uint64
	}
	open := make([]extent, 0)
	for i := range candidates {
		c := &candidates[i]
		for len(open) > 0 && open[len(open)-1].end <= c.Offset {
			open = open[:len(open)-1]
		}
		if len(open) > 0 {
			container := open[len(open)-1].offset
			c.InsideOf = &container
		}
		var length uint64
		if c.Status != CandidateStatusRejected {
			length = c.VolumeLen
		}
		if length > 0 {
			end := c.Offset + length
			if end < c.Offset {
				end = math.MaxUint64
			}
			open = append(open, extent{offset: c.Offset, end: end})
		}
	}

	return &ScanReport{
		SectorSize:   sectorSize,
		BytesScanned: bytesScanned,
		Candidates:   candidates,
		RejectedHits: rejectedHits,
		Truncated:    truncated,
	}, nil
}

func scanSectorSize(src source.ByteSource) (uint64, error) {
	size := uint64(src.SectorSize())
	if size < 512 || size&(size-1) != 0 {
		return 0, invalid("invalid sector size %d: must be a power of two >= 512", size)
	}
	return size, nil
}

// confirm applies the extra checks a signature alone cannot make.  Some
// formats repeat their own superblock inside the volume; the repeat is
// byte-identical except for the field that names where it sits, and that field
// is the proof.
func confirm(id string, head []byte) bool {
	switch id {
	case "btrfs-volume":
		// The primary is at 64 KiB; mirrors at 64 MiB and 256 GiB record
		// their own address.
		value, ok := u64leAt(head, 65536+48)
		return ok && value == 65536
	case "ext-volume":
		log, ok := u32leAt(head, 1024+24)
		return ok && log <= 6
	case "ntfs-volume", "exfat-volume":
		value, ok := u16leAt(head, 11)
		return ok && isSectorSize(value)
	case "hfs-volume":
		version, okVersion := u16beAt(head, 1024+2)
		blockSize, okBlock := u32beAt(head, 1024+40)
		blocks, okBlocks := u32beAt(head, 1024+44)
		return okVersion && (version == 4 || version == 5) &&
			okBlock && blockSize >= 512 && blockSize <= (1<<20) && scanPow2U32(blockSize) &&
			okBlocks && blocks > 0
	case "hfs-classic-volume":
		blockSize, okBlock := u32beAt(head, 1024+20)
		blocks, okBlocks := u16beAt(head, 1024+18)
		allocationStart, okStart := u16beAt(head, 1024+28)
		nameLen, okName := byteAt(head, 1024+36)
		return okBlock && blockSize >= 512 && blockSize <= (1<<20) && scanPow2U32(blockSize) &&
			okBlocks && blocks > 0 &&
			okStart && allocationStart >= 3 &&
			okName && nameLen <= 27
	case "erofs-volume":
		bits, okBits := byteAt(head, 1024+12)
		blocks, okBlocks := u32leAt(head, 1024+36)
		return okBits && bits >= 9 && bits <= 16 && okBlocks && blocks > 0
	case "reiserfs-volume":
		blockSize, okBlock := u16leAt(head, 8*1024+0x2C)
		size := uint64(blockSize)
		blocks, okBlocks := u32leAt(head, 8*1024)
		return okBlock && size >= 1024 && size <= 65536 && scanPow2U64(size) &&
			okBlocks && blocks > 0
	case "jfs-volume":
		version, okVersion := u32leAt(head, 0x8004)
		blockSize, okBlock := u32leAt(head, 0x8010)
		log, okLog := u16leAt(head, 0x8014)
		return okVersion && version <= 2 && okBlock && blockSize == 4096 && okLog && log == 12
	case "minix-volume":
		return confirmMinix(head)
	case "befs-volume":
		magic, ok := sliceAt(head, 512+32, 4)
		if !ok {
			return false
		}
		switch {
		case bytes.Equal(magic, []byte{0x31, 0x53, 0x46, 0x42}):
			order, ok := sliceAt(head, 512+36, 4)
			return ok && bytes.Equal(order, []byte{0x45, 0x47, 0x49, 0x42})
		case bytes.Equal(magic, []byte{0x42, 0x46, 0x53, 0x31}):
			order, ok := sliceAt(head, 512+36, 4)
			return ok && bytes.Equal(order, []byte{0x42, 0x49, 0x47, 0x45})
		default:
			return false
		}
	case "qnx6-volume":
		return confirmQNX6(head)
	case "jffs2-volume":
		length, ok := u32leAt(head, 4)
		return ok && length >= 12 && length <= 16*1024*1024 && length%4 == 0
	default:
		return true
	}
}

func confirmMinix(head []byte) bool {
	littlePair, okPair := sliceAt(head, 1024+16, 2)
	v3Pair, okV3 := sliceAt(head, 1024+24, 2)
	swapped := (okPair && (bytes.Equal(littlePair, []byte{0x13, 0x7F}) ||
		bytes.Equal(littlePair, []byte{0x13, 0x8F}) ||
		bytes.Equal(littlePair, []byte{0x24, 0x68}) ||
		bytes.Equal(littlePair, []byte{0x24, 0x78}))) ||
		(okV3 && bytes.Equal(v3Pair, []byte{0x4D, 0x5A}))
	if swapped {
		if okV3 && bytes.Equal(v3Pair, []byte{0x4D, 0x5A}) {
			size, okSize := u16beAt(head, 1024+28)
			log, okLog := u16beAt(head, 1024+12)
			first, okFirst := u16beAt(head, 1024+10)
			return okSize && (size == 1024 || size == 2048 || size == 4096) &&
				okLog && log <= 8 &&
				okFirst && first >= 3
		}
		inodes, okInodes := u16beAt(head, 1024)
		log, okLog := u16beAt(head, 1024+10)
		first, okFirst := u16beAt(head, 1024+8)
		return okInodes && inodes > 0 && okLog && log <= 8 && okFirst && first >= 3
	}
	if okV3 && bytes.Equal(v3Pair, []byte{0x5A, 0x4D}) {
		size, okSize := u16leAt(head, 1024+28)
		log, okLog := u16leAt(head, 1024+12)
		first, okFirst := u16leAt(head, 1024+10)
		return okSize && (size == 1024 || size == 2048 || size == 4096) &&
			okLog && log <= 8 &&
			okFirst && first >= 3
	}
	log, okLog := u16leAt(head, 1024+10)
	first, okFirst := u16leAt(head, 1024+8)
	return okLog && log <= 8 && okFirst && first >= 3
}

func confirmQNX6(head []byte) bool {
	little := []byte{0x22, 0x11, 0x19, 0x68}
	big := []byte{0x68, 0x19, 0x11, 0x22}
	order := func(offset int) (bigOrder bool, ok bool) {
		magic, ok := sliceAt(head, offset, 4)
		if !ok {
			return false, false
		}
		if bytes.Equal(magic, little) {
			return false, true
		}
		if bytes.Equal(magic, big) {
			return true, true
		}
		return false, false
	}
	check := func(blockSize, blocks uint32, okBlock, okBlocks bool) bool {
		return okBlock && blockSize >= 512 && blockSize <= 4096 && scanPow2U32(blockSize) &&
			okBlocks && blocks > 0
	}

	bigOrder, ok8 := order(8192)
	if ok8 {
		if bigOrder {
			blockSize, okBlock := u32beAt(head, 0x2030)
			blocks, okBlocks := u32beAt(head, 0x203C)
			return check(blockSize, blocks, okBlock, okBlocks)
		}
		blockSize, okBlock := u32leAt(head, 0x2030)
		blocks, okBlocks := u32leAt(head, 0x203C)
		return check(blockSize, blocks, okBlock, okBlocks)
	}
	bigOrder, ok0 := order(0)
	if ok0 {
		if bigOrder {
			blockSize, okBlock := u32beAt(head, 0x28)
			blocks, okBlocks := u32beAt(head, 0x34)
			return check(blockSize, blocks, okBlock, okBlocks)
		}
		blockSize, okBlock := u32leAt(head, 0x28)
		blocks, okBlocks := u32leAt(head, 0x34)
		return check(blockSize, blocks, okBlock, okBlocks)
	}
	return false
}

// volumeLength returns the length a volume states for itself, with the field
// it came from.  The bool is false when the format has no field this slice
// trusts (LUKS describes its payload, not its extent; UFS needs its
// superblock's byte order; BitLocker keeps its size in metadata not decoded
// yet).
func volumeLength(id string, head []byte) (uint64, string, bool) {
	// sized mirrors the Rust `sized` closure: zero or absent means no length
	// is reported.
	sized := func(value uint64, ok bool, basis string) (uint64, string, bool) {
		if !ok || value == 0 {
			return 0, "", false
		}
		return value, basis, true
	}

	switch id {
	case "ntfs-volume":
		sectors, okSectors := u64leAt(head, 40)
		bytesPerSector, okSector := u16leAt(head, 11)
		if !okSectors || !okSector || !isSectorSize(bytesPerSector) {
			return 0, "", false
		}
		value, ok := scanMul(sectors, uint64(bytesPerSector))
		return sized(value, ok, "total sectors x bytes per sector")
	case "exfat-volume":
		shift, okShift := byteAt(head, 108)
		if !okShift || shift > 12 {
			return 0, "", false
		}
		length, okLength := u64leAt(head, 72)
		if !okLength {
			return 0, "", false
		}
		value, ok := scanShl(length, uint32(shift))
		return sized(value, ok, "volume length x sector size")
	case "fat-volume":
		bytesPerSector, okSector := u16leAt(head, 11)
		if !okSector || !isSectorSize(bytesPerSector) {
			return 0, "", false
		}
		var sectors uint64
		var ok bool
		if sectors16, ok16 := u16leAt(head, 19); ok16 && sectors16 != 0 {
			sectors, ok = uint64(sectors16), true
		} else if sectors32, ok32 := u32leAt(head, 32); ok32 {
			sectors, ok = uint64(sectors32), true
		}
		if !ok {
			return 0, "", false
		}
		value, ok := scanMul(sectors, uint64(bytesPerSector))
		return sized(value, ok, "total sectors x bytes per sector")
	case "ext-volume":
		log, okLog := u32leAt(head, 1024+24)
		if !okLog || log > 6 {
			return 0, "", false
		}
		blocks, okBlocks := u32leAt(head, 1024+4)
		if !okBlocks {
			return 0, "", false
		}
		value, ok := scanMul(uint64(blocks), uint64(1024)<<log)
		return sized(value, ok, "block count x block size")
	case "xfs-volume":
		blockSize, okBlock := u32beAt(head, 4)
		blocks, okBlocks := u64beAt(head, 8)
		if !okBlock || !okBlocks {
			return 0, "", false
		}
		value, ok := scanMul(blocks, uint64(blockSize))
		return sized(value, ok, "dblocks x block size")
	case "btrfs-volume":
		totalBytes, ok := u64leAt(head, 65536+112)
		return sized(totalBytes, ok, "total_bytes")
	case "apfs-volume":
		blockSize, okBlock := u32leAt(head, 36)
		blocks, okBlocks := u64leAt(head, 40)
		if !okBlock || !okBlocks {
			return 0, "", false
		}
		value, ok := scanMul(blocks, uint64(blockSize))
		return sized(value, ok, "block count x block size")
	case "hfs-volume":
		blockSize, okBlock := u32beAt(head, 1024+40)
		blocks, okBlocks := u32beAt(head, 1024+44)
		if !okBlock || !okBlocks {
			return 0, "", false
		}
		value, ok := scanMul(uint64(blocks), uint64(blockSize))
		return sized(value, ok, "total blocks x block size")
	case "hfs-classic-volume":
		allocationStart, okStart := u16beAt(head, 1024+28)
		blockSize, okBlock := u32beAt(head, 1024+20)
		blocks, okBlocks := u16beAt(head, 1024+18)
		if !okStart || !okBlock || !okBlocks {
			return 0, "", false
		}
		startBytes, okStartMul := scanMul(uint64(allocationStart), 512)
		areaBytes, okAreaMul := scanMul(uint64(blocks), uint64(blockSize))
		if !okStartMul || !okAreaMul {
			return 0, "", false
		}
		value, ok := scanAdd(startBytes, areaBytes)
		return sized(value, ok, "allocation start + block count x block size")
	case "iso-volume":
		blockSize, okBlock := u16beAt(head, 0x8000+130)
		blocks, okBlocks := u32beAt(head, 0x8000+84)
		if !okBlock || !okBlocks {
			return 0, "", false
		}
		value, ok := scanMul(uint64(blocks), uint64(blockSize))
		return sized(value, ok, "volume space size x logical block size")
	case "squashfs-volume":
		bytesUsed, ok := u64leAt(head, 40)
		return sized(bytesUsed, ok, "bytes used")
	case "cramfs-volume":
		size, ok := u32leAt(head, 4)
		return sized(uint64(size), ok, "image size")
	case "erofs-volume":
		bits, okBits := byteAt(head, 1024+12)
		blocks, okBlocks := u32leAt(head, 1024+36)
		if !okBits || bits < 9 || bits > 16 || !okBlocks {
			return 0, "", false
		}
		value, ok := scanMul(uint64(blocks), uint64(1)<<bits)
		return sized(value, ok, "blocks x block size")
	case "reiserfs-volume":
		blocks, okBlocks := u32leAt(head, 8*1024)
		blockSize, okBlock := u16leAt(head, 8*1024+0x2C)
		if !okBlocks || !okBlock {
			return 0, "", false
		}
		value, ok := scanMul(uint64(blocks), uint64(blockSize))
		return sized(value, ok, "block count x block size")
	case "jfs-volume":
		sizeRaw, okSize := u64leAt(head, 0x8008)
		shift, okShift := u16leAt(head, 0x8016)
		blockSize, okBlock := u32leAt(head, 0x8010)
		if !okSize || !okShift || shift > 16 || !okBlock {
			return 0, "", false
		}
		value, ok := scanMul(sizeRaw>>shift, uint64(blockSize))
		return sized(value, ok, "aggregate blocks x block size")
	case "minix-volume":
		return minixVolumeLength(head)
	case "befs-volume":
		magic, ok := sliceAt(head, 512+32, 4)
		if !ok || !bytes.Equal(magic, []byte{0x31, 0x53, 0x46, 0x42}) {
			return 0, "", false
		}
		blocksRaw, okBlocks := sl64leAt(head, 512+48)
		blockSize, okBlock := u32leAt(head, 512+40)
		if !okBlocks || blocksRaw <= 0 || !okBlock {
			return 0, "", false
		}
		value, ok := scanMul(uint64(blocksRaw), uint64(blockSize))
		return sized(value, ok, "block count x block size")
	case "ocfs2-volume":
		var value uint64
		found := false
		for _, blockSize := range []int{512, 1024, 2048, 4096} {
			at := 2 * blockSize
			magic, ok := sliceAt(head, at, 6)
			if !ok || !bytes.Equal(magic, []byte("OCFSV2")) {
				continue
			}
			clusters, okClusters := u32leAt(head, at+0x14)
			shift, okShift := u32leAt(head, at+0xC0+0x3C)
			if okClusters && okShift && shift >= 12 && shift <= 20 {
				value, found = scanShl(uint64(clusters), shift)
			}
			break
		}
		return sized(value, found, "clusters x cluster size")
	case "qnx6-volume":
		return qnx6VolumeLength(head)
	case "hpfs-volume":
		sectors, ok := u32leAt(head, 0x2000+0x10)
		if !ok {
			return 0, "", false
		}
		value, ok := scanMul(uint64(sectors), 512)
		return sized(value, ok, "volume sectors x sector size")
	default:
		return 0, "", false
	}
}

// minixVolumeLength handles the two zone-count spellings and the V3 layout.
func minixVolumeLength(head []byte) (uint64, string, bool) {
	blockSize := func(size, log uint16) (uint64, bool) {
		if log > 8 {
			return 0, false
		}
		return scanShl(uint64(size), uint32(log))
	}
	v3Pair, okV3 := sliceAt(head, 1024+24, 2)
	isV3 := okV3 && bytes.Equal(v3Pair, []byte{0x5A, 0x4D})

	var zones uint64
	var okZones bool
	var zoneSize uint64
	var okSize bool
	if isV3 {
		zones32, ok := u32leAt(head, 1024+20)
		zones, okZones = uint64(zones32), ok
		size, okS := u16leAt(head, 1024+28)
		log, okL := u16leAt(head, 1024+12)
		if okS && okL {
			zoneSize, okSize = blockSize(size, log)
		}
	} else {
		magic, okMagic := u16leAt(head, 1024+16)
		zones16, ok16 := u16leAt(head, 1024+2)
		zones32, ok32 := u32leAt(head, 1024+20)
		switch {
		case okMagic && (magic == 0x137F || magic == 0x138F):
			if ok16 && zones16 != 0 {
				zones, okZones = uint64(zones16), true
			} else if ok32 {
				zones, okZones = uint64(zones32), true
			}
		case okMagic && (magic == 0x2468 || magic == 0x2478):
			if ok32 && zones32 != 0 {
				zones, okZones = uint64(zones32), true
			} else if ok16 {
				zones, okZones = uint64(zones16), true
			}
		}
		log, okL := u16leAt(head, 1024+10)
		if okL {
			zoneSize, okSize = blockSize(1024, log)
		}
	}
	if !okZones || !okSize {
		return 0, "", false
	}
	value, ok := scanMul(zones, zoneSize)
	if !ok || value == 0 {
		return 0, "", false
	}
	return value, "zones x zone size", true
}

func qnx6VolumeLength(head []byte) (uint64, string, bool) {
	little := []byte{0x22, 0x11, 0x19, 0x68}
	big := []byte{0x68, 0x19, 0x11, 0x22}

	var base uint64
	var orderBig bool
	var boot uint64
	switch {
	case sliceEqualAt(head, 0x2000, little):
		base, orderBig, boot = 0x2000, false, 0x2000
	case sliceEqualAt(head, 0x2000, big):
		base, orderBig, boot = 0x2000, true, 0x2000
	case sliceEqualAt(head, 0, little):
		base, orderBig, boot = 0, false, 0
	case sliceEqualAt(head, 0, big):
		base, orderBig, boot = 0, true, 0
	default:
		return 0, "", false
	}

	field32 := func(offset uint64) (uint32, bool) {
		if orderBig {
			return u32beAt(head, int(offset))
		}
		return u32leAt(head, int(offset))
	}
	var blockSizeAt, blocksAt uint64
	if base == 0 {
		blockSizeAt, blocksAt = base+0x28, base+0x34
	} else {
		blockSizeAt, blocksAt = base+0x30, base+0x3C
	}
	blockSize, okSize := field32(blockSizeAt)
	blocks, okBlocks := field32(blocksAt)
	if !okSize || !okBlocks ||
		blockSize < 512 || blockSize > 4096 || !scanPow2U32(blockSize) ||
		blocks == 0 {
		return 0, "", false
	}
	size := uint64(blockSize)
	if 0x1000%size != 0 || boot%size != 0 {
		return 0, "", false
	}
	bootBlocks := boot / size
	superBlocks := uint64(0x1000) / size
	total, ok := scanAdd(bootBlocks, superBlocks)
	if !ok {
		return 0, "", false
	}
	total, ok = scanAdd(total, uint64(blocks))
	if !ok {
		return 0, "", false
	}
	total, ok = scanAdd(total, 1)
	if !ok {
		return 0, "", false
	}
	value, ok := scanMul(total, size)
	if !ok || value == 0 {
		return 0, "", false
	}
	return value, "device blocks including the backup superblock x block size", true
}

// The helpers below read little- or big-endian fields without panicking on a
// short head, mirroring the Rust Option-returning accessors.

func byteAt(data []byte, offset int) (byte, bool) {
	if offset < 0 || offset >= len(data) {
		return 0, false
	}
	return data[offset], true
}

func sliceAt(data []byte, offset, length int) ([]byte, bool) {
	if offset < 0 || length < 0 || offset+length > len(data) {
		return nil, false
	}
	return data[offset : offset+length], true
}

func sliceEqualAt(data []byte, offset int, want []byte) bool {
	got, ok := sliceAt(data, offset, len(want))
	return ok && bytes.Equal(got, want)
}

func u16leAt(data []byte, offset int) (uint16, bool) {
	slice, ok := sliceAt(data, offset, 2)
	if !ok {
		return 0, false
	}
	return uint16(slice[0]) | uint16(slice[1])<<8, true
}

func u32leAt(data []byte, offset int) (uint32, bool) {
	slice, ok := sliceAt(data, offset, 4)
	if !ok {
		return 0, false
	}
	return uint32(slice[0]) | uint32(slice[1])<<8 | uint32(slice[2])<<16 | uint32(slice[3])<<24, true
}

func u64leAt(data []byte, offset int) (uint64, bool) {
	low, ok := u32leAt(data, offset)
	if !ok {
		return 0, false
	}
	high, ok := u32leAt(data, offset+4)
	if !ok {
		return 0, false
	}
	return uint64(low) | uint64(high)<<32, true
}

func sl64leAt(data []byte, offset int) (int64, bool) {
	value, ok := u64leAt(data, offset)
	return int64(value), ok
}

func u16beAt(data []byte, offset int) (uint16, bool) {
	slice, ok := sliceAt(data, offset, 2)
	if !ok {
		return 0, false
	}
	return uint16(slice[0])<<8 | uint16(slice[1]), true
}

func u32beAt(data []byte, offset int) (uint32, bool) {
	slice, ok := sliceAt(data, offset, 4)
	if !ok {
		return 0, false
	}
	return uint32(slice[0])<<24 | uint32(slice[1])<<16 | uint32(slice[2])<<8 | uint32(slice[3]), true
}

func u64beAt(data []byte, offset int) (uint64, bool) {
	high, ok := u32beAt(data, offset)
	if !ok {
		return 0, false
	}
	low, ok := u32beAt(data, offset+4)
	if !ok {
		return 0, false
	}
	return uint64(high)<<32 | uint64(low), true
}

func isSectorSize(value uint16) bool {
	switch value {
	case 256, 512, 1024, 2048, 4096:
		return true
	default:
		return false
	}
}

func scanPow2U32(value uint32) bool { return value != 0 && value&(value-1) == 0 }
func scanPow2U64(value uint64) bool { return value != 0 && value&(value-1) == 0 }

func scanMul(a, b uint64) (uint64, bool) {
	if a != 0 && b > math.MaxUint64/a {
		return 0, false
	}
	return a * b, true
}

func scanAdd(a, b uint64) (uint64, bool) {
	if a > math.MaxUint64-b {
		return 0, false
	}
	return a + b, true
}

func scanShl(value uint64, shift uint32) (uint64, bool) {
	if shift >= 64 {
		return 0, false
	}
	if value > math.MaxUint64>>shift {
		return 0, false
	}
	return value << shift, true
}
