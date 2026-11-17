package ubifs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

// UBI on-media constants.  The two header magics are big-endian byte strings
// that read as "UBI#" and "UBI!".
const (
	ECMagic  uint32 = 0x5542_4923
	VIDMagic uint32 = 0x5542_4921

	// HeaderBytes is the size of both UBI headers.
	HeaderBytes = 64
	// HeaderCRCBytes is the prefix each header CRC covers.
	HeaderCRCBytes = HeaderBytes - 4

	// LayoutVolumeID is UBI's internal volume holding the volume table.
	LayoutVolumeID uint32 = 0x7FFF_EFFF
	// UnusableVolumeID marks PEBs UBI gave up on.
	UnusableVolumeID uint32 = 0x7FFF_FFFF
)

// UBI scan bounds.
const (
	MaxPEBs          uint64 = 65_536
	MaxScanBytes     uint64 = 64 * 1024 * 1024
	maxECCcandidates        = 4096
	maxVTBLRecords          = 4096
	maxVIDVoters            = 64
	maxVolumeName           = 127
	maxLEBSize       uint64 = 64 * 1024 * 1024
	scanChunk               = 1024 * 1024
)

var vtblStrides = [...]int{172, 180}

// VolumeType is a volume's update strategy.
type VolumeType uint8

// UBI volume types.
const (
	VolumeDynamic VolumeType = 1
	VolumeStatic  VolumeType = 2
)

// Label returns the volume type's name.
func (v VolumeType) Label() string {
	switch v {
	case VolumeDynamic:
		return "dynamic"
	case VolumeStatic:
		return "static"
	default:
		return "unknown"
	}
}

func volumeTypeFromRaw(value uint32) (VolumeType, bool) {
	switch value {
	case 1:
		return VolumeDynamic, true
	case 2:
		return VolumeStatic, true
	default:
		return 0, false
	}
}

// EcHeader is an erase-counter header and its CRC state.
type EcHeader struct {
	Offset      uint64
	Version     uint8
	EC          uint64
	ImageSeq    uint64
	StoredCRC   uint32
	ComputedCRC uint32
	Verified    bool
}

// CRCState returns "verified" or "mismatch".
func (h EcHeader) CRCState() string {
	if h.Verified {
		return "verified"
	}
	return "mismatch"
}

// VidHeader is a volume-identifier header and its CRC state.
type VidHeader struct {
	Offset      uint64
	Version     uint8
	VolType     VolumeType
	CopyFlag    bool
	Compat      uint8
	VolID       uint32
	Lnum        uint32
	DataSize    uint32
	UsedEBs     uint32
	DataPad     uint32
	DataCRC     uint32
	Sqnum       uint64
	StoredCRC   uint32
	ComputedCRC uint32
	Verified    bool
}

// CRCState returns "verified" or "mismatch".
func (h VidHeader) CRCState() string {
	if h.Verified {
		return "verified"
	}
	return "mismatch"
}

// VolumeTableEntry is one record of a UBI volume table.
type VolumeTableEntry struct {
	VolID        uint32
	ReservedPEBs uint32
	Alignment    uint32
	DataPad      uint32
	VolType      VolumeType
	UpdMarker    uint32
	Name         string
	Flags        uint8
	Verified     bool
	Offset       uint64
}

// VolumeTable is one parsed copy of the table.
type VolumeTable struct {
	Entries         []VolumeTableEntry
	VerifiedRecords int
	Slots           int
	RecordStride    int
}

// TableState says how the two volume-table copies compare.
type TableState uint8

// Table states.
const (
	TableMissing TableState = iota
	TablePartial
	TableVerified
	TableDisagreement
)

// Label returns the state's report name.
func (s TableState) Label() string {
	switch s {
	case TableMissing:
		return "missing"
	case TablePartial:
		return "partial"
	case TableVerified:
		return "verified"
	case TableDisagreement:
		return "disagreement"
	default:
		return "unknown"
	}
}

// TableReport holds both table copies and their comparison.
type TableReport struct {
	State TableState
	Copy0 *VolumeTable
	Copy1 *VolumeTable
}

// Layout is how LEB bytes map onto the image.
type Layout struct {
	PEBSize    uint64
	PEBCount   uint64
	PageSize   uint64
	OOBSize    uint64
	VIDOffset  uint64
	DataOffset uint64
	LEBSize    uint64
}

// LogicalPEBSize is the bytes of page data in one PEB, OOB removed.
func (l Layout) LogicalPEBSize() uint64 {
	if l.OOBSize == 0 {
		return l.PEBSize
	}
	stride := l.PageSize + l.OOBSize
	return (l.PEBSize / stride) * l.PageSize
}

// ImageOffset translates a logical byte inside a PEB to an image offset,
// skipping OOB bytes.
func (l Layout) ImageOffset(pebStart, logical uint64) uint64 {
	if l.OOBSize == 0 {
		return pebStart + logical
	}
	stride := l.PageSize + l.OOBSize
	page := logical / l.PageSize
	within := logical % l.PageSize
	return pebStart + page*stride + within
}

// Peb is one physical erase block met by the scan.
type Peb struct {
	Index    uint64
	Offset   uint64
	EC       *EcHeader
	VID      *VidHeader
	Bad      bool
	Unmapped bool
}

// ReservedVolume is a UBI-internal volume reported but never mounted.
type ReservedVolume struct {
	VolID uint32
	LEBs  []ReservedLEB
}

// ReservedLEB names a mapped LEB and its PEB's image offset.
type ReservedLEB struct {
	Lnum   uint32
	Offset uint64
}

// VolumeInfo is one user volume the scan found.
type VolumeInfo struct {
	VolID        uint32
	Name         string
	ReservedPEBs uint32
	Alignment    uint32
	DataPad      uint32
	VolType      VolumeType
	Len          uint64
	// UBIFS is true when LEB 0 begins with a valid-looking UBIFS superblock
	// magic.
	UBIFS bool
}

type lebKey struct {
	volID uint32
	lnum  uint32
}

// UbiImage is a scanned UBI image.
type UbiImage struct {
	source         source.ByteSource
	layout         Layout
	pebs           []Peb
	table          TableReport
	volumes        []VolumeInfo
	layoutVolume   *ReservedVolume
	unusableVolume *ReservedVolume
	lebMap         map[lebKey]int

	badBlocks        uint64
	unmappedPEBs     uint64
	staleLEBCopies   uint64
	ecHeaders        uint64
	ecCRCMismatches  uint64
	vidCRCMismatches uint64
	scanTruncated    bool
	refusals         map[string]uint64
}

// HasECMagic reports whether src starts with an erase-counter header.
func HasECMagic(src source.ByteSource) (bool, error) {
	if src.Len() < HeaderBytes {
		return false, nil
	}
	var magic [4]byte
	if err := source.ReadExactAt(src, 0, magic[:]); err != nil {
		return false, err
	}
	return string(magic[:]) == "UBI#", nil
}

// OpenUBI scans a UBI image, measures its geometry and reads both volume-table
// copies.
func OpenUBI(src source.ByteSource) (*UbiImage, error) {
	ecs, truncated, err := scanECHeaders(src)
	if err != nil {
		return nil, err
	}
	verified := make([]EcHeader, 0, len(ecs))
	for _, header := range ecs {
		if header.Verified {
			verified = append(verified, header)
		}
	}
	if len(verified) == 0 {
		return nil, corruptf("erase-block headers were found but none verified: the UBI CRC is wrong or the image is not UBI")
	}
	base := verified[0].Offset
	for _, header := range verified[1:] {
		if header.Offset < base {
			base = header.Offset
		}
	}
	stride, pebCount, strideRefusals, err := deriveStride(src, verified, base, truncated)
	if err != nil {
		return nil, err
	}
	vidOffset, err := detectVIDOffset(src, base, stride, pebCount)
	if err != nil {
		return nil, err
	}
	pageSize, oobSize, dataOffset, err := detectGeometry(src, base, stride, pebCount, vidOffset)
	if err != nil {
		return nil, err
	}
	logicalPEB := stride
	if oobSize != 0 {
		unit := pageSize + oobSize
		logicalPEB = (stride / unit) * pageSize
	}
	if dataOffset >= logicalPEB {
		return nil, corruptf("the UBI data offset %d is outside a %d-byte logical PEB", dataOffset, logicalPEB)
	}
	lebSize := logicalPEB - dataOffset
	if lebSize > maxLEBSize {
		return nil, unsupportedf("the UBI LEB size %d is past the %d-byte reader cap", lebSize, maxLEBSize)
	}
	layout := Layout{
		PEBSize:    stride,
		PEBCount:   pebCount,
		PageSize:   pageSize,
		OOBSize:    oobSize,
		VIDOffset:  vidOffset,
		DataOffset: dataOffset,
		LEBSize:    lebSize,
	}
	image := &UbiImage{
		source:        src,
		layout:        layout,
		pebs:          make([]Peb, 0, pebCount),
		table:         TableReport{State: TableMissing},
		lebMap:        make(map[lebKey]int),
		ecHeaders:     uint64(len(ecs)),
		scanTruncated: truncated,
		refusals:      strideRefusals,
	}
	if image.refusals == nil {
		image.refusals = make(map[string]uint64)
	}
	if err := image.buildPEBs(base); err != nil {
		return nil, err
	}
	image.buildLEBMap()
	if err := image.readVolumeTable(); err != nil {
		return nil, err
	}
	image.buildVolumeList()
	return image, nil
}

// Layout returns the measured geometry.
func (u *UbiImage) Layout() Layout { return u.layout }

// Source returns the scanned source.
func (u *UbiImage) Source() source.ByteSource { return u.source }

// SourceID returns the source's id.
func (u *UbiImage) SourceID() source.ID { return u.source.SourceID() }

// PEBS returns the scanned erase blocks.
func (u *UbiImage) PEBS() []Peb {
	out := make([]Peb, len(u.pebs))
	copy(out, u.pebs)
	return out
}

// Table returns both volume-table copies and their state.
func (u *UbiImage) Table() TableReport { return u.table }

// Volumes returns the user volumes.  It returns nil when the two volume-table
// copies disagree, because choosing one silently is exactly what the report
// must not do.
func (u *UbiImage) Volumes() []VolumeInfo {
	if u.table.State == TableDisagreement {
		return nil
	}
	out := make([]VolumeInfo, len(u.volumes))
	copy(out, u.volumes)
	return out
}

// LayoutVolume returns UBI's layout volume, when mapped.
func (u *UbiImage) LayoutVolume() *ReservedVolume { return u.layoutVolume }

// UnusableVolume returns the volume that marks unusable PEBs, when mapped.
func (u *UbiImage) UnusableVolume() *ReservedVolume { return u.unusableVolume }

// BadBlocks returns PEBs with no valid erase-block header.
func (u *UbiImage) BadBlocks() uint64 { return u.badBlocks }

// UnmappedPEBs returns good PEBs with no valid volume header.
func (u *UbiImage) UnmappedPEBs() uint64 { return u.unmappedPEBs }

// StaleLEBCopies returns superseded copies of a (volume, LEB) pair.
func (u *UbiImage) StaleLEBCopies() uint64 { return u.staleLEBCopies }

// ECCRCMismatches returns erase-block headers whose CRC did not verify.
func (u *UbiImage) ECCRCMismatches() uint64 { return u.ecCRCMismatches }

// VIDCRCMismatches returns volume headers whose CRC did not verify.
func (u *UbiImage) VIDCRCMismatches() uint64 { return u.vidCRCMismatches }

// ScanTruncated reports whether the erase-block search hit its byte cap.
func (u *UbiImage) ScanTruncated() bool { return u.scanTruncated }

// Refusals returns feature/condition counts, sorted by name.
func (u *UbiImage) Refusals() [][2]string {
	names := make([]string, 0, len(u.refusals))
	for name := range u.refusals {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([][2]string, 0, len(names))
	for _, name := range names {
		out = append(out, [2]string{name, fmt.Sprint(u.refusals[name])})
	}
	return out
}

// VolumeLen returns a volume's logical length from its reserved PEB count.
func (u *UbiImage) VolumeLen(volID uint32) (uint64, bool) {
	for _, volume := range u.volumes {
		if volume.VolID == volID {
			return volume.Len, true
		}
	}
	return 0, false
}

// VolumeIsUBIFS reports whether a volume's LEB 0 starts with UBIFS magic.
func (u *UbiImage) VolumeIsUBIFS(volID uint32) bool {
	for _, volume := range u.volumes {
		if volume.VolID == volID {
			return volume.UBIFS
		}
	}
	return false
}

// ImageOffset translates a logical byte in a mapped LEB to its image offset.
func (u *UbiImage) ImageOffset(volID, lnum uint32, logical uint64) (uint64, bool) {
	index, found := u.lebMap[lebKey{volID: volID, lnum: lnum}]
	if !found || logical >= u.layout.LEBSize {
		return 0, false
	}
	peb := u.pebs[index]
	return u.layout.ImageOffset(peb.Offset, u.layout.DataOffset+logical), true
}

// ImageRanges returns image runs that hold a logical LEB range, split wherever
// an OOB gap interrupts it.
func (u *UbiImage) ImageRanges(volID, lnum uint32, logical, length uint64) ([][2]uint64, bool) {
	index, found := u.lebMap[lebKey{volID: volID, lnum: lnum}]
	if !found {
		return nil, false
	}
	if logical > u.layout.LEBSize || length > u.layout.LEBSize-logical {
		return nil, false
	}
	peb := u.pebs[index]
	var runs [][2]uint64
	for done := uint64(0); done < length; {
		at := u.layout.DataOffset + logical + done
		page := at / u.layout.PageSize
		within := at % u.layout.PageSize
		take := length - done
		if remaining := u.layout.PageSize - within; take > remaining {
			take = remaining
		}
		stride := u.layout.PageSize + u.layout.OOBSize
		runs = append(runs, [2]uint64{peb.Offset + page*stride + within, take})
		done += take
	}
	return runs, true
}

// ReadLEB reads from a volume's LEB.  An unmapped LEB is an error, not a read
// of zeros: UBI never wrote it, so calling its bytes zero would invent data.
func (u *UbiImage) ReadLEB(volID, lnum uint32, offset uint64, buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	index, found := u.lebMap[lebKey{volID: volID, lnum: lnum}]
	if !found {
		return corruptf("volume %d LEB %d is not mapped to any PEB", volID, lnum)
	}
	if offset > u.layout.LEBSize || uint64(len(buf)) > u.layout.LEBSize-offset {
		return corruptf("read [%d, +%d) passes LEB %d of volume %d, which is %d bytes",
			offset, len(buf), lnum, volID, u.layout.LEBSize)
	}
	return u.readPEBLogical(u.pebs[index].Offset, u.layout.DataOffset+offset, buf)
}

// Facts returns the reference reader's key/value report.
func (u *UbiImage) Facts() [][2]string {
	layout := u.layout
	facts := [][2]string{
		{"type", "UBI"},
		{"peb_size", fmt.Sprint(layout.PEBSize)},
		{"peb_count", fmt.Sprint(layout.PEBCount)},
		{"page_size", fmt.Sprint(layout.PageSize)},
		{"oob_size", fmt.Sprint(layout.OOBSize)},
		{"vid_offset", fmt.Sprint(layout.VIDOffset)},
		{"data_offset", fmt.Sprint(layout.DataOffset)},
		{"leb_size", fmt.Sprint(layout.LEBSize)},
		{"ec_headers", fmt.Sprint(u.ecHeaders)},
		{"volume_table", u.table.State.Label()},
	}
	if u.table.State == TableDisagreement {
		if u.table.Copy0 != nil {
			facts = append(facts, [2]string{"volume_table_copy0", describeTable(u.table.Copy0)})
		}
		if u.table.Copy1 != nil {
			facts = append(facts, [2]string{"volume_table_copy1", describeTable(u.table.Copy1)})
		}
	}
	if u.layoutVolume != nil {
		facts = append(facts, [2]string{"layout_volume",
			fmt.Sprintf("vol %#x with %d LEB(s)", u.layoutVolume.VolID, len(u.layoutVolume.LEBs))})
	}
	if u.unusableVolume != nil {
		facts = append(facts, [2]string{"unusable_volume",
			fmt.Sprintf("vol %#x with %d PEB(s)", u.unusableVolume.VolID, len(u.unusableVolume.LEBs))})
	}
	for _, volume := range u.volumes {
		name := volume.Name
		if name == "" {
			name = "<unnamed>"
		}
		suffix := ""
		if volume.UBIFS {
			suffix = ", UBIFS"
		}
		facts = append(facts, [2]string{"volume", fmt.Sprintf(
			"vol %d %s (%s, %d PEBs, %d bytes%s)",
			volume.VolID, name, volume.VolType.Label(), volume.ReservedPEBs, volume.Len, suffix)})
	}
	if u.badBlocks > 0 {
		facts = append(facts, [2]string{"bad_blocks", fmt.Sprint(u.badBlocks)})
	}
	if u.unmappedPEBs > 0 {
		facts = append(facts, [2]string{"unmapped_pebs", fmt.Sprint(u.unmappedPEBs)})
	}
	if u.staleLEBCopies > 0 {
		facts = append(facts, [2]string{"stale_leb_copies", fmt.Sprint(u.staleLEBCopies)})
	}
	if u.ecCRCMismatches > 0 {
		facts = append(facts, [2]string{"ec_crc_mismatches", fmt.Sprint(u.ecCRCMismatches)})
	}
	if u.vidCRCMismatches > 0 {
		facts = append(facts, [2]string{"vid_crc_mismatches", fmt.Sprint(u.vidCRCMismatches)})
	}
	if u.scanTruncated {
		facts = append(facts, [2]string{"scan_truncated",
			fmt.Sprintf("the erase-block scan stopped at %d bytes", MaxScanBytes)})
	}
	names := make([]string, 0, len(u.refusals))
	for name := range u.refusals {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		facts = append(facts, [2]string{"refused", fmt.Sprintf("%s (%d)", name, u.refusals[name])})
	}
	return facts
}

func describeTable(table *VolumeTable) string {
	names := make([]string, 0, len(table.Entries))
	for _, entry := range table.Entries {
		name := entry.Name
		if name == "" {
			name = "<unnamed>"
		}
		names = append(names, fmt.Sprintf("vol %d %s (%d PEBs)", entry.VolID, name, entry.ReservedPEBs))
	}
	sort.Strings(names)
	return fmt.Sprintf("%d record(s) verified in %d slots, stride %d: %s",
		table.VerifiedRecords, table.Slots, table.RecordStride, strings.Join(names, ", "))
}

func (u *UbiImage) refuse(name string) {
	u.refusals[name]++
}

func crcHeader(bytes []byte) uint32 {
	return foundation.CRC32Seeded(0xFFFF_FFFF, bytes[:HeaderCRCBytes])
}

func parseEC(offset uint64, bytes []byte) (EcHeader, bool) {
	if len(bytes) < HeaderBytes || string(bytes[:4]) != "UBI#" {
		return EcHeader{}, false
	}
	stored := binary.BigEndian.Uint32(bytes[60:64])
	computed := crcHeader(bytes)
	return EcHeader{
		Offset:      offset,
		Version:     bytes[4],
		EC:          binary.BigEndian.Uint64(bytes[8:16]),
		ImageSeq:    uint64(binary.BigEndian.Uint32(bytes[24:28])),
		StoredCRC:   stored,
		ComputedCRC: computed,
		Verified:    stored == computed,
	}, true
}

func parseVID(offset uint64, bytes []byte) (VidHeader, bool) {
	if len(bytes) < HeaderBytes || string(bytes[:4]) != "UBI!" {
		return VidHeader{}, false
	}
	volType, ok := volumeTypeFromRaw(uint32(bytes[5]))
	if !ok {
		return VidHeader{}, false
	}
	stored := binary.BigEndian.Uint32(bytes[60:64])
	computed := crcHeader(bytes)
	return VidHeader{
		Offset:      offset,
		Version:     bytes[4],
		VolType:     volType,
		CopyFlag:    bytes[6] != 0,
		Compat:      bytes[7],
		VolID:       binary.BigEndian.Uint32(bytes[8:12]),
		Lnum:        binary.BigEndian.Uint32(bytes[12:16]),
		DataSize:    binary.BigEndian.Uint32(bytes[20:24]),
		UsedEBs:     binary.BigEndian.Uint32(bytes[24:28]),
		DataPad:     binary.BigEndian.Uint32(bytes[28:32]),
		DataCRC:     binary.BigEndian.Uint32(bytes[32:36]),
		Sqnum:       binary.BigEndian.Uint64(bytes[40:48]),
		StoredCRC:   stored,
		ComputedCRC: computed,
		Verified:    stored == computed,
	}, true
}

func scanECHeaders(src source.ByteSource) ([]EcHeader, bool, error) {
	var headers []EcHeader
	seen := make(map[uint64]bool)
	truncated := false
	length := src.Len()
	var scanned, offset uint64
	for scanned < MaxScanBytes && offset < length {
		take := uint64(scanChunk)
		if remaining := length - offset; take > remaining {
			take = remaining
		}
		chunk := make([]byte, int(take))
		if err := source.ReadExactAt(src, offset, chunk); err != nil {
			break
		}
		start := 0
		for start < len(chunk) {
			found := bytes.Index(chunk[start:], []byte("UBI#"))
			if found < 0 {
				break
			}
			at := offset + uint64(start+found)
			var headerBytes [HeaderBytes]byte
			if err := source.ReadExactAt(src, at, headerBytes[:]); err == nil {
				if header, ok := parseEC(at, headerBytes[:]); ok {
					if !seen[at] {
						seen[at] = true
						headers = append(headers, header)
					}
					if len(headers) >= maxECCcandidates {
						truncated = true
						break
					}
				}
			}
			start += found + 4
		}
		if len(headers) >= maxECCcandidates {
			break
		}
		step := take
		if take > 4 {
			step = take - 3
		}
		scanned += step
		offset += step
	}
	if scanned >= MaxScanBytes && offset < length {
		truncated = true
	}
	return headers, truncated, nil
}

func gcd(left, right uint64) uint64 {
	for right != 0 {
		left, right = right, left%right
	}
	return left
}

func deriveStride(src source.ByteSource, verified []EcHeader, base uint64, scanTruncated bool) (uint64, uint64, map[string]uint64, error) {
	refusals := make(map[string]uint64)
	offsets := make([]uint64, 0, len(verified))
	for _, header := range verified {
		offsets = append(offsets, header.Offset)
	}
	sort.Slice(offsets, func(left, right int) bool { return offsets[left] < offsets[right] })
	unique := offsets[:0]
	for _, offset := range offsets {
		if len(unique) == 0 || unique[len(unique)-1] != offset {
			unique = append(unique, offset)
		}
	}
	offsets = unique
	if len(offsets) < 2 {
		return 0, 0, nil, corruptf("only one erase-block header verified; the PEB stride cannot be measured")
	}
	diffs := make([]uint64, 0, len(offsets)-1)
	for index := 1; index < len(offsets); index++ {
		diff := offsets[index] - offsets[index-1]
		if diff >= HeaderBytes {
			diffs = append(diffs, diff)
		}
	}
	if len(diffs) == 0 {
		return 0, 0, nil, corruptf("erase-block headers do not repeat at a usable stride")
	}
	minDiff := diffs[0]
	for _, diff := range diffs[1:] {
		if diff < minDiff {
			minDiff = diff
		}
	}
	gcdAll := diffs[0]
	for _, diff := range diffs[1:] {
		gcdAll = gcd(gcdAll, diff)
	}
	candidates := make(map[uint64]bool)
	candidates[minDiff] = true
	if gcdAll >= HeaderBytes {
		candidates[gcdAll] = true
	}
	if minDiff/2 >= HeaderBytes {
		candidates[minDiff/2] = true
	}
	ordered := make([]uint64, 0, len(candidates))
	for stride := range candidates {
		ordered = append(ordered, stride)
	}
	sort.Slice(ordered, func(left, right int) bool { return ordered[left] < ordered[right] })
	var valid [][2]uint64
	for _, stride := range ordered {
		if stride < HeaderBytes {
			continue
		}
		aligned := true
		for _, offset := range offsets {
			if offset < base || (offset-base)%stride != 0 {
				aligned = false
				break
			}
		}
		if !aligned {
			continue
		}
		hits, positions, err := countECAtStride(src, base, stride)
		if err != nil {
			return 0, 0, nil, err
		}
		if hits >= 2 && hits*4 >= positions*3 {
			valid = append(valid, [2]uint64{stride, hits})
		}
	}
	if len(valid) == 0 {
		return 0, 0, nil, corruptf("no PEB stride candidate has a verified erase-block header at every multiple")
	}
	if len(valid) > 1 {
		names := make([]string, 0, len(valid))
		for _, entry := range valid {
			names = append(names, fmt.Sprintf("%d bytes (%d headers)", entry[0], entry[1]))
		}
		return 0, 0, nil, unsupportedf("ambiguous PEB stride: %s all validate; refusing to choose", strings.Join(names, " and "))
	}
	stride := valid[0][0]
	total := (src.Len() - base) / stride
	pebCount := total
	if pebCount > MaxPEBs {
		pebCount = MaxPEBs
		refusals["PEB scan cap reached"]++
	}
	if scanTruncated {
		refusals["erase-block header search stopped at the scan cap"]++
	}
	return stride, pebCount, refusals, nil
}

func countECAtStride(src source.ByteSource, base, stride uint64) (uint64, uint64, error) {
	length := src.Len()
	var hits, positions uint64
	for index := uint64(0); index < MaxPEBs; index++ {
		at := base + index*stride
		if at > length || HeaderBytes > length-at {
			break
		}
		positions++
		var bytes [HeaderBytes]byte
		if err := source.ReadExactAt(src, at, bytes[:]); err == nil {
			if header, ok := parseEC(at, bytes[:]); ok && header.Verified {
				hits++
			}
		}
	}
	return hits, positions, nil
}

func detectVIDOffset(src source.ByteSource, base, stride, pebCount uint64) (uint64, error) {
	search := stride
	if search > 4096 {
		search = 4096
	}
	votes := make(map[uint64]uint64)
	voters := pebCount
	if voters > maxVIDVoters {
		voters = maxVIDVoters
	}
	for index := uint64(0); index < voters; index++ {
		pebStart := base + index*stride
		for offset := uint64(HeaderBytes); offset+HeaderBytes <= search; offset++ {
			at := pebStart + offset
			if at > src.Len() || HeaderBytes > src.Len()-at {
				break
			}
			var bytes [HeaderBytes]byte
			if err := source.ReadExactAt(src, at, bytes[:]); err == nil && string(bytes[:4]) == "UBI!" {
				if header, ok := parseVID(at, bytes[:]); ok && header.Verified {
					votes[offset]++
					break
				}
			}
		}
	}
	if len(votes) == 0 {
		return 0, corruptf("no verified volume header was found in the first PEBs")
	}
	if len(votes) > 1 {
		offsets := make([]uint64, 0, len(votes))
		for offset := range votes {
			offsets = append(offsets, offset)
		}
		sort.Slice(offsets, func(left, right int) bool { return offsets[left] < offsets[right] })
		names := make([]string, 0, len(offsets))
		for _, offset := range offsets {
			names = append(names, fmt.Sprintf("%d (%d PEBs)", offset, votes[offset]))
		}
		return 0, unsupportedf("ambiguous VID header offset: %s; refusing to choose", strings.Join(names, " and "))
	}
	for offset := range votes {
		return offset, nil
	}
	return 0, corruptf("no verified volume header offset")
}

type geometry struct {
	pageSize uint64
	oobSize  uint64
}

func detectGeometry(src source.ByteSource, base, stride, pebCount, vidOffset uint64) (uint64, uint64, uint64, error) {
	geometries := make(map[geometry]bool)
	geometries[geometry{pageSize: stride}] = true
	for _, page := range []uint64{512, 1024, 2048, 4096, 8192, 16384} {
		for _, oob := range []uint64{16, 32, 64, 128, 224, 256, 512} {
			unit := page + oob
			if stride%unit != 0 {
				continue
			}
			pages := stride / unit
			if pages >= 2 && pages <= 4096 {
				geometries[geometry{pageSize: page, oobSize: oob}] = true
			}
		}
	}
	keys := make([]geometry, 0, len(geometries))
	for key := range geometries {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		if keys[left].pageSize != keys[right].pageSize {
			return keys[left].pageSize < keys[right].pageSize
		}
		return keys[left].oobSize < keys[right].oobSize
	})
	type candidate struct {
		page       uint64
		oob        uint64
		dataOffset uint64
		score      uint32
	}
	var candidates []candidate
	for _, key := range keys {
		logicalPEB := stride
		if key.oobSize != 0 {
			unit := key.pageSize + key.oobSize
			logicalPEB = (stride / unit) * key.pageSize
		}
		lowest := vidOffset + HeaderBytes
		highest := logicalPEB
		if lowest+64*1024 < highest {
			highest = lowest + 64*1024
		}
		offsets := make(map[uint64]bool)
		for at := lowest; at+4096 <= highest; at += 512 {
			offsets[at] = true
		}
		first := (lowest + 511) / 512 * 512
		for at := first; at+4096 <= highest; at += 512 {
			offsets[at] = true
		}
		ordered := make([]uint64, 0, len(offsets))
		for offset := range offsets {
			ordered = append(ordered, offset)
		}
		sort.Slice(ordered, func(left, right int) bool { return ordered[left] < ordered[right] })
		for _, dataOffset := range ordered {
			score, err := scoreGeometry(src, base, stride, pebCount, vidOffset, key, dataOffset)
			if err != nil {
				return 0, 0, 0, err
			}
			if score > 0 {
				candidates = append(candidates, candidate{
					page: key.pageSize, oob: key.oobSize, dataOffset: dataOffset, score: score,
				})
			}
		}
	}
	if len(candidates) == 0 {
		return 0, 0, 0, corruptf("no data offset made either a volume-table record or a UBIFS superblock verify; the image's LEB data offset cannot be established")
	}
	sort.SliceStable(candidates, func(left, right int) bool { return candidates[left].score > candidates[right].score })
	bestScore := candidates[0].score
	type mapping [3]uint64
	mappings := make(map[mapping]bool)
	descriptions := make(map[[3]uint64]bool)
	for _, candidate := range candidates {
		if candidate.score != bestScore {
			continue
		}
		logical := stride
		if candidate.oob != 0 {
			unit := candidate.page + candidate.oob
			logical = (stride / unit) * candidate.page
		}
		mappings[mapping{logical, candidate.oob, candidate.dataOffset}] = true
		descriptions[mapping{candidate.page, candidate.oob, candidate.dataOffset}] = true
	}
	if len(mappings) > 1 {
		names := make([]string, 0, len(descriptions))
		for key := range descriptions {
			names = append(names, fmt.Sprintf("page %d OOB %d data offset %d", key[0], key[1], key[2]))
		}
		sort.Strings(names)
		return 0, 0, 0, unsupportedf("ambiguous UBI geometry: %s all verify structures; refusing to choose", strings.Join(names, " and "))
	}
	best := candidates[0]
	return best.page, best.oob, best.dataOffset, nil
}

func scoreGeometry(src source.ByteSource, base, stride, pebCount, vidOffset uint64, geometry geometry, dataOffset uint64) (uint32, error) {
	logicalPEB := stride
	if geometry.oobSize != 0 {
		unit := geometry.pageSize + geometry.oobSize
		logicalPEB = (stride / unit) * geometry.pageSize
	}
	if dataOffset >= logicalPEB {
		return 0, nil
	}
	lebSize := logicalPEB - dataOffset
	if lebSize < 4096 {
		return 0, nil
	}
	layout := Layout{
		PEBSize: stride, PEBCount: pebCount,
		PageSize: geometry.pageSize, OOBSize: geometry.oobSize,
		VIDOffset: vidOffset, DataOffset: dataOffset, LEBSize: lebSize,
	}
	var score uint32
	voters := pebCount
	if voters > 16 {
		voters = 16
	}
	checkedSuperblock := false
	for index := uint64(0); index < voters; index++ {
		pebStart := base + index*stride
		vidAt := layout.ImageOffset(pebStart, vidOffset)
		var header [HeaderBytes]byte
		if vidAt > src.Len() || HeaderBytes > src.Len()-vidAt {
			continue
		}
		if err := source.ReadExactAt(src, vidAt, header[:]); err != nil {
			continue
		}
		vid, ok := parseVID(vidAt, header[:])
		if !ok || !vid.Verified {
			continue
		}
		if vid.VolID == LayoutVolumeID {
			readLen := lebSize
			if readLen > 4096 {
				readLen = 4096
			}
			bytes := make([]byte, int(readLen))
			if err := readPEBLogical(src, layout, pebStart, dataOffset, bytes); err == nil {
				for _, stride := range vtblStrides {
					table := parseVolumeTableWith(bytes, stride)
					score += uint32(table.VerifiedRecords) * 4
				}
			}
		} else if vid.Lnum == 0 && !checkedSuperblock {
			bytes := make([]byte, 4096)
			if err := readPEBLogical(src, layout, pebStart, dataOffset, bytes); err == nil &&
				looksLikeUBIFSSuperblock(bytes) {
				score += 20
				checkedSuperblock = true
			}
		}
	}
	return score, nil
}

func readPEBLogical(src source.ByteSource, layout Layout, pebStart, logical uint64, buf []byte) error {
	logicalPEB := layout.LogicalPEBSize()
	if logical > logicalPEB || uint64(len(buf)) > logicalPEB-logical {
		return corruptf("logical offset %d with %d bytes is outside a %d-byte PEB", logical, len(buf), logicalPEB)
	}
	for done := 0; done < len(buf); {
		at := logical + uint64(done)
		page := at / layout.PageSize
		within := at % layout.PageSize
		take := len(buf) - done
		if remaining := int(layout.PageSize - within); take > remaining {
			take = remaining
		}
		stride := layout.PageSize + layout.OOBSize
		physical := pebStart + page*stride + within
		if physical > src.Len() || uint64(take) > src.Len()-physical {
			return source.NewUnexpectedEOF(physical)
		}
		if err := source.ReadExactAt(src, physical, buf[done:done+take]); err != nil {
			return err
		}
		done += take
	}
	return nil
}

func parseVolumeTable(bytes []byte) *VolumeTable {
	var best *VolumeTable
	for _, stride := range vtblStrides {
		table := parseVolumeTableWith(bytes, stride)
		if table.VerifiedRecords == 0 {
			continue
		}
		if best == nil || table.VerifiedRecords > best.VerifiedRecords {
			best = &table
		}
	}
	return best
}

func parseVolumeTableWith(bytes []byte, stride int) VolumeTable {
	table := VolumeTable{RecordStride: stride, Slots: len(bytes) / stride}
	crcOffset := stride - 4
	if crcOffset < 24 || table.Slots == 0 {
		return table
	}
	limit := table.Slots
	if limit > maxVTBLRecords {
		limit = maxVTBLRecords
	}
	for slot := 0; slot < limit; slot++ {
		at := slot * stride
		record := bytes[at : at+stride]
		allZero := true
		for _, value := range record {
			if value != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			continue
		}
		stored := binary.BigEndian.Uint32(record[crcOffset : crcOffset+4])
		computed := foundation.CRC32Seeded(0xFFFF_FFFF, record[:crcOffset])
		if stored != computed {
			continue
		}
		table.VerifiedRecords++
		reserved := binary.BigEndian.Uint32(record[0:4])
		alignment := binary.BigEndian.Uint32(record[4:8])
		dataPad := binary.BigEndian.Uint32(record[8:12])
		rawType := binary.BigEndian.Uint32(record[12:16])
		updMarker := binary.BigEndian.Uint32(record[16:20])
		nameLen := int(binary.BigEndian.Uint32(record[20:24]))
		if nameLen > maxVolumeName {
			nameLen = maxVolumeName
		}
		nameEnd := 24 + nameLen
		if nameEnd > 152 {
			nameEnd = 152
		}
		name := strings.ToValidUTF8(string(record[24:nameEnd]), "�")
		flags := record[152]
		volType, ok := volumeTypeFromRaw(rawType)
		if !ok || reserved == 0 {
			continue
		}
		table.Entries = append(table.Entries, VolumeTableEntry{
			VolID: uint32(slot), ReservedPEBs: reserved, Alignment: alignment,
			DataPad: dataPad, VolType: volType, UpdMarker: updMarker,
			Name: name, Flags: flags, Verified: true, Offset: uint64(at),
		})
	}
	return table
}

func looksLikeUBIFSSuperblock(bytes []byte) bool {
	if len(bytes) != 4096 {
		return false
	}
	if binary.LittleEndian.Uint32(bytes[0:4]) != Magic {
		return false
	}
	stored := binary.LittleEndian.Uint32(bytes[4:8])
	length := binary.LittleEndian.Uint32(bytes[16:20])
	return length == 4096 && bytes[20] == nodeSuperblock &&
		stored == foundation.CRC32Seeded(0xFFFF_FFFF, bytes[8:])
}

func sameVolumes(first, second *VolumeTable) bool {
	if len(first.Entries) != len(second.Entries) {
		return false
	}
	for index := range first.Entries {
		left, right := first.Entries[index], second.Entries[index]
		if left.VolID != right.VolID || left.ReservedPEBs != right.ReservedPEBs ||
			left.Alignment != right.Alignment || left.DataPad != right.DataPad ||
			left.VolType != right.VolType || left.UpdMarker != right.UpdMarker ||
			left.Name != right.Name || left.Flags != right.Flags {
			return false
		}
	}
	return true
}

func (u *UbiImage) buildPEBs(base uint64) error {
	length := u.source.Len()
	for index := uint64(0); index < u.layout.PEBCount; index++ {
		offset := base + index*u.layout.PEBSize
		if offset >= length {
			break
		}
		var header [HeaderBytes]byte
		var ec *EcHeader
		if err := source.ReadExactAt(u.source, offset, header[:]); err == nil {
			if parsed, ok := parseEC(offset, header[:]); ok {
				ec = &parsed
			}
		}
		bad := true
		if ec != nil {
			if ec.Verified {
				bad = false
			} else {
				u.ecCRCMismatches++
				u.refuse("erase-block header CRC mismatch")
			}
		}
		var vid *VidHeader
		if !bad {
			var videoBytes [HeaderBytes]byte
			at := u.layout.ImageOffset(offset, u.layout.VIDOffset)
			if at <= length && HeaderBytes <= length-at {
				if err := source.ReadExactAt(u.source, at, videoBytes[:]); err == nil {
					if parsed, ok := parseVID(at, videoBytes[:]); ok {
						if parsed.Verified {
							vid = &parsed
						} else {
							u.vidCRCMismatches++
							u.refuse("volume header CRC mismatch")
						}
					}
				}
			}
		}
		unmapped := !bad && vid == nil
		if bad {
			u.badBlocks++
			u.refuse("bad erase block (no valid erase-block header)")
		} else if unmapped {
			u.unmappedPEBs++
		}
		u.pebs = append(u.pebs, Peb{
			Index: index, Offset: offset, EC: ec, VID: vid, Bad: bad, Unmapped: unmapped,
		})
	}
	return nil
}

func (u *UbiImage) buildLEBMap() {
	equalConflicts := uint64(0)
	for index, peb := range u.pebs {
		if peb.VID == nil || !peb.VID.Verified {
			continue
		}
		key := lebKey{volID: peb.VID.VolID, lnum: peb.VID.Lnum}
		previous, found := u.lebMap[key]
		if !found {
			u.lebMap[key] = index
			continue
		}
		previousSqnum := uint64(0)
		if u.pebs[previous].VID != nil {
			previousSqnum = u.pebs[previous].VID.Sqnum
		}
		if peb.VID.Sqnum > previousSqnum {
			u.staleLEBCopies++
			u.lebMap[key] = index
		} else if peb.VID.Sqnum == previousSqnum {
			equalConflicts++
		} else {
			u.staleLEBCopies++
		}
	}
	if equalConflicts > 0 {
		u.refuse("duplicate LEB sequence number")
	}
}

func (u *UbiImage) readVolumeTable() error {
	var copy0, copy1 *VolumeTable
	for slot, lnum := range []uint32{0, 1} {
		index, found := u.lebMap[lebKey{volID: LayoutVolumeID, lnum: lnum}]
		if !found {
			continue
		}
		peb := u.pebs[index]
		bytes := make([]byte, int(u.layout.LEBSize))
		if err := u.readPEBLogical(peb.Offset, u.layout.DataOffset, bytes); err != nil {
			continue
		}
		table := parseVolumeTable(bytes)
		if slot == 0 {
			copy0 = table
		} else {
			copy1 = table
		}
	}
	state := TableMissing
	switch {
	case copy0 == nil && copy1 == nil:
		state = TableMissing
	case copy0 == nil || copy1 == nil:
		state = TablePartial
	case sameVolumes(copy0, copy1):
		state = TableVerified
	default:
		state = TableDisagreement
	}
	if state == TableDisagreement {
		u.refuse("volume-table copies disagree")
	}
	if state == TableMissing {
		u.refuse("volume table is missing from both layout-volume LEBs")
	}
	u.table = TableReport{State: state, Copy0: copy0, Copy1: copy1}
	return nil
}

func (u *UbiImage) readPEBLogical(pebStart, logical uint64, buf []byte) error {
	return readPEBLogical(u.source, u.layout, pebStart, logical, buf)
}

func (u *UbiImage) buildVolumeList() {
	byID := make(map[uint32]VolumeInfo)
	if u.table.State != TableDisagreement {
		var table *VolumeTable
		switch u.table.State {
		case TableVerified, TablePartial:
			if u.table.Copy0 != nil {
				table = u.table.Copy0
			} else {
				table = u.table.Copy1
			}
		}
		if table != nil {
			for _, entry := range table.Entries {
				if entry.ReservedPEBs == 0 || entry.VolID >= LayoutVolumeID {
					continue
				}
				byID[entry.VolID] = VolumeInfo{
					VolID: entry.VolID, Name: entry.Name, ReservedPEBs: entry.ReservedPEBs,
					Alignment: entry.Alignment, DataPad: entry.DataPad, VolType: entry.VolType,
					Len: uint64(entry.ReservedPEBs) * u.layout.LEBSize,
				}
			}
		}
	}
	seen := make(map[uint32]uint32)
	for key := range u.lebMap {
		if key.volID >= LayoutVolumeID {
			continue
		}
		if key.lnum > seen[key.volID] {
			seen[key.volID] = key.lnum
		}
	}
	ids := make([]uint32, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	for _, id := range ids {
		if _, found := byID[id]; found {
			continue
		}
		u.refuse("volume header names a volume the table does not")
		reserved := seen[id] + 1
		byID[id] = VolumeInfo{
			VolID: id, Name: fmt.Sprintf("volume-%d", id), ReservedPEBs: reserved,
			Alignment: 1, VolType: VolumeDynamic,
			Len: uint64(reserved) * u.layout.LEBSize,
		}
	}
	ids = ids[:0]
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	u.volumes = make([]VolumeInfo, 0, len(ids))
	for _, id := range ids {
		volume := byID[id]
		if index, found := u.lebMap[lebKey{volID: volume.VolID, lnum: 0}]; found {
			peb := u.pebs[index]
			var magic [4]byte
			if err := u.readPEBLogical(peb.Offset, u.layout.DataOffset, magic[:]); err == nil &&
				binary.LittleEndian.Uint32(magic[:]) == Magic {
				volume.UBIFS = true
			}
		}
		u.volumes = append(u.volumes, volume)
	}
	u.layoutVolume = u.reserved(LayoutVolumeID)
	u.unusableVolume = u.reserved(UnusableVolumeID)
}

func (u *UbiImage) reserved(volID uint32) *ReservedVolume {
	var lebs []ReservedLEB
	for key := range u.lebMap {
		if key.volID != volID {
			continue
		}
		index := u.lebMap[key]
		lebs = append(lebs, ReservedLEB{Lnum: key.lnum, Offset: u.pebs[index].Offset})
	}
	sort.Slice(lebs, func(left, right int) bool { return lebs[left].Lnum < lebs[right].Lnum })
	if len(lebs) == 0 {
		return nil
	}
	return &ReservedVolume{VolID: volID, LEBs: lebs}
}
