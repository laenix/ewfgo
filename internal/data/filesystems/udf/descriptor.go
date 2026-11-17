package udf

// Volume-level descriptors: the anchor, the descriptor sequence, the partition
// it describes, the file set, and the integrity record.

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

// AnchorSector is the logical sector of the first anchor, in 2048-byte units.
// ECMA-167 fixes this position for every volume, whatever its block size.
const AnchorSector uint64 = 256

// SectorBytes is the size of that sector.
const SectorBytes uint64 = 2048

// UdfTime is one UDF timestamp.
type UdfTime struct {
	// Seconds since the Unix epoch, already adjusted to UTC.
	Seconds int64
	// Nanoseconds within the second.
	Nanoseconds int32
	// Valid reports whether the twelve bytes decoded to civil fields.
	Valid bool
}

// Time returns the timestamp, or the zero time when it did not decode.
func (t UdfTime) Time() time.Time {
	if !t.Valid {
		return time.Time{}
	}
	return time.Unix(t.Seconds, int64(t.Nanoseconds)).UTC()
}

// UnixNanos returns the timestamp in nanoseconds. It can overflow int64 for
// dates outside roughly 1678..2262; use Time for those.
func (t UdfTime) UnixNanos() int64 {
	if !t.Valid {
		return 0
	}
	return t.Seconds*1_000_000_000 + int64(t.Nanoseconds)
}

// parseUdfTime decodes the twelve-byte form.
//
// The high nibble of the first field is the timestamp type: only type 1 (local
// time) uses the low twelve bits, a signed count of minutes from UTC; -2047
// means "not specified". Types 0 and 2 are already UTC.
//
// The three sub-second fields are only meaningful when all are below 100, each
// a decimal fraction of the next unit.
func parseUdfTime(b []byte) (UdfTime, bool) {
	if len(b) < 12 {
		return UdfTime{}, false
	}
	typeAndZone := le16(b, 0)
	year := int(le16(b, 2))
	month := int(b[4])
	day := int(b[5])
	hour := int(b[6])
	minute := int(b[7])
	second := int(b[8])
	if year == 0 || month == 0 || day == 0 {
		return UdfTime{}, false
	}
	kind := typeAndZone >> 12
	offset := int32(typeAndZone & 0x0FFF)
	if offset&0x0800 != 0 {
		offset -= 0x1000
	}
	offsetMinutes := int32(0)
	if kind == 1 && offset != -2047 {
		offsetMinutes = offset
	}
	seconds, ok := unixSecondsFromCivil(int64(year), month, day, hour, minute, second)
	if !ok {
		return UdfTime{}, false
	}
	seconds -= int64(offsetMinutes) * 60
	var nanos int32
	centi, hundreds, micro := b[9], b[10], b[11]
	if centi < 100 && hundreds < 100 && micro < 100 {
		nanos = int32(centi)*10_000_000 + int32(hundreds)*100_000 + int32(micro)*1_000
	}
	return UdfTime{Seconds: seconds, Nanoseconds: nanos, Valid: true}, true
}

func isLeapYear(year int64) bool {
	return (year%4 == 0 && year%100 != 0) || year%400 == 0
}

func daysInMonth(year int64, month int) int {
	switch month {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	case 2:
		if isLeapYear(year) {
			return 29
		}
		return 28
	default:
		return 0
	}
}

func unixSecondsFromCivil(year int64, month, day, hour, minute, second int) (int64, bool) {
	if month < 1 || month > 12 || day == 0 || day > daysInMonth(year, month) {
		return 0, false
	}
	if hour > 23 || minute > 59 || second > 59 {
		return 0, false
	}
	days := daysFromCivil(year, month, day)
	return days*86400 + int64(hour)*3600 + int64(minute)*60 + int64(second), true
}

// daysFromCivil converts a proleptic Gregorian date to days since 1970-01-01.
func daysFromCivil(year int64, month, day int) int64 {
	if month <= 2 {
		year--
	}
	era := year / 400
	if year < 0 && year%400 != 0 {
		era--
	}
	yoe := year - era*400
	mp := int64(month)
	if mp > 2 {
		mp -= 3
	} else {
		mp += 9
	}
	doy := (153*mp+2)/5 + int64(day) - 1
	doe := yoe*365 + yoe/4 - yoe/100 + doy
	return era*146097 + doe - 719468
}

// dstring decodes a UDF dstring: one compression-identifier byte, then either
// 8-bit characters (compression 8) or UCS-2 big-endian (compression 16).
// Trailing NUL padding is dropped; an unknown scheme is refused.
func dstring(b []byte) (string, bool) {
	if len(b) == 0 {
		return "", false
	}
	compression := b[0]
	rest := b[1:]
	end := len(rest)
	for end > 0 && rest[end-1] == 0 {
		end--
	}
	text := rest[:end]
	switch compression {
	case 8:
		runes := make([]rune, len(text))
		for i, v := range text {
			runes[i] = rune(v)
		}
		return string(runes), true
	case 16:
		if len(text)%2 != 0 {
			return "", false
		}
		units := make([]uint16, 0, len(text)/2)
		for i := 0; i+1 < len(text); i += 2 {
			unit := uint16(text[i])<<8 | uint16(text[i+1])
			if unit != 0 {
				units = append(units, unit)
			}
		}
		return string(utf16.Decode(units)), true
	default:
		return "", false
	}
}

func fieldText(b []byte) string {
	end := len(b)
	for end > 0 && b[end-1] == 0 {
		end--
	}
	runes := make([]rune, end)
	for i := 0; i < end; i++ {
		runes[i] = rune(b[i])
	}
	return string(runes)
}

// RegId is a registered identifier: a one-byte flags field, a 23-byte
// identifier and an 8-byte suffix. The identifier is compared as bytes.
type RegId struct {
	Flags  uint8
	Ident  [23]byte
	Suffix [8]byte
}

// NewRegId parses a registered identifier.
func NewRegId(b []byte) (RegId, bool) {
	if len(b) < 32 {
		return RegId{}, false
	}
	var id RegId
	id.Flags = b[0]
	copy(id.Ident[:], b[1:24])
	copy(id.Suffix[:], b[24:32])
	return id, true
}

// IdentText returns the identifier with trailing NULs removed, decoded as
// Latin-1.
func (r RegId) IdentText() string { return fieldText(r.Ident[:]) }

// SuffixHex returns the suffix as sixteen hex digits.
func (r RegId) SuffixHex() string {
	const digits = "0123456789abcdef"
	out := make([]byte, 16)
	for i, v := range r.Suffix {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&0xF]
	}
	return string(out)
}

// Anchor is the anchor volume descriptor pointer.
type Anchor struct {
	Tag     Tag
	Main    ExtentAd
	Reserve ExtentAd
}

func parseAnchor(b []byte) (Anchor, bool) {
	tag, ok := ParseTag(b)
	if !ok || tag.Ident != TagAVDP {
		return Anchor{}, false
	}
	main, ok := extentAD(b, 16)
	if !ok {
		return Anchor{}, false
	}
	reserve, ok := extentAD(b, 24)
	if !ok {
		return Anchor{}, false
	}
	return Anchor{Tag: tag, Main: main, Reserve: reserve}, true
}

// PrimaryVolume is the primary volume descriptor: the labels a user sees.
type PrimaryVolume struct {
	Tag               Tag
	Sequence          uint32
	Number            uint32
	VolumeID          string
	VolumeSetID       string
	VolumeSequence    uint16
	MaxVolumeSequence uint16
	Recorded          UdfTime
	Flags             uint16
	Application       string
	ApplicationSuffix string
}

func parsePrimary(b []byte) (PrimaryVolume, bool) {
	tag, ok := ParseTag(b)
	if !ok || tag.Ident != TagPVD {
		return PrimaryVolume{}, false
	}
	if len(b) < 376 {
		return PrimaryVolume{}, false
	}
	p := PrimaryVolume{
		Tag:               tag,
		Sequence:          le32(b, 16),
		Number:            le32(b, 20),
		VolumeSequence:    le16(b, 56),
		MaxVolumeSequence: le16(b, 58),
		Flags:             le16(b, 488),
	}
	if p.VolumeID, ok = dstring(b[24:56]); !ok {
		return PrimaryVolume{}, false
	}
	if p.VolumeSetID, ok = dstring(b[72:200]); !ok {
		p.VolumeSetID = ""
	}
	p.Recorded, _ = parseUdfTime(b[376:388])
	if id, ok := NewRegId(b[344:376]); ok {
		p.Application = id.IdentText()
		p.ApplicationSuffix = id.SuffixHex()
	}
	return p, true
}

// Partition is a partition descriptor.
type Partition struct {
	Tag        Tag
	Sequence   uint32
	Flags      uint16
	Number     uint16
	Contents   string
	AccessType uint32
	// Start is the first block of the partition, in volume logical blocks.
	Start uint32
	// Length is the length of the partition, in volume logical blocks.
	Length uint32
	// UnallocatedBitmap is the unallocated space bitmap's short allocation
	// descriptor, as a block within this partition. Nil when none is recorded.
	UnallocatedBitmap *ShortAd
}

// AccessLabel labels the media access type.
func (p Partition) AccessLabel() string {
	switch p.AccessType {
	case 0:
		return "none"
	case 1:
		return "read-only"
	case 2:
		return "write-once"
	case 3:
		return "rewritable"
	case 4:
		return "overwritable"
	default:
		return "unknown"
	}
}

const (
	partitionContentsUse = 56
	phdUnallocatedBitmap = partitionContentsUse + 8
)

func parsePartition(b []byte) (Partition, bool) {
	tag, ok := ParseTag(b)
	if !ok || tag.Ident != TagPD {
		return Partition{}, false
	}
	if len(b) < 196 {
		return Partition{}, false
	}
	p := Partition{
		Tag:        tag,
		Sequence:   le32(b, 16),
		Flags:      le16(b, 20),
		Number:     le16(b, 22),
		AccessType: le32(b, 184),
		Start:      le32(b, 188),
		Length:     le32(b, 192),
	}
	if id, ok := NewRegId(b[24:56]); ok {
		p.Contents = id.IdentText()
	}
	if bitmap, ok := shortAD(b, phdUnallocatedBitmap); ok {
		if bitmap.ExtentLength() != 0 && bitmap.Kind() == ExtRecordedAllocated {
			p.UnallocatedBitmap = &bitmap
		}
	}
	return p, true
}

// PartitionMap is one entry of the logical volume's partition map table.
type PartitionMap struct {
	Kind            uint8
	Length          uint8
	VolumeSequence  uint16
	PartitionNumber uint16
	Ident           [23]byte
	Suffix          [8]byte
	// Metadata is present only for a UDF 2.50 metadata partition map whose
	// entry is long enough to carry its fields.
	Metadata *MetadataMap
}

// IdentText returns the type 2 entity identifier, or "" for other kinds.
func (m PartitionMap) IdentText() string {
	if m.Kind != 2 {
		return ""
	}
	return fieldText(m.Ident[:])
}

// SuffixRevision returns the little-endian revision in a type 2 suffix.
func (m PartitionMap) SuffixRevision() uint16 {
	if m.Kind != 2 {
		return 0
	}
	return uint16(m.Suffix[0]) | uint16(m.Suffix[1])<<8
}

// MetadataMap holds the UDF 2.50 fields a metadata partition map carries.
type MetadataMap struct {
	FileBlock      uint32
	MirrorBlock    uint32
	BitmapBlock    uint32
	AllocationUnit uint32
	AlignmentUnit  uint16
	Duplicate      bool
}

var metadataIdent = []byte("*UDF Metadata Partition")

// LogicalVolume is the logical volume descriptor.
type LogicalVolume struct {
	Tag            Tag
	Sequence       uint32
	VolumeID       string
	BlockSize      uint32
	Domain         string
	DomainSuffix   string
	DomainFlags    uint8
	ContentsUse    [16]byte
	MapTableLength uint32
	MapCount       uint32
	Integrity      ExtentAd
	Maps           []PartitionMap
}

// RootDescriptor returns the file set descriptor's long allocation descriptor.
func (l LogicalVolume) RootDescriptor() (LongAd, bool) {
	return longAD(l.ContentsUse[:], 0)
}

// IsUdfDomain reports whether the domain identifier names UDF.
func (l LogicalVolume) IsUdfDomain() bool {
	return strings.HasPrefix(l.Domain, "*OSTA UDF Compliant")
}

func parseLogical(b []byte) (LogicalVolume, bool) {
	tag, ok := ParseTag(b)
	if !ok || tag.Ident != TagLVD {
		return LogicalVolume{}, false
	}
	if len(b) < 440 {
		return LogicalVolume{}, false
	}
	l := LogicalVolume{
		Tag:            tag,
		Sequence:       le32(b, 16),
		BlockSize:      le32(b, 212),
		MapTableLength: le32(b, 264),
		MapCount:       le32(b, 268),
	}
	if l.VolumeID, ok = dstring(b[84:212]); !ok {
		l.VolumeID = ""
	}
	if id, ok := NewRegId(b[216:248]); ok {
		l.Domain = id.IdentText()
		l.DomainSuffix = id.SuffixHex()
		l.DomainFlags = id.Flags
	}
	copy(l.ContentsUse[:], b[248:264])
	if l.Integrity, ok = extentAD(b, 432); !ok {
		return LogicalVolume{}, false
	}
	end := 440 + int(l.MapTableLength)
	if end > len(b) {
		end = len(b)
	}
	table := b[440:end]
	for len(table) >= 2 && len(l.Maps) < 64 {
		kind := table[0]
		length := table[1]
		if length < 2 || int(length) > len(table) {
			break
		}
		entry := PartitionMap{Kind: kind, Length: length}
		switch {
		case kind == 1 && length >= 6:
			entry.VolumeSequence = le16(table, 2)
			entry.PartitionNumber = le16(table, 4)
		case kind == 2 && length >= 40:
			copy(entry.Ident[:], table[5:28])
			copy(entry.Suffix[:], table[28:36])
			entry.VolumeSequence = le16(table, 36)
			entry.PartitionNumber = le16(table, 38)
			if length >= 64 && strings.HasPrefix(string(entry.Ident[:]), string(metadataIdent)) {
				entry.Metadata = &MetadataMap{
					FileBlock:      le32(table, 40),
					MirrorBlock:    le32(table, 44),
					BitmapBlock:    le32(table, 48),
					AllocationUnit: le32(table, 52),
					AlignmentUnit:  le16(table, 56),
					Duplicate:      table[58]&0x01 != 0,
				}
			}
		}
		l.Maps = append(l.Maps, entry)
		table = table[int(length):]
	}
	return l, true
}

// Integrity is the logical volume integrity descriptor.
type Integrity struct {
	Tag              Tag
	Closed           *bool
	NumPartitions    uint32
	FreeSpace        []uint32
	Sizes            []uint32
	NumFiles         *uint32
	NumDirectories   *uint32
	MinReadRevision  *uint16
	MinWriteRevision *uint16
}

// ReadRevision returns the minimum read revision as major.minor BCD.
func (i Integrity) ReadRevision() (string, bool) {
	if i.MinReadRevision == nil {
		return "", false
	}
	return bcdRevision(*i.MinReadRevision)
}

// WriteRevision returns the minimum write revision as major.minor BCD.
func (i Integrity) WriteRevision() (string, bool) {
	if i.MinWriteRevision == nil {
		return "", false
	}
	return bcdRevision(*i.MinWriteRevision)
}

func bcdRevision(value uint16) (string, bool) {
	high := (value >> 12) & 0xF
	low := (value >> 8) & 0xF
	minorHigh := (value >> 4) & 0xF
	minorLow := value & 0xF
	if high > 9 || low > 9 || minorHigh > 9 || minorLow > 9 {
		return "", false
	}
	return fmt.Sprintf("%d.%d%d", high*10+low, minorHigh, minorLow), true
}

func parseIntegrity(b []byte) (Integrity, bool) {
	tag, ok := ParseTag(b)
	if !ok || tag.Ident != TagLVID {
		return Integrity{}, false
	}
	if len(b) < 80 {
		return Integrity{}, false
	}
	in := Integrity{Tag: tag}
	switch le32(b, 28) {
	case 0:
		closed := false
		in.Closed = &closed
	case 1:
		closed := true
		in.Closed = &closed
	}
	in.NumPartitions = le32(b, 72)
	impUseLength := int(le32(b, 76))
	count := int(in.NumPartitions)
	if count < 0 || count > (len(b)-80)/8 {
		return Integrity{}, false
	}
	in.FreeSpace = make([]uint32, count)
	in.Sizes = make([]uint32, count)
	for i := 0; i < count; i++ {
		in.FreeSpace[i] = le32(b, 80+i*4)
		in.Sizes[i] = le32(b, 80+count*4+i*4)
	}
	impAt := 80 + count*8
	areaEnd := impAt + impUseLength
	if areaEnd > len(b) || impUseLength < 44 {
		return in, true
	}
	area := b[impAt:areaEnd]
	files := le32(area, 32)
	dirs := le32(area, 36)
	minRead := le16(area, 40)
	minWrite := le16(area, 42)
	in.NumFiles = &files
	in.NumDirectories = &dirs
	in.MinReadRevision = &minRead
	in.MinWriteRevision = &minWrite
	return in, true
}

// FileSet is the file set descriptor.
type FileSet struct {
	Tag      Tag
	Recorded UdfTime
	VolumeID string
	SetID    string
	Root     LongAd
}

func parseFileSet(b []byte) (FileSet, bool) {
	tag, ok := ParseTag(b)
	if !ok || tag.Ident != TagFSD {
		return FileSet{}, false
	}
	if len(b) < 416 {
		return FileSet{}, false
	}
	root, ok := longAD(b, 400)
	if !ok {
		return FileSet{}, false
	}
	f := FileSet{Tag: tag, Root: root}
	f.Recorded, _ = parseUdfTime(b[16:28])
	if f.VolumeID, ok = dstring(b[112:240]); !ok {
		f.VolumeID = ""
	}
	if f.SetID, ok = dstring(b[304:336]); !ok {
		f.SetID = ""
	}
	return f, true
}
