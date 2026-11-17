// Package lvm decodes LVM2 physical-volume metadata: the LABELONE sector, the
// metadata-area header, and the volume-group text it holds. It is a pure-Go
// port of forensic-core's data/lvm.rs.
package lvm

import (
	"errors"
	"fmt"
	"hash/crc32"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// LabelOffset is the byte offset of the LABELONE sector.
	LabelOffset = 512
	// LabelBytes is the fixed label-sector size.
	LabelBytes = 512
	// MaxMetadataBytes bounds the metadata text.
	MaxMetadataBytes = 4 * 1024 * 1024
	// MetadataHeaderBytes is the size of the metadata-area header.
	MetadataHeaderBytes = 512
)

var (
	// ErrLabel means the LABELONE sector is not a valid LVM2 label.
	ErrLabel = errors.New("lvm: label")
	// ErrMetadata means the metadata-area header is not what it claims.
	ErrMetadata = errors.New("lvm: metadata")
	// ErrText means the volume-group text has a syntax error.
	ErrText = errors.New("lvm: metadata text")
	// ErrTooLarge means the metadata exceeds MaxMetadataBytes.
	ErrTooLarge = errors.New("lvm: metadata too large")
	// ErrTruncated means a structure extends past the source.
	ErrTruncated = errors.New("lvm: truncated")
)

const (
	labelMagic  = "LABELONE"
	labelType   = "LVM2 001"
	mdaMagic    = " LVM2 x[5A%r0N*>"
	rawLocBytes = 24
	maxDepth    = 32
	maxEntries  = 100000
)

// Area is a region of the physical volume.
type Area struct {
	// Offset is the byte offset from the start of the volume.
	Offset uint64
	// Size is the area size; zero means "to the end of the device".
	Size uint64
}

// PvLabel is the decoded LABELONE sector.
type PvLabel struct {
	Sector        uint64
	ChecksumOK    bool
	StoredCRC     uint32
	ComputedCRC   uint32
	PVUUID        string
	DeviceSize    uint64
	DataAreas     []Area
	MetadataAreas []Area
}

// MetadataArea returns the first metadata area, where the primary metadata
// lives.
func (p PvLabel) MetadataArea() (Area, bool) {
	if len(p.MetadataAreas) == 0 {
		return Area{}, false
	}
	return p.MetadataAreas[0], true
}

// RawLocation is one raw location inside the metadata area.
type RawLocation struct {
	Offset   uint64
	Size     uint64
	Checksum uint32
	Flags    uint32
}

// IgnoresChecksum reports whether LVM wrote this location without a checksum.
func (r RawLocation) IgnoresChecksum() bool { return r.Flags&0x2 != 0 }

// MetadataArea is the 512-byte metadata-area header plus its raw locations.
type MetadataArea struct {
	ChecksumOK bool
	Version    uint32
	Start      uint64
	Size       uint64
	Locations  []RawLocation
}

// PhysicalVolumeEntry is one PV as the volume group lists it.
type PhysicalVolumeEntry struct {
	Name       string
	UUID       string
	Device     string
	Status     []string
	PEStart    uint64
	PECount    uint64
	HasPEStart bool
	HasPECount bool
}

// Stripe is one stripe of a segment.
type Stripe struct {
	PVUUID      string
	StartExtent uint64
}

// Segment is one segment of a logical volume.
type Segment struct {
	Index         uint64
	StartExtent   uint64
	ExtentCount   uint64
	Kind          string
	StripeCount   uint64
	StripeSize    uint64
	HasStripeSize bool
	Stripes       []Stripe
	// Other holds keys this reader does not interpret.
	Other []KV
}

// KV is one uninterpreted metadata key/value pair.
type KV struct {
	Key   string
	Value string
}

// LogicalVolume is one logical volume.
type LogicalVolume struct {
	Name         string
	UUID         string
	Status       []string
	SegmentCount uint64
	Segments     []Segment
}

// ExtentTotal returns the extents covered by the segments.
func (v LogicalVolume) ExtentTotal() uint64 {
	var total uint64
	for _, segment := range v.Segments {
		total += segment.ExtentCount
	}
	return total
}

// VolumeGroup is the volume group the text metadata describes.
type VolumeGroup struct {
	Name            string
	UUID            string
	Seqno           uint64
	Status          []string
	ExtentSize      uint64 // in 512-byte sectors
	PVCount         uint64
	LVCount         uint64
	CreationHost    string
	CreationTime    uint64
	PhysicalVolumes []PhysicalVolumeEntry
	LogicalVolumes  []LogicalVolume
}

// ExtentBytes returns the extent size in bytes when the metadata records one.
func (g VolumeGroup) ExtentBytes() (uint64, bool) {
	if g.ExtentSize == 0 {
		return 0, false
	}
	return g.ExtentSize * 512, true
}

// LVM is everything the reader decoded about one physical volume.
type LVM struct {
	Label              PvLabel
	MetadataArea       *MetadataArea
	MetadataOffset     *uint64
	MetadataBytes      uint64
	MetadataChecksumOK *bool
	Group              *VolumeGroup
	Warnings           []string
}

// Describe returns a one-line description for a report header.
func (l LVM) Describe() string {
	if l.Group == nil {
		return fmt.Sprintf("LVM2 physical volume %s", l.Label.PVUUID)
	}
	var extents uint64
	for _, pv := range l.Group.PhysicalVolumes {
		extents += pv.PECount
	}
	bytes, _ := l.Group.ExtentBytes()
	return fmt.Sprintf("LVM2 physical volume in VG `%s`, %d extent(s) of %d B, %d logical volume(s)",
		l.Group.Name, extents, bytes, len(l.Group.LogicalVolumes))
}

// Read reads the LVM label and metadata at the start of a volume. A nil result
// with a nil error means byte 512 does not hold LABELONE.
func Read(src source.ByteSource) (*LVM, error) {
	if src.Len() < LabelOffset+LabelBytes {
		return nil, nil
	}
	labelBytes, err := source.ReadVecAt(src, LabelOffset, LabelBytes)
	if err != nil {
		return nil, err
	}
	if string(labelBytes[0:len(labelMagic)]) != labelMagic {
		return nil, nil
	}
	l, err := decodeLabel(labelBytes)
	if err != nil {
		return nil, err
	}
	if area, ok := l.Label.MetadataArea(); ok {
		if err := decodeMetadata(src, area, l); err != nil {
			return nil, err
		}
	} else {
		l.Warnings = append(l.Warnings, "the label lists no metadata area")
	}
	return l, nil
}

// Identify decodes a label from a head buffer that already covers byte 512.
func Identify(head []byte) (*LVM, error) {
	if len(head) < LabelOffset+LabelBytes {
		return nil, nil
	}
	labelBytes := head[LabelOffset : LabelOffset+LabelBytes]
	if string(labelBytes[0:len(labelMagic)]) != labelMagic {
		return nil, nil
	}
	return decodeLabel(labelBytes)
}

func decodeLabel(bytes []byte) (*LVM, error) {
	if len(bytes) < LabelBytes {
		return nil, fmt.Errorf("%w: need %d bytes, got %d", ErrTruncated, LabelBytes, len(bytes))
	}
	if string(bytes[24:32]) != labelType {
		return nil, fmt.Errorf("%w: label type is not `LVM2 001`", ErrLabel)
	}
	sector := le64(bytes[8:16])
	storedCRC := le32(bytes[16:20])
	computedCRC := labelCRC(bytes)
	headerOffset := int(le32(bytes[20:24]))
	if headerOffset < 32 || headerOffset+32 > len(bytes) {
		return nil, fmt.Errorf("%w: pv_header offset is outside the label sector", ErrLabel)
	}
	pvUUID := textAt(bytes[headerOffset : headerOffset+32])
	if len(pvUUID) != 32 || !isASCIIGraphic(pvUUID) {
		return nil, fmt.Errorf("%w: pv_uuid is not 32 printable bytes", ErrLabel)
	}

	afterUUID := headerOffset + 32
	var deviceSize uint64
	var dataAreas, metadataAreas []Area
	if len(bytes) >= afterUUID+8 {
		deviceSize = le64(bytes[afterUUID : afterUUID+8])
		offset := afterUUID + 8
		// disk_areas_xl holds two NULL-terminated lists: data areas first,
		// then metadata-area headers.
		for list := 0; list < 2; list++ {
			for offset+16 <= len(bytes) {
				start := le64(bytes[offset : offset+8])
				size := le64(bytes[offset+8 : offset+16])
				offset += 16
				if start == 0 && size == 0 {
					break
				}
				area := Area{Offset: start, Size: size}
				if list == 0 {
					dataAreas = append(dataAreas, area)
				} else {
					metadataAreas = append(metadataAreas, area)
				}
			}
		}
	}

	label := PvLabel{
		Sector:        sector,
		ChecksumOK:    storedCRC == computedCRC,
		StoredCRC:     storedCRC,
		ComputedCRC:   computedCRC,
		PVUUID:        pvUUID,
		DeviceSize:    deviceSize,
		DataAreas:     dataAreas,
		MetadataAreas: metadataAreas,
	}
	l := &LVM{Label: label}
	if len(label.DataAreas) == 0 {
		l.Warnings = append(l.Warnings, "the label lists no data area")
	}
	if len(label.MetadataAreas) == 0 {
		l.Warnings = append(l.Warnings, "the label lists no metadata area")
	}
	if !label.ChecksumOK {
		l.Warnings = append(l.Warnings,
			fmt.Sprintf("label CRC is 0x%08x, computed 0x%08x", storedCRC, computedCRC))
	}
	return l, nil
}

func labelCRC(bytes []byte) uint32 {
	copyBytes := append([]byte(nil), bytes[:LabelBytes]...)
	clear(copyBytes[16:20])
	return crc32.ChecksumIEEE(copyBytes)
}

func decodeMetadata(src source.ByteSource, area Area, l *LVM) error {
	if area.Offset >= src.Len() {
		return fmt.Errorf("%w: LVM structure needs %d bytes, source has %d",
			ErrTruncated, area.Offset+512, src.Len())
	}
	header, err := source.ReadVecAt(src, area.Offset, MetadataHeaderBytes)
	if err != nil {
		return err
	}
	if string(header[4:20]) != mdaMagic {
		return fmt.Errorf("%w: metadata-area magic is not ` LVM2 x[5A%%r0N*>`", ErrMetadata)
	}
	stored := le32(header[0:4])
	crcInput := append([]byte(nil), header...)
	clear(crcInput[0:4])
	computed := crc32.ChecksumIEEE(crcInput)
	mda := &MetadataArea{
		ChecksumOK: stored == computed,
		Version:    le32(header[20:24]),
		Start:      le64(header[24:32]),
		Size:       le64(header[32:40]),
	}
	for offset := 40; offset+rawLocBytes <= len(header); offset += rawLocBytes {
		location := RawLocation{
			Offset:   le64(header[offset : offset+8]),
			Size:     le64(header[offset+8 : offset+16]),
			Checksum: le32(header[offset+16 : offset+20]),
			Flags:    le32(header[offset+20 : offset+24]),
		}
		if location.Offset == 0 && location.Size == 0 {
			break
		}
		mda.Locations = append(mda.Locations, location)
	}
	if !mda.ChecksumOK {
		l.Warnings = append(l.Warnings,
			fmt.Sprintf("metadata-area header CRC is 0x%08x, computed 0x%08x", stored, computed))
	}
	if mda.Version != 1 {
		l.Warnings = append(l.Warnings, fmt.Sprintf("metadata-area header version %d", mda.Version))
	}

	start := mda.Start
	if start == 0 {
		start = area.Offset
	}
	areaSize := area.Size
	if areaSize == 0 {
		areaSize = mda.Size
	} else if mda.Size != 0 && area.Size != mda.Size {
		l.Warnings = append(l.Warnings,
			fmt.Sprintf("the label gives the metadata area %d bytes, its header %d", area.Size, mda.Size))
		if mda.Size < areaSize {
			areaSize = mda.Size
		}
	}
	l.MetadataArea = mda
	if len(mda.Locations) == 0 {
		l.Warnings = append(l.Warnings, "the metadata area has no used location")
		return nil
	}
	location := mda.Locations[0]
	if location.Size > MaxMetadataBytes {
		return fmt.Errorf("%w: LVM metadata is %d bytes, limit %d", ErrTooLarge, location.Size, MaxMetadataBytes)
	}

	text, err := readText(src, start, areaSize, location)
	if err != nil {
		return err
	}
	metadataOffset := start + location.Offset
	l.MetadataOffset = &metadataOffset
	l.MetadataBytes = location.Size
	if !location.IgnoresChecksum() && location.Checksum != 0 {
		ok := crc32.ChecksumIEEE(text) == location.Checksum
		l.MetadataChecksumOK = &ok
		if !ok {
			l.Warnings = append(l.Warnings,
				fmt.Sprintf("metadata text CRC is 0x%08x, computed 0x%08x", location.Checksum, crc32.ChecksumIEEE(text)))
		}
	}
	group, err := decodeText(text)
	if err != nil {
		return err
	}
	l.Group = group
	return nil
}

// readText reads the metadata text, joining it from the area's start when it
// wraps. LVM measures a raw location from the start of the metadata area; when
// the text runs past the end it continues after the 512-byte header.
func readText(src source.ByteSource, start, areaSize uint64, location RawLocation) ([]byte, error) {
	if location.Offset < MetadataHeaderBytes {
		return nil, fmt.Errorf("%w: raw location starts inside the metadata-area header", ErrMetadata)
	}
	if areaSize == 0 {
		if start >= src.Len() {
			areaSize = 0
		} else {
			areaSize = src.Len() - start
		}
	}
	if location.Offset >= areaSize {
		return nil, fmt.Errorf("%w: raw location starts past the metadata area", ErrMetadata)
	}
	firstLen := location.Size
	if firstLen > areaSize-location.Offset {
		firstLen = areaSize - location.Offset
	}
	text, err := source.ReadVecAt(src, start+location.Offset, firstLen)
	if err != nil {
		return nil, err
	}
	remaining := location.Size - firstLen
	if remaining > 0 {
		tail, err := source.ReadVecAt(src, start+MetadataHeaderBytes, remaining)
		if err != nil {
			return nil, err
		}
		text = append(text, tail...)
	}
	if uint64(len(text)) < location.Size {
		return nil, fmt.Errorf("%w: need %d bytes, got %d", ErrTruncated, location.Size, len(text))
	}
	return text, nil
}

// --------------------------------------------------------------------------
// Text metadata

type nodeKind uint8

const (
	nodeScalar nodeKind = iota
	nodeArray
	nodeSection
)

type kv struct {
	key   string
	value node
}

type node struct {
	kind    nodeKind
	scalar  string
	array   []node
	entries []kv
}

func (n node) get(key string) (node, bool) {
	for _, entry := range n.entries {
		if entry.key == key {
			return entry.value, true
		}
	}
	return node{}, false
}

func (n node) scalarValue() (string, bool) {
	if n.kind != nodeScalar {
		return "", false
	}
	return n.scalar, true
}

func (n node) number() (uint64, bool) {
	value, ok := n.scalarValue()
	if !ok {
		return 0, false
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func (n node) strings() []string {
	switch n.kind {
	case nodeArray:
		out := make([]string, 0, len(n.array))
		for _, item := range n.array {
			if value, ok := item.scalarValue(); ok {
				out = append(out, value)
			}
		}
		return out
	case nodeScalar:
		return []string{n.scalar}
	default:
		return nil
	}
}

type textParser struct {
	bytes   []byte
	pos     int
	entries int
}

func decodeText(bytes []byte) (*VolumeGroup, error) {
	p := &textParser{bytes: bytes}
	p.skipSpace()
	name, section, ok, err := p.section(0)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w at byte %d: no volume group section", ErrText, p.pos)
	}

	group := &VolumeGroup{Name: name}
	if value, ok := section.get("id"); ok {
		group.UUID, _ = value.scalarValue()
	}
	if value, ok := section.get("seqno"); ok {
		group.Seqno, _ = value.number()
	}
	if value, ok := section.get("status"); ok {
		group.Status = value.strings()
	}
	if value, ok := section.get("extent_size"); ok {
		group.ExtentSize, _ = value.number()
	}
	if value, ok := section.get("pv_count"); ok {
		group.PVCount, _ = value.number()
	}
	if value, ok := section.get("lv_count"); ok {
		group.LVCount, _ = value.number()
	}
	if value, ok := section.get("creation_host"); ok {
		group.CreationHost, _ = value.scalarValue()
	}
	if value, ok := section.get("creation_time"); ok {
		group.CreationTime, _ = value.number()
	}

	if pvs, ok := section.get("physical_volumes"); ok {
		for _, entry := range pvs.entries {
			group.PhysicalVolumes = append(group.PhysicalVolumes, decodePhysicalVolume(entry.key, entry.value))
		}
	}
	if lvs, ok := section.get("logical_volumes"); ok {
		for _, entry := range lvs.entries {
			group.LogicalVolumes = append(group.LogicalVolumes, decodeLogicalVolume(entry.key, entry.value))
		}
	}
	return group, nil
}

func decodePhysicalVolume(name string, n node) PhysicalVolumeEntry {
	pv := PhysicalVolumeEntry{Name: name}
	if value, ok := n.get("id"); ok {
		pv.UUID, _ = value.scalarValue()
	}
	if value, ok := n.get("device"); ok {
		pv.Device, _ = value.scalarValue()
	}
	if value, ok := n.get("status"); ok {
		pv.Status = value.strings()
	}
	if value, ok := n.get("pe_start"); ok {
		pv.PEStart, pv.HasPEStart = value.number()
	}
	if value, ok := n.get("pe_count"); ok {
		pv.PECount, pv.HasPECount = value.number()
	}
	return pv
}

func decodeLogicalVolume(name string, n node) LogicalVolume {
	lv := LogicalVolume{Name: name}
	if value, ok := n.get("id"); ok {
		lv.UUID, _ = value.scalarValue()
	}
	if value, ok := n.get("status"); ok {
		lv.Status = value.strings()
	}
	if value, ok := n.get("segment_count"); ok {
		lv.SegmentCount, _ = value.number()
	}
	for _, entry := range n.entries {
		if !strings.HasPrefix(entry.key, "segment") {
			continue
		}
		index, err := strconv.ParseUint(strings.TrimPrefix(entry.key, "segment"), 10, 64)
		if err != nil {
			continue
		}
		lv.Segments = append(lv.Segments, decodeSegment(index, entry.value))
	}
	sort.Slice(lv.Segments, func(i, j int) bool { return lv.Segments[i].Index < lv.Segments[j].Index })
	return lv
}

func decodeSegment(index uint64, n node) Segment {
	segment := Segment{Index: index}
	known := map[string]bool{
		"start_extent": true, "extent_count": true, "type": true,
		"stripe_count": true, "stripe_size": true, "stripes": true,
	}
	for _, entry := range n.entries {
		if known[entry.key] {
			continue
		}
		switch entry.value.kind {
		case nodeScalar:
			segment.Other = append(segment.Other, KV{Key: entry.key, Value: entry.value.scalar})
		case nodeArray:
			segment.Other = append(segment.Other, KV{Key: entry.key, Value: strings.Join(entry.value.strings(), ", ")})
		case nodeSection:
			segment.Other = append(segment.Other, KV{Key: entry.key, Value: "(section)"})
		}
	}

	if value, ok := n.get("start_extent"); ok {
		segment.StartExtent, _ = value.number()
	}
	if value, ok := n.get("extent_count"); ok {
		segment.ExtentCount, _ = value.number()
	}
	if value, ok := n.get("type"); ok {
		segment.Kind, _ = value.scalarValue()
	}
	if value, ok := n.get("stripe_count"); ok {
		segment.StripeCount, _ = value.number()
	}
	if value, ok := n.get("stripe_size"); ok {
		segment.StripeSize, segment.HasStripeSize = value.number()
	}
	if value, ok := n.get("stripes"); ok {
		items := value.strings()
		for i := 0; i+1 < len(items); i += 2 {
			start, _ := strconv.ParseUint(items[i+1], 10, 64)
			segment.Stripes = append(segment.Stripes, Stripe{PVUUID: items[i], StartExtent: start})
		}
	}
	return segment
}

func (p *textParser) skipSpace() {
	for {
		for p.pos < len(p.bytes) && isSpace(p.bytes[p.pos]) {
			p.pos++
		}
		if p.pos < len(p.bytes) && p.bytes[p.pos] == '#' {
			for p.pos < len(p.bytes) && p.bytes[p.pos] != '\n' {
				p.pos++
			}
			continue
		}
		break
	}
}

func (p *textParser) peek() (byte, bool) {
	p.skipSpace()
	if p.pos >= len(p.bytes) {
		return 0, false
	}
	return p.bytes[p.pos], true
}

func (p *textParser) section(depth int) (string, node, bool, error) {
	if depth > maxDepth {
		return "", node{}, false, fmt.Errorf("%w at byte %d: sections nested too deeply", ErrText, p.pos)
	}
	first, ok := p.peek()
	if !ok {
		return "", node{}, false, nil
	}
	if !isWordStart(first) {
		return "", node{}, false, fmt.Errorf("%w at byte %d: expected a section name", ErrText, p.pos)
	}
	name, err := p.word()
	if err != nil {
		return "", node{}, false, err
	}
	if next, ok := p.peek(); !ok || next != '{' {
		return "", node{}, false, fmt.Errorf("%w at byte %d: expected `{` after the section name", ErrText, p.pos)
	}
	p.pos++
	body, err := p.sectionBody(depth + 1)
	if err != nil {
		return "", node{}, false, err
	}
	return name, body, true, nil
}

func (p *textParser) sectionBody(depth int) (node, error) {
	var entries []kv
	for {
		next, ok := p.peek()
		if !ok {
			return node{}, fmt.Errorf("%w at byte %d: unterminated section", ErrText, p.pos)
		}
		if next == '}' {
			p.pos++
			break
		}
		key, err := p.word()
		if err != nil {
			return node{}, err
		}
		var value node
		if next, ok := p.peek(); ok && next == '{' {
			p.pos++
			if depth > maxDepth {
				return node{}, fmt.Errorf("%w at byte %d: sections nested too deeply", ErrText, p.pos)
			}
			value, err = p.sectionBody(depth + 1)
			if err != nil {
				return node{}, err
			}
		} else {
			if next, ok := p.peek(); !ok || next != '=' {
				return node{}, fmt.Errorf("%w at byte %d: expected `=` after a key", ErrText, p.pos)
			}
			p.pos++
			value, err = p.value(depth)
			if err != nil {
				return node{}, err
			}
		}
		p.entries++
		if p.entries > maxEntries {
			return node{}, fmt.Errorf("%w at byte %d: too many entries", ErrText, p.pos)
		}
		entries = append(entries, kv{key: key, value: value})
	}
	return node{kind: nodeSection, entries: entries}, nil
}

func (p *textParser) value(depth int) (node, error) {
	if depth > maxDepth {
		return node{}, fmt.Errorf("%w at byte %d: nesting is too deep", ErrText, p.pos)
	}
	next, ok := p.peek()
	if !ok {
		return node{}, fmt.Errorf("%w at byte %d: expected a value", ErrText, p.pos)
	}
	switch {
	case next == '"':
		value, err := p.string()
		if err != nil {
			return node{}, err
		}
		return node{kind: nodeScalar, scalar: value}, nil
	case next == '[':
		p.pos++
		var items []node
		for {
			next, ok := p.peek()
			if !ok {
				return node{}, fmt.Errorf("%w at byte %d: unterminated array", ErrText, p.pos)
			}
			switch next {
			case ']':
				p.pos++
				return node{kind: nodeArray, array: items}, nil
			case ',':
				p.pos++
			default:
				item, err := p.value(depth + 1)
				if err != nil {
					return node{}, err
				}
				items = append(items, item)
			}
		}
	case isWordStart(next):
		value, err := p.word()
		if err != nil {
			return node{}, err
		}
		return node{kind: nodeScalar, scalar: value}, nil
	default:
		return node{}, fmt.Errorf("%w at byte %d: expected a value", ErrText, p.pos)
	}
}

func (p *textParser) word() (string, error) {
	p.skipSpace()
	start := p.pos
	for p.pos < len(p.bytes) && isWordByte(p.bytes[p.pos]) {
		p.pos++
	}
	if p.pos == start {
		return "", fmt.Errorf("%w at byte %d: expected a word", ErrText, p.pos)
	}
	return string(p.bytes[start:p.pos]), nil
}

func (p *textParser) string() (string, error) {
	p.pos++ // opening quote
	var out strings.Builder
	for {
		if p.pos >= len(p.bytes) {
			return "", fmt.Errorf("%w at byte %d: unterminated string", ErrText, p.pos)
		}
		switch b := p.bytes[p.pos]; b {
		case '"':
			p.pos++
			return out.String(), nil
		case '\\':
			if p.pos+1 >= len(p.bytes) {
				return "", fmt.Errorf("%w at byte %d: unterminated escape", ErrText, p.pos)
			}
			switch escaped := p.bytes[p.pos+1]; escaped {
			case '"':
				out.WriteByte('"')
			case '\\':
				out.WriteByte('\\')
			case 'n':
				out.WriteByte('\n')
			case 't':
				out.WriteByte('\t')
			default:
				out.WriteByte(escaped)
			}
			p.pos += 2
		default:
			out.WriteByte(b)
			p.pos++
		}
	}
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == '\v' || b == '\f'
}

func isWordStart(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' ||
		b == '_' || b == '.' || b == '/' || b == '-'
}

func isWordByte(b byte) bool { return isWordStart(b) || b == '+' || b == ':' }

func isASCIIGraphic(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7E {
			return false
		}
	}
	return true
}

// textAt decodes bytes as text, stopping at NUL. Invalid UTF-8 yields "".
func textAt(bytes []byte) string {
	end := len(bytes)
	for i, b := range bytes {
		if b == 0 {
			end = i
			break
		}
	}
	if !utf8.Valid(bytes[:end]) {
		return ""
	}
	return string(bytes[:end])
}

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func le64(b []byte) uint64 {
	return uint64(le32(b)) | uint64(le32(b[4:]))<<32
}
