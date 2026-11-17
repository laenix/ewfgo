package ldm

import (
	"encoding/binary"
	"sort"
	"strings"
)

// Raw VBLK records as decoded from the stream, before the cross-links are
// joined into the public database.
type diskRecord struct {
	id   uint64
	name *string
	guid *string
	// guidAlternate is the same 16 bytes read as a Microsoft GUID struct
	// (little-endian first three fields). Revision-4 records store raw bytes;
	// this reader does not know from a primary source which order the writer
	// used, so identity is matched against both readings.
	guidAlternate *string
}

type partitionRecord struct {
	id           uint64
	name         *string
	diskID       uint64
	componentID  *uint64
	startLBA     uint64
	volumeOffset uint64
	sizeSectors  uint64
	flags        uint32
	// column is the stripe column index from the optional VBLK flag 0x08
	// field.
	column *uint64
}

type componentRecord struct {
	id       uint64
	volumeID *uint64
	layout   Layout
	// stripeBlocks is the stripe unit in device blocks, from the optional
	// VBLK flag 0x10 fields.
	stripeBlocks *uint64
	// columns is the column count, from the same optional fields.
	columns *uint64
}

type volumeRecord struct {
	id            uint64
	name          *string
	volumeType    *string
	state         *string
	sizeSectors   uint64
	driveHint     *string
	partitionType uint8
	guid          *string
	// chunkBlocks is the stripe/chunk size in device blocks, from the
	// optional VBLK flag 0x80 field.
	chunkBlocks *uint64
	// componentCount is the number of components the record declares.
	componentCount uint64
}

type groupRecord struct {
	name *string
	guid *string
}

type rawRecords struct {
	disks      []diskRecord
	partitions []partitionRecord
	components []componentRecord
	volumes    []volumeRecord
	groups     []groupRecord
	skipped    int
	malformed  int
	undecoded  map[uint8]int
}

func (r *rawRecords) componentByID(id uint64) *componentRecord {
	for i := range r.components {
		if r.components[i].id == id {
			return &r.components[i]
		}
	}
	return nil
}

func (r *rawRecords) volumeByID(id uint64) *volumeRecord {
	for i := range r.volumes {
		if r.volumes[i].id == id {
			return &r.volumes[i]
		}
	}
	return nil
}

type vblkHeader struct {
	group     uint32
	fragment  uint16
	fragments uint16
	flags     uint8
	kind      uint8
	bodyLen   uint32
}

func parseVBLKHeader(record []byte) (vblkHeader, error) {
	if len(record) < vblkHeaderBytes {
		return vblkHeader{}, corruptf(
			"LDM VBLK record is %d bytes, shorter than its %d-byte header", len(record), vblkHeaderBytes)
	}
	return vblkHeader{
		group:     binary.BigEndian.Uint32(record[0x08:]),
		fragment:  binary.BigEndian.Uint16(record[0x0C:]),
		fragments: binary.BigEndian.Uint16(record[0x0E:]),
		flags:     record[0x12],
		kind:      record[0x13],
		bodyLen:   binary.BigEndian.Uint32(record[0x14:]),
	}, nil
}

// decode parses one record body. An unknown kind is counted as skipped; a known
// kind whose body does not parse is counted as malformed. Neither is silently
// dropped.
func (r *rawRecords) decode(record []byte, header vblkHeader) {
	cursor := &vblkCursor{data: record, pos: vblkHeaderBytes}
	var err error
	switch header.kind {
	case 0x32:
		err = r.decodeComponent(cursor, header.flags)
	case 0x33:
		err = r.decodePartition(cursor, header.flags)
	case 0x34:
		err = r.decodeDiskV3(cursor)
	case 0x35:
		err = r.decodeDiskGroup(cursor, false)
	case 0x44:
		err = r.decodeDiskV4(cursor)
	case 0x45:
		err = r.decodeDiskGroup(cursor, true)
	case 0x51:
		err = r.decodeVolume(cursor, header.flags)
	default:
		r.undecoded[header.kind]++
		r.skipped++
		return
	}
	if err != nil {
		r.malformed++
		r.skipped++
	}
}

func (r *rawRecords) decodeDiskV3(cursor *vblkCursor) error {
	id, err := cursor.vnum()
	if err != nil {
		return err
	}
	name, err := stringField(cursor)
	if err != nil {
		return err
	}
	guid, err := stringField(cursor)
	if err != nil {
		return err
	}
	if _, err := cursor.vstr(); err != nil {
		return err
	}
	if _, err := cursor.u32(); err != nil {
		return err
	}
	if _, err := cursor.u64(); err != nil {
		return err
	}
	r.disks = append(r.disks, diskRecord{id: id, name: name, guid: guid})
	return nil
}

func (r *rawRecords) decodeDiskV4(cursor *vblkCursor) error {
	id, err := cursor.vnum()
	if err != nil {
		return err
	}
	name, err := stringField(cursor)
	if err != nil {
		return err
	}
	bytes, err := cursor.take(16)
	if err != nil {
		return err
	}
	guid := formatGUIDBytes(bytes)
	alternate := formatGUIDBytesMixed(bytes)
	if _, err := cursor.take(16); err != nil {
		return err
	}
	if _, err := cursor.vstr(); err != nil {
		return err
	}
	if _, err := cursor.u32(); err != nil {
		return err
	}
	if _, err := cursor.u64(); err != nil {
		return err
	}
	r.disks = append(r.disks, diskRecord{id: id, name: name, guid: &guid, guidAlternate: &alternate})
	return nil
}

func (r *rawRecords) decodePartition(cursor *vblkCursor, flags uint8) error {
	id, err := cursor.vnum()
	if err != nil {
		return err
	}
	name, err := stringField(cursor)
	if err != nil {
		return err
	}
	partitionFlags, err := cursor.u32()
	if err != nil {
		return err
	}
	if _, err := cursor.u64(); err != nil {
		return err
	}
	startLBA, err := cursor.u64()
	if err != nil {
		return err
	}
	volumeOffset, err := cursor.u64()
	if err != nil {
		return err
	}
	sizeSectors, err := cursor.vnum()
	if err != nil {
		return err
	}
	component, err := cursor.vnum()
	if err != nil {
		return err
	}
	diskID, err := cursor.vnum()
	if err != nil {
		return err
	}
	var column *uint64
	if flags&0x08 != 0 {
		value, err := cursor.vnum()
		if err != nil {
			return err
		}
		column = &value
	}
	if flags&0x20 != 0 {
		if _, err := cursor.take(8); err != nil {
			return err
		}
	}
	if flags&0x02 != 0 {
		if _, err := cursor.vnum(); err != nil {
			return err
		}
	}
	var componentID *uint64
	if component != 0 {
		componentID = &component
	}
	r.partitions = append(r.partitions, partitionRecord{
		id:           id,
		name:         name,
		diskID:       diskID,
		componentID:  componentID,
		startLBA:     startLBA,
		volumeOffset: volumeOffset,
		sizeSectors:  sizeSectors,
		flags:        partitionFlags,
		column:       column,
	})
	return nil
}

func (r *rawRecords) decodeComponent(cursor *vblkCursor, flags uint8) error {
	id, err := cursor.vnum()
	if err != nil {
		return err
	}
	if _, err := cursor.vstr(); err != nil {
		return err
	}
	if _, err := cursor.vstr(); err != nil {
		return err
	}
	layoutByte, err := cursor.u8()
	if err != nil {
		return err
	}
	layout := layoutFromByte(layoutByte)
	if _, err := cursor.u32(); err != nil {
		return err
	}
	if _, err := cursor.vnum(); err != nil {
		return err
	}
	if _, err := cursor.u64(); err != nil {
		return err
	}
	if _, err := cursor.u64(); err != nil {
		return err
	}
	volume, err := cursor.vnum()
	if err != nil {
		return err
	}
	// A stripe set and a RAID-5 set record the stripe unit and the number of
	// columns after the volume id. A concatenated component does not.
	var stripeBlocks, columns *uint64
	if flags&0x10 != 0 {
		stripe, err := cursor.vnum()
		if err != nil {
			return err
		}
		columnCount, err := cursor.vnum()
		if err != nil {
			return err
		}
		stripeBlocks, columns = &stripe, &columnCount
	}
	var volumeID *uint64
	if volume != 0 {
		volumeID = &volume
	}
	r.components = append(r.components, componentRecord{
		id:           id,
		volumeID:     volumeID,
		layout:       layout,
		stripeBlocks: stripeBlocks,
		columns:      columns,
	})
	return nil
}

func (r *rawRecords) decodeVolume(cursor *vblkCursor, flags uint8) error {
	id, err := cursor.vnum()
	if err != nil {
		return err
	}
	name, err := stringField(cursor)
	if err != nil {
		return err
	}
	volumeType, err := stringField(cursor)
	if err != nil {
		return err
	}
	if _, err := cursor.vstr(); err != nil {
		return err
	}
	stateBytes, err := cursor.take(14)
	if err != nil {
		return err
	}
	state := fixedString(stateBytes, 0, 14)
	if _, err := cursor.u8(); err != nil {
		return err
	}
	if _, err := cursor.vnum(); err != nil {
		return err
	}
	if _, err := cursor.u32(); err != nil {
		return err
	}
	componentCount, err := cursor.vnum()
	if err != nil {
		return err
	}
	if _, err := cursor.u64(); err != nil {
		return err
	}
	if _, err := cursor.u64(); err != nil {
		return err
	}
	sizeSectors, err := cursor.vnum()
	if err != nil {
		return err
	}
	if _, err := cursor.u32(); err != nil {
		return err
	}
	partitionType, err := cursor.u8()
	if err != nil {
		return err
	}
	guidBytes, err := cursor.take(16)
	if err != nil {
		return err
	}
	guid := formatGUIDBytes(guidBytes)
	if flags&0x08 != 0 {
		if _, err := cursor.vnum(); err != nil {
			return err
		}
	}
	if flags&0x20 != 0 {
		if _, err := cursor.vnum(); err != nil {
			return err
		}
	}
	// Flag 0x80 adds the stripe/chunk size, in the same device blocks the rest
	// of the database uses. It is kept separate from the component's copy so a
	// disagreement can be refused instead of papered over.
	var chunkBlocks *uint64
	if flags&0x80 != 0 {
		value, err := cursor.vnum()
		if err != nil {
			return err
		}
		chunkBlocks = &value
	}
	var driveHint *string
	if flags&0x02 != 0 {
		value, err := stringField(cursor)
		if err != nil {
			return err
		}
		driveHint = value
	}
	var statePtr *string
	if state != "" {
		statePtr = &state
	}
	r.volumes = append(r.volumes, volumeRecord{
		id:             id,
		name:           name,
		volumeType:     volumeType,
		state:          statePtr,
		sizeSectors:    sizeSectors,
		driveHint:      driveHint,
		partitionType:  partitionType,
		guid:           &guid,
		chunkBlocks:    chunkBlocks,
		componentCount: componentCount,
	})
	return nil
}

func (r *rawRecords) decodeDiskGroup(cursor *vblkCursor, revision4 bool) error {
	if _, err := cursor.vnum(); err != nil {
		return err
	}
	name, err := stringField(cursor)
	if err != nil {
		return err
	}
	var guid *string
	if revision4 {
		bytes, err := cursor.take(16)
		if err != nil {
			return err
		}
		value := formatGUIDBytes(bytes)
		guid = &value
		if _, err := cursor.take(16); err != nil {
			return err
		}
	} else {
		guid, err = stringField(cursor)
		if err != nil {
			return err
		}
	}
	r.groups = append(r.groups, groupRecord{name: name, guid: guid})
	return nil
}

// vblkCursor reads the variable-length body fields of a record.
type vblkCursor struct {
	data []byte
	pos  int
}

func (c *vblkCursor) take(length int) ([]byte, error) {
	if length < 0 || c.pos < 0 || c.pos > len(c.data) {
		return nil, corruptf("LDM VBLK field length overflows")
	}
	if uint64(length) > uint64(len(c.data)-c.pos) {
		return nil, corruptf("LDM VBLK record ends inside a field at byte %d", c.pos)
	}
	slice := c.data[c.pos : c.pos+length]
	c.pos += length
	return slice, nil
}

func (c *vblkCursor) u8() (uint8, error) {
	bytes, err := c.take(1)
	if err != nil {
		return 0, err
	}
	return bytes[0], nil
}

func (c *vblkCursor) u32() (uint32, error) {
	bytes, err := c.take(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(bytes), nil
}

func (c *vblkCursor) u64() (uint64, error) {
	bytes, err := c.take(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(bytes), nil
}

// vnum reads a one-byte-length-prefixed big-endian number.
func (c *vblkCursor) vnum() (uint64, error) {
	length, err := c.u8()
	if err != nil {
		return 0, err
	}
	if length > 8 {
		return 0, corruptf("LDM variable-length number claims %d bytes", length)
	}
	bytes, err := c.take(int(length))
	if err != nil {
		return 0, err
	}
	var value uint64
	for _, b := range bytes {
		value = value<<8 | uint64(b)
	}
	return value, nil
}

// vstr reads a one-byte-length-prefixed single-byte string.
func (c *vblkCursor) vstr() (string, error) {
	length, err := c.u8()
	if err != nil {
		return "", err
	}
	bytes, err := c.take(int(length))
	if err != nil {
		return "", err
	}
	return strings.ToValidUTF8(string(bytes), "�"), nil
}

func stringField(cursor *vblkCursor) (*string, error) {
	value, err := cursor.vstr()
	if err != nil {
		return nil, err
	}
	if value == "" {
		return nil, nil
	}
	return &value, nil
}

type fragment struct {
	parts  [][]byte
	header []byte
	broken bool
}

// readVBLKs walks the fixed-stride VBLK stream, reassembling fragmented records
// by their group number. Structural impossibilities (a declared body that
// cannot fit its slot) are errors; an empty or unknown slot is counted.
func readVBLKs(stream []byte, stride int, count uint32, raw *rawRecords) error {
	fragments := make(map[uint32]*fragment)

	for index := 0; index < int(count); index++ {
		if stride <= 0 {
			return corruptf("LDM VBLK stream has a zero stride")
		}
		start64 := uint64(index) * uint64(stride)
		if start64 > uint64(len(stream)) || uint64(stride) > uint64(len(stream))-start64 {
			raw.skipped++
			continue
		}
		start := int(start64)
		slot := stream[start : start+stride]
		if len(slot) < vblkHeaderBytes || string(slot[0:4]) != VBLKMagic {
			// A slot past the last committed record, or one left by a torn
			// update. It is not a record the database claims.
			raw.skipped++
			continue
		}
		header, err := parseVBLKHeader(slot)
		if err != nil {
			return err
		}
		if header.fragments == 0 {
			raw.skipped++
			continue
		}
		if header.fragments == 1 {
			if err := checkVBLKBodyLen(slot, header, index); err != nil {
				return err
			}
			end := vblkHeaderBytes + int(header.bodyLen)
			raw.decode(slot[:end], header)
			continue
		}

		if header.fragments > maxVBLKFragmentCount || header.fragment >= header.fragments {
			raw.skipped++
			delete(fragments, header.group)
			continue
		}
		entry := fragments[header.group]
		if entry == nil {
			entry = &fragment{parts: make([][]byte, header.fragments)}
			fragments[header.group] = entry
		}
		slotIndex := int(header.fragment)
		if len(entry.parts) != int(header.fragments) || entry.parts[slotIndex] != nil {
			entry.broken = true
			continue
		}
		if header.fragment == 0 {
			entry.header = append([]byte(nil), slot[:0x10]...)
		}
		entry.parts[slotIndex] = append([]byte(nil), slot[0x10:]...)
	}

	groups := make([]uint32, 0, len(fragments))
	for group := range fragments {
		groups = append(groups, group)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i] < groups[j] })
	for _, group := range groups {
		frag := fragments[group]
		broken := frag.broken || frag.header == nil
		if !broken {
			for _, part := range frag.parts {
				if part == nil {
					broken = true
					break
				}
			}
		}
		if broken {
			raw.skipped++
			continue
		}
		record := append([]byte(nil), frag.header...)
		for _, part := range frag.parts {
			record = append(record, part...)
		}
		if len(record) < vblkHeaderBytes || string(record[0:4]) != VBLKMagic {
			raw.skipped++
			continue
		}
		header, err := parseVBLKHeader(record)
		if err != nil {
			return err
		}
		if uint64(vblkHeaderBytes)+uint64(header.bodyLen) > uint64(len(record)) {
			return corruptf(
				"fragmented LDM VBLK group %d declares %d body bytes, its %d-byte record holds %d",
				group, header.bodyLen, len(record), len(record)-vblkHeaderBytes)
		}
		end := vblkHeaderBytes + int(header.bodyLen)
		raw.decode(record[:end], header)
	}
	return nil
}

func checkVBLKBodyLen(slot []byte, header vblkHeader, index int) error {
	bodyLen := header.bodyLen
	if bodyLen < 2 {
		return corruptf(
			"LDM VBLK %d declares a %d-byte body, too short to hold an object id", index, bodyLen)
	}
	if uint64(vblkHeaderBytes)+uint64(bodyLen) > uint64(len(slot)) {
		return corruptf(
			"LDM VBLK %d declares %d body bytes, its %d-byte slot holds %d",
			index, bodyLen, len(slot), len(slot)-vblkHeaderBytes)
	}
	return nil
}
