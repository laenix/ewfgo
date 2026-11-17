package zfs

import (
	"strconv"
)

// System attributes (SA) and the legacy znode bonus buffer.
//
// A ZPL object's POSIX metadata lives in its dnode's bonus buffer. Which
// encoding was used is a property of the object, not of the dataset: a pool
// upgraded in place holds both.
//
//   - dn_bonustype 44 (DMU_OT_SA) starts with an sa_hdr_phys_t: a magic, a
//     layout/header word, then one length per variable-length attribute. The
//     layout indexes the dataset's LAYOUTS ZAP; the REGISTRY ZAP maps each id
//     back to a name, a fixed length (0 for variable) and a byte-swap class.
//   - dn_bonustype 17 (DMU_OT_ZNODE) is the pre-SA znode_phys_t.
//
// Nothing here is guessed: an unknown layout, an unregistered attribute id, a
// header whose size disagrees with its layout, or a non-8-byte word is refused
// by name, and a missing attribute stays missing.

const (
	saMagic          = 0x2F505A
	saAttrsEntry     = "SA_ATTRS"
	saLayoutsEntry   = "LAYOUTS"
	saRegistryEntry  = "REGISTRY"
	legacyZnodeSize  = 0x108
	saHeaderFixed    = 6
	saTableLimit     = 4096
	maxSymlinkTarget = 1 << 20
	masterNodeObject = 1
	poolDirectoryID  = 1
	rootDatasetEntry = "root_dataset"
	rootObjectEntry  = "ROOT"
)

const (
	zplAtime   = "ZPL_ATIME"
	zplMtime   = "ZPL_MTIME"
	zplCtime   = "ZPL_CTIME"
	zplCrtime  = "ZPL_CRTIME"
	zplGen     = "ZPL_GEN"
	zplMode    = "ZPL_MODE"
	zplSize    = "ZPL_SIZE"
	zplParent  = "ZPL_PARENT"
	zplLinks   = "ZPL_LINKS"
	zplXattr   = "ZPL_XATTR"
	zplRdev    = "ZPL_RDEV"
	zplFlags   = "ZPL_FLAGS"
	zplUID     = "ZPL_UID"
	zplGID     = "ZPL_GID"
	zplSymlink = "ZPL_SYMLINK"
)

// SaAttribute is one registration from the dataset's REGISTRY ZAP.
type SaAttribute struct {
	ID uint16
	// Name is the attribute's registered name.
	Name string
	// Length is the fixed length in bytes; 0 means a per-object length.
	Length uint16
	// Bswap is the byte-swap class; only meaningful for a byte-swapped pool.
	Bswap uint8
}

// SaTables is a dataset's SA layout and registry maps.
type SaTables struct {
	layouts    map[uint16][]uint16
	attributes map[uint16]SaAttribute
}

func newSATables() *SaTables {
	return &SaTables{layouts: map[uint16][]uint16{}, attributes: map[uint16]SaAttribute{}}
}

// loadSATables reads the tables the dataset's master node points at.
//
// SA_ATTRS absent is a fact about an old dataset, not an error. When it is
// present, its LAYOUTS/REGISTRY keys may still be absent: the two maps are
// created lazily on first use.
func loadSATables(reader *BlockReader, objset *Objset) (*SaTables, error) {
	master, err := objset.zapObject(reader, masterNodeObject)
	if err != nil {
		return nil, err
	}
	object, ok := master.unsigned(saAttrsEntry)
	if !ok {
		return newSATables(), nil
	}
	node, err := objset.dnode(reader, object)
	if err != nil {
		return nil, err
	}
	if node.kind == dmuOtNone {
		return nil, corruptf("the master node's %q names free object %d", saAttrsEntry, object)
	}
	saMaster, err := readZapUpTo(reader, node, saTableLimit)
	if err != nil {
		return nil, err
	}
	tables := newSATables()
	if layouts, ok := saMaster.unsigned(saLayoutsEntry); ok {
		if err := tables.readLayouts(reader, objset, layouts); err != nil {
			return nil, err
		}
	}
	if registry, ok := saMaster.unsigned(saRegistryEntry); ok {
		if err := tables.readRegistry(reader, objset, registry); err != nil {
			return nil, err
		}
	}
	return tables, nil
}

func (t *SaTables) readLayouts(reader *BlockReader, objset *Objset, object uint64) error {
	zap, err := objset.zapObjectUpTo(reader, object, saTableLimit)
	if err != nil {
		return err
	}
	for _, entry := range zap.entries() {
		number, err := strconv.ParseUint(entry.name, 10, 16)
		if err != nil {
			return corruptf("the layout map holds %q, which is not a layout number", entry.name)
		}
		if len(entry.value) == 0 || len(entry.value)%2 != 0 {
			return corruptf("layout %d is %d bytes; a layout is an array of 2-byte attribute ids",
				number, len(entry.value))
		}
		ids := make([]uint16, 0, len(entry.value)/2)
		for at := 0; at+2 <= len(entry.value); at += 2 {
			ids = append(ids, uint16(entry.value[at])|uint16(entry.value[at+1])<<8)
		}
		t.layouts[uint16(number)] = ids
	}
	return nil
}

func (t *SaTables) readRegistry(reader *BlockReader, objset *Objset, object uint64) error {
	zap, err := objset.zapObjectUpTo(reader, object, saTableLimit)
	if err != nil {
		return err
	}
	for _, entry := range zap.entries() {
		if len(entry.value) != 8 {
			return corruptf("attribute %q is registered with %d bytes; a registration is 8",
				entry.name, len(entry.value))
		}
		word := leUint64(entry.value)
		attribute := SaAttribute{
			ID:     uint16(word & 0xffff),
			Bswap:  uint8((word >> 16) & 0xff),
			Length: uint16((word >> 24) & 0xffff),
			Name:   entry.name,
		}
		if existing, ok := t.attributes[attribute.ID]; ok {
			return corruptf("attribute id %d is registered twice, as %q and %q",
				attribute.ID, existing.Name, entry.name)
		}
		t.attributes[attribute.ID] = attribute
	}
	return nil
}

func (t *SaTables) layout(number uint16) []uint16 { return t.layouts[number] }

func (t *SaTables) attribute(id uint16) (SaAttribute, bool) {
	value, ok := t.attributes[id]
	return value, ok
}

func (t *SaTables) attributeByName(name string) (SaAttribute, bool) {
	for _, attribute := range t.attributes {
		if attribute.Name == name {
			return attribute, true
		}
	}
	return SaAttribute{}, false
}

// AttributeSource says how an object's attributes were stored.
type AttributeSource struct {
	// Layout is the SA layout number; meaningful when Legacy is false.
	Layout uint16
	// Legacy marks a pre-SA znode_phys_t.
	Legacy bool
}

// Time is a ZFS timestamp: seconds since the Unix epoch and the nanoseconds
// within that second.
type Time struct {
	Seconds int64
	Nanos   uint32
}

// ZplAttributes is the POSIX metadata an object carries.
//
// A nil pointer means the attribute is absent from this object's encoding, not
// that it is zero: ZFS omits ZPL_RDEV on everything that is not a device.
type ZplAttributes struct {
	Object uint64
	Source AttributeSource
	Kind   DType
	Mode   *uint32
	Size   *uint64
	UID    *uint64
	GID    *uint64
	Links  *uint64
	Parent *uint64
	Gen    *uint64
	Atime  *Time
	Mtime  *Time
	Ctime  *Time
	Btime  *Time
	// Symlink is the target bytes of a symbolic link, exactly as stored.
	Symlink []byte
	values  map[string][]byte
}

// Raw returns the raw bytes of attribute name, if the object carries it.
func (a *ZplAttributes) Raw(name string) ([]byte, bool) {
	value, ok := a.values[name]
	return value, ok
}

// readAttributes reads one object's ZPL attributes.
func readAttributes(reader *BlockReader, objset *Objset, object uint64, tables *SaTables) (*ZplAttributes, error) {
	node, err := objset.dnode(reader, object)
	if err != nil {
		return nil, err
	}
	if node.isFree() {
		return nil, corruptf("object %d is free", object)
	}
	var source AttributeSource
	var values map[string][]byte
	switch node.bonustype {
	case dmuOtSA:
		layout, decoded, err := decodeSABuffer(node.bonus, tables, object, "bonus")
		if err != nil {
			return nil, err
		}
		values = decoded
		if pointer := node.spillPointer(); pointer != nil {
			if pointer.isHole() {
				return nil, corruptf("object %d marks a spilled bonus but its spill pointer is a hole", object)
			}
			spill, err := reader.read(*pointer)
			if err != nil {
				return nil, err
			}
			_, spillValues, err := decodeSABuffer(spill, tables, object, "spill")
			if err != nil {
				return nil, err
			}
			for name, value := range spillValues {
				if _, exists := values[name]; !exists {
					values[name] = value
				}
			}
		}
		source = AttributeSource{Layout: layout}
	case dmuOtZnode:
		legacy, err := legacyValues(reader, node, object)
		if err != nil {
			return nil, err
		}
		values = legacy
		source = AttributeSource{Legacy: true}
	default:
		return nil, unsupportedf("object %d's bonus type is %d, which is neither an SA buffer nor a znode",
			object, node.bonustype)
	}
	return summarizeAttributes(object, node.kind, source, values)
}

// decodeSABuffer decodes one SA buffer into attribute name → bytes. It returns
// the layout number even when the buffer holds no attributes.
func decodeSABuffer(buffer []byte, tables *SaTables, object uint64, which string) (uint16, map[string][]byte, error) {
	if len(buffer) < saHeaderFixed {
		if allZeroBytes(buffer) {
			return 0, map[string][]byte{}, nil
		}
		return 0, nil, corruptf("object %d's %s SA buffer is %d bytes; a header alone is %d",
			object, which, len(buffer), saHeaderFixed)
	}
	magic := uint32(buffer[0]) | uint32(buffer[1])<<8 | uint32(buffer[2])<<16 | uint32(buffer[3])<<24
	// An all-zero buffer is an object with no attributes; ZFS accepts magic 0
	// and maps its layout 0 to the empty dummy layout.
	if magic == 0 {
		return 0, map[string][]byte{}, nil
	}
	if magic != saMagic {
		if swap32(magic) == saMagic {
			return 0, nil, unsupportedf("object %d's %s SA header is byte-swapped", object, which)
		}
		return 0, nil, corruptf("object %d's %s SA header magic is 0x%06x", object, which, magic)
	}
	info := uint16(buffer[4]) | uint16(buffer[5])<<8
	layout := info & 0x3ff
	declaredHeader := int((info>>10)&0x3f) * 8
	// On an SA object layout 0 is the empty dummy layout, never the legacy
	// one; only a DMU_OT_ZNODE bonus uses the legacy layout.
	if layout <= 1 {
		return layout, map[string][]byte{}, nil
	}
	ids := tables.layout(layout)
	if ids == nil {
		return 0, nil, corruptf("object %d uses SA layout %d, which the dataset's %q map does not hold",
			object, layout, saLayoutsEntry)
	}
	resolved := make([]SaAttribute, 0, len(ids))
	for _, id := range ids {
		attribute, ok := tables.attribute(id)
		if !ok {
			return 0, nil, corruptf("object %d uses SA attribute id %d, which the dataset's %q does not hold",
				object, id, saRegistryEntry)
		}
		resolved = append(resolved, attribute)
	}
	variable := 0
	for _, attribute := range resolved {
		if attribute.Length == 0 {
			variable++
		}
	}
	dataStart := align8Int(saHeaderFixed + 2*variable)
	// The writer stores exactly this size; a disagreement means the two
	// buffers describe different layouts and neither can be trusted.
	if declaredHeader != dataStart {
		return 0, nil, corruptf("object %d's %s SA header says %d bytes for layout %d, which needs %d",
			object, which, declaredHeader, layout, dataStart)
	}
	if dataStart > len(buffer) {
		return 0, nil, corruptf("object %d's %s SA header is %d bytes, longer than the %d available",
			object, which, dataStart, len(buffer))
	}
	values := map[string][]byte{}
	cursor := dataStart
	variableIndex := 0
	for _, attribute := range resolved {
		length := int(attribute.Length)
		if attribute.Length == 0 {
			at := saHeaderFixed + 2*variableIndex
			if at+2 > len(buffer) {
				return 0, nil, corruptf("object %d's %s header is missing the length of attribute %q",
					object, which, attribute.Name)
			}
			length = int(uint16(buffer[at]) | uint16(buffer[at+1])<<8)
			variableIndex++
		}
		end := cursor + length
		if end < cursor || end > len(buffer) {
			return 0, nil, corruptf("object %d's %s attribute %q runs %d bytes into a %d-byte buffer",
				object, which, attribute.Name, end, len(buffer))
		}
		values[attribute.Name] = append([]byte(nil), buffer[cursor:end]...)
		cursor = align8Int(end)
	}
	return layout, values, nil
}

// legacyValues presents a pre-SA znode_phys_t as the same map.
func legacyValues(reader *BlockReader, node *Dnode, object uint64) (map[string][]byte, error) {
	bonus := node.bonus
	if len(bonus) < legacyZnodeSize {
		return nil, corruptf("object %d's znode bonus is %d bytes; a znode_phys_t is %d",
			object, len(bonus), legacyZnodeSize)
	}
	fields := []struct {
		name   string
		offset int
		length int
	}{
		{zplAtime, 0, 16}, {zplMtime, 16, 16}, {zplCtime, 32, 16}, {zplCrtime, 48, 16},
		{zplGen, 64, 8}, {zplMode, 72, 8}, {zplSize, 80, 8}, {zplParent, 88, 8},
		{zplLinks, 96, 8}, {zplXattr, 104, 8}, {zplRdev, 112, 8}, {zplFlags, 120, 8},
		{zplUID, 128, 8}, {zplGID, 136, 8},
	}
	values := make(map[string][]byte, len(fields)+1)
	for _, field := range fields {
		values[field.name] = append([]byte(nil), bonus[field.offset:field.offset+field.length]...)
	}
	mode, _ := leWord(values[zplMode])
	if mode&0xf000 == 0o120000 {
		size, _ := leWord(values[zplSize])
		if size > maxSymlinkTarget {
			return nil, corruptf("object %d's symlink target is %d bytes, past the %d-byte bound",
				object, size, maxSymlinkTarget)
		}
		var target []byte
		if legacyZnodeSize+int(size) <= len(bonus) {
			target = append([]byte(nil), bonus[legacyZnodeSize:legacyZnodeSize+int(size)]...)
		} else {
			data, err := readObject(reader, node, 0, int(size))
			if err != nil {
				return nil, err
			}
			target = data
		}
		values[zplSymlink] = target
	}
	return values, nil
}

func summarizeAttributes(object uint64, nodeKind uint8, source AttributeSource, values map[string][]byte) (*ZplAttributes, error) {
	attributes := &ZplAttributes{Object: object, Source: source, values: values}
	if bytes, ok := values[zplMode]; ok {
		value, err := attributeWord(object, zplMode, bytes)
		if err != nil {
			return nil, err
		}
		mode := uint32(value)
		attributes.Mode = &mode
	}
	if bytes, ok := values[zplSize]; ok {
		value, err := attributeWord(object, zplSize, bytes)
		if err != nil {
			return nil, err
		}
		attributes.Size = &value
	}
	switch {
	case attributes.Mode != nil && *attributes.Mode&0xf000 != 0:
		attributes.Kind = dTypeFromBits(uint8((*attributes.Mode & 0xf000) >> 12))
	case nodeKind == dmuOtDirectoryContents:
		// A directory's dnode type is unambiguous; anything else without a
		// mode stays unknown rather than being guessed from its dnode kind.
		attributes.Kind = DTypeDirectory
	default:
		attributes.Kind = DTypeUnknown
	}
	if attributes.Kind == DTypeSymlink {
		target, ok := values[zplSymlink]
		if !ok {
			return nil, corruptf("object %d's mode is a symbolic link but it carries no %q", object, zplSymlink)
		}
		if attributes.Size != nil && *attributes.Size != uint64(len(target)) {
			return nil, corruptf("object %d's symlink target is %d bytes but %q is %d",
				object, len(target), zplSize, *attributes.Size)
		}
		attributes.Symlink = append([]byte(nil), target...)
	}
	var err error
	if attributes.UID, err = optionalAttributeWord(object, values, zplUID); err != nil {
		return nil, err
	}
	if attributes.GID, err = optionalAttributeWord(object, values, zplGID); err != nil {
		return nil, err
	}
	if attributes.Links, err = optionalAttributeWord(object, values, zplLinks); err != nil {
		return nil, err
	}
	if attributes.Parent, err = optionalAttributeWord(object, values, zplParent); err != nil {
		return nil, err
	}
	if attributes.Gen, err = optionalAttributeWord(object, values, zplGen); err != nil {
		return nil, err
	}
	if attributes.Atime, err = attributeTime(object, values, zplAtime); err != nil {
		return nil, err
	}
	if attributes.Mtime, err = attributeTime(object, values, zplMtime); err != nil {
		return nil, err
	}
	if attributes.Ctime, err = attributeTime(object, values, zplCtime); err != nil {
		return nil, err
	}
	if attributes.Btime, err = attributeTime(object, values, zplCrtime); err != nil {
		return nil, err
	}
	return attributes, nil
}

func attributeWord(object uint64, name string, bytes []byte) (uint64, error) {
	if len(bytes) != 8 {
		return 0, corruptf("object %d's %q is %d bytes; a word is 8", object, name, len(bytes))
	}
	return leUint64(bytes), nil
}

func optionalAttributeWord(object uint64, values map[string][]byte, name string) (*uint64, error) {
	bytes, ok := values[name]
	if !ok {
		return nil, nil
	}
	value, err := attributeWord(object, name, bytes)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func leWord(bytes []byte) (uint64, bool) {
	if len(bytes) != 8 {
		return 0, false
	}
	return leUint64(bytes), true
}

func attributeTime(object uint64, values map[string][]byte, name string) (*Time, error) {
	bytes, ok := values[name]
	if !ok {
		return nil, nil
	}
	if len(bytes) != 16 {
		return nil, corruptf("object %d's %q is %d bytes; a timestamp is two words", object, name, len(bytes))
	}
	seconds := leUint64(bytes[0:8])
	nanos := leUint64(bytes[8:16])
	if nanos >= 1_000_000_000 {
		return nil, corruptf("object %d's %q holds %d nanoseconds, past the end of its second",
			object, name, nanos)
	}
	return &Time{Seconds: int64(seconds), Nanos: uint32(nanos)}, nil
}

func align8Int(value int) int { return (value + 7) &^ 7 }

func swap32(value uint32) uint32 {
	return value>>24 | (value>>8)&0xff00 | (value<<8)&0xff0000 | value<<24
}

func allZeroBytes(bytes []byte) bool {
	for _, b := range bytes {
		if b != 0 {
			return false
		}
	}
	return true
}
