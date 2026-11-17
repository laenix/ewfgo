package zfs

// Object sets: the 1 KiB (or larger) block a block pointer at a dataset's (or
// the pool's MOS) root leads to.
//
// The first 512 bytes are the dnode of the object set's dnode array. That is
// the bootstrap: object 0 is described inline, every other object's dnode is
// read from object 0's data at object-number times 512. The type field says
// whether this is the MOS (metadata), a filesystem, or a zvol; reading one as
// another would produce plausible but wrong objects.

const (
	metaDslSizeV1 = 1024
	osTypeOffset  = 512 + 192
	osFlagsOffset = 712
	osMacOffset   = 720
	osLocalMacOff = 752
	osTypeMacEnd  = osLocalMacOff + 32
)

// ObjsetType is the kind of object set the type field names.
type ObjsetType uint64

const (
	ObjsetTypeNone ObjsetType = 0
	ObjsetTypeMeta ObjsetType = 1
	ObjsetTypeZFS  ObjsetType = 2
	ObjsetTypeZvol ObjsetType = 3
)

// Aliases used by the test builder and by callers that spell the pool's
// metadata object set in either case.
const (
	objsetTypeMeta = uint64(ObjsetTypeMeta)
	objsetTypeZFS  = uint64(ObjsetTypeZFS)
	objsetTypeZvol = uint64(ObjsetTypeZvol)
)

func objsetTypeFromID(id uint64) ObjsetType {
	switch id {
	case 0:
		return ObjsetTypeNone
	case 1:
		return ObjsetTypeMeta
	case 2:
		return ObjsetTypeZFS
	case 3:
		return ObjsetTypeZvol
	default:
		return ObjsetType(id)
	}
}

func (t ObjsetType) label() string {
	switch t {
	case ObjsetTypeNone:
		return "none"
	case ObjsetTypeMeta:
		return "mos"
	case ObjsetTypeZFS:
		return "zfs"
	case ObjsetTypeZvol:
		return "zvol"
	default:
		return "other"
	}
}

// Objset is a parsed object-set block.
type Objset struct {
	// Meta is object 0: the dnode array.
	Meta        *Dnode
	osType      ObjsetType
	flags       uint64
	portableMAC [32]byte
	localMAC    [32]byte
	hasMACs     bool
}

func parseObjset(bytes []byte) (*Objset, error) {
	if len(bytes) < metaDslSizeV1 {
		return nil, corruptf("an object set of %d bytes; the smallest is %d", len(bytes), metaDslSizeV1)
	}
	if len(bytes) < osTypeOffset+8 {
		return nil, corruptf("an object set without its type field")
	}
	meta, err := parseDnode(bytes[:512], 0)
	if err != nil {
		return nil, err
	}
	if meta.kind != dmuOtDnode {
		return nil, corruptf("an object set whose first dnode is %s", objectTypeName(meta.kind))
	}
	objset := &Objset{
		Meta:   meta,
		osType: objsetTypeFromID(leUint64(bytes[osTypeOffset:])),
		flags:  leUint64(bytes[osFlagsOffset:]),
	}
	if len(bytes) >= osTypeMacEnd {
		copy(objset.portableMAC[:], bytes[osMacOffset:osMacOffset+32])
		copy(objset.localMAC[:], bytes[osLocalMacOff:osLocalMacOff+32])
		objset.hasMACs = true
	}
	return objset, nil
}

// dnode reads one object's dnode, including its extra slots.
func (o *Objset) dnode(reader *BlockReader, object uint64) (*Dnode, error) {
	if object>>48 != 0 {
		return nil, corruptf("object number %d exceeds 48 bits", object)
	}
	if object > (^uint64(0))/512 {
		return nil, corruptf("an object number overflows the dnode array")
	}
	offset := object * 512
	first, err := readObject(reader, o.Meta, offset, 512)
	if err != nil {
		return nil, err
	}
	extra := int(first[12])
	bytes := first
	if extra != 0 {
		bytes, err = readObject(reader, o.Meta, offset, (extra+1)*512)
		if err != nil {
			return nil, err
		}
	}
	return parseDnode(bytes, object)
}

// zap reads a ZAP object described by node.
func (o *Objset) zap(reader *BlockReader, node *Dnode) (*Zap, error) {
	if node.kind == dmuOtNone {
		return nil, corruptf("object %d is free", node.object)
	}
	return readZap(reader, node)
}

// zapObject reads an object by number as a ZAP.
func (o *Objset) zapObject(reader *BlockReader, object uint64) (*Zap, error) {
	node, err := o.dnode(reader, object)
	if err != nil {
		return nil, err
	}
	return o.zap(reader, node)
}

// zapObjectUpTo reads an object by number as a ZAP, stopping at limit entries.
func (o *Objset) zapObjectUpTo(reader *BlockReader, object uint64, limit int) (*Zap, error) {
	node, err := o.dnode(reader, object)
	if err != nil {
		return nil, err
	}
	if node.kind == dmuOtNone {
		return nil, corruptf("object %d is free", object)
	}
	return readZapUpTo(reader, node, limit)
}

// isEncrypted reports a checksum-protected object set, which advertises
// itself with a non-zero MAC.
func (o *Objset) isEncrypted() bool {
	if !o.hasMACs {
		return false
	}
	for _, b := range o.portableMAC {
		if b != 0 {
			return true
		}
	}
	for _, b := range o.localMAC {
		if b != 0 {
			return true
		}
	}
	return false
}

// requireMeta refuses an object set that is not the pool's metadata set.
func (o *Objset) requireMeta() error {
	if o.osType == ObjsetTypeMeta {
		return nil
	}
	return unsupportedf("an object set of type `%s` where the MOS belongs", o.osType.label())
}

// requireZFS refuses a dataset object set that is not a filesystem.
func (o *Objset) requireZFS() error {
	switch o.osType {
	case ObjsetTypeZFS:
		return nil
	case ObjsetTypeZvol:
		return unsupportedf("a zvol dataset, whose block device contents are not a filesystem")
	default:
		return unsupportedf("a dataset object set of type `%s`", o.osType.label())
	}
}
