package zfs

// DSL datasets and directories — the objects that name a filesystem.
//
// The MOS object directory maps `root_dataset` to the pool's root DSL
// directory; that directory's bonus (dsl_dir_phys_t) names the head dataset,
// whose own bonus holds dsl_dataset_phys_t. Its ds_bp is the block pointer to
// the dataset's object set.
//
// A dataset and a DSL directory are identified by their bonus type, not their
// data type. A data-less object is zapified into DMU_OTN_ZAP_METADATA while
// keeping the struct in its bonus.

const (
	dsDirObj         = 0
	dsNumChildren    = 40
	dsCreationTime   = 48
	dsCreationTXG    = 56
	dsBP             = 128
	datasetPhysMin   = dsBP + 128
	ddHeadDatasetObj = 8
	ddParentObj      = 16
	ddChildDirZapObj = 32
	ddPropsZapObj    = 80
	dslDirPhysMin    = ddChildDirZapObj + 8
)

// DatasetPhys is one dsl_dataset_phys_t.
type DatasetPhys struct {
	dirObj            uint64
	prevSnapObj       uint64
	prevSnapTXG       uint64
	nextSnapObj       uint64
	snapnamesZapObj   uint64
	numChildren       uint64
	creationTime      uint64
	creationTXG       uint64
	deadlistObj       uint64
	referencedBytes   uint64
	compressedBytes   uint64
	uncompressedBytes uint64
	uniqueBytes       uint64
	fsidGUID          uint64
	guid              uint64
	flags             uint64
	bp                BlockPointer
}

func parseDatasetPhys(bonus []byte) (*DatasetPhys, error) {
	if len(bonus) < datasetPhysMin {
		return nil, corruptf("a DSL dataset bonus of %d bytes; ds_bp needs %d", len(bonus), datasetPhysMin)
	}
	bp, err := parseBlockPointer(bonus[dsBP : dsBP+blockPointerSize])
	if err != nil {
		return nil, err
	}
	return &DatasetPhys{
		dirObj:            leUint64(bonus[dsDirObj:]),
		prevSnapObj:       leUint64(bonus[8:]),
		prevSnapTXG:       leUint64(bonus[16:]),
		nextSnapObj:       leUint64(bonus[24:]),
		snapnamesZapObj:   leUint64(bonus[32:]),
		numChildren:       leUint64(bonus[dsNumChildren:]),
		creationTime:      leUint64(bonus[dsCreationTime:]),
		creationTXG:       leUint64(bonus[dsCreationTXG:]),
		deadlistObj:       leUint64(bonus[64:]),
		referencedBytes:   leUint64(bonus[72:]),
		compressedBytes:   leUint64(bonus[80:]),
		uncompressedBytes: leUint64(bonus[88:]),
		uniqueBytes:       leUint64(bonus[96:]),
		fsidGUID:          leUint64(bonus[104:]),
		guid:              leUint64(bonus[112:]),
		flags:             leUint64(bonus[120:]),
		bp:                bp,
	}, nil
}

// isSnapshot reports OpenZFS's dsl_dataset_is_snapshot(): a snapshot dataset
// object has children. A head dataset's snapshot list lives in
// ds_snapnames_zapobj, not in this count.
func (d *DatasetPhys) isSnapshot() bool { return d.numChildren != 0 }

// DslDirPhys is one dsl_dir_phys_t.
type DslDirPhys struct {
	headDatasetObj uint64
	parentObj      uint64
	originObj      uint64
	childDirZapObj uint64
	propsZapObj    uint64
}

func parseDslDirPhys(bonus []byte) (*DslDirPhys, error) {
	if len(bonus) < dslDirPhysMin {
		return nil, corruptf("a DSL directory bonus of %d bytes; needs %d", len(bonus), dslDirPhysMin)
	}
	propsZapObj := uint64(0)
	if len(bonus) >= ddPropsZapObj+8 {
		propsZapObj = leUint64(bonus[ddPropsZapObj:])
	}
	return &DslDirPhys{
		headDatasetObj: leUint64(bonus[ddHeadDatasetObj:]),
		parentObj:      leUint64(bonus[ddParentObj:]),
		originObj:      leUint64(bonus[24:]),
		childDirZapObj: leUint64(bonus[ddChildDirZapObj:]),
		propsZapObj:    propsZapObj,
	}, nil
}
