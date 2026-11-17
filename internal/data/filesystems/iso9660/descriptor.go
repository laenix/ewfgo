package iso9660

import (
	"encoding/binary"
	"strings"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	descriptorBytes = 2048
	vrsSector       = 16
	terminator      = 255
	maxDescriptors  = 64
)

// DescriptorType is the kind of one 2048-byte volume descriptor.
type DescriptorType uint8

const (
	DescriptorBoot DescriptorType = iota
	DescriptorPrimary
	DescriptorSupplementary
	DescriptorPartition
	DescriptorTerminator
)

func descriptorTypeFromByte(b byte) DescriptorType {
	switch b {
	case 0:
		return DescriptorBoot
	case 1:
		return DescriptorPrimary
	case 2:
		return DescriptorSupplementary
	case 3:
		return DescriptorPartition
	case terminator:
		return DescriptorTerminator
	default:
		return DescriptorType(b)
	}
}

// Label returns the descriptor type's name.
func (t DescriptorType) Label() string {
	switch t {
	case DescriptorBoot:
		return "boot"
	case DescriptorPrimary:
		return "primary"
	case DescriptorSupplementary:
		return "supplementary"
	case DescriptorPartition:
		return "partition"
	case DescriptorTerminator:
		return "terminator"
	default:
		return "other"
	}
}

// VolumeDescriptor holds the fields this reader uses.
type VolumeDescriptor struct {
	Kind            DescriptorType
	SystemID        string
	VolumeID        string
	VolumeSpaceSize uint32
	VolumeSetSize   uint16
	VolumeSequence  uint16
	BlockSize       uint32
	PathTableSize   uint32
	PathTableL      uint32
	PathTableM      uint32
	Root            [34]byte
	VolumeSetID     string
	Publisher       string
	Preparer        string
	Application     string
	CopyrightFile   string
	AbstractFile    string
	Bibliographic   string
	Created         IsoTime
	HasCreated      bool
	Modified        IsoTime
	HasModified     bool
	Expires         IsoTime
	HasExpires      bool
	Effective       IsoTime
	HasEffective    bool
	JolietLevel     uint8
	IsJoliet        bool
}

// Label returns the volume identifier.
func (d *VolumeDescriptor) Label() string { return d.VolumeID }

// DescriptorSet is the parsed volume descriptor set.
type DescriptorSet struct {
	Primary        VolumeDescriptor
	Joliet         *VolumeDescriptor
	Supplementary  int
	BootRecords    int
	BootCatalogLBA uint32
	HasBootCatalog bool
	Descriptors    int
}

func elToritoCatalog(bytes []byte) (uint32, bool) {
	const id = "EL TORITO SPECIFICATION"
	if len(bytes) < 39 || !strings.HasPrefix(string(bytes[7:39]), id) {
		return 0, false
	}
	if len(bytes) < 75 {
		return 0, false
	}
	lba := binary.LittleEndian.Uint32(bytes[71:75])
	return lba, lba != 0
}

// readDescriptorSet reads the volume recognition sequence. It refuses an
// image whose set carries no primary descriptor.
func readDescriptorSet(src source.ByteSource) (*DescriptorSet, error) {
	var set DescriptorSet
	var primary *VolumeDescriptor
	var joliet *VolumeDescriptor
	for index := 0; index < maxDescriptors; index++ {
		sector := uint64(vrsSector + index)
		bytes := make([]byte, descriptorBytes)
		if err := source.ReadExactAt(src, sector*descriptorBytes, bytes); err != nil {
			return nil, err
		}
		if string(bytes[1:6]) != "CD001" {
			return nil, corruptf("volume descriptor %d at sector %d carries no CD001 signature", index, sector)
		}
		set.Descriptors++
		kind := descriptorTypeFromByte(bytes[0])
		switch kind {
		case DescriptorBoot:
			set.BootRecords++
			if !set.HasBootCatalog {
				if lba, ok := elToritoCatalog(bytes); ok {
					set.BootCatalogLBA = lba
					set.HasBootCatalog = true
				}
			}
		case DescriptorPrimary:
			descriptor, err := parseDescriptor(bytes)
			if err != nil {
				return nil, err
			}
			if primary == nil {
				primary = descriptor
			}
		case DescriptorSupplementary:
			set.Supplementary++
			descriptor, err := parseDescriptor(bytes)
			if err != nil {
				return nil, err
			}
			if joliet == nil && descriptor.IsJoliet {
				joliet = descriptor
			}
		case DescriptorTerminator:
			if primary == nil {
				return nil, corruptf("no primary volume descriptor before the terminator")
			}
			set.Primary = *primary
			set.Joliet = joliet
			return &set, nil
		}
	}
	if primary == nil {
		return nil, corruptf("no primary volume descriptor before the terminator")
	}
	set.Primary = *primary
	set.Joliet = joliet
	return &set, nil
}

func parseDescriptor(bytes []byte) (*VolumeDescriptor, error) {
	if len(bytes) < descriptorBytes {
		return nil, corruptf("short volume descriptor")
	}
	blockSizeValue, _, err := bothU16(bytes, 128)
	if err != nil {
		return nil, err
	}
	blockSize := uint32(blockSizeValue)
	if blockSize != 512 && blockSize != 1024 && blockSize != 2048 {
		return nil, unsupportedf("logical block size %d (only 512, 1024 and 2048 are defined)", blockSize)
	}
	spaceSize, _, err := bothU32(bytes, 80)
	if err != nil {
		return nil, err
	}
	if spaceSize == 0 {
		return nil, corruptf("volume space size is zero")
	}
	var root [34]byte
	copy(root[:], bytes[156:190])
	if root[0] < 34 {
		return nil, corruptf("root directory record is %d bytes, shorter than its 34-byte header", root[0])
	}
	volumeSetSize, _, err := bothU16(bytes, 120)
	if err != nil {
		return nil, err
	}
	volumeSequence, _, err := bothU16(bytes, 124)
	if err != nil {
		return nil, err
	}
	pathTableSize, _, err := bothU32(bytes, 132)
	if err != nil {
		return nil, err
	}
	descriptor := &VolumeDescriptor{
		Kind:            descriptorTypeFromByte(bytes[0]),
		SystemID:        latin1Text(bytes[8:40]),
		VolumeID:        latin1Text(bytes[40:72]),
		VolumeSpaceSize: spaceSize,
		VolumeSetSize:   volumeSetSize,
		VolumeSequence:  volumeSequence,
		BlockSize:       blockSize,
		PathTableSize:   pathTableSize,
		PathTableL:      binary.LittleEndian.Uint32(bytes[140:144]),
		PathTableM:      binary.BigEndian.Uint32(bytes[148:152]),
		Root:            root,
		VolumeSetID:     latin1Text(bytes[190:318]),
		Publisher:       latin1Text(bytes[318:446]),
		Preparer:        latin1Text(bytes[446:574]),
		Application:     latin1Text(bytes[574:702]),
		CopyrightFile:   latin1Text(bytes[702:739]),
		AbstractFile:    latin1Text(bytes[739:776]),
		Bibliographic:   latin1Text(bytes[776:813]),
	}
	if time, ok := isoTimeFromASCII(bytes[813:830]); ok {
		descriptor.Created, descriptor.HasCreated = time, true
	}
	if time, ok := isoTimeFromASCII(bytes[830:847]); ok {
		descriptor.Modified, descriptor.HasModified = time, true
	}
	if time, ok := isoTimeFromASCII(bytes[847:864]); ok {
		descriptor.Expires, descriptor.HasExpires = time, true
	}
	if time, ok := isoTimeFromASCII(bytes[864:881]); ok {
		descriptor.Effective, descriptor.HasEffective = time, true
	}
	switch string(bytes[88:91]) {
	case "%/@":
		descriptor.JolietLevel, descriptor.IsJoliet = 1, true
	case "%/C":
		descriptor.JolietLevel, descriptor.IsJoliet = 2, true
	case "%/E":
		descriptor.JolietLevel, descriptor.IsJoliet = 3, true
	}
	return descriptor, nil
}

// Detect reports whether the source's sector 16 names ISO 9660.
func Detect(src source.ByteSource) (bool, error) {
	offset := uint64(vrsSector) * descriptorBytes
	if src.Len() < offset+descriptorBytes {
		return false, nil
	}
	bytes := make([]byte, descriptorBytes)
	if err := source.ReadExactAt(src, offset, bytes); err != nil {
		return false, err
	}
	if string(bytes[1:6]) != "CD001" {
		return false, nil
	}
	switch bytes[0] {
	case 0, 1, 2, 3, terminator:
		return true, nil
	default:
		return false, nil
	}
}

// latin1Text decodes a space- and NUL-padded identifier byte-for-byte as
// Latin-1, so no character is silently replaced.
func latin1Text(bytes []byte) string {
	end := len(bytes)
	for i := len(bytes) - 1; i >= 0; i-- {
		if bytes[i] != 0 && bytes[i] != ' ' {
			end = i + 1
			break
		}
		if i == 0 {
			end = 0
		}
	}
	var builder strings.Builder
	for _, b := range bytes[:end] {
		builder.WriteRune(rune(b))
	}
	return builder.String()
}

func bothU16(bytes []byte, at int) (uint16, bool, error) {
	if at < 0 || at+4 > len(bytes) {
		return 0, false, corruptf("field at %d runs past the descriptor", at)
	}
	le := binary.LittleEndian.Uint16(bytes[at:])
	be := binary.BigEndian.Uint16(bytes[at+2:])
	return le, le == be, nil
}

func bothU32(bytes []byte, at int) (uint32, bool, error) {
	if at < 0 || at+8 > len(bytes) {
		return 0, false, corruptf("field at %d runs past the descriptor", at)
	}
	le := binary.LittleEndian.Uint32(bytes[at:])
	be := binary.BigEndian.Uint32(bytes[at+4:])
	return le, le == be, nil
}
