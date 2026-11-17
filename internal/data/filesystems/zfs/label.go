package zfs

import (
	"fmt"
	"sort"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Vdev labels: the pool's identity and its transaction-group rings.
//
// Each leaf vdev carries four labels — two at the start and two at the end —
// of 256 KiB each. A label is an 8 KiB pad, an 8 KiB boot environment, a
// 112 KiB vdev_phys at offset 16 KiB (an XDR nvlist plus a 40-byte
// self-checksum), and a 128 KiB uberblock ring starting at 128 KiB.

// LabelSize is one vdev label.
const LabelSize uint64 = 256 << 10

// LabelPhysOffset is where the vdev_phys buffer begins inside a label.
const LabelPhysOffset uint64 = 16 << 10

// LabelPhysSize is the vdev_phys size, including its embedded checksum.
const LabelPhysSize = 112 << 10

// LabelECKSize is the embedded checksum trailer: magic plus 32 digest bytes.
const LabelECKSize = 40

// ZECMagic marks the embedded checksum a vdev_phys buffer ends with.
const ZECMagic uint64 = 0x0210da7ab10c7a11

// UberblockRingSize is the ring a label ends with.
const UberblockRingSize = 128 << 10

// VDevLabelStartSize is the bytes a leaf reserves before its allocatable
// area: two 256 KiB labels plus the 3.5 MiB boot area. A DVA offset is an
// offset in that allocatable area, so the physical offset adds this constant.
const VDevLabelStartSize uint64 = 4 << 20

// VDevLabelEndSize is the trailing label pair. Allocated data never reaches
// into it.
const VDevLabelEndSize uint64 = 512 << 10

// maxLabelAttempts bounds the work label reading may do on a hostile device.
const maxLabelAttempts = 4

type labelOffset struct {
	index  int
	offset uint64
}

// labelOffsets returns the offsets of the four labels for a device of psize
// bytes. A device whose size is not a multiple of the label size has no
// trustworthy tail pair, so only the two head labels are returned.
func labelOffsets(psize uint64) []labelOffset {
	offsets := []labelOffset{{index: 0, offset: 0}, {index: 1, offset: LabelSize}}
	if psize%LabelSize == 0 && psize >= 4*LabelSize {
		offsets = append(offsets,
			labelOffset{index: 2, offset: psize - 2*LabelSize},
			labelOffset{index: 3, offset: psize - LabelSize},
		)
	}
	return offsets
}

// PoolConfig is the part of a pool configuration a forensic reader reports.
type PoolConfig struct {
	Name            string
	GUID            uint64
	GUIDPresent     bool
	Version         uint64
	TXG             uint64
	Ashift          uint64
	AshiftPresent   bool
	Vdev            *VdevConfig
	FeaturesForRead []string
}

// VdevConfig is one node of the label's vdev tree.
type VdevConfig struct {
	Kind          string
	ID            uint64
	IDPresent     bool
	GUID          uint64
	GUIDPresent   bool
	Path          string
	PathPresent   bool
	Ashift        uint64
	AshiftPresent bool
	Asize         uint64
	AsizePresent  bool
	Children      []VdevConfig
}

func poolConfigFromNvlist(list *NvList) PoolConfig {
	config := PoolConfig{
		Name:   list.String("name"),
		Vdev:   vdevConfigFromNvlist(list.List("vdev_tree")),
		Ashift: 0,
	}
	if value, ok := list.Unsigned("pool_guid"); ok {
		config.GUID, config.GUIDPresent = value, true
	}
	if value, ok := list.Unsigned("version"); ok {
		config.Version = value
	}
	if value, ok := list.Unsigned("txg"); ok {
		config.TXG = value
	}
	if config.Vdev != nil {
		config.Ashift, config.AshiftPresent = config.Vdev.Ashift, config.Vdev.AshiftPresent
	}
	if features := list.List("features_for_read"); features != nil {
		config.FeaturesForRead = features.Names()
		sort.Strings(config.FeaturesForRead)
	}
	return config
}

func vdevConfigFromNvlist(list *NvList) *VdevConfig {
	if list == nil {
		return nil
	}
	vdev := &VdevConfig{}
	if value := list.String("type"); value != "" {
		vdev.Kind = value
	}
	if value, ok := list.Unsigned("id"); ok {
		vdev.ID, vdev.IDPresent = value, true
	}
	if value, ok := list.Unsigned("guid"); ok {
		vdev.GUID, vdev.GUIDPresent = value, true
	}
	if value := list.String("path"); value != "" {
		vdev.Path, vdev.PathPresent = value, true
	}
	if value, ok := list.Unsigned("ashift"); ok {
		vdev.Ashift, vdev.AshiftPresent = value, true
	}
	if value, ok := list.Unsigned("asize"); ok {
		vdev.Asize, vdev.AsizePresent = value, true
	}
	for _, child := range list.Lists("children") {
		parsed := vdevConfigFromNvlist(&child)
		if parsed != nil {
			vdev.Children = append(vdev.Children, *parsed)
		}
	}
	return vdev
}

// leaves returns the vdev tree's leaf nodes in config order.
func (p PoolConfig) leaves() []*VdevConfig {
	var out []*VdevConfig
	var walk func(vdev *VdevConfig)
	walk = func(vdev *VdevConfig) {
		if len(vdev.Children) == 0 {
			out = append(out, vdev)
			return
		}
		for i := range vdev.Children {
			walk(&vdev.Children[i])
		}
	}
	if p.Vdev != nil {
		walk(p.Vdev)
	}
	return out
}

// Label is one verified vdev label.
type Label struct {
	Index    int
	Offset   uint64
	Verified string
	Pool     PoolConfig
	// TXG is the label's own transaction group (the last synced txg).
	TXG  uint64
	ring []byte
}

// LabelReport is a verified label without its 128 KiB ring.
type LabelReport struct {
	Index    int
	Offset   uint64
	Verified string
	TXG      uint64
}

// readLabels reads every label the device holds. A label that fails is
// reported in problems and skipped; the caller can still open the pool from
// the others. Reads that fail at the source are collected as problems too,
// because a label beyond the device is absent, not evidence.
func readLabels(src source.ByteSource) ([]Label, []string, error) {
	psize := src.Len()
	var labels []Label
	var problems []string
	offsets := labelOffsets(psize)
	if len(offsets) > maxLabelAttempts {
		offsets = offsets[:maxLabelAttempts]
	}
	for _, at := range offsets {
		label, err := readLabel(src, at.index, at.offset)
		if err != nil {
			problems = append(problems, fmt.Sprintf("label %d at %d: %v", at.index, at.offset, err))
			continue
		}
		labels = append(labels, label)
	}
	if len(labels) == 0 {
		return nil, problems, corruptf("no readable ZFS label (%d problem(s)): %v", len(problems), problems)
	}
	return labels, problems, nil
}

func readLabel(src source.ByteSource, index int, offset uint64) (Label, error) {
	physOffset := offset + LabelPhysOffset
	phys := make([]byte, LabelPhysSize)
	if err := source.ReadExactAt(src, physOffset, phys); err != nil {
		return Label{}, err
	}
	eckOffset := LabelPhysSize - LabelECKSize
	if leUint64(phys[eckOffset:eckOffset+8]) != ZECMagic {
		return Label{}, corruptf("embedded checksum magic 0x%016x is not 0x%016x",
			leUint64(phys[eckOffset:eckOffset+8]), ZECMagic)
	}
	verified, err := verifyLabel(phys, physOffset)
	if err != nil {
		return Label{}, err
	}
	list, _, err := decodeNvlistPrefix(phys[:eckOffset])
	if err != nil {
		return Label{}, err
	}
	pool := poolConfigFromNvlist(list)

	ring := make([]byte, UberblockRingSize)
	ringOffset := offset + LabelPhysOffset + LabelPhysSize
	if err := source.ReadExactAt(src, ringOffset, ring); err != nil {
		return Label{}, err
	}
	return Label{
		Index:    index,
		Offset:   offset,
		Verified: verified,
		Pool:     pool,
		TXG:      pool.TXG,
		ring:     ring,
	}, nil
}

// verifyLabel replaces the checksum field with the label verifier and hashes
// the whole 112 KiB. The verifier is the absolute device offset of the
// vdev_phys buffer (label offset + LabelPhysOffset), which is the offset the
// buffer is written at, not the 256 KiB label slot's own offset. A failed
// checksum usually means one torn label write, not a broken pool.
func verifyLabel(phys []byte, absoluteOffset uint64) (string, error) {
	eckOffset := len(phys) - LabelECKSize
	buffer := append([]byte(nil), phys...)
	verifier := make([]byte, 32)
	putLEUint64(verifier[0:], absoluteOffset)
	copy(buffer[eckOffset+8:eckOffset+LabelECKSize], verifier)
	stored := phys[eckOffset+8 : eckOffset+LabelECKSize]

	ok, err := verifyChecksum(ChecksumSHA256, buffer, stored)
	if err != nil {
		return "", err
	}
	if ok {
		return "sha256", nil
	}
	// Pools older than the SHA-256 label checksum used fletcher4.
	ok, err = verifyChecksum(ChecksumFletcher4, buffer, stored)
	if err != nil {
		return "", err
	}
	if ok {
		return "fletcher4", nil
	}
	return "", corruptf("the label checksum does not match its bytes; this label was not fully written")
}

// Uberblocks returns this label's ring, newest first, plus the slots that
// failed to parse.
func (l Label) Uberblocks() ([]Uberblock, []string) {
	return scanUberblockRing(l.ring, l.Index)
}
