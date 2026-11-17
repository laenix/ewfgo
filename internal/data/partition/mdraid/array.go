package mdraid

import (
	"fmt"
	"sync"

	"github.com/laenix/ewfgo/internal/data/source"
)

// ArrayMember is one member image plus the superblock decoded from it.
type ArrayMember struct {
	Superblock *Superblock
	Data       source.ByteSource
}

// StripePlacement records where one data role lives.
type StripePlacement struct {
	Role       uint16
	MemberUUID string
	DataOffset uint64
	Checksum   Checksum
}

type mappingKind uint8

const (
	mappingRaid0 mappingKind = iota
	mappingRaid10
	mappingParity
)

// stripeMapping places a logical chunk on a member. RAID4/5/6 parity is
// recognised but not assembled yet.
type stripeMapping struct {
	kind         mappingKind
	members      uint64
	nearCopies   uint64
	farCopies    uint64
	farOffset    bool
	farSetSize   uint64
	strideChunks uint64
	level        int32
	layout       uint32
	dataDisks    uint64
}

func (m stripeMapping) copyCount() uint64 {
	if m.kind == mappingRaid10 {
		return m.nearCopies * m.farCopies
	}
	return 1
}

// copyPlacement returns the role and member-chunk index of one copy of a
// logical chunk, in the kernel's copy order.
func (m stripeMapping) copyPlacement(chunkIndex, copy uint64) (uint64, uint64) {
	switch m.kind {
	case mappingParity:
		stripe := parityStripe(m.level, m.layout, chunkIndex, m.members, m.dataDisks)
		return stripe.data, stripe.memberChunk
	case mappingRaid10:
		// handled below
	default:
		return chunkIndex % m.members, chunkIndex / m.members
	}

	virtualChunk := chunkIndex * m.nearCopies
	dev := virtualChunk % m.members
	memberChunk := virtualChunk / m.members
	if m.farOffset {
		memberChunk *= m.farCopies
	}
	lastFarSetStart := (m.members/m.farSetSize - 1) * m.farSetSize
	lastFarSetSize := m.farSetSize + m.members%m.farSetSize
	slot := uint64(0)
	for near := uint64(0); near < m.nearCopies; near++ {
		farDev, farChunk := dev, memberChunk
		if slot == copy {
			return farDev, farChunk
		}
		slot++
		for far := uint64(1); far < m.farCopies; far++ {
			set := farDev / m.farSetSize
			farDev += m.nearCopies
			if m.members%m.farSetSize != 0 && farDev > lastFarSetStart {
				farDev -= lastFarSetStart
				farDev %= lastFarSetSize
				farDev += lastFarSetStart
			} else {
				farDev %= m.farSetSize
				farDev += m.farSetSize * set
			}
			farChunk += m.strideChunks
			if slot == copy {
				return farDev, farChunk
			}
			slot++
		}
		dev++
		if dev >= m.members {
			dev = 0
			memberChunk++
		}
	}
	return 0, 0
}

// ArraySource is a reassembled Linux RAID0 or RAID10 array. RAID4/5/6 parity
// layouts are recognised but not assembled yet.
type ArraySource struct {
	id         source.ID
	imageID    source.ImageID
	chunkBytes uint64
	length     uint64
	mapping    stripeMapping
	// Indexed by role; nil means the image does not hold that member.
	members    []source.ByteSource
	placements []StripePlacement
	counters   source.Counters
}

// Raid0 assembles a RAID0 array. Members may arrive in any order and may
// include spares or faulty members; every data role must be present.
func Raid0(id source.ID, members []ArrayMember) (*ArraySource, error) {
	if len(members) == 0 {
		return nil, fmt.Errorf("%w: a RAID0 array needs at least one member", ErrUnsupported)
	}
	first := members[0].Superblock
	if first == nil {
		return nil, fmt.Errorf("%w: member has no superblock", ErrUnsupported)
	}
	if first.Level != 0 {
		return nil, fmt.Errorf("%w: mdraid level %s (code %d) is not a RAID0 array",
			ErrUnsupported, first.LevelName(), first.Level)
	}
	chunkBytes := first.ChunkSizeBytes
	if chunkBytes == 0 {
		return nil, fmt.Errorf("%w: the RAID0 superblock records a chunk size of 0", ErrUnsupported)
	}
	if chunkBytes%SectorBytes != 0 {
		return nil, fmt.Errorf("%w: the RAID0 chunk size %d is not a whole number of %d-byte sectors",
			ErrUnsupported, chunkBytes, SectorBytes)
	}
	raidDisks := int(first.RaidDisks)
	if raidDisks == 0 {
		return nil, fmt.Errorf("%w: the RAID0 superblock records 0 members", ErrUnsupported)
	}

	arrayUUID := first.ArrayUUID()
	slots := make([]source.ByteSource, raidDisks)
	placements := make([]StripePlacement, raidDisks)
	filled := make([]bool, raidDisks)
	var memberLen uint64
	haveLen := false

	for index, member := range members {
		sb := member.Superblock
		if sb == nil {
			return nil, fmt.Errorf("%w: member %d has no superblock", ErrUnsupported, index)
		}
		if sb.ArrayUUID() != arrayUUID || sb.Level != first.Level ||
			sb.ChunkSizeBytes != chunkBytes || sb.RaidDisks != first.RaidDisks {
			return nil, fmt.Errorf("%w: member %d (device number %d) disagrees with the first member of array %s on set identifier, level, chunk size or member count",
				ErrUnsupported, index, sb.DevNumber, arrayUUID)
		}
		role, ok := sb.Role()
		if !ok {
			return nil, fmt.Errorf("%w: member %d (device number %d) has no entry in its own dev_roles array",
				ErrUnsupported, index, sb.DevNumber)
		}
		if role >= mdDiskRoleMax {
			continue // spare, faulty or journal
		}
		if int(role) >= raidDisks {
			return nil, fmt.Errorf("%w: member %d claims role %d, but array %s records %d members",
				ErrUnsupported, index, role, arrayUUID, raidDisks)
		}
		if filled[role] {
			return nil, fmt.Errorf("%w: two members of array %s claim role %d",
				ErrUnsupported, arrayUUID, role)
		}
		if member.Data == nil {
			return nil, fmt.Errorf("%w: member %d has no data source", ErrUnsupported, index)
		}
		length := member.Data.Len()
		if length == 0 {
			return nil, fmt.Errorf("%w: member %d of array %s has an empty data area",
				ErrUnsupported, index, arrayUUID)
		}
		if haveLen && length != memberLen {
			return nil, fmt.Errorf("%w: members of array %s have different data-area sizes (%d and %d bytes)",
				ErrUnsupported, arrayUUID, memberLen, length)
		}
		memberLen = length
		haveLen = true
		filled[role] = true
		slots[role] = member.Data
		placements[role] = StripePlacement{
			Role:       role,
			MemberUUID: sb.MemberUUID(),
			DataOffset: sb.DataOffsetBytes(),
			Checksum:   sb.Checksum,
		}
	}

	present := 0
	for _, ok := range filled {
		if ok {
			present++
		}
	}
	if present != raidDisks {
		return nil, fmt.Errorf("%w: the image holds %d of %d data members of RAID0 array %s; a striped array cannot be read without every stripe",
			ErrUnsupported, present, raidDisks, arrayUUID)
	}

	total, ok := checkedMul(memberLen, uint64(raidDisks))
	if !ok {
		return nil, fmt.Errorf("%w: RAID0 array %s length overflows a byte count", ErrUnsupported, arrayUUID)
	}

	return &ArraySource{
		id:         id,
		imageID:    slots[0].ImageID(),
		chunkBytes: chunkBytes,
		length:     total,
		mapping:    stripeMapping{kind: mappingRaid0, members: uint64(raidDisks)},
		members:    slots,
		placements: placements,
	}, nil
}

// Raid10 assembles a RAID10 array. Members may arrive in any order and may
// include spares, faulty members, or a missing member as long as every logical
// chunk keeps at least one surviving copy.
func Raid10(id source.ID, members []ArrayMember) (*ArraySource, error) {
	if len(members) == 0 {
		return nil, fmt.Errorf("%w: a RAID10 array needs at least one member", ErrUnsupported)
	}
	first := members[0].Superblock
	if first == nil {
		return nil, fmt.Errorf("%w: member has no superblock", ErrUnsupported)
	}
	if first.Level != 10 {
		return nil, fmt.Errorf("%w: mdraid level %s (code %d) is not a RAID10 array",
			ErrUnsupported, first.LevelName(), first.Level)
	}
	chunkBytes := first.ChunkSizeBytes
	if chunkBytes == 0 {
		return nil, fmt.Errorf("%w: the RAID10 superblock records a chunk size of 0", ErrUnsupported)
	}
	if chunkBytes%SectorBytes != 0 {
		return nil, fmt.Errorf("%w: the RAID10 chunk size %d is not a whole number of %d-byte sectors",
			ErrUnsupported, chunkBytes, SectorBytes)
	}
	if chunkBytes < 4096 || chunkBytes&(chunkBytes-1) != 0 {
		return nil, fmt.Errorf("%w: the RAID10 chunk size %d is not a power of two of at least 4096 bytes",
			ErrUnsupported, chunkBytes)
	}
	raidDisks := uint64(first.RaidDisks)
	layout := first.Layout
	if layout>>19 != 0 {
		return nil, fmt.Errorf("%w: the RAID10 layout word %#x uses reserved bits above 18",
			ErrUnsupported, layout)
	}
	nearCopies := uint64(layout & 0xFF)
	farCopies := uint64((layout >> 8) & 0xFF)
	farOffset := layout&(1<<16) != 0
	copies := nearCopies * farCopies
	if nearCopies == 0 || farCopies == 0 || copies < 2 || copies > raidDisks {
		return nil, fmt.Errorf("%w: the RAID10 layout word %#x records %d near and %d far copies over %d members",
			ErrUnsupported, layout, nearCopies, farCopies, raidDisks)
	}
	if layout>>17 > 2 {
		return nil, fmt.Errorf("%w: the RAID10 layout word %#x names far-set variant %d",
			ErrUnsupported, layout, layout>>17)
	}
	componentBytes := first.ComponentSizeBytes()
	if componentBytes == 0 {
		return nil, fmt.Errorf("%w: array %s records a component size of 0",
			ErrUnsupported, first.ArrayUUID())
	}
	arrayUUID := first.ArrayUUID()

	slots := make([]source.ByteSource, raidDisks)
	placements := make([]StripePlacement, raidDisks)
	filled := make([]bool, raidDisks)
	for index, member := range members {
		sb := member.Superblock
		if sb == nil {
			return nil, fmt.Errorf("%w: member %d has no superblock", ErrUnsupported, index)
		}
		if sb.ArrayUUID() != arrayUUID || sb.Level != first.Level ||
			sb.ChunkSizeBytes != chunkBytes || sb.RaidDisks != first.RaidDisks ||
			sb.Layout != layout || sb.ComponentSizeBytes() != componentBytes {
			return nil, fmt.Errorf("%w: member %d (device number %d) disagrees with the first member of RAID10 array %s",
				ErrUnsupported, index, sb.DevNumber, arrayUUID)
		}
		role, ok := sb.Role()
		if !ok {
			return nil, fmt.Errorf("%w: member %d (device number %d) has no entry in its own dev_roles array",
				ErrUnsupported, index, sb.DevNumber)
		}
		if role >= mdDiskRoleMax {
			continue
		}
		if uint64(role) >= raidDisks {
			return nil, fmt.Errorf("%w: member %d claims role %d, but RAID10 array %s records %d members",
				ErrUnsupported, index, role, arrayUUID, raidDisks)
		}
		if filled[role] {
			return nil, fmt.Errorf("%w: two members of array %s claim role %d",
				ErrUnsupported, arrayUUID, role)
		}
		if member.Data == nil || member.Data.Len() < componentBytes {
			return nil, fmt.Errorf("%w: member %d of RAID10 array %s has a data area smaller than the %d-byte component size",
				ErrUnsupported, index, arrayUUID, componentBytes)
		}
		filled[role] = true
		slots[role] = member.Data
		placements[role] = StripePlacement{
			Role:       role,
			MemberUUID: sb.MemberUUID(),
			DataOffset: sb.DataOffsetBytes(),
			Checksum:   sb.Checksum,
		}
	}

	componentChunks := componentBytes / chunkBytes
	arrayChunks := componentChunks * raidDisks / copies
	if arrayChunks == 0 {
		return nil, fmt.Errorf("%w: RAID10 array %s has fewer chunks than one logical chunk",
			ErrUnsupported, arrayUUID)
	}
	length, ok := checkedMul(arrayChunks, chunkBytes)
	if !ok {
		return nil, fmt.Errorf("%w: RAID10 array %s length overflows a byte count", ErrUnsupported, arrayUUID)
	}

	var farSetSize uint64
	switch layout >> 17 {
	case 0:
		farSetSize = raidDisks
	case 1:
		farSetSize = raidDisks / farCopies
	default:
		farSetSize = copies
	}
	if farSetSize == 0 {
		return nil, fmt.Errorf("%w: RAID10 array %s has an empty far set", ErrUnsupported, arrayUUID)
	}

	strideChunks := uint64(1)
	if !farOffset {
		used := (componentChunks / farCopies) * raidDisks / nearCopies * copies
		strideChunks = ceilDiv(used, raidDisks) / farCopies
	}

	mapping := stripeMapping{
		kind:         mappingRaid10,
		members:      raidDisks,
		nearCopies:   nearCopies,
		farCopies:    farCopies,
		farOffset:    farOffset,
		farSetSize:   farSetSize,
		strideChunks: strideChunks,
	}

	present := 0
	for _, ok := range filled {
		if ok {
			present++
		}
	}
	if present < int(raidDisks) {
		period := raidDisks / gcd(raidDisks, nearCopies)
		limit := period
		if arrayChunks < limit {
			limit = arrayChunks
		}
		for chunk := uint64(0); chunk < limit; chunk++ {
			readable := false
			for copy := uint64(0); copy < copies; copy++ {
				role, _ := mapping.copyPlacement(chunk, copy)
				if role < raidDisks && slots[role] != nil {
					readable = true
					break
				}
			}
			if !readable {
				return nil, fmt.Errorf("%w: the image holds %d of %d members of RAID10 array %s, and every copy of logical chunk %d is missing",
					ErrUnsupported, present, raidDisks, arrayUUID, chunk)
			}
		}
	}

	var imageID source.ImageID
	for _, slot := range slots {
		if slot != nil {
			imageID = slot.ImageID()
			break
		}
	}
	live := make([]StripePlacement, 0, len(placements))
	for role, place := range placements {
		if slots[role] != nil {
			live = append(live, place)
		}
	}

	return &ArraySource{
		id:         id,
		imageID:    imageID,
		chunkBytes: chunkBytes,
		length:     length,
		mapping:    mapping,
		members:    slots,
		placements: live,
	}, nil
}

const (
	algorithmLeftAsymmetric    uint32 = 0
	algorithmRightAsymmetric   uint32 = 1
	algorithmLeftSymmetric     uint32 = 2
	algorithmRightSymmetric    uint32 = 3
	algorithmParity0           uint32 = 4
	algorithmParityN           uint32 = 5
	algorithmRotatingZeroStart uint32 = 8
	algorithmRotatingNStart    uint32 = 9
	algorithmRotatingNContinue uint32 = 10
	algorithmLeftAsymmetric6   uint32 = 16
	algorithmRightAsymmetric6  uint32 = 17
	algorithmLeftSymmetric6    uint32 = 18
	algorithmRightSymmetric6   uint32 = 19
	algorithmParity0_6         uint32 = 20
)

// Raid456 assembles a RAID4, RAID5 or RAID6 array. It tolerates one missing
// member (P suffices) and, for RAID6, two missing members when P and Q
// together can rebuild them.
func Raid456(id source.ID, members []ArrayMember) (*ArraySource, error) {
	if len(members) == 0 {
		return nil, fmt.Errorf("%w: a RAID4/5/6 array needs at least one member", ErrUnsupported)
	}
	first := members[0].Superblock
	if first == nil {
		return nil, fmt.Errorf("%w: member has no superblock", ErrUnsupported)
	}
	level := first.Level
	if level < 4 || level > 6 {
		return nil, fmt.Errorf("%w: mdraid level %s (code %d) is not a RAID4/5/6 array",
			ErrUnsupported, first.LevelName(), level)
	}
	kind := first.LevelName()
	chunkBytes := first.ChunkSizeBytes
	if chunkBytes == 0 {
		return nil, fmt.Errorf("%w: the %s superblock records a chunk size of 0", ErrUnsupported, kind)
	}
	if chunkBytes%SectorBytes != 0 {
		return nil, fmt.Errorf("%w: the %s chunk size %d is not a whole number of %d-byte sectors",
			ErrUnsupported, kind, chunkBytes, SectorBytes)
	}
	raidDisks := int(first.RaidDisks)
	parityDisks := 1
	if level == 6 {
		parityDisks = 2
	}
	if raidDisks <= parityDisks {
		return nil, fmt.Errorf("%w: array %s records %d member(s), leaving no data disk for a %s array",
			ErrUnsupported, first.ArrayUUID(), raidDisks, kind)
	}
	layout := first.Layout
	if !layoutSupported(level, layout) {
		return nil, fmt.Errorf("%w: the %s layout %d is not one this reader maps",
			ErrUnsupported, kind, layout)
	}
	arrayUUID := first.ArrayUUID()
	componentBytes := first.ComponentSizeBytes()
	if componentBytes == 0 {
		return nil, fmt.Errorf("%w: array %s records a component size of 0", ErrUnsupported, arrayUUID)
	}

	slots := make([]source.ByteSource, raidDisks)
	placements := make([]StripePlacement, raidDisks)
	filled := make([]bool, raidDisks)
	for index, member := range members {
		sb := member.Superblock
		if sb == nil {
			return nil, fmt.Errorf("%w: member %d has no superblock", ErrUnsupported, index)
		}
		if sb.ArrayUUID() != arrayUUID || sb.Level != level ||
			sb.ChunkSizeBytes != chunkBytes || sb.RaidDisks != first.RaidDisks ||
			sb.Layout != layout || sb.ComponentSizeBytes() != componentBytes {
			return nil, fmt.Errorf("%w: member %d (device number %d) disagrees with the first member of %s array %s",
				ErrUnsupported, index, sb.DevNumber, kind, arrayUUID)
		}
		role, ok := sb.Role()
		if !ok {
			return nil, fmt.Errorf("%w: member %d (device number %d) has no entry in its own dev_roles array",
				ErrUnsupported, index, sb.DevNumber)
		}
		if role >= mdDiskRoleMax {
			continue
		}
		if int(role) >= raidDisks {
			return nil, fmt.Errorf("%w: member %d claims role %d, but %s array %s records %d members",
				ErrUnsupported, index, role, kind, arrayUUID, raidDisks)
		}
		if filled[role] {
			return nil, fmt.Errorf("%w: two members of array %s claim role %d",
				ErrUnsupported, arrayUUID, role)
		}
		if member.Data == nil || member.Data.Len() < componentBytes {
			return nil, fmt.Errorf("%w: member %d of %s array %s has a data area smaller than the %d-byte component size",
				ErrUnsupported, index, kind, arrayUUID, componentBytes)
		}
		filled[role] = true
		slots[role] = member.Data
		placements[role] = StripePlacement{
			Role:       role,
			MemberUUID: sb.MemberUUID(),
			DataOffset: sb.DataOffsetBytes(),
			Checksum:   sb.Checksum,
		}
	}

	present := 0
	for _, ok := range filled {
		if ok {
			present++
		}
	}
	missing := raidDisks - present
	if missing > parityDisks {
		detail := "the array has only one parity block to rebuild from"
		if level == 6 {
			detail = "RAID6 can rebuild at most two lost members"
		}
		return nil, fmt.Errorf("%w: the image holds %d of %d members of %s array %s; %d members are missing, and %s",
			ErrUnsupported, present, raidDisks, kind, arrayUUID, missing, detail)
	}
	if level == 6 && missing == 2 {
		switch layout {
		case algorithmRotatingZeroStart, algorithmRotatingNStart, algorithmRotatingNContinue:
			return nil, fmt.Errorf("%w: two-gap recovery on a DDF layout is not implemented", ErrUnsupported)
		}
	}

	dataDisks := uint64(raidDisks - parityDisks)
	length, ok := checkedMul(componentBytes, dataDisks)
	if !ok {
		return nil, fmt.Errorf("%w: %s array %s length overflows a byte count", ErrUnsupported, kind, arrayUUID)
	}
	var imageID source.ImageID
	for _, slot := range slots {
		if slot != nil {
			imageID = slot.ImageID()
			break
		}
	}
	live := make([]StripePlacement, 0, present)
	for role, place := range placements {
		if slots[role] != nil {
			live = append(live, place)
		}
	}

	return &ArraySource{
		id:         id,
		imageID:    imageID,
		chunkBytes: chunkBytes,
		length:     length,
		mapping: stripeMapping{
			kind:      mappingParity,
			members:   uint64(raidDisks),
			level:     level,
			layout:    layout,
			dataDisks: dataDisks,
		},
		members:    slots,
		placements: live,
	}, nil
}

// ChunkBytes returns the stripe unit.
func (a *ArraySource) ChunkBytes() uint64 { return a.chunkBytes }

// Placements returns one entry per present data role, in role order.
func (a *ArraySource) Placements() []StripePlacement { return a.placements }

// MissingRoles returns roles the image does not hold.
func (a *ArraySource) MissingRoles() []uint16 {
	var out []uint16
	for role, member := range a.members {
		if member == nil {
			out = append(out, uint16(role))
		}
	}
	return out
}

func (a *ArraySource) SourceID() source.ID     { return a.id }
func (a *ArraySource) Len() uint64             { return a.length }
func (a *ArraySource) ImageID() source.ImageID { return a.imageID }
func (a *ArraySource) SectorSize() uint32      { return uint32(SectorBytes) }
func (a *ArraySource) IsEmpty() bool           { return a.length == 0 }
func (a *ArraySource) Stats() source.Stats     { return a.counters.Snapshot() }

type arrayPiece struct {
	role         uint16
	memberOffset uint64
	length       uint64
}

func (a *ArraySource) forEachPiece(from, to uint64, fn func(arrayPiece) (bool, error)) error {
	at := from
	for at < to {
		index := at / a.chunkBytes
		within := at % a.chunkBytes
		length := a.chunkBytes - within
		if length > to-at {
			length = to - at
		}

		role, memberChunk := a.mapping.copyPlacement(index, 0)
		if a.mapping.kind == mappingRaid10 {
			found := false
			for copy := uint64(0); copy < a.mapping.copyCount(); copy++ {
				candidate, chunk := a.mapping.copyPlacement(index, copy)
				if candidate < uint64(len(a.members)) && a.members[candidate] != nil {
					role, memberChunk, found = candidate, chunk, true
					break
				}
			}
			if !found {
				return fmt.Errorf("%w: logical chunk %d has no surviving member", ErrUnsupported, index)
			}
		}
		if role >= uint64(len(a.members)) {
			return fmt.Errorf("%w: logical chunk %d maps to role %d outside the array", ErrUnsupported, index, role)
		}
		// A parity array may hand back a missing data role; the reader rebuilds
		// it. RAID0/RAID10 never do: their constructors proved survival.
		if a.members[role] == nil && a.mapping.kind != mappingParity {
			return fmt.Errorf("%w: logical chunk %d is on a missing member", ErrUnsupported, index)
		}
		p := arrayPiece{
			role:         uint16(role),
			memberOffset: memberChunk*a.chunkBytes + within,
			length:       length,
		}
		at += length
		stop, err := fn(p)
		if err != nil || stop {
			return err
		}
	}
	return nil
}

func (a *ArraySource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		a.counters.AddRead(0)
		return 0, nil
	}
	if offset >= a.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), a.length)
	}
	want := int(minU64(a.length-offset, uint64(len(buf))))
	at := 0
	err := a.forEachPiece(offset, offset+uint64(want), func(p arrayPiece) (bool, error) {
		target := buf[at : at+int(p.length)]
		member := a.members[p.role]
		if member == nil {
			if err := a.rebuild(int(p.role), p.memberOffset, target, false); err != nil {
				return true, err
			}
			at += len(target)
			return false, nil
		}
		n, err := member.ReadAt(p.memberOffset, target)
		if err != nil {
			return true, err
		}
		at += n
		if n < int(p.length) {
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return 0, err
	}
	a.counters.AddRead(at)
	return at, nil
}

func (a *ArraySource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		a.counters.AddRead(0)
		return 0, nil
	}
	if offset >= a.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), a.length)
	}
	want := int(minU64(a.length-offset, uint64(len(buf))))
	at := 0
	err := a.forEachPiece(offset, offset+uint64(want), func(p arrayPiece) (bool, error) {
		target := buf[at : at+int(p.length)]
		member := a.members[p.role]
		if member == nil {
			if err := a.rebuild(int(p.role), p.memberOffset, target, true); err != nil {
				return true, err
			}
			at += len(target)
			return false, nil
		}
		n, err := member.ReadAtLossy(p.memberOffset, target)
		if err != nil {
			return true, err
		}
		at += n
		if n < int(p.length) {
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return 0, err
	}
	a.counters.AddRead(at)
	return at, nil
}

func (a *ArraySource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > a.length || length > a.length-offset {
		return out, source.NewOutOfRange(offset, length, a.length)
	}
	if length == 0 {
		return out, nil
	}
	at := offset
	err := a.forEachPiece(offset, offset+length, func(p arrayPiece) (bool, error) {
		if member := a.members[p.role]; member != nil {
			out = append(out, source.ParentRange{
				Parent:       member.SourceID(),
				ParentOffset: p.memberOffset,
				Len:          p.length,
				Kind:         source.RangeData,
			})
		} else {
			out = append(out, source.ParentRange{
				Parent: a.id, ParentOffset: at, Len: p.length, Kind: source.RangeDerived,
			})
		}
		at += p.length
		return false, nil
	})
	return out, err
}

func (a *ArraySource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return a.ExtentsInto(offset, length, nil)
}

func (a *ArraySource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	if offset > a.length || length > a.length-offset {
		return nil, source.NewOutOfRange(offset, length, a.length)
	}
	var out []source.ImageRange
	err := a.forEachPiece(offset, offset+length, func(p arrayPiece) (bool, error) {
		if member := a.members[p.role]; member != nil {
			mapped, err := member.MapToImage(p.memberOffset, p.length)
			if err != nil {
				return true, err
			}
			out = append(out, mapped...)
		} else {
			out = append(out, source.ImageRange{
				ImageID: a.imageID, ImageOffset: 0, Len: p.length, Kind: source.RangeDerived,
			})
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

var _ source.ByteSource = (*ArraySource)(nil)

type parityStripeInfo struct {
	data        uint64
	pd          uint64
	qd          int64 // -1 when the level has no Q block
	memberChunk uint64
}

// parityStripe follows raid5_compute_sector in drivers/md/raid5.c.
func parityStripe(level int32, layout uint32, chunkIndex, members, dataDisks uint64) parityStripeInfo {
	stripe := chunkIndex / dataDisks
	data := chunkIndex % dataDisks
	rotation := stripe
	var pd uint64
	qd := int64(-1)

	switch level {
	case 4:
		pd = dataDisks
	case 5:
		switch layout {
		case algorithmLeftAsymmetric:
			pd = dataDisks - rotation%members
			if data >= pd {
				data++
			}
		case algorithmRightAsymmetric:
			pd = rotation % members
			if data >= pd {
				data++
			}
		case algorithmLeftSymmetric:
			pd = dataDisks - rotation%members
			data = (pd + 1 + data) % members
		case algorithmRightSymmetric:
			pd = rotation % members
			data = (pd + 1 + data) % members
		case algorithmParity0:
			pd = 0
			data++
		case algorithmParityN:
			pd = dataDisks
		}
	case 6:
		switch layout {
		case algorithmLeftAsymmetric:
			pd = members - 1 - rotation%members
			qd = int64(pd + 1)
			if pd == members-1 {
				data++
				qd = 0
			} else if data >= pd {
				data += 2
			}
		case algorithmRightAsymmetric, algorithmRotatingZeroStart:
			pd = rotation % members
			qd = int64(pd + 1)
			if pd == members-1 {
				data++
				qd = 0
			} else if data >= pd {
				data += 2
			}
		case algorithmRotatingNStart:
			rotation++
			pd = members - 1 - rotation%members
			qd = int64(pd + 1)
			if pd == members-1 {
				data++
				qd = 0
			} else if data >= pd {
				data += 2
			}
		case algorithmLeftSymmetric:
			pd = members - 1 - rotation%members
			qd = int64((pd + 1) % members)
			data = (pd + 2 + data) % members
		case algorithmRightSymmetric:
			pd = rotation % members
			qd = int64((pd + 1) % members)
			data = (pd + 2 + data) % members
		case algorithmParity0:
			pd = 0
			qd = 1
			data += 2
		case algorithmParityN:
			pd = dataDisks
			qd = int64(dataDisks + 1)
		case algorithmRotatingNContinue:
			pd = members - 1 - rotation%members
			qd = int64((pd + members - 1) % members)
			data = (pd + 1 + data) % members
		case algorithmLeftAsymmetric6:
			pd = dataDisks - rotation%(members-1)
			if data >= pd {
				data++
			}
			qd = int64(members - 1)
		case algorithmRightAsymmetric6:
			pd = rotation % (members - 1)
			if data >= pd {
				data++
			}
			qd = int64(members - 1)
		case algorithmLeftSymmetric6:
			pd = dataDisks - rotation%(members-1)
			data = (pd + 1 + data) % (members - 1)
			qd = int64(members - 1)
		case algorithmRightSymmetric6:
			pd = rotation % (members - 1)
			data = (pd + 1 + data) % (members - 1)
			qd = int64(members - 1)
		case algorithmParity0_6:
			pd = 0
			data++
			qd = int64(members - 1)
		}
	}

	return parityStripeInfo{data: data, pd: pd, qd: qd, memberChunk: stripe}
}

func layoutSupported(level int32, layout uint32) bool {
	switch level {
	case 4:
		return true
	case 5:
		return layout <= algorithmParityN
	case 6:
		return layout <= algorithmParityN ||
			(layout >= algorithmRotatingZeroStart && layout <= algorithmRotatingNContinue) ||
			(layout >= algorithmLeftAsymmetric6 && layout <= algorithmParity0_6)
	default:
		return false
	}
}

// raid6Slots numbers the data slots of one stripe the way the kernel does.
func raid6Slots(members int, pd, qd uint64) []int {
	slots := make([]int, members)
	start := 0
	if qd != uint64(members-1) {
		start = int(qd) + 1
	}
	slot := 0
	role := start
	for {
		if uint64(role) != pd && uint64(role) != qd {
			slots[role] = slot
			slot++
		}
		role = (role + 1) % members
		if role == start {
			break
		}
	}
	return slots
}

func (a *ArraySource) rebuild(missing int, memberOffset uint64, out []byte, lossy bool) error {
	mapping := a.mapping
	if mapping.kind != mappingParity {
		return source.NewCorrupt(memberOffset, "a non-parity array has no parity to rebuild a missing member from")
	}
	stripe := parityStripe(mapping.level, mapping.layout,
		(memberOffset/a.chunkBytes)*mapping.dataDisks, mapping.members, mapping.dataDisks)

	var missingRoles []int
	for role, member := range a.members {
		if member == nil {
			missingRoles = append(missingRoles, role)
		}
	}
	if mapping.level == 6 && len(missingRoles) == 2 {
		other := missingRoles[0]
		if other == missing {
			other = missingRoles[1]
		}
		if uint64(other) == stripe.pd {
			return a.rebuildFromQ(missing, stripe, memberOffset, out, lossy)
		}
		if stripe.qd < 0 || uint64(other) != uint64(stripe.qd) {
			return a.rebuildFromTwoData(missing, other, stripe, memberOffset, out, lossy)
		}
		// The other gap is Q: P alone still rebuilds this data chunk.
	}

	clear(out)
	scratch := make([]byte, len(out))
	for role := 0; role < int(mapping.members); role++ {
		if role == missing || a.members[role] == nil {
			continue
		}
		if stripe.qd >= 0 && uint64(role) == uint64(stripe.qd) {
			continue
		}
		if err := a.xorMember(role, memberOffset, out, scratch, lossy); err != nil {
			return err
		}
	}
	return nil
}

func (a *ArraySource) rebuildFromQ(missing int, stripe parityStripeInfo, memberOffset uint64, out []byte, lossy bool) error {
	qd := uint64(stripe.qd)
	slots := raid6Slots(len(a.members), stripe.pd, qd)
	clear(out)
	scratch := make([]byte, len(out))
	for role, slot := range slots {
		if uint64(role) == stripe.pd || uint64(role) == qd || role == missing {
			continue
		}
		coefficient := gfPow(uint64(slot))
		if err := a.readMember(role, memberOffset, scratch, lossy); err != nil {
			return err
		}
		for i := range out {
			out[i] ^= gfMul(coefficient, scratch[i])
		}
	}
	if err := a.readMember(int(qd), memberOffset, scratch, lossy); err != nil {
		return err
	}
	inverse := gfInv(gfPow(uint64(slots[missing])))
	for i := range out {
		out[i] = gfMul(out[i]^scratch[i], inverse)
	}
	return nil
}

func (a *ArraySource) rebuildFromTwoData(missing, other int, stripe parityStripeInfo, memberOffset uint64, out []byte, lossy bool) error {
	pd := int(stripe.pd)
	qd := int(stripe.qd)
	slots := raid6Slots(len(a.members), stripe.pd, uint64(qd))
	clear(out)
	q := make([]byte, len(out))
	scratch := make([]byte, len(out))
	for role, slot := range slots {
		if role == missing || role == other || role == pd || role == qd {
			continue
		}
		if err := a.readMember(role, memberOffset, scratch, lossy); err != nil {
			return err
		}
		coefficient := gfPow(uint64(slot))
		for i := range out {
			out[i] ^= scratch[i]
			q[i] ^= gfMul(coefficient, scratch[i])
		}
	}
	if err := a.readMember(pd, memberOffset, scratch, lossy); err != nil {
		return err
	}
	for i := range out {
		out[i] ^= scratch[i]
	}
	if err := a.readMember(qd, memberOffset, scratch, lossy); err != nil {
		return err
	}
	for i := range q {
		q[i] ^= scratch[i]
	}
	missingCoefficient := gfPow(uint64(slots[missing]))
	otherCoefficient := gfPow(uint64(slots[other]))
	inverse := gfInv(missingCoefficient ^ otherCoefficient)
	for i := range out {
		out[i] ^= gfMul(q[i]^gfMul(missingCoefficient, out[i]), inverse)
	}
	return nil
}

func (a *ArraySource) xorMember(role int, memberOffset uint64, out, scratch []byte, lossy bool) error {
	if err := a.readMember(role, memberOffset, scratch, lossy); err != nil {
		return err
	}
	for i := range out {
		out[i] ^= scratch[i]
	}
	return nil
}

func (a *ArraySource) readMember(role int, memberOffset uint64, out []byte, lossy bool) error {
	member := a.members[role]
	if member == nil {
		return source.NewCorrupt(memberOffset, fmt.Sprintf("role %d is missing, so the parity stripe cannot be read", role))
	}
	var (
		n   int
		err error
	)
	if lossy {
		n, err = member.ReadAtLossy(memberOffset, out)
	} else {
		n, err = member.ReadAt(memberOffset, out)
	}
	if err != nil {
		return err
	}
	if n < len(out) {
		return source.NewUnexpectedEOF(memberOffset + uint64(n))
	}
	return nil
}

type gfTables struct {
	exp [510]byte
	log [256]byte
}

var (
	gfOnce  sync.Once
	gfTable gfTables
)

func gfTablesInit() *gfTables {
	gfOnce.Do(func() {
		value := byte(1)
		for slot := 0; slot < 255; slot++ {
			gfTable.exp[slot] = value
			gfTable.log[value] = byte(slot)
			value = gfMulSlow(value, 2)
		}
		for slot := 255; slot < 510; slot++ {
			gfTable.exp[slot] = gfTable.exp[slot-255]
		}
	})
	return &gfTable
}

func gfMulSlow(a, b byte) byte {
	var product byte
	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			product ^= a
		}
		high := a&0x80 != 0
		a <<= 1
		if high {
			a ^= 0x1D
		}
		b >>= 1
	}
	return product
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	tables := gfTablesInit()
	return tables.exp[int(tables.log[a])+int(tables.log[b])]
}

func gfPow(exponent uint64) byte {
	tables := gfTablesInit()
	return tables.exp[exponent%255]
}

func gfInv(value byte) byte {
	tables := gfTablesInit()
	return tables.exp[255-int(tables.log[value])]
}

func gcd(a, b uint64) uint64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func ceilDiv(a, b uint64) uint64 {
	return (a + b - 1) / b
}
