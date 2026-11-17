package udf

// Extent descriptors and the addresses inside them.
//
// UDF names data with a logical address: a block number inside a partition plus
// the partition's reference number. Four forms appear, differing in how much
// they say: short keeps the block in the same partition, long names a
// partition, extended also records the length the data claims, and an
// in-ICB form embeds the data.
//
// The top two bits of an allocation descriptor's length are its type, not part
// of the length: recorded, not recorded but allocated, not recorded and not
// allocated, or a pointer to the next allocation-extent descriptor block.

// ExtLengthMask masks the recorded length out of an allocation descriptor.
const ExtLengthMask uint32 = 0x3FFF_FFFF

// ExtTypeMask is the type bits at the top of an allocation descriptor's length.
const ExtTypeMask uint32 = 0xC000_0000

const (
	ExtRecordedAllocated       uint32 = 0x0000_0000
	ExtNotRecordedAllocated    uint32 = 0x4000_0000
	ExtNotRecordedNotAllocated uint32 = 0x8000_0000
	ExtNextExtentAllocDescs    uint32 = 0xC000_0000
)

// Bytes of each allocation descriptor form.
const (
	ShortADBytes    = 8
	LongADBytes     = 16
	ExtendedADBytes = 20
)

// LbAddr is a block inside a partition.
type LbAddr struct {
	Block     uint32
	Partition uint16
}

// ExtentAd is a volume-level extent: blocks of the volume, not a partition.
type ExtentAd struct {
	Length   uint32
	Location uint32
}

// End returns the block just past the extent.
func (e ExtentAd) End() uint64 { return uint64(e.Location) + uint64(e.Length) }

// LongAd is a long allocation descriptor.
type LongAd struct {
	Length uint32
	Addr   LbAddr
}

// ExtentLength returns the recorded length without its type bits.
func (a LongAd) ExtentLength() uint32 { return a.Length & ExtLengthMask }

// Kind returns the descriptor's type bits.
func (a LongAd) Kind() uint32 { return a.Length & ExtTypeMask }

// IsContinuation reports a pointer to another descriptor block.
func (a LongAd) IsContinuation() bool { return a.Kind() == ExtNextExtentAllocDescs }

// IsHole reports one of the two not-recorded forms.
func (a LongAd) IsHole() bool {
	return a.Kind() == ExtNotRecordedAllocated || a.Kind() == ExtNotRecordedNotAllocated
}

// ShortAd is a short allocation descriptor.
type ShortAd struct {
	Length uint32
	Block  uint32
}

// ExtentLength returns the recorded length without its type bits.
func (a ShortAd) ExtentLength() uint32 { return a.Length & ExtLengthMask }

// Kind returns the descriptor's type bits.
func (a ShortAd) Kind() uint32 { return a.Length & ExtTypeMask }

// IsContinuation reports a pointer to another descriptor block.
func (a ShortAd) IsContinuation() bool { return a.Kind() == ExtNextExtentAllocDescs }

// IsHole reports one of the two not-recorded forms.
func (a ShortAd) IsHole() bool {
	return a.Kind() == ExtNotRecordedAllocated || a.Kind() == ExtNotRecordedNotAllocated
}

// ExtendedAd is an extended allocation descriptor.
type ExtendedAd struct {
	Length      uint32
	Recorded    uint32
	Information uint32
	Addr        LbAddr
}

// ExtentLength returns the recorded length without its type bits.
func (a ExtendedAd) ExtentLength() uint32 { return a.Length & ExtLengthMask }

// Kind returns the descriptor's type bits.
func (a ExtendedAd) Kind() uint32 { return a.Length & ExtTypeMask }

// IsContinuation reports a pointer to another descriptor block.
func (a ExtendedAd) IsContinuation() bool { return a.Kind() == ExtNextExtentAllocDescs }

// IsHole reports one of the two not-recorded forms.
func (a ExtendedAd) IsHole() bool {
	return a.Kind() == ExtNotRecordedAllocated || a.Kind() == ExtNotRecordedNotAllocated
}

func lbAddr(b []byte, at int) (LbAddr, bool) {
	block, ok := le32ok(b, at)
	if !ok {
		return LbAddr{}, false
	}
	part, ok := le16ok(b, at+4)
	if !ok {
		return LbAddr{}, false
	}
	return LbAddr{Block: block, Partition: part}, true
}

func extentAD(b []byte, at int) (ExtentAd, bool) {
	length, ok := le32ok(b, at)
	if !ok {
		return ExtentAd{}, false
	}
	loc, ok := le32ok(b, at+4)
	if !ok {
		return ExtentAd{}, false
	}
	return ExtentAd{Length: length, Location: loc}, true
}

func longAD(b []byte, at int) (LongAd, bool) {
	length, ok := le32ok(b, at)
	if !ok {
		return LongAd{}, false
	}
	addr, ok := lbAddr(b, at+4)
	if !ok {
		return LongAd{}, false
	}
	return LongAd{Length: length, Addr: addr}, true
}

func shortAD(b []byte, at int) (ShortAd, bool) {
	length, ok := le32ok(b, at)
	if !ok {
		return ShortAd{}, false
	}
	block, ok := le32ok(b, at+4)
	if !ok {
		return ShortAd{}, false
	}
	return ShortAd{Length: length, Block: block}, true
}

func extendedAD(b []byte, at int) (ExtendedAd, bool) {
	length, ok := le32ok(b, at)
	if !ok {
		return ExtendedAd{}, false
	}
	recorded, ok := le32ok(b, at+4)
	if !ok {
		return ExtendedAd{}, false
	}
	information, ok := le32ok(b, at+8)
	if !ok {
		return ExtendedAd{}, false
	}
	addr, ok := lbAddr(b, at+12)
	if !ok {
		return ExtendedAd{}, false
	}
	return ExtendedAd{Length: length, Recorded: recorded, Information: information, Addr: addr}, true
}
