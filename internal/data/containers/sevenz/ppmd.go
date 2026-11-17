// PPMd var.H (PPMd7) decoder, ported from 7-Zip 25.01 C/Ppmd7.c and
// C/Ppmd7Dec.c, following forensic-core's ppmd.rs.
//
// 7z stores a PPMd folder as coder 03 04 01 whose five property bytes are the
// model order and the little-endian model size.  The payload is one
// range-coded symbol stream with no header: the decoder allocates the model
// block named by the properties, primes the range decoder with five bytes, and
// decodes exactly the folder's declared output size.
//
// The model lives in one flat block -- raw text grows up from the bottom,
// state vectors and context records grow down from the top -- and every
// reference inside it is a 32-bit offset from the block start.  Every access
// is bounds-checked, so a damaged stream that names a context outside the
// block is reported instead of read.

package sevenz

import (
	"encoding/binary"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	ppmdUnit       uint32 = 12
	ppmdNumIndexes        = 38
	ppmdMaxFreq    uint32 = 124
	ppmdIntBits    uint32 = 7
	ppmdPeriodBits uint32 = 7
	ppmdBinScale          = uint32(1) << (ppmdIntBits + ppmdPeriodBits)
	ppmdTop        uint32 = 1 << 24
	ppmdNumSee            = 25
	ppmdSeeSize           = 16
	ppmdSymEnd     int32  = -1
)

var ppmdExpEscape = [16]byte{25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2}

var ppmdInitBinEsc = [8]uint16{
	0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051,
}

// ppmdState is one decoded symbol state: the 6 live bytes of a 12-byte unit.
type ppmdState struct {
	symbol    byte
	freq      byte
	successor uint32
}

// ppmdSee is one SEE context: Summ, Shift and Count packed in that order.
type ppmdSee struct {
	summ  uint16
	shift byte
	count byte
}

// decodePPMdFolder decodes one 7z PPMd folder.
func decodePPMdFolder(offset uint64, props, input []byte, unpack uint64) ([]byte, error) {
	if len(props) != 5 {
		return nil, source.NewCorrupt(offset, "7z PPMd coder properties are not 5 bytes")
	}
	order := uint32(props[0])
	size := binary.LittleEndian.Uint32(props[1:5])
	if order < 2 || order > 64 {
		return nil, source.NewCorrupt(offset, "7z PPMd model order is outside 2..=64")
	}
	if size < 1<<11 {
		return nil, source.NewCorrupt(offset, "7z PPMd model is smaller than 2048 bytes")
	}
	if size > 0xFFFFFFC4 {
		return nil, source.NewCorrupt(offset, "7z PPMd model is larger than 4 GiB")
	}
	if size > ppmdMemoryLimit {
		return nil, unsupportedError(fmt.Sprintf(
			"PPMd model of %d bytes exceeds the %d byte budget", size, ppmdMemoryLimit))
	}
	if unpack > uint64(maxInt()) {
		return nil, unsupportedError(fmt.Sprintf(
			"PPMd output of %d bytes does not fit in memory", unpack))
	}

	model, ok := newPpmdModel(order, size)
	if !ok {
		return nil, source.NewCorrupt(offset, "PPMd model could not be initialised inside its block")
	}
	if !model.rangeDecInit(input) {
		return nil, source.NewCorrupt(offset,
			"7z PPMd stream: range coder header is not a valid five-byte start")
	}

	out := make([]byte, 0, int(unpack))
	for uint64(len(out)) < unpack {
		symbol, ok := model.decodeSymbol()
		if !ok {
			return nil, source.NewCorrupt(offset, "7z PPMd model reference is outside its block")
		}
		if symbol < 0 {
			return nil, source.NewCorrupt(offset,
				"7z PPMd stream: payload ends before the declared output size")
		}
		out = append(out, byte(symbol))
	}
	if model.code != 0 {
		return nil, source.NewCorrupt(offset, "7z PPMd stream: range coder is not finished")
	}
	if model.extra || model.cursor != len(input) {
		return nil, source.NewCorrupt(offset, "7z PPMd stream: payload is not fully consumed")
	}
	return out, nil
}

type ppmModel struct {
	base  []byte
	input []byte
	// cursor is the next unread input byte.
	cursor int
	extra  bool

	size        uint32
	text        uint32
	loUnit      uint32
	hiUnit      uint32
	unitsStart  uint32
	minContext  uint32
	maxContext  uint32
	foundState  uint32
	orderFall   uint32
	initEsc     uint32
	prevSuccess uint32
	maxOrder    uint32
	hiBitsFlag  uint32
	runLength   int32
	initRL      int32
	glueCount   uint32

	indx2Units [ppmdNumIndexes + 2]byte
	units2indx [128]byte
	freeList   [ppmdNumIndexes]uint32
	ns2bsindx  [256]byte
	ns2indx    [256]byte
	binSumm    [128][64]uint16
	see        [ppmdNumSee][ppmdSeeSize]ppmdSee
	dummySee   ppmdSee

	rnge uint32
	code uint32
}

func newPpmdModel(order, size uint32) (*ppmModel, bool) {
	align := (4 - size%4) % 4
	total := uint64(align) + uint64(size)
	if total > uint64(maxInt()) {
		return nil, false
	}
	model := &ppmModel{
		base:       make([]byte, int(total)),
		size:       size,
		maxOrder:   order,
		indx2Units: [ppmdNumIndexes + 2]byte{},
		units2indx: [128]byte{},
		freeList:   [ppmdNumIndexes]uint32{},
		ns2bsindx:  [256]byte{},
		ns2indx:    [256]byte{},
		binSumm:    [128][64]uint16{},
		see:        [ppmdNumSee][ppmdSeeSize]ppmdSee{},
		dummySee:   ppmdSee{shift: byte(ppmdPeriodBits), count: 64},
	}
	model.constructTables()
	if !model.restartModel() {
		return nil, false
	}
	return model, true
}

func (m *ppmModel) constructTables() {
	k := 0
	for i := 0; i < ppmdNumIndexes; i++ {
		step := 4
		if i < 12 {
			step = (i >> 2) + 1
		}
		for j := 0; j < step; j++ {
			m.units2indx[k] = byte(i)
			k++
		}
		m.indx2Units[i] = byte(k)
	}

	m.ns2bsindx[0] = 0
	m.ns2bsindx[1] = 1 << 1
	for index := 2; index < 11; index++ {
		m.ns2bsindx[index] = 2 << 1
	}
	for index := 11; index < 256; index++ {
		m.ns2bsindx[index] = 3 << 1
	}

	for i := 0; i < 3; i++ {
		m.ns2indx[i] = byte(i)
	}
	mm := 3
	kk := 1
	for i := 3; i < 256; i++ {
		m.ns2indx[i] = byte(mm)
		kk--
		if kk == 0 {
			mm++
			kk = mm - 2
		}
	}
}

// ----- raw memory access -------------------------------------------------

func (m *ppmModel) bytesAt(at, length uint32) ([]byte, bool) {
	start := uint64(at)
	end := start + uint64(length)
	if end > uint64(len(m.base)) {
		return nil, false
	}
	return m.base[start:end], true
}

func (m *ppmModel) u8At(at uint32) (byte, bool) {
	if int(at) >= len(m.base) {
		return 0, false
	}
	return m.base[at], true
}

func (m *ppmModel) u16At(at uint32) (uint16, bool) {
	data, ok := m.bytesAt(at, 2)
	if !ok {
		return 0, false
	}
	return binary.LittleEndian.Uint16(data), true
}

func (m *ppmModel) u32At(at uint32) (uint32, bool) {
	data, ok := m.bytesAt(at, 4)
	if !ok {
		return 0, false
	}
	return binary.LittleEndian.Uint32(data), true
}

func (m *ppmModel) putU8(at uint32, value byte) bool {
	if int(at) >= len(m.base) {
		return false
	}
	m.base[at] = value
	return true
}

func (m *ppmModel) putU16(at uint32, value uint16) bool {
	if uint64(at)+2 > uint64(len(m.base)) {
		return false
	}
	binary.LittleEndian.PutUint16(m.base[at:at+2], value)
	return true
}

func (m *ppmModel) putU32(at uint32, value uint32) bool {
	if uint64(at)+4 > uint64(len(m.base)) {
		return false
	}
	binary.LittleEndian.PutUint32(m.base[at:at+4], value)
	return true
}

func (m *ppmModel) stateAt(at uint32) (ppmdState, bool) {
	data, ok := m.bytesAt(at, 6)
	if !ok {
		return ppmdState{}, false
	}
	return ppmdState{
		symbol:    data[0],
		freq:      data[1],
		successor: binary.LittleEndian.Uint32(data[2:6]),
	}, true
}

func (m *ppmModel) writeState(at uint32, state ppmdState) bool {
	if uint64(at)+6 > uint64(len(m.base)) {
		return false
	}
	m.base[at] = state.symbol
	m.base[at+1] = state.freq
	binary.LittleEndian.PutUint32(m.base[at+2:at+6], state.successor)
	return true
}

func (m *ppmModel) numStats(context uint32) (uint16, bool) { return m.u16At(context) }

func (m *ppmModel) summFreq(context uint32) (uint16, bool) { return m.u16At(context + 2) }

func (m *ppmModel) statsRef(context uint32) (uint32, bool) { return m.u32At(context + 4) }

func (m *ppmModel) suffix(context uint32) (uint32, bool) { return m.u32At(context + 8) }

// oneState returns the single state of a one-state context: it lives where the
// context's SummFreq would be, and its successor where Stats would be.
func (m *ppmModel) oneState(context uint32) (ppmdState, bool) { return m.stateAt(context + 2) }

func (m *ppmModel) setSuccessor(state, successor uint32) bool {
	return m.putU32(state+2, successor)
}

func (m *ppmModel) i2u(indx uint32) uint32 {
	if int(indx) >= len(m.indx2Units) {
		return 0
	}
	return uint32(m.indx2Units[indx])
}

func (m *ppmModel) u2i(nu uint32) uint32 {
	index := nu
	if index > 0 {
		index--
	}
	if index > 127 {
		index = 127
	}
	return uint32(m.units2indx[index])
}

func (m *ppmModel) copyUnits(dst, src, units uint32) bool {
	length := uint64(units) * uint64(ppmdUnit)
	srcStart := uint64(src)
	dstStart := uint64(dst)
	if srcStart+length > uint64(len(m.base)) || dstStart+length > uint64(len(m.base)) {
		return false
	}
	copy(m.base[dstStart:dstStart+length], m.base[srcStart:srcStart+length])
	return true
}

// ----- model allocator ---------------------------------------------------

func (m *ppmModel) insertNode(node, indx uint32) bool {
	if int(indx) >= len(m.freeList) {
		return false
	}
	next := m.freeList[indx]
	if !m.putU32(node, next) {
		return false
	}
	m.freeList[indx] = node
	return true
}

func (m *ppmModel) removeNode(indx uint32) (uint32, bool) {
	if int(indx) >= len(m.freeList) {
		return 0, false
	}
	slot := m.freeList[indx]
	next, ok := m.u32At(slot)
	if !ok {
		return 0, false
	}
	m.freeList[indx] = next
	return slot, true
}

func (m *ppmModel) splitBlock(ptr, oldIndx, newIndx uint32) bool {
	oldUnits := m.i2u(oldIndx)
	newUnits := m.i2u(newIndx)
	if oldUnits < newUnits {
		return false
	}
	nu := oldUnits - newUnits
	ptr += ppmdUnit * newUnits
	i := m.u2i(nu)
	if m.i2u(i) != nu {
		if i == 0 {
			return false
		}
		i--
		k := m.i2u(i)
		if !m.insertNode(ptr+ppmdUnit*k, nu-k-1) {
			return false
		}
	}
	return m.insertNode(ptr, i)
}

func (m *ppmModel) glueFreeBlocks() bool {
	m.glueCount = 255
	if m.loUnit != m.hiUnit {
		if !m.putU16(m.loUnit, 1) {
			return false
		}
	}

	var n uint32
	for i := 0; i < ppmdNumIndexes; i++ {
		nu := uint32(m.indx2Units[i])
		next := m.freeList[i]
		m.freeList[i] = 0
		for next != 0 {
			node := next
			value, ok := m.u32At(node)
			if !ok {
				return false
			}
			next = value
			if !m.putU16(node, 0) || !m.putU16(node+2, uint16(nu)) ||
				!m.putU32(node+4, n) {
				return false
			}
			n = node
		}
	}

	head := n
	prevLink := uint32(0)
	havePrev := false
	cursor := n
	for cursor != 0 {
		node := cursor
		nuValue, ok := m.u16At(node + 2)
		if !ok {
			return false
		}
		nu := uint32(nuValue)
		value, ok := m.u32At(node + 4)
		if !ok {
			return false
		}
		cursor = value
		if nu == 0 {
			if havePrev {
				if !m.putU32(prevLink+4, cursor) {
					return false
				}
			} else {
				head = cursor
			}
			continue
		}
		prevLink = node
		havePrev = true
		for {
			node2 := node + ppmdUnit*nu
			stamp, ok := m.u16At(node2)
			if !ok {
				return false
			}
			nextNu, ok := m.u16At(node2 + 2)
			if !ok {
				return false
			}
			nu += uint32(nextNu)
			if stamp != 0 || nu >= 0x10000 {
				break
			}
			if !m.putU16(node+2, uint16(nu)) || !m.putU16(node2+2, 0) {
				return false
			}
		}
	}

	cursor = head
	for cursor != 0 {
		node := cursor
		nu, ok := m.u16At(node + 2)
		if !ok {
			return false
		}
		value, ok := m.u32At(node + 4)
		if !ok {
			return false
		}
		cursor = value
		if nu == 0 {
			continue
		}
		for nu > 128 {
			if !m.insertNode(node, ppmdNumIndexes-1) {
				return false
			}
			nu -= 128
			node += 128 * ppmdUnit
		}
		i := m.u2i(uint32(nu))
		if m.i2u(i) != uint32(nu) {
			if i == 0 {
				return false
			}
			i--
			k := m.i2u(i)
			if !m.insertNode(node+ppmdUnit*k, uint32(nu)-k-1) {
				return false
			}
		}
		if !m.insertNode(node, i) {
			return false
		}
	}
	return true
}

func (m *ppmModel) allocUnitsRare(indx uint32) (uint32, bool) {
	if m.glueCount == 0 {
		if !m.glueFreeBlocks() {
			return 0, false
		}
		if indx < uint32(len(m.freeList)) && m.freeList[indx] != 0 {
			return m.removeNode(indx)
		}
	}

	i := indx
	for {
		i++
		if i == ppmdNumIndexes {
			numBytes := ppmdUnit * m.i2u(indx)
			unitsStart := m.unitsStart
			m.glueCount--
			if unitsStart > m.text && unitsStart-m.text > numBytes {
				m.unitsStart = unitsStart - numBytes
				return m.unitsStart, true
			}
			return 0, false
		}
		if i < uint32(len(m.freeList)) && m.freeList[i] != 0 {
			block, ok := m.removeNode(i)
			if !ok {
				return 0, false
			}
			if !m.splitBlock(block, i, indx) {
				return 0, false
			}
			return block, true
		}
	}
}

func (m *ppmModel) allocUnits(indx uint32) (uint32, bool) {
	if int(indx) < len(m.freeList) && m.freeList[indx] != 0 {
		return m.removeNode(indx)
	}
	numBytes := ppmdUnit * m.i2u(indx)
	lo := m.loUnit
	if m.hiUnit >= lo && m.hiUnit-lo >= numBytes {
		m.loUnit = lo + numBytes
		return lo, true
	}
	return m.allocUnitsRare(indx)
}

func (m *ppmModel) allocContext() (uint32, bool) {
	if m.hiUnit != m.loUnit {
		m.hiUnit -= ppmdUnit
		return m.hiUnit, true
	}
	if m.freeList[0] != 0 {
		return m.removeNode(0)
	}
	return m.allocUnitsRare(0)
}

// ----- model initialisation ---------------------------------------------

func (m *ppmModel) restartModel() bool {
	m.freeList = [ppmdNumIndexes]uint32{}
	m.text = (4 - m.size%4) % 4
	m.hiUnit = m.text + m.size
	perEighth := m.size / 8 / ppmdUnit * 7 * ppmdUnit
	m.unitsStart = m.hiUnit - perEighth
	m.loUnit = m.unitsStart
	m.glueCount = 0

	m.orderFall = m.maxOrder
	limit := int32(12)
	if m.maxOrder < 12 {
		limit = int32(m.maxOrder)
	}
	m.runLength = -limit - 1
	m.initRL = m.runLength
	m.prevSuccess = 0

	m.hiUnit -= ppmdUnit
	context := m.hiUnit
	stats := m.loUnit
	m.loUnit += ppmdUnit * (256 / 2)
	m.maxContext = context
	m.minContext = context
	m.foundState = stats

	if !m.putU16(context, 256) || !m.putU16(context+2, 256+1) ||
		!m.putU32(context+4, stats) || !m.putU32(context+8, 0) {
		return false
	}
	for i := uint32(0); i < 256; i++ {
		if !m.writeState(stats+6*i, ppmdState{symbol: byte(i), freq: 1, successor: 0}) {
			return false
		}
	}

	for i := 0; i < 128; i++ {
		for k, escape := range ppmdInitBinEsc {
			value := uint16(ppmdBinScale) - escape/(uint16(i)+2)
			for mm := 0; mm < 64; mm += 8 {
				m.binSumm[i][k+mm] = value
			}
		}
	}

	for i := 0; i < ppmdNumSee; i++ {
		summ := uint16(((5*uint32(i) + 10) << (ppmdPeriodBits - 4)))
		for k := 0; k < ppmdSeeSize; k++ {
			m.see[i][k] = ppmdSee{
				summ:  summ,
				shift: byte(ppmdPeriodBits - 4),
				count: 4,
			}
		}
	}
	m.dummySee = ppmdSee{summ: 0, shift: byte(ppmdPeriodBits), count: 64}
	return true
}

// ----- model update ------------------------------------------------------

func (m *ppmModel) createSuccessors() (uint32, bool) {
	c := m.minContext
	found, ok := m.stateAt(m.foundState)
	if !ok {
		return 0, false
	}
	upBranch := found.successor
	var ps [64]uint32
	numPs := 0

	if m.orderFall != 0 {
		ps[0] = m.foundState
		numPs = 1
	}

	for {
		next, ok := m.suffix(c)
		if !ok {
			return 0, false
		}
		if next == 0 {
			break
		}
		c = next
		foundState, ok := m.stateAt(m.foundState)
		if !ok {
			return 0, false
		}
		foundSymbol := foundState.symbol
		var state uint32
		count, ok := m.numStats(c)
		if !ok {
			return 0, false
		}
		if count != 1 {
			base, ok := m.statsRef(c)
			if !ok {
				return 0, false
			}
			state = base
			for {
				current, ok := m.stateAt(state)
				if !ok {
					return 0, false
				}
				if current.symbol == foundSymbol {
					break
				}
				state += 6
				if state >= base+6*uint32(count) {
					return 0, false
				}
			}
		} else {
			state = c + 2
		}
		current, ok := m.stateAt(state)
		if !ok {
			return 0, false
		}
		if current.successor != upBranch {
			c = current.successor
			if numPs == 0 {
				return c, true
			}
			break
		}
		if numPs == len(ps) {
			return 0, false
		}
		ps[numPs] = state
		numPs++
	}

	newSymbol, ok := m.u8At(upBranch)
	if !ok {
		return 0, false
	}
	upBranch++

	var newFreq uint32
	count, ok := m.numStats(c)
	if !ok {
		return 0, false
	}
	if count == 1 {
		one, ok := m.oneState(c)
		if !ok {
			return 0, false
		}
		newFreq = uint32(one.freq)
	} else {
		base, ok := m.statsRef(c)
		if !ok {
			return 0, false
		}
		state := base
		for {
			current, ok := m.stateAt(state)
			if !ok {
				return 0, false
			}
			if current.symbol == newSymbol {
				break
			}
			state += 6
			if state >= base+6*uint32(count) {
				return 0, false
			}
		}
		current, ok := m.stateAt(state)
		if !ok || current.freq == 0 {
			return 0, false
		}
		cf := uint32(current.freq - 1)
		summ, ok := m.summFreq(c)
		if !ok {
			return 0, false
		}
		s0 := uint32(summ) - uint32(count) - cf
		if 2*cf <= s0 {
			newFreq = 1 + boolToU32(5*cf > s0)
		} else {
			if s0 == 0 {
				return 0, false
			}
			newFreq = 1 + (2*cf+s0-1)/(2*s0) + 1
		}
	}

	for {
		context, ok := m.allocContext()
		if !ok {
			return 0, false
		}
		if numPs == 0 {
			return 0, false
		}
		if !m.putU16(context, 1) ||
			!m.writeState(context+2, ppmdState{
				symbol: newSymbol, freq: byte(newFreq), successor: upBranch,
			}) ||
			!m.putU32(context+8, c) {
			return 0, false
		}
		numPs--
		if !m.setSuccessor(ps[numPs], context) {
			return 0, false
		}
		c = context
		if numPs == 0 {
			break
		}
	}
	return c, true
}

func (m *ppmModel) updateModel() bool {
	found, ok := m.stateAt(m.foundState)
	if !ok {
		return false
	}
	if uint32(found.freq) < ppmdMaxFreq/4 {
		suffix, ok := m.suffix(m.minContext)
		if !ok {
			return false
		}
		if suffix != 0 {
			c := suffix
			count, ok := m.numStats(c)
			if !ok {
				return false
			}
			if count == 1 {
				state, ok := m.oneState(c)
				if !ok {
					return false
				}
				if state.freq < 32 {
					state.freq++
					if !m.writeState(c+2, state) {
						return false
					}
				}
			} else {
				base, ok := m.statsRef(c)
				if !ok {
					return false
				}
				foundState, ok := m.stateAt(m.foundState)
				if !ok {
					return false
				}
				symbol := foundState.symbol
				state := base
				first, ok := m.stateAt(state)
				if !ok {
					return false
				}
				if first.symbol != symbol {
					for {
						state += 6
						if state >= base+6*uint32(count) {
							return false
						}
						current, ok := m.stateAt(state)
						if !ok {
							return false
						}
						if current.symbol == symbol {
							break
						}
					}
					current, ok := m.stateAt(state)
					if !ok || state < 6 {
						return false
					}
					previous, ok := m.stateAt(state - 6)
					if !ok {
						return false
					}
					if current.freq >= previous.freq {
						if !m.writeState(state, previous) || !m.writeState(state-6, current) {
							return false
						}
						state -= 6
					}
				}
				current, ok := m.stateAt(state)
				if !ok {
					return false
				}
				if uint32(current.freq) < ppmdMaxFreq-9 {
					current.freq += 2
					if !m.writeState(state, current) {
						return false
					}
					summ, ok := m.summFreq(c)
					if !ok {
						return false
					}
					if !m.putU16(c+2, summ+2) {
						return false
					}
				}
			}
		}
	}

	if m.orderFall == 0 {
		context, ok := m.createSuccessors()
		if !ok {
			return m.restartModel()
		}
		m.maxContext = context
		m.minContext = context
		return m.setSuccessor(m.foundState, context)
	}

	// Non-maximum-order context: record the symbol in the raw text.
	foundState, ok := m.stateAt(m.foundState)
	if !ok {
		return false
	}
	symbol := foundState.symbol
	text := m.text
	if !m.putU8(text, symbol) {
		return false
	}
	m.text = text + 1
	if m.text >= m.unitsStart {
		return m.restartModel()
	}
	maxSuccessor := m.text
	foundState, ok = m.stateAt(m.foundState)
	if !ok {
		return false
	}
	minSuccessor := foundState.successor

	if minSuccessor != 0 {
		if minSuccessor <= maxSuccessor {
			context, ok := m.createSuccessors()
			if !ok {
				return m.restartModel()
			}
			minSuccessor = context
		}
		m.orderFall--
		if m.orderFall == 0 {
			maxSuccessor = minSuccessor
			if m.maxContext != m.minContext {
				m.text--
			}
		}
	} else {
		if !m.setSuccessor(m.foundState, maxSuccessor) {
			return false
		}
		minSuccessor = m.minContext
	}

	mc := m.minContext
	c := m.maxContext
	m.maxContext = minSuccessor
	m.minContext = minSuccessor
	if c == mc {
		return true
	}

	ns, ok := m.numStats(mc)
	if !ok {
		return false
	}
	summ, ok := m.summFreq(mc)
	if !ok {
		return false
	}
	foundState, ok = m.stateAt(m.foundState)
	if !ok {
		return false
	}
	s0 := uint32(summ) - uint32(ns) - (uint32(foundState.freq) - 1)

	for {
		ns1, ok := m.numStats(c)
		if !ok {
			return false
		}
		var sum uint32
		if ns1 != 1 {
			if ns1&1 == 0 {
				oldNu := uint32(ns1) >> 1
				i := m.u2i(oldNu)
				if i != m.u2i(oldNu+1) {
					ptr, ok := m.allocUnits(i + 1)
					if !ok {
						return m.restartModel()
					}
					oldPtr, ok := m.statsRef(c)
					if !ok {
						return false
					}
					if !m.copyUnits(ptr, oldPtr, oldNu) {
						return false
					}
					if !m.insertNode(oldPtr, i) || !m.putU32(c+4, ptr) {
						return false
					}
				}
			}
			total, ok := m.summFreq(c)
			if !ok {
				return false
			}
			value := uint32(total)
			value += boolToU32(2*uint32(ns1) < uint32(ns)) +
				2*(boolToU32(4*uint32(ns1) <= uint32(ns))&boolToU32(value <= 8*uint32(ns1)))
			sum = value
		} else {
			stats, ok := m.allocUnits(0)
			if !ok {
				return m.restartModel()
			}
			old, ok := m.oneState(c)
			if !ok {
				return false
			}
			freq0 := uint32(old.freq)
			if !m.putU32(c+4, stats) {
				return false
			}
			var freq uint32
			if freq0 < ppmdMaxFreq/4-1 {
				freq = freq0 << 1
			} else {
				freq = ppmdMaxFreq - 4
			}
			if !m.writeState(stats, ppmdState{
				symbol: old.symbol, freq: byte(freq), successor: old.successor,
			}) {
				return false
			}
			sum = freq + m.initEsc + boolToU32(uint32(ns) > 3)
		}

		base, ok := m.statsRef(c)
		if !ok {
			return false
		}
		state := base + 6*uint32(ns1)
		found, ok := m.stateAt(m.foundState)
		if !ok {
			return false
		}
		cf0 := 2 * (sum + 6) * uint32(found.freq)
		sf := s0 + sum
		if !m.putU8(state, found.symbol) {
			return false
		}
		if !m.putU16(c, ns1+1) {
			return false
		}
		if !m.setSuccessor(state, maxSuccessor) {
			return false
		}
		var cf, total uint32
		if cf0 < 6*sf {
			cf = 1 + boolToU32(cf0 > sf) + boolToU32(cf0 >= 4*sf)
			total = sum + 3
		} else {
			cf = 4 + boolToU32(cf0 >= 9*sf) + boolToU32(cf0 >= 12*sf) + boolToU32(cf0 >= 15*sf)
			total = sum + cf
		}
		if !m.putU16(c+2, uint16(total)) || !m.putU8(state+1, byte(cf)) {
			return false
		}

		next, ok := m.suffix(c)
		if !ok {
			return false
		}
		c = next
		if c == mc {
			break
		}
	}
	return true
}

func (m *ppmModel) rescale() bool {
	stats, ok := m.statsRef(m.minContext)
	if !ok {
		return false
	}
	s := m.foundState

	// Move the found state to the front, shifting the rest right.
	if s != stats {
		found, ok := m.stateAt(s)
		if !ok {
			return false
		}
		for {
			if s < 6 {
				return false
			}
			previous, ok := m.stateAt(s - 6)
			if !ok {
				return false
			}
			if !m.writeState(s, previous) {
				return false
			}
			s -= 6
			if s == stats {
				break
			}
		}
		if !m.writeState(s, found) {
			return false
		}
	}

	first, ok := m.stateAt(s)
	if !ok {
		return false
	}
	sumFreq := uint32(first.freq)
	summ, ok := m.summFreq(m.minContext)
	if !ok {
		return false
	}
	escFreq := uint32(summ) - sumFreq
	adder := boolToU32(m.orderFall != 0)
	sumFreq = (sumFreq + 4 + adder) >> 1
	numStats, ok := m.numStats(m.minContext)
	if !ok || numStats == 0 {
		return false
	}
	i := uint32(numStats) - 1
	found := first
	found.freq = byte(sumFreq)
	if !m.writeState(s, found) {
		return false
	}

	for {
		s += 6
		current, ok := m.stateAt(s)
		if !ok {
			return false
		}
		freq := uint32(current.freq)
		escFreq -= freq
		freq = (freq + adder) >> 1
		sumFreq += freq
		current.freq = byte(freq)
		if !m.writeState(s, current) {
			return false
		}
		if s < 6 {
			return false
		}
		previous, ok := m.stateAt(s - 6)
		if !ok {
			return false
		}
		if freq > uint32(previous.freq) {
			moving, ok := m.stateAt(s)
			if !ok {
				return false
			}
			s1 := s
			for {
				if s1 < 6 {
					return false
				}
				s1 -= 6
				prev2, ok := m.stateAt(s1)
				if !ok {
					return false
				}
				if !m.writeState(s1+6, prev2) {
					return false
				}
				if s1 == stats {
					break
				}
				prev3, ok := m.stateAt(s1 - 6)
				if !ok {
					return false
				}
				if freq <= uint32(prev3.freq) {
					break
				}
			}
			if !m.writeState(s1, moving) {
				return false
			}
		}
		i--
		if i == 0 {
			break
		}
	}

	stateS, ok := m.stateAt(s)
	if !ok {
		return false
	}
	if stateS.freq == 0 {
		var count uint32
		for {
			count++
			if s < 6 {
				return false
			}
			s -= 6
			if s < stats {
				return false
			}
			current, ok := m.stateAt(s)
			if !ok {
				return false
			}
			if current.freq != 0 {
				break
			}
		}
		escFreq += count

		mc := m.minContext
		ns, ok := m.numStats(mc)
		if !ok {
			return false
		}
		numStatsNew := uint32(ns) - count
		if !m.putU16(mc, uint16(numStatsNew)) {
			return false
		}
		n0 := (uint32(ns) + 1) >> 1

		if numStatsNew == 1 {
			firstState, ok := m.stateAt(stats)
			if !ok {
				return false
			}
			freq := uint32(firstState.freq)
			for {
				escFreq >>= 1
				freq = (freq + 1) >> 1
				if escFreq <= 1 {
					break
				}
			}
			firstState.freq = byte(freq)
			if !m.writeState(mc+2, firstState) {
				return false
			}
			m.foundState = mc + 2
			return m.insertNode(stats, m.u2i(n0))
		}

		n1 := (numStatsNew + 1) >> 1
		if n0 != n1 {
			i0 := m.u2i(n0)
			i1 := m.u2i(n1)
			if i0 != i1 {
				if i1 < uint32(len(m.freeList)) && m.freeList[i1] != 0 {
					ptr, ok := m.removeNode(i1)
					if !ok {
						return false
					}
					if !m.putU32(mc+4, ptr) || !m.copyUnits(ptr, stats, n1) ||
						!m.insertNode(stats, i0) {
						return false
					}
				} else if !m.splitBlock(stats, i0, i1) {
					return false
				}
			}
		}
	}

	total := sumFreq + (escFreq - escFreq>>1)
	if !m.putU16(m.minContext+2, uint16(total)) {
		return false
	}
	ref, ok := m.statsRef(m.minContext)
	if !ok {
		return false
	}
	m.foundState = ref
	return true
}

// makeEscFreq returns row, column, escape and whether a SEE context applies.
// The final bool is false on a malformed model.
func (m *ppmModel) makeEscFreq(numMasked uint32) (int, int, uint32, bool, bool) {
	mc := m.minContext
	numStats, ok := m.numStats(mc)
	if !ok {
		return 0, 0, 0, false, false
	}
	if numStats == 256 {
		return 0, 0, 0, false, true
	}
	if numMasked > uint32(numStats) {
		return 0, 0, 0, false, false
	}
	nonMasked := uint32(numStats) - numMasked
	row := int(m.ns2indx[nonMasked-1])
	if row >= ppmdNumSee {
		return 0, 0, 0, false, false
	}
	suffix, ok := m.suffix(mc)
	if !ok {
		return 0, 0, 0, false, false
	}
	suffixStats, ok := m.numStats(suffix)
	if !ok {
		return 0, 0, 0, false, false
	}
	summ, ok := m.summFreq(mc)
	if !ok {
		return 0, 0, 0, false, false
	}
	column := boolToInt(nonMasked < uint32(suffixStats)-uint32(numStats)) +
		2*boolToInt(uint32(summ) < 11*uint32(numStats)) +
		4*boolToInt(numMasked > nonMasked) +
		int(m.hiBitsFlag)
	if column >= ppmdSeeSize {
		column = ppmdSeeSize - 1
	}
	see := &m.see[row][column]
	value := uint32(see.summ)
	r := value >> see.shift
	see.summ = uint16(value - r)
	return row, column, r + boolToU32(r == 0), true, true
}

func (m *ppmModel) updateSee(row, column int) {
	see := &m.see[row][column]
	if see.shift < byte(ppmdPeriodBits) {
		see.count--
		if see.count == 0 {
			see.summ = uint16(uint32(see.summ) << 1)
			see.count = 3 << see.shift
			see.shift++
		}
	}
}

func (m *ppmModel) nextContext() bool {
	found, ok := m.stateAt(m.foundState)
	if !ok {
		return false
	}
	context := found.successor
	if m.orderFall == 0 && context > m.text {
		m.maxContext = context
		m.minContext = context
		return true
	}
	return m.updateModel()
}

func (m *ppmModel) update1() bool {
	s := m.foundState
	found, ok := m.stateAt(s)
	if !ok {
		return false
	}
	freq := uint32(found.freq) + 4
	summ, ok := m.summFreq(m.minContext)
	if !ok {
		return false
	}
	if !m.putU16(m.minContext+2, summ+4) {
		return false
	}
	found.freq = byte(freq)
	if !m.writeState(s, found) {
		return false
	}
	if s < 6 {
		return false
	}
	previous, ok := m.stateAt(s - 6)
	if !ok {
		return false
	}
	if freq > uint32(previous.freq) {
		current, ok := m.stateAt(s)
		if !ok {
			return false
		}
		if !m.writeState(s, previous) || !m.writeState(s-6, current) {
			return false
		}
		m.foundState = s - 6
		if freq > ppmdMaxFreq {
			if !m.rescale() {
				return false
			}
		}
	}
	return m.nextContext()
}

func (m *ppmModel) update1Zero() bool {
	s := m.foundState
	mc := m.minContext
	found, ok := m.stateAt(s)
	if !ok {
		return false
	}
	freq := uint32(found.freq)
	summ, ok := m.summFreq(mc)
	if !ok {
		return false
	}
	m.prevSuccess = boolToU32(2*freq > uint32(summ))
	m.runLength += int32(m.prevSuccess)
	if !m.putU16(mc+2, summ+4) {
		return false
	}
	freq += 4
	found.freq = byte(freq)
	if !m.writeState(s, found) {
		return false
	}
	if freq > ppmdMaxFreq {
		if !m.rescale() {
			return false
		}
	}
	return m.nextContext()
}

func (m *ppmModel) update2() bool {
	s := m.foundState
	found, ok := m.stateAt(s)
	if !ok {
		return false
	}
	freq := uint32(found.freq) + 4
	m.runLength = m.initRL
	summ, ok := m.summFreq(m.minContext)
	if !ok {
		return false
	}
	if !m.putU16(m.minContext+2, summ+4) {
		return false
	}
	found.freq = byte(freq)
	if !m.writeState(s, found) {
		return false
	}
	if freq > ppmdMaxFreq {
		if !m.rescale() {
			return false
		}
	}
	return m.updateModel()
}

// ----- range decoder -----------------------------------------------------

func (m *ppmModel) rangeDecInit(input []byte) bool {
	m.input = input
	m.cursor = 0
	m.extra = false
	m.code = 0
	m.rnge = ^uint32(0)
	if m.readByte() != 0 {
		return false
	}
	for i := 0; i < 4; i++ {
		m.code = (m.code << 8) | uint32(m.readByte())
	}
	return m.code < ^uint32(0)
}

func (m *ppmModel) readByte() byte {
	if m.cursor < len(m.input) {
		value := m.input[m.cursor]
		m.cursor++
		return value
	}
	m.extra = true
	return 0
}

func (m *ppmModel) normalizeOnce() {
	if m.rnge < ppmdTop {
		m.code = (m.code << 8) | uint32(m.readByte())
		m.rnge <<= 8
	}
}

func (m *ppmModel) normalize() {
	m.normalizeOnce()
	m.normalizeOnce()
}

func (m *ppmModel) rcDecode(start, size uint32) {
	m.code -= start * m.rnge
	m.rnge *= size
}

func (m *ppmModel) rcDecodeFinal(start, size uint32) {
	m.rcDecode(start, size)
	m.normalize()
}

func (m *ppmModel) rcThreshold(total uint32) (uint32, bool) {
	if total == 0 {
		return 0, false
	}
	m.rnge /= total
	if m.rnge == 0 {
		return 0, false
	}
	return m.code / m.rnge, true
}

// ----- symbol decoding ---------------------------------------------------

func (m *ppmModel) binSummSlot() (int, int, bool) {
	one, ok := m.oneState(m.minContext)
	if !ok {
		return 0, 0, false
	}
	suffix, ok := m.suffix(m.minContext)
	if !ok || suffix == 0 {
		return 0, 0, false
	}
	suffixStats, ok := m.numStats(suffix)
	if !ok || suffixStats == 0 {
		return 0, 0, false
	}
	if one.freq == 0 {
		return 0, 0, false
	}
	row := int(one.freq) - 1
	run := (uint32(m.runLength) >> 26) & 0x20
	found, ok := m.stateAt(m.foundState)
	if !ok {
		return 0, 0, false
	}
	m.hiBitsFlag = hiBits3(found.symbol)
	column := m.prevSuccess + run +
		uint32(m.ns2bsindx[suffixStats-1]) + hiBits4(one.symbol) + m.hiBitsFlag
	if row >= 128 {
		return 0, 0, false
	}
	return row, int(column) & 63, true
}

func (m *ppmModel) decodeSymbol() (int32, bool) {
	var mask [256]byte

	firstCount, ok := m.numStats(m.minContext)
	if !ok {
		return 0, false
	}
	if firstCount != 1 {
		mc := m.minContext
		summ, ok := m.summFreq(mc)
		if !ok {
			return 0, false
		}
		base, ok := m.statsRef(mc)
		if !ok {
			return 0, false
		}
		s := base
		value, ok := m.rcThreshold(uint32(summ))
		if !ok {
			return 0, false
		}
		hiCnt := value

		first, ok := m.stateAt(s)
		if !ok {
			return 0, false
		}
		value -= uint32(first.freq)
		if int32(value) < 0 {
			m.rcDecodeFinal(0, uint32(first.freq))
			m.foundState = s
			symbol := first.symbol
			if !m.update1Zero() {
				return 0, false
			}
			return int32(symbol), true
		}

		m.prevSuccess = 0
		i := uint32(firstCount) - 1
		for {
			s += 6
			state, ok := m.stateAt(s)
			if !ok {
				return 0, false
			}
			value -= uint32(state.freq)
			if int32(value) < 0 {
				m.rcDecodeFinal(
					hiCnt-value-uint32(state.freq),
					uint32(state.freq))
				m.foundState = s
				if !m.update1() {
					return 0, false
				}
				return int32(state.symbol), true
			}
			i--
			if i == 0 {
				break
			}
		}

		if hiCnt >= uint32(summ) {
			return 0, false
		}
		hiCnt -= value
		m.rcDecode(hiCnt, uint32(summ)-hiCnt)

		found, ok := m.stateAt(m.foundState)
		if !ok {
			return 0, false
		}
		m.hiBitsFlag = hiBits3(found.symbol)
		for index := range mask {
			mask[index] = 0xFF
		}
		s2 := base
		symbolState, ok := m.stateAt(s)
		if !ok {
			return 0, false
		}
		mask[symbolState.symbol] = 0
		for {
			sym0State, ok := m.stateAt(s2)
			if !ok {
				return 0, false
			}
			sym1State, ok := m.stateAt(s2 + 6)
			if !ok {
				return 0, false
			}
			s2 += 12
			mask[sym0State.symbol] = 0
			mask[sym1State.symbol] = 0
			if s2 >= s {
				break
			}
		}
	} else {
		one, ok := m.oneState(m.minContext)
		if !ok {
			return 0, false
		}
		row, column, ok := m.binSummSlot()
		if !ok {
			return 0, false
		}
		prob := uint32(m.binSumm[row][column])
		size0 := (m.rnge >> 14) * prob
		pr := prob - ((prob + (1 << (ppmdIntBits - 2))) >> ppmdIntBits)

		if m.code < size0 {
			m.binSumm[row][column] = uint16(pr + (1 << ppmdIntBits))
			m.rnge = size0
			m.normalizeOnce()

			context := one.successor
			symbol := one.symbol
			m.foundState = m.minContext + 2
			m.prevSuccess = 1
			m.runLength++
			state, ok := m.oneState(m.minContext)
			if !ok {
				return 0, false
			}
			if state.freq < 128 {
				state.freq++
			}
			if !m.writeState(m.minContext+2, state) {
				return 0, false
			}
			if m.orderFall == 0 && context > m.text {
				m.maxContext = context
				m.minContext = context
			} else if !m.updateModel() {
				return 0, false
			}
			return int32(symbol), true
		}

		m.binSumm[row][column] = uint16(pr)
		m.initEsc = uint32(ppmdExpEscape[(pr>>10)&0x0F])
		m.code -= size0
		m.rnge -= size0
		m.normalize()

		for index := range mask {
			mask[index] = 0xFF
		}
		state, ok := m.oneState(m.minContext)
		if !ok {
			return 0, false
		}
		mask[state.symbol] = 0
		m.prevSuccess = 0
	}

	for {
		m.normalize()
		mc := m.minContext
		numMasked, ok := m.numStats(mc)
		if !ok {
			return 0, false
		}
		for {
			m.orderFall++
			suffix, ok := m.suffix(mc)
			if !ok {
				return 0, false
			}
			if suffix == 0 {
				return ppmdSymEnd, true
			}
			mc = suffix
			count, ok := m.numStats(mc)
			if !ok {
				return 0, false
			}
			if count != numMasked {
				break
			}
		}
		m.minContext = mc

		base, ok := m.statsRef(mc)
		if !ok {
			return 0, false
		}
		count, ok := m.numStats(mc)
		if !ok {
			return 0, false
		}
		s := base
		odd := uint32(count) & 1
		first, ok := m.stateAt(s)
		if !ok {
			return 0, false
		}
		hiCnt := uint32(first.freq) & uint32(mask[first.symbol]) & (0 - odd)
		s += 6 * odd
		pairs := uint32(count) / 2
		for remaining := pairs; remaining > 0; remaining-- {
			sym0State, ok := m.stateAt(s)
			if !ok {
				return 0, false
			}
			sym1State, ok := m.stateAt(s + 6)
			if !ok {
				return 0, false
			}
			s += 12
			state0, ok := m.stateAt(s - 12)
			if !ok {
				return 0, false
			}
			state1, ok := m.stateAt(s - 6)
			if !ok {
				return 0, false
			}
			hiCnt += uint32(state0.freq) & uint32(mask[sym0State.symbol])
			hiCnt += uint32(state1.freq) & uint32(mask[sym1State.symbol])
		}

		row, column, escape, present, ok := m.makeEscFreq(uint32(numMasked))
		if !ok {
			return 0, false
		}
		freqSum := 1 + hiCnt
		if present {
			freqSum = escape + hiCnt
		}
		value, ok := m.rcThreshold(freqSum)
		if !ok {
			return 0, false
		}

		if value < hiCnt {
			base2, ok := m.statsRef(m.minContext)
			if !ok {
				return 0, false
			}
			s := base2
			threshold := value
			value2 := value
			for {
				state, ok := m.stateAt(s)
				if !ok {
					return 0, false
				}
				value2 -= uint32(state.freq) & uint32(mask[state.symbol])
				s += 6
				if int32(value2) < 0 {
					break
				}
				if s >= base2+6*uint32(count) {
					return 0, false
				}
			}
			s -= 6
			state, ok := m.stateAt(s)
			if !ok {
				return 0, false
			}
			m.rcDecodeFinal(
				threshold-value2-uint32(state.freq),
				uint32(state.freq))
			if present {
				m.updateSee(row, column)
			}
			m.foundState = s
			symbol := state.symbol
			if !m.update2() {
				return 0, false
			}
			return int32(symbol), true
		}

		if value >= freqSum {
			return 0, false
		}
		m.rcDecode(hiCnt, freqSum-hiCnt)

		if present {
			summ := m.see[row][column].summ + uint16(freqSum)
			m.see[row][column].summ = summ
		}

		base2, ok := m.statsRef(m.minContext)
		if !ok {
			return 0, false
		}
		count2, ok := m.numStats(m.minContext)
		if !ok {
			return 0, false
		}
		s2 := base2
		end := base2 + 6*uint32(count2)
		for {
			state, ok := m.stateAt(s2)
			if !ok {
				return 0, false
			}
			mask[state.symbol] = 0
			s2 += 6
			if s2 == end {
				break
			}
		}
	}
}

func hiBits3(symbol byte) uint32 {
	return ((uint32(symbol) + 0xC0) >> (8 - 3)) & (1 << 3)
}

func hiBits4(symbol byte) uint32 {
	return ((uint32(symbol) + 0xC0) >> (8 - 4)) & (1 << 4)
}

func boolToU32(value bool) uint32 {
	if value {
		return 1
	}
	return 0
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
