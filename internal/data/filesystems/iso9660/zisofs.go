package iso9660

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"io"
	"sync/atomic"

	"github.com/laenix/ewfgo/internal/data/source"
)

var zisofsMagic = [8]byte{0x37, 0xE4, 0x53, 0x96, 0xC9, 0xDB, 0xD6, 0x07}

const (
	zisofsHeaderBytes    = 16
	zisofsMinBlockShift  = 12
	zisofsMaxBlockShift  = 17
	zisofsMinHeaderWords = 4
)

// ZisofsMark is the ZF SUSP entry a Rock Ridge record carries for a zisofs
// file. Its fields duplicate the file header and are cross-checked on open.
type ZisofsMark struct {
	Algorithm       [2]byte
	HeaderSize      uint8
	BlockShift      uint8
	UncompressedLen uint32
	SizeAgrees      bool
}

// BlockSize returns the compression block size, when the shift is accepted.
func (m ZisofsMark) BlockSize() (uint64, bool) {
	if m.BlockShift < zisofsMinBlockShift || m.BlockShift > zisofsMaxBlockShift {
		return 0, false
	}
	return 1 << m.BlockShift, true
}

// ZisofsStats is a point-in-time view of a volume's zisofs counters.
type ZisofsStats struct {
	Files             uint64
	DecompressedBytes uint64
	Blocks            uint64
	Refusals          uint64
	CorruptHeaders    uint64
}

type zisofsCounters struct {
	files             atomic.Uint64
	decompressedBytes atomic.Uint64
	blocks            atomic.Uint64
	refusals          atomic.Uint64
	corruptHeaders    atomic.Uint64
}

func (c *zisofsCounters) addFile()                 { c.files.Add(1) }
func (c *zisofsCounters) addBlock()                { c.blocks.Add(1) }
func (c *zisofsCounters) addDecompressed(n uint64) { c.decompressedBytes.Add(n) }
func (c *zisofsCounters) addRefusal()              { c.refusals.Add(1) }
func (c *zisofsCounters) addCorruptHeader()        { c.corruptHeaders.Add(1) }

func (c *zisofsCounters) snapshot() ZisofsStats {
	return ZisofsStats{
		Files:             c.files.Load(),
		DecompressedBytes: c.decompressedBytes.Load(),
		Blocks:            c.blocks.Load(),
		Refusals:          c.refusals.Load(),
		CorruptHeaders:    c.corruptHeaders.Load(),
	}
}

// zisofsFile is one validated zisofs file.
type zisofsFile struct {
	run             Run
	storedLen       uint64
	uncompressedLen uint64
	blockSize       uint64
	pointers        []uint32
	path            string
	counters        *zisofsCounters
}

func (f *zisofsFile) refuse(corruptHeader bool, reason string) error {
	f.counters.addRefusal()
	if corruptHeader {
		f.counters.addCorruptHeader()
	}
	return corruptf("%s", reason)
}

// openZisofs validates the header and pointer table of a file the walk marked
// with ZF, and prepares it for reads.
func openZisofs(src source.ByteSource, run Run, storedLen uint64, mark *ZisofsMark, path string, counters *zisofsCounters) (*zisofsFile, error) {
	refuse := func(corruptHeader bool, reason string) (*zisofsFile, error) {
		counters.addRefusal()
		if corruptHeader {
			counters.addCorruptHeader()
		}
		return nil, corruptf("%s", reason)
	}
	if mark.Algorithm != [2]byte{'p', 'z'} {
		return refuse(false, "zisofs file "+path+" declares an algorithm other than pz")
	}
	if !mark.SizeAgrees {
		return refuse(true, "zisofs file "+path+" has a ZF entry whose little- and big-endian uncompressed sizes disagree")
	}
	if run.Len != storedLen {
		return refuse(false, "zisofs file "+path+" names a stored length that does not match its extent")
	}
	if storedLen < zisofsHeaderBytes {
		return refuse(true, "zisofs file "+path+" is shorter than its header")
	}
	header, err := source.ReadVecAt(src, run.Offset, zisofsHeaderBytes)
	if err != nil {
		return refuse(true, "zisofs header of "+path+" could not be read: "+err.Error())
	}
	if !bytes.Equal(header[:8], zisofsMagic[:]) {
		return refuse(true, "zisofs file "+path+" does not begin with the 37 E4 53 96 C9 DB D6 07 magic")
	}
	if header[14] != 0 || header[15] != 0 {
		return refuse(true, "zisofs file "+path+" has non-zero reserved header bytes")
	}
	headerWords := header[12]
	blockShift := header[13]
	uncompressedLen := binary.LittleEndian.Uint32(header[8:12])
	if headerWords < zisofsMinHeaderWords {
		return refuse(true, "zisofs file "+path+" declares a header smaller than four words")
	}
	if blockShift < zisofsMinBlockShift || blockShift > zisofsMaxBlockShift {
		return refuse(true, "zisofs file "+path+" declares block shift outside the accepted range")
	}
	if headerWords != mark.HeaderSize || blockShift != mark.BlockShift || uncompressedLen != mark.UncompressedLen {
		return refuse(true, "zisofs file "+path+" header disagrees with its ZF entry")
	}

	blockSize := uint64(1) << blockShift
	uncompressed := uint64(uncompressedLen)
	blocks := (uncompressed + blockSize - 1) / blockSize
	headerBytes := uint64(headerWords) * 4
	pointerBytes := (blocks + 1) * 4
	tableEnd := headerBytes + pointerBytes
	if tableEnd > storedLen {
		return refuse(false, "zisofs file "+path+" needs more bytes for its header and pointers than its extent holds")
	}
	table, err := source.ReadVecAt(src, run.Offset+headerBytes, pointerBytes)
	if err != nil {
		return refuse(false, "zisofs pointer table of "+path+" could not be read: "+err.Error())
	}
	pointers := make([]uint32, blocks+1)
	for i := range pointers {
		pointers[i] = binary.LittleEndian.Uint32(table[i*4:])
	}
	previous := tableEnd
	for index, raw := range pointers {
		pointer := uint64(raw)
		if pointer < previous {
			return refuse(false, "zisofs file "+path+" pointer points before the previous boundary")
		}
		if pointer > storedLen {
			return refuse(false, "zisofs file "+path+" pointer lies past the stored extent")
		}
		if index > 0 {
			compressed := pointer - previous
			if compressed > deflateBound(blockSize) {
				return refuse(false, "zisofs file "+path+" stores a block above the deflate bound")
			}
		}
		previous = pointer
	}

	file := &zisofsFile{
		run:             run,
		storedLen:       storedLen,
		uncompressedLen: uncompressed,
		blockSize:       blockSize,
		pointers:        pointers,
		path:            path,
		counters:        counters,
	}
	if err := file.checkFinalPointer(); err != nil {
		return nil, err
	}
	return file, nil
}

func (f *zisofsFile) checkFinalPointer() error {
	var final uint64
	if len(f.pointers) > 0 {
		final = uint64(f.pointers[len(f.pointers)-1])
	}
	if final > f.storedLen {
		return f.refuse(false, "zisofs file "+f.path+" ends past its stored extent")
	}
	return nil
}

func (f *zisofsFile) len() uint64            { return f.uncompressedLen }
func (f *zisofsFile) storedLenValue() uint64 { return f.storedLen }
func (f *zisofsFile) runValue() Run          { return f.run }

// blockLen returns the logical bytes in block index; the last may be short.
func (f *zisofsFile) blockLen(index uint64) uint64 {
	start := index * f.blockSize
	return minU64(f.uncompressedLen-start, f.blockSize)
}

// readBlock decodes block index into out, which must be exactly its logical
// length. A zero-length stored range is an all-zero block.
func (f *zisofsFile) readBlock(src source.ByteSource, index uint64, out []byte) error {
	f.counters.addBlock()
	start := uint64(f.pointers[index])
	end := uint64(f.pointers[index+1])
	if start == end {
		for i := range out {
			out[i] = 0
		}
		return nil
	}
	compressed, err := source.ReadVecAt(src, f.run.Offset+start, end-start)
	if err != nil {
		return err
	}
	reader, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		f.counters.addRefusal()
		return corruptf("zisofs file %s block %d: zlib: %v", f.path, index, err)
	}
	decoded, readErr := io.ReadAll(io.LimitReader(reader, int64(len(out))+1))
	closeErr := reader.Close()
	if readErr != nil {
		f.counters.addRefusal()
		return corruptf("zisofs file %s block %d: zlib: %v", f.path, index, readErr)
	}
	if closeErr != nil {
		f.counters.addRefusal()
		return corruptf("zisofs file %s block %d: zlib: %v", f.path, index, closeErr)
	}
	if len(decoded) != len(out) {
		f.counters.addRefusal()
		return corruptf("zisofs file %s block %d decoded %d of %d expected bytes",
			f.path, index, len(decoded), len(out))
	}
	copy(out, decoded)
	return nil
}

// readAt serves logical bytes from the compressed blocks.
func (f *zisofsFile) readAt(src source.ByteSource, offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= f.uncompressedLen {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), f.uncompressedLen)
	}
	want := int(minU64(f.uncompressedLen-offset, uint64(len(buf))))
	scratch := make([]byte, int(f.blockSize))
	done := 0
	logical := offset
	for done < want {
		index := logical / f.blockSize
		blockStart := index * f.blockSize
		inBlock := int(logical - blockStart)
		produced := int(f.blockLen(index))
		take := produced - inBlock
		if remaining := want - done; take > remaining {
			take = remaining
		}
		if err := f.readBlock(src, index, scratch[:produced]); err != nil {
			return 0, err
		}
		copy(buf[done:done+take], scratch[inBlock:inBlock+take])
		done += take
		logical += uint64(take)
	}
	f.counters.addDecompressed(uint64(want))
	return want, nil
}

// extentsInto describes the stored blocks a logical range touches.
func (f *zisofsFile) extentsInto(parent source.ID, offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > f.uncompressedLen || length > f.uncompressedLen-offset {
		return out, source.NewOutOfRange(offset, length, f.uncompressedLen)
	}
	if length == 0 {
		return out, nil
	}
	end := offset + length
	first := offset / f.blockSize
	last := (end - 1) / f.blockSize
	for index := first; index <= last; index++ {
		blockStart := index * f.blockSize
		blockEnd := blockStart + f.blockLen(index)
		from := maxU64(offset, blockStart)
		to := minU64(end, blockEnd)
		if from >= to {
			continue
		}
		start := uint64(f.pointers[index])
		stop := uint64(f.pointers[index+1])
		if start == stop {
			out = append(out, source.ParentRange{Parent: parent, Len: to - from, Kind: source.RangeZero})
		} else {
			out = append(out, source.ParentRange{
				Parent:       parent,
				ParentOffset: f.run.Offset + start,
				Len:          stop - start,
				Kind:         source.RangeData,
			})
		}
	}
	return out, nil
}

// deflateBound is zlib's deflateBound() for a block of input bytes.
func deflateBound(input uint64) uint64 {
	return input + (input >> 12) + (input >> 14) + (input >> 25) + 13
}
