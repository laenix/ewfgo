// 7z signature header and property-tree parser.
//
// The format is a little-endian property tree.  Every structure is a run of
// variable-length integers (7 bits per byte for the first eight bytes, then
// whole bytes) followed by blocks whose length is itself a number.  This file
// turns that tree into plain Go values and validates the cross references --
// folder to coders, folder to packed streams, file to substream -- so the
// reader never indexes a stream that does not exist.
//
// Parsing is structural only: no payload is decompressed here.  The reader
// decodes folders, including the encoded header, through coders.go.

package sevenz

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"unicode/utf16"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/foundation"
)

// signature is the six-byte start of every 7z file.
var signature = [6]byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}

// signatureHeaderLen is the fixed signature header before the next-header
// offset.
const signatureHeaderLen = 32

// maxItems is a ceiling on any count read from the header before it is used to
// size a slice.  The archive budget still enforces the caller's entry limit.
const maxItems = 1 << 22

// maxCoders bounds one folder's coder chain.
const maxCoders = 64

// Property ids.
const (
	kEnd                   uint64 = 0x00
	kHeader                uint64 = 0x01
	kArchiveProperties     uint64 = 0x02
	kAdditionalStreamsInfo uint64 = 0x03
	kMainStreamsInfo       uint64 = 0x04
	kFilesInfo             uint64 = 0x05
	kPackInfo              uint64 = 0x06
	kUnpackInfo            uint64 = 0x07
	kSubstreamsInfo        uint64 = 0x08
	kSize                  uint64 = 0x09
	kCRC                   uint64 = 0x0A
	kFolder                uint64 = 0x0B
	kCodersUnpackSize      uint64 = 0x0C
	kNumUnpackStream       uint64 = 0x0D
	kEmptyStream           uint64 = 0x0E
	kEmptyFile             uint64 = 0x0F
	kAnti                  uint64 = 0x10
	kName                  uint64 = 0x11
	kCTime                 uint64 = 0x12
	kATime                 uint64 = 0x13
	kMTime                 uint64 = 0x14
	kWinAttrib             uint64 = 0x15
	kEncodedHeader         uint64 = 0x17
	kStartPos              uint64 = 0x18
)

// Coder ids, as stored byte strings.  The shorter forms are the 7-Zip
// registration; the longer forms are the fully qualified method ids some
// writers emit.
var (
	idCopy      = []byte{0x00}
	idLZMA      = []byte{0x03, 0x01, 0x01}
	idLZMA2     = []byte{0x21}
	idDeflate   = []byte{0x04, 0x01, 0x08}
	idDeflate64 = []byte{0x04, 0x01, 0x09}
	idBzip2     = []byte{0x04, 0x02, 0x02}
	idAES       = []byte{0x06, 0xF1, 0x07, 0x01}
	idDelta     = []byte{0x03}
	idBCJX86    = []byte{0x03, 0x03, 0x01, 0x03}
	idBCJ2      = []byte{0x03, 0x03, 0x01, 0x1B}
	idPPMd      = []byte{0x03, 0x04, 0x01}
	idBCJAlpha  = []byte{0x03, 0x03, 0x03, 0x01}
	idBCJPPC    = []byte{0x03, 0x03, 0x02, 0x05}
	idBCJIA64   = []byte{0x03, 0x03, 0x04, 0x01}
	idBCJARM    = []byte{0x03, 0x03, 0x05, 0x01}
	idBCJARMT   = []byte{0x03, 0x03, 0x07, 0x01}
	idBCJSPARC  = []byte{0x03, 0x03, 0x08, 0x05}
	idBCJARM64  = []byte{0x0A}
	idBCJRISCV  = []byte{0x0B}
	idSwap2     = []byte{0x02, 0x03, 0x02}
	idSwap4     = []byte{0x02, 0x03, 0x04}
)

// coderLabel names a coder id for refusal messages.
func coderLabel(id []byte) string {
	switch {
	case bytes.Equal(id, idCopy):
		return "Copy"
	case bytes.Equal(id, idLZMA):
		return "LZMA"
	case bytes.Equal(id, idLZMA2):
		return "LZMA2"
	case bytes.Equal(id, idDeflate):
		return "Deflate"
	case bytes.Equal(id, idDeflate64):
		return "Deflate64"
	case bytes.Equal(id, idBzip2):
		return "BZip2"
	case bytes.Equal(id, idAES):
		return "AES-256"
	case bytes.Equal(id, idDelta):
		return "Delta"
	case bytes.Equal(id, idBCJX86):
		return "BCJ x86"
	case bytes.Equal(id, idBCJ2):
		return "BCJ2"
	case bytes.Equal(id, idPPMd):
		return "PPMd"
	case bytes.Equal(id, idBCJAlpha):
		return "BCJ Alpha"
	case bytes.Equal(id, idBCJPPC):
		return "BCJ PPC"
	case bytes.Equal(id, idBCJIA64):
		return "BCJ IA-64"
	case bytes.Equal(id, idBCJARM):
		return "BCJ ARM"
	case bytes.Equal(id, idBCJARMT):
		return "BCJ ARM-Thumb"
	case bytes.Equal(id, idBCJSPARC):
		return "BCJ SPARC"
	case bytes.Equal(id, idBCJARM64):
		return "BCJ ARM64"
	case bytes.Equal(id, idBCJRISCV):
		return "BCJ RISC-V"
	case bytes.Equal(id, idSwap2):
		return "Swap2"
	case bytes.Equal(id, idSwap4):
		return "Swap4"
	}
	return fmt.Sprintf("0x%x", id)
}

// coderSupported reports whether this reader can decode the coder.  It mirrors
// the switch in volume.applyCoder so an entry whose folder needs a coder the
// port lacks is refused when it is opened, not after the caller has accepted a
// source that can never produce bytes.  AES is handled separately as a
// decryption refusal.
func coderSupported(id []byte) bool {
	switch {
	case bytes.Equal(id, idCopy),
		bytes.Equal(id, idLZMA),
		bytes.Equal(id, idLZMA2),
		bytes.Equal(id, idDeflate),
		bytes.Equal(id, idBzip2),
		bytes.Equal(id, idPPMd),
		bytes.Equal(id, idDelta),
		bytes.Equal(id, idBCJX86),
		bytes.Equal(id, idBCJ2),
		bytes.Equal(id, idBCJPPC),
		bytes.Equal(id, idBCJIA64),
		bytes.Equal(id, idBCJARM),
		bytes.Equal(id, idBCJARMT),
		bytes.Equal(id, idBCJSPARC),
		bytes.Equal(id, idBCJARM64),
		bytes.Equal(id, idBCJRISCV),
		bytes.Equal(id, idSwap2),
		bytes.Equal(id, idSwap4):
		return true
	}
	return false
}

// fileSignature is the fixed part of the signature header.
type fileSignature struct {
	// nextOffset is the offset of the next header, relative to the end of the
	// 32-byte signature header.
	nextOffset uint64
	nextSize   uint64
	nextCRC    uint32
}

// parseSignature validates the 32-byte signature header and returns the
// next-header location.
//
// The start-header CRC covers the twenty bytes that follow it: the offset, the
// size, and the CRC of the next header.  A mismatch means the file was
// truncated, padded, or altered, so nothing after it can be trusted.
func parseSignature(head []byte) (fileSignature, error) {
	if len(head) < signatureHeaderLen {
		return fileSignature{}, archive.Invalidf(
			"7z signature header is truncated: %d bytes", len(head))
	}
	if !bytes.Equal(head[:6], signature[:]) {
		return fileSignature{}, archive.Invalidf("7z signature is missing")
	}
	startCRC := binary.LittleEndian.Uint32(head[8:12])
	if foundation.CRC32(head[12:32]) != startCRC {
		return fileSignature{}, archive.Invalidf("7z start-header CRC does not match")
	}
	return fileSignature{
		nextOffset: binary.LittleEndian.Uint64(head[12:20]),
		nextSize:   binary.LittleEndian.Uint64(head[20:28]),
		nextCRC:    binary.LittleEndian.Uint32(head[28:32]),
	}, nil
}

// verifyNextCRC reports whether data holds a complete header whose trailing
// CRC matches.
func verifyNextCRC(data []byte, expected uint32) bool {
	return foundation.CRC32(data) == expected
}

// coder is one coder in a folder.
type coder struct {
	id     []byte
	props  []byte
	numIn  uint64
	numOut uint64
}

func (c *coder) is(id []byte) bool { return bytes.Equal(c.id, id) }

// bindPair joins a coder output stream to a coder input stream.
type bindPair struct {
	input  uint64
	output uint64
}

// folder is one coder chain that produces one unpacked byte stream.
type folder struct {
	coders []coder
	// bindPairs join the coders: (input stream, output stream).
	bindPairs []bindPair
	// totalIn and totalOut are the stream counts across the coders.
	totalIn  uint64
	totalOut uint64
	// unpackSizes holds one number per coder output stream, in coder order.
	unpackSizes []uint64
	// crc is the CRC-32 of the whole unpacked folder, when recorded.
	crc *uint32
	// numSubstreams is the number of substreams the folder holds.
	numSubstreams uint64
	// subSizes is the size of each substream.
	subSizes []uint64
	// subCRCs is the CRC-32 of each substream, when recorded.
	subCRCs []*uint32
	// firstPackStream is the global index of this folder's first packed
	// stream.
	firstPackStream int
	// packedCount is the number of packed streams the folder consumes.
	packedCount int
	// packedInputs is the input stream index fed by each packed stream, in
	// packed order.
	packedInputs []int
}

// chain returns the coder path in the order the decoders run.
//
// Stream numbering gives coder i input i and output i whenever every coder has
// one input and one output, so a bind pair names the coders it joins directly.
// ok is false when the folder is not a single such path: more than one packed
// stream, a multi-stream coder (BCJ2), bind pairs that branch or cycle, or a
// coder whose output nothing consumes.
func (f *folder) chain() ([]int, bool) {
	count := len(f.coders)
	if count == 0 || f.packedCount != 1 {
		return nil, false
	}
	for index := range f.coders {
		if f.coders[index].numIn != 1 || f.coders[index].numOut != 1 {
			return nil, false
		}
	}
	if len(f.bindPairs)+1 != count {
		return nil, false
	}
	next := make([]int, count)
	for index := range next {
		next[index] = -1
	}
	hasInput := make([]bool, count)
	usedInput := make([]bool, count)
	usedOutput := make([]bool, count)
	for _, pair := range f.bindPairs {
		if pair.input >= uint64(count) || pair.output >= uint64(count) ||
			usedInput[pair.input] || usedOutput[pair.output] {
			return nil, false
		}
		usedInput[pair.input] = true
		usedOutput[pair.output] = true
		hasInput[pair.input] = true
		next[pair.output] = int(pair.input)
	}
	start := -1
	for index := 0; index < count; index++ {
		if !hasInput[index] {
			start = index
			break
		}
	}
	if start < 0 {
		return nil, false
	}
	order := make([]int, 0, count)
	current := start
	for current >= 0 {
		order = append(order, current)
		current = next[current]
	}
	// A cycle or a disconnected remainder would not reach every coder.
	if len(order) != count {
		return nil, false
	}
	return order, true
}

// unpackSize returns the size of the folder's output: the one output stream no
// bind pair sends on to another coder.  Coder order does not decide this -- an
// AES coder can be written before or after the compressor it wraps.
func (f *folder) unpackSize() uint64 {
	for index := 0; index < int(f.totalOut); index++ {
		bound := false
		for _, pair := range f.bindPairs {
			if pair.output == uint64(index) {
				bound = true
				break
			}
		}
		if bound {
			continue
		}
		if index < len(f.unpackSizes) {
			return f.unpackSizes[index]
		}
		break
	}
	if len(f.unpackSizes) > 0 {
		return f.unpackSizes[len(f.unpackSizes)-1]
	}
	return 0
}

// encryption returns the coder that would decrypt this folder, if any.
func (f *folder) encryption() *coder {
	for index := range f.coders {
		if f.coders[index].is(idAES) {
			return &f.coders[index]
		}
	}
	return nil
}

// packInfo is the packed-stream table.
type packInfo struct {
	// packPos is the offset of the packed streams relative to the end of the
	// signature header.
	packPos uint64
	sizes   []uint64
}

// streamsInfo is a folder table plus its packed streams -- the shape both the
// main header and an encoded header use.
type streamsInfo struct {
	pack    packInfo
	folders []folder
}

// packedRange is the absolute file offset and length of one packed stream.
type packedRange struct {
	offset uint64
	size   uint64
}

// packedRanges returns the absolute offset and length of every packed stream,
// in order.
func (s *streamsInfo) packedRanges() []packedRange {
	ranges := make([]packedRange, 0, len(s.pack.sizes))
	offset := uint64(signatureHeaderLen) + s.pack.packPos
	for _, size := range s.pack.sizes {
		ranges = append(ranges, packedRange{offset: offset, size: size})
		offset += size
	}
	return ranges
}

// rawFile is one file as the header describes it, before path normalization.
type rawFile struct {
	name string
	// folder and sub name the folder/substream pair for a file with data.
	hasStream bool
	folder    int
	sub       int
	isDir     bool
	anti      bool
	size      uint64
	crc       *uint32
	modified  *int64
}

// nextHeader is either the full property tree or a streams table that
// describes a compressed header the caller must decode first.
type nextHeader struct {
	plain   *parsedHeader
	encoded *streamsInfo
}

// parsedHeader is the parsed main header.
type parsedHeader struct {
	streams streamsInfo
	files   []rawFile
}

// parseNextHeader parses the bytes the signature header points at.
func parseNextHeader(data []byte) (nextHeader, error) {
	reader := newHeaderReader(data, "7z next header")
	number, err := reader.number()
	if err != nil {
		return nextHeader{}, err
	}
	switch number {
	case kEncodedHeader:
		streams, err := parseStreamsInfo(reader)
		if err != nil {
			return nextHeader{}, err
		}
		return nextHeader{encoded: streams}, nil
	case kHeader:
		header, err := parseHeaderBody(reader)
		if err != nil {
			return nextHeader{}, err
		}
		return nextHeader{plain: header}, nil
	default:
		return nextHeader{}, archive.Invalidf(
			"7z next header starts with property %#x, not a header", number)
	}
}

// parsePlainHeader parses a decoded (plain) header.  An encoded header is not
// accepted.
func parsePlainHeader(data []byte) (*parsedHeader, error) {
	reader := newHeaderReader(data, "7z decoded header")
	number, err := reader.number()
	if err != nil {
		return nil, err
	}
	if number != kHeader {
		return nil, archive.Invalidf(
			"7z decoded header does not start with a header property")
	}
	return parseHeaderBody(reader)
}

func parseHeaderBody(reader *headerReader) (*parsedHeader, error) {
	header := &parsedHeader{}
	seenStreams := false
	seenFiles := false
	for {
		id, err := reader.number()
		if err != nil {
			return nil, err
		}
		switch id {
		case kEnd:
			if !streamsHasPacked(&header.streams) && !filesHaveStreams(header.files) {
				return header, nil
			}
			if err := resolveStreamSizes(header); err != nil {
				return nil, err
			}
			return header, nil
		case kArchiveProperties:
			if err := skipProperties(reader); err != nil {
				return nil, err
			}
		case kAdditionalStreamsInfo:
			// Additional streams carry recovery data; they are parsed for
			// structure so the tree stays in sync, then dropped.
			if _, err := parseStreamsInfo(reader); err != nil {
				return nil, err
			}
		case kMainStreamsInfo:
			if seenStreams {
				return nil, archive.Invalidf("7z header repeats the main streams info")
			}
			seenStreams = true
			streams, err := parseStreamsInfo(reader)
			if err != nil {
				return nil, err
			}
			header.streams = *streams
		case kFilesInfo:
			if seenFiles {
				return nil, archive.Invalidf("7z header repeats the files info")
			}
			seenFiles = true
			files, err := parseFilesInfo(reader, &header.streams)
			if err != nil {
				return nil, err
			}
			header.files = files
		default:
			return nil, archive.Invalidf("7z header has an unknown property %#x", id)
		}
	}
}

func streamsHasPacked(streams *streamsInfo) bool {
	return len(streams.pack.sizes) > 0
}

func filesHaveStreams(files []rawFile) bool {
	for index := range files {
		if files[index].hasStream && !files[index].anti {
			return true
		}
	}
	return false
}

// resolveStreamSizes fills in substream sizes/CRC defaults and checks folder
// arithmetic.  It is called once after the files exist, so every file's stream
// reference can be checked against the substream it names.
func resolveStreamSizes(header *parsedHeader) error {
	folders := header.streams.folders
	nextPack := 0
	for index := range folders {
		target := &folders[index]
		target.firstPackStream = nextPack
		nextPack += target.packedCount
		var total uint64
		for _, size := range target.subSizes {
			if size > math.MaxUint64-total {
				return archive.Invalidf("7z folder substream sizes overflow")
			}
			total += size
		}
		if target.numSubstreams == 0 && len(target.subSizes) > 0 {
			return archive.Invalidf(
				"7z folder declares substream sizes but no substreams")
		}
		if target.numSubstreams > 0 && total != target.unpackSize() {
			return archive.Invalidf(
				"7z folder substreams add up to %d bytes but the folder unpacks to %d",
				total, target.unpackSize())
		}
		if uint64(len(target.subCRCs)) != target.numSubstreams {
			target.subCRCs = resizeCRCs(target.subCRCs, int(target.numSubstreams))
		}
	}
	if nextPack != len(header.streams.pack.sizes) {
		return archive.Invalidf(
			"7z header has %d packed streams but its folders use %d",
			len(header.streams.pack.sizes), nextPack)
	}
	var streams uint64
	for index := range folders {
		streams += folders[index].numSubstreams
	}
	for index := range header.files {
		file := &header.files[index]
		if !file.hasStream {
			continue
		}
		if file.folder < 0 || file.folder >= len(folders) {
			return archive.Invalidf(
				"7z file %s names folder %d", file.name, file.folder)
		}
		target := &folders[file.folder]
		if uint64(file.sub) >= target.numSubstreams {
			return archive.Invalidf(
				"7z file %s names substream %d of a folder with %d",
				file.name, file.sub, target.numSubstreams)
		}
	}
	used := 0
	for index := range header.files {
		if header.files[index].hasStream {
			used++
		}
	}
	if used > int(streams) && streams > 0 {
		return archive.Invalidf(
			"7z header has %d files with data but only %d substreams", used, streams)
	}
	return nil
}

func resizeCRCs(values []*uint32, count int) []*uint32 {
	if len(values) >= count {
		return values[:count]
	}
	out := make([]*uint32, count)
	copy(out, values)
	return out
}

func parseStreamsInfo(reader *headerReader) (*streamsInfo, error) {
	info := &streamsInfo{}
	for {
		id, err := reader.number()
		if err != nil {
			return nil, err
		}
		switch id {
		case kEnd:
			for index := range info.folders {
				if uint64(len(info.folders[index].unpackSizes)) != info.folders[index].totalOut {
					return nil, archive.Invalidf(
						"7z folder does not declare an unpack size for every coder output")
				}
			}
			return info, nil
		case kPackInfo:
			pack, err := parsePackInfo(reader)
			if err != nil {
				return nil, err
			}
			info.pack = *pack
		case kUnpackInfo:
			if err := parseUnpackInfo(reader, &info.folders); err != nil {
				return nil, err
			}
		case kSubstreamsInfo:
			if len(info.folders) == 0 {
				return nil, archive.Invalidf("7z substreams info precedes any folder")
			}
			if err := parseSubstreamsInfo(reader, info.folders); err != nil {
				return nil, err
			}
		default:
			return nil, archive.Invalidf("7z streams info has an unknown property %#x", id)
		}
	}
}

func parsePackInfo(reader *headerReader) (*packInfo, error) {
	packPos, err := reader.number()
	if err != nil {
		return nil, err
	}
	count, err := reader.number()
	if err != nil {
		return nil, err
	}
	if count > maxItems {
		return nil, archive.Limitf("7z declares %d packed streams", count)
	}
	var sizes []uint64
	for {
		id, err := reader.number()
		if err != nil {
			return nil, err
		}
		switch id {
		case kEnd:
			if uint64(len(sizes)) != count {
				return nil, archive.Invalidf(
					"7z pack info does not declare a size for every stream")
			}
			return &packInfo{packPos: packPos, sizes: sizes}, nil
		case kSize:
			sizes = make([]uint64, 0, count)
			for index := uint64(0); index < count; index++ {
				size, err := reader.number()
				if err != nil {
					return nil, err
				}
				sizes = append(sizes, size)
			}
		case kCRC:
			// Packed-stream digests are not used: every folder and substream
			// CRC is checked against the decoded bytes instead.
			if _, err := parseDigests(reader, count); err != nil {
				return nil, err
			}
		default:
			return nil, archive.Invalidf("7z pack info has an unknown property %#x", id)
		}
	}
}

func parseUnpackInfo(reader *headerReader, folders *[]folder) error {
	id, err := reader.number()
	if err != nil {
		return err
	}
	if id != kFolder {
		return archive.Invalidf("7z unpack info does not start with a folder table")
	}
	count, err := reader.number()
	if err != nil {
		return err
	}
	if count > maxItems {
		return archive.Limitf("7z declares %d folders", count)
	}
	external, err := reader.byte()
	if err != nil {
		return err
	}
	if external != 0 {
		return archive.Unsupportedf("7z folder data stored in an additional stream")
	}
	*folders = make([]folder, 0, count)
	for index := uint64(0); index < count; index++ {
		parsed, err := parseFolder(reader)
		if err != nil {
			return err
		}
		*folders = append(*folders, *parsed)
	}
	for {
		id, err := reader.number()
		if err != nil {
			return err
		}
		switch id {
		case kEnd:
			return nil
		case kCodersUnpackSize:
			for index := range *folders {
				target := &(*folders)[index]
				target.unpackSizes = make([]uint64, 0, target.totalOut)
				for out := uint64(0); out < target.totalOut; out++ {
					size, err := reader.number()
					if err != nil {
						return err
					}
					target.unpackSizes = append(target.unpackSizes, size)
				}
			}
		case kCRC:
			digests, err := parseDigests(reader, count)
			if err != nil {
				return err
			}
			for index := range *folders {
				if index < len(digests) {
					(*folders)[index].crc = digests[index]
				}
			}
		default:
			return archive.Invalidf("7z unpack info has an unknown property %#x", id)
		}
	}
}

func parseFolder(reader *headerReader) (*folder, error) {
	numCoders, err := reader.number()
	if err != nil {
		return nil, err
	}
	if numCoders == 0 || numCoders > maxCoders {
		return nil, archive.Invalidf("7z folder declares %d coders", numCoders)
	}
	result := &folder{}
	result.totalIn = 0
	result.totalOut = 0
	for index := uint64(0); index < numCoders; index++ {
		flags, err := reader.byte()
		if err != nil {
			return nil, err
		}
		idSize := flags & 0x0F
		if idSize == 0 || idSize > 15 {
			return nil, archive.Invalidf("7z coder id is %d bytes", idSize)
		}
		idBytes, err := reader.bytes(int(idSize))
		if err != nil {
			return nil, err
		}
		numIn, numOut := uint64(1), uint64(1)
		if flags&0x10 != 0 {
			if numIn, err = reader.number(); err != nil {
				return nil, err
			}
			if numOut, err = reader.number(); err != nil {
				return nil, err
			}
		}
		if numIn == 0 || numOut == 0 {
			return nil, archive.Invalidf("7z coder has no input or no output stream")
		}
		if numIn > maxItems || numOut > maxItems {
			return nil, archive.Limitf(
				"7z coder declares %d input and %d output streams", numIn, numOut)
		}
		var props []byte
		if flags&0x20 != 0 {
			size, err := reader.number()
			if err != nil {
				return nil, err
			}
			if size > 64 {
				return nil, archive.Limitf("7z coder properties are %d bytes", size)
			}
			props, err = reader.bytes(int(size))
			if err != nil {
				return nil, err
			}
		}
		if flags&0x80 != 0 {
			return nil, archive.Unsupportedf("7z folder with alternative coder methods")
		}
		result.totalIn += numIn
		result.totalOut += numOut
		if result.totalIn > maxItems || result.totalOut > maxItems {
			return nil, archive.Limitf(
				"7z folder declares %d input and %d output streams",
				result.totalIn, result.totalOut)
		}
		result.coders = append(result.coders, coder{
			id: append([]byte(nil), idBytes...), props: append([]byte(nil), props...),
			numIn: numIn, numOut: numOut,
		})
	}
	if result.totalOut == 0 || result.totalOut > result.totalIn {
		return nil, archive.Invalidf("7z folder has more bind pairs than input streams")
	}
	bindCount := int(result.totalOut - 1)
	result.bindPairs = make([]bindPair, 0, bindCount)
	for index := 0; index < bindCount; index++ {
		input, err := reader.number()
		if err != nil {
			return nil, err
		}
		output, err := reader.number()
		if err != nil {
			return nil, err
		}
		if input >= result.totalIn || output >= result.totalOut {
			return nil, archive.Invalidf(
				"7z bind pair (%d, %d) is outside %d in / %d out streams",
				input, output, result.totalIn, result.totalOut)
		}
		result.bindPairs = append(result.bindPairs, bindPair{input: input, output: output})
	}
	packedCount := int(result.totalIn) - bindCount
	if packedCount == 0 {
		return nil, archive.Invalidf("7z folder has no packed stream")
	}
	result.packedCount = packedCount
	result.packedInputs = make([]int, 0, packedCount)
	if packedCount > 1 {
		for index := 0; index < packedCount; index++ {
			value, err := reader.number()
			if err != nil {
				return nil, err
			}
			if value >= result.totalIn {
				return nil, archive.Invalidf(
					"7z packed stream index %d is outside %d input streams",
					value, result.totalIn)
			}
			if len(result.packedInputs) > 0 &&
				value <= uint64(result.packedInputs[len(result.packedInputs)-1]) {
				return nil, archive.Invalidf("7z packed stream indices are not increasing")
			}
			result.packedInputs = append(result.packedInputs, int(value))
		}
	} else {
		// One packed stream: it feeds the only input no bind pair names.
		found := -1
		for input := 0; input < int(result.totalIn); input++ {
			bound := false
			for _, pair := range result.bindPairs {
				if pair.input == uint64(input) {
					bound = true
					break
				}
			}
			if !bound {
				found = input
				break
			}
		}
		if found < 0 {
			return nil, archive.Invalidf("7z folder leaves no input for its packed stream")
		}
		result.packedInputs = append(result.packedInputs, found)
	}
	result.numSubstreams = 1
	return result, nil
}

func parseSubstreamsInfo(reader *headerReader, folders []folder) error {
	counts := make([]uint64, len(folders))
	for index := range counts {
		counts[index] = 1
	}
	var sizes [][]uint64
	for {
		id, err := reader.number()
		if err != nil {
			return err
		}
		switch id {
		case kEnd:
			goto finish
		case kNumUnpackStream:
			var total uint64
			for index := range counts {
				value, err := reader.number()
				if err != nil {
					return err
				}
				if value > maxItems {
					return archive.Limitf("7z folder declares %d substreams", value)
				}
				total += value
				if total > maxItems {
					return archive.Limitf(
						"7z folders declare more than %d substreams", maxItems)
				}
				counts[index] = value
			}
		case kSize:
			table := make([][]uint64, 0, len(folders))
			for _, count := range counts {
				sub := make([]uint64, 0, count)
				for index := uint64(0); index+1 < count; index++ {
					value, err := reader.number()
					if err != nil {
						return err
					}
					sub = append(sub, value)
				}
				table = append(table, sub)
			}
			sizes = table
		case kCRC:
			// A single-substream folder whose folder CRC is defined uses that
			// CRC directly; every other substream has its own entry.
			type target struct {
				folder int
				sub    int
			}
			var needed []target
			for index, count := range counts {
				if count == 1 && folders[index].crc != nil {
					continue
				}
				for sub := uint64(0); sub < count; sub++ {
					needed = append(needed, target{folder: index, sub: int(sub)})
				}
			}
			digests, err := parseDigests(reader, uint64(len(needed)))
			if err != nil {
				return err
			}
			for index, item := range needed {
				if index >= len(digests) {
					break
				}
				target := &folders[item.folder]
				if len(target.subCRCs) <= item.sub {
					grown := make([]*uint32, item.sub+1)
					copy(grown, target.subCRCs)
					target.subCRCs = grown
				}
				target.subCRCs[item.sub] = digests[index]
			}
		default:
			return archive.Invalidf("7z substreams info has an unknown property %#x", id)
		}
	}

finish:
	for index := range folders {
		target := &folders[index]
		target.numSubstreams = counts[index]
		if counts[index] == 0 {
			target.subSizes = nil
			target.subCRCs = nil
			continue
		}
		total := target.unpackSize()
		var partial []uint64
		if sizes != nil && index < len(sizes) {
			partial = sizes[index]
		}
		switch {
		case counts[index] == 1:
			target.subSizes = []uint64{total}
		case partial != nil:
			var used uint64
			for _, value := range partial {
				if value > math.MaxUint64-used {
					return archive.Invalidf("7z folder %d substream sizes overflow", index)
				}
				used += value
			}
			if used > total {
				return archive.Invalidf(
					"7z folder %d substream sizes add up to %d, past its %d bytes",
					index, used, total)
			}
			sub := make([]uint64, 0, len(partial)+1)
			sub = append(sub, partial...)
			sub = append(sub, total-used)
			target.subSizes = sub
		default:
			return archive.Invalidf(
				"7z folder %d has %d substreams but no sizes", index, counts[index])
		}
		if uint64(len(target.subCRCs)) != target.numSubstreams {
			target.subCRCs = resizeCRCs(target.subCRCs, int(target.numSubstreams))
			if target.numSubstreams == 1 && target.crc != nil {
				target.subCRCs[0] = target.crc
			}
		}
	}
	return nil
}

// parseDefinedValues reads a defined-value vector followed by its values.
//
// Every property of this shape starts with an AllAreDefined byte; when it is
// zero, a bit vector of count bits follows, and values are stored only for the
// defined positions.  The byte after the vector says whether the values live
// in an additional stream; this reader refuses that form.
func parseDefinedValues(reader *headerReader, count uint64, size int, context string, leastSignificantFirst bool) ([]*uint64, error) {
	all, err := reader.byte()
	if err != nil {
		return nil, err
	}
	var defined []bool
	if all != 0 {
		defined = make([]bool, count)
		for index := range defined {
			defined[index] = true
		}
	} else {
		defined, err = reader.bitsOrder(count, leastSignificantFirst)
		if err != nil {
			return nil, err
		}
	}
	external, err := reader.byte()
	if err != nil {
		return nil, err
	}
	if external != 0 {
		return nil, archive.Unsupportedf("7z %s stored in an additional stream", context)
	}
	values := make([]*uint64, count)
	for index, present := range defined {
		if !present {
			continue
		}
		var value uint64
		switch size {
		case 1:
			byteValue, err := reader.byte()
			if err != nil {
				return nil, err
			}
			value = uint64(byteValue)
		case 4:
			u32, err := reader.u32()
			if err != nil {
				return nil, err
			}
			value = uint64(u32)
		case 8:
			u64, err := reader.u64()
			if err != nil {
				return nil, err
			}
			value = u64
		default:
			return nil, archive.Invalidf("7z defined-value width %d", size)
		}
		stored := value
		values[index] = &stored
	}
	return values, nil
}

func parseDigests(reader *headerReader, count uint64) ([]*uint32, error) {
	all, err := reader.byte()
	if err != nil {
		return nil, err
	}
	var defined []bool
	if all != 0 {
		defined = make([]bool, count)
		for index := range defined {
			defined[index] = true
		}
	} else {
		defined, err = reader.bits(count)
		if err != nil {
			return nil, err
		}
	}
	digests := make([]*uint32, count)
	for index, present := range defined {
		if !present {
			continue
		}
		value, err := reader.u32()
		if err != nil {
			return nil, err
		}
		stored := value
		digests[index] = &stored
	}
	return digests, nil
}

func parseFilesInfo(reader *headerReader, streams *streamsInfo) ([]rawFile, error) {
	count, err := reader.number()
	if err != nil {
		return nil, err
	}
	if count > maxItems {
		return nil, archive.Limitf("7z header declares %d files", count)
	}
	countInt := int(count)

	emptyStream := make([]bool, countInt)
	var emptyFile []bool
	var anti []bool
	var names []string
	mtimes := make([]*int64, countInt)

	// Every substream belongs to exactly one non-empty file, so the number of
	// files without an empty-stream bit must equal the folder table's total.
	// That equality also tells us which bit order the header used: 7-Zip's
	// order is most-significant first, but the reference fixture corpus packs
	// vectors least-significant first.  The wrong order both misclassifies
	// directories and makes an empty file look like it owns a substream, so
	// choose the order consistent with the substream count; 7-Zip's order wins
	// when both or neither fit.
	var totalSubstreams uint64
	if streams != nil {
		for index := range streams.folders {
			totalSubstreams += streams.folders[index].numSubstreams
		}
	}
	leastSignificantFirst := false

	for {
		id, err := reader.number()
		if err != nil {
			return nil, err
		}
		if id == kEnd {
			break
		}
		size, err := reader.number()
		if err != nil {
			return nil, err
		}
		body, err := reader.bytes(int(size))
		if err != nil {
			return nil, err
		}
		property := newHeaderReader(body, "7z file property")
		switch id {
		case kEmptyStream:
			emptyStream, err = property.bits(count)
			if err != nil {
				return nil, err
			}
			if totalSubstreams > 0 {
				alternative, altErr := newHeaderReader(body, "7z file property").bitsOrder(count, true)
				if altErr == nil {
					specFiles := count - countTrue(emptyStream)
					alternativeFiles := count - countTrue(alternative)
					if specFiles != totalSubstreams && alternativeFiles == totalSubstreams {
						emptyStream = alternative
						leastSignificantFirst = true
					}
				}
			}
		case kEmptyFile:
			emptyCount := countTrue(emptyStream)
			emptyFile, err = property.bitsOrder(emptyCount, leastSignificantFirst)
			if err != nil {
				return nil, err
			}
		case kAnti:
			emptyCount := countTrue(emptyStream)
			anti, err = property.bitsOrder(emptyCount, leastSignificantFirst)
			if err != nil {
				return nil, err
			}
		case kName:
			external, err := property.byte()
			if err != nil {
				return nil, err
			}
			if external != 0 {
				return nil, archive.Unsupportedf(
					"7z file names stored in an additional stream")
			}
			names, err = property.names(count)
			if err != nil {
				return nil, err
			}
		case kMTime, kCTime, kATime:
			values, err := parseDefinedValues(property, count, 8, "file times", leastSignificantFirst)
			if err != nil {
				return nil, err
			}
			if id == kMTime {
				for index, value := range values {
					if value == nil {
						mtimes[index] = nil
						continue
					}
					mtimes[index] = filetimeToUnix(*value)
				}
			}
		case kWinAttrib:
			// Parsed for structure only: the archive model records the entry
			// kind, not the raw attribute word.
			if _, err := parseDefinedValues(property, count, 4, "file attributes", leastSignificantFirst); err != nil {
				return nil, err
			}
		case kStartPos:
			if _, err := parseDefinedValues(property, count, 8, "file start positions", leastSignificantFirst); err != nil {
				return nil, err
			}
		}
	}

	if names == nil {
		return nil, archive.Invalidf("7z files info has no name table")
	}
	if len(names) != countInt {
		return nil, archive.Invalidf(
			"7z name table holds %d names for %d files", len(names), countInt)
	}

	emptyIndices := make([]int, 0, countInt)
	for index, empty := range emptyStream {
		if empty {
			emptyIndices = append(emptyIndices, index)
		}
	}
	emptyFileFlags := emptyFile
	if emptyFileFlags == nil {
		emptyFileFlags = make([]bool, len(emptyIndices))
	}
	antiFlags := anti
	if antiFlags == nil {
		antiFlags = make([]bool, len(emptyIndices))
	}
	if len(emptyFileFlags) != len(emptyIndices) || len(antiFlags) != len(emptyIndices) {
		return nil, archive.Invalidf(
			"7z empty-file or anti-file vector does not match the empty streams")
	}

	// Substreams are consumed by non-empty files in file order, folder by
	// folder and substream by substream.
	type streamRef struct {
		folder int
		sub    int
	}
	var streamsInOrder []streamRef
	var totalStreams uint64
	for folderIndex, entry := range streams.folders {
		totalStreams += entry.numSubstreams
		if totalStreams > maxItems {
			return nil, archive.Limitf(
				"7z header declares more than %d substreams", maxItems)
		}
		for sub := 0; sub < int(entry.numSubstreams); sub++ {
			streamsInOrder = append(streamsInOrder, streamRef{folder: folderIndex, sub: sub})
		}
	}
	nextStream := 0

	files := make([]rawFile, 0, countInt)
	emptySeen := 0
	for index := 0; index < countInt; index++ {
		file := rawFile{name: names[index], modified: mtimes[index]}
		if emptyStream[index] {
			isAnti := antiFlags[emptySeen]
			isEmptyFile := emptyFileFlags[emptySeen]
			emptySeen++
			// An empty stream with the EmptyFile bit clear is a directory.
			file.isDir = !isEmptyFile && !isAnti
			file.anti = isAnti
		} else {
			if nextStream >= len(streamsInOrder) {
				return nil, archive.Invalidf(
					"7z file %s has data but the header has no more substreams",
					file.name)
			}
			ref := streamsInOrder[nextStream]
			nextStream++
			target := &streams.folders[ref.folder]
			file.hasStream = true
			file.folder = ref.folder
			file.sub = ref.sub
			if ref.sub < len(target.subSizes) {
				file.size = target.subSizes[ref.sub]
			}
			if ref.sub < len(target.subCRCs) {
				file.crc = target.subCRCs[ref.sub]
			}
		}
		files = append(files, file)
	}
	return files, nil
}

func countTrue(values []bool) uint64 {
	var count uint64
	for _, value := range values {
		if value {
			count++
		}
	}
	return count
}

// filetimeToUnix converts a Windows FILETIME (100 ns since 1601-01-01) to Unix
// seconds.  The division is floored, so a time before 1970 becomes a negative
// number of seconds rather than wrapping.
func filetimeToUnix(filetime uint64) *int64 {
	const epochDifference int64 = 11_644_473_600
	ticks := int64(filetime / 10_000_000)
	seconds := ticks - epochDifference
	// The reference computes in i128 and only fails when the result does not
	// fit i64; uint64/10^7 always fits, so only the subtraction can overflow,
	// and wrapping here mirrors the Rust cast for values near the boundary.
	return &seconds
}

// headerReader is a bounds-checked cursor over one header slice.
type headerReader struct {
	data    []byte
	pos     int
	context string
}

func newHeaderReader(data []byte, context string) *headerReader {
	return &headerReader{data: data, context: context}
}

func (r *headerReader) atEnd() bool { return r.pos == len(r.data) }

func (r *headerReader) truncated() error {
	return archive.Invalidf(
		"7z %s is truncated at byte %d of %d", r.context, r.pos, len(r.data))
}

func (r *headerReader) byte() (byte, error) {
	if r.pos >= len(r.data) {
		return 0, r.truncated()
	}
	value := r.data[r.pos]
	r.pos++
	return value, nil
}

func (r *headerReader) u32() (uint32, error) {
	data, err := r.bytes(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(data), nil
}

func (r *headerReader) u64() (uint64, error) {
	data, err := r.bytes(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(data), nil
}

func (r *headerReader) bytes(size int) ([]byte, error) {
	if size < 0 || r.pos > len(r.data)-size {
		return nil, r.truncated()
	}
	start := r.pos
	r.pos += size
	return r.data[start:r.pos], nil
}

// number reads one 7z variable-length number.
//
// The high bit of each byte of the first byte is a continuation flag; the first
// clear bit ends the prefix, and the low bits of the first byte become the
// highest part of the value.  After eight set bits the first byte is 0xFF and
// the following eight bytes are the value.
func (r *headerReader) number() (uint64, error) {
	first, err := r.byte()
	if err != nil {
		return 0, err
	}
	mask := byte(0x80)
	var value uint64
	for index := 0; index < 8; index++ {
		if first&mask == 0 {
			value |= uint64(first&(mask-1)) << (8 * uint(index))
			return value, nil
		}
		next, err := r.byte()
		if err != nil {
			return 0, err
		}
		value |= uint64(next) << (8 * uint(index))
		mask >>= 1
	}
	return value, nil
}

// bits reads count bits, most-significant bit of each byte first.
//
// 7-Zip packs a bit vector with the first item in the high bit of the first
// byte.  The Rust reference's helper reads these least-significant first, which
// is invisible for the all-defined vectors its fixtures contain but marks
// every empty directory as data on a real archive that stores one (the high
// bits of the EmptyStream byte are the directories).
func (r *headerReader) bits(count uint64) ([]bool, error) {
	return r.bitsOrder(count, false)
}

// bitsOrder reads count bits in either 7-Zip's order (most-significant bit of
// each byte first) or the least-significant-first order used by the reference
// fixture corpus.  Callers must decide the order from structural evidence
// before trusting the result; see parseFilesInfo.
func (r *headerReader) bitsOrder(count uint64, leastSignificantFirst bool) ([]bool, error) {
	if count > maxItems {
		return nil, archive.Limitf("7z bit vector declares %d bits", count)
	}
	byteCount := int((count + 7) / 8)
	data, err := r.bytes(byteCount)
	if err != nil {
		return nil, err
	}
	out := make([]bool, count)
	for index := uint64(0); index < count; index++ {
		mask := byte(0x80 >> (index % 8))
		if leastSignificantFirst {
			mask = byte(1 << (index % 8))
		}
		out[index] = data[index/8]&mask != 0
	}
	return out, nil
}

// names reads count NUL-terminated UTF-16LE names.
func (r *headerReader) names(count uint64) ([]string, error) {
	capacity := count
	if capacity > maxItems {
		capacity = maxItems
	}
	names := make([]string, 0, int(capacity))
	for index := uint64(0); index < count; index++ {
		units := make([]uint16, 0, 32)
		for {
			data, err := r.bytes(2)
			if err != nil {
				return nil, err
			}
			unit := binary.LittleEndian.Uint16(data)
			if unit == 0 {
				break
			}
			units = append(units, unit)
		}
		name, err := decodeUTF16(units)
		if err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	if !r.atEnd() {
		return nil, archive.Invalidf(
			"7z name table has %d unread byte(s)", len(r.data)-r.pos)
	}
	return names, nil
}

// decodeUTF16 converts UTF-16 units, rejecting unpaired surrogates exactly as
// the reference does.
func decodeUTF16(units []uint16) (string, error) {
	for index := 0; index < len(units); index++ {
		unit := units[index]
		if unit >= 0xD800 && unit <= 0xDBFF {
			if index+1 >= len(units) || units[index+1] < 0xDC00 || units[index+1] > 0xDFFF {
				return "", archive.Invalidf("7z file name holds an unpaired surrogate")
			}
			index++
			continue
		}
		if unit >= 0xDC00 && unit <= 0xDFFF {
			return "", archive.Invalidf("7z file name holds an unpaired surrogate")
		}
	}
	return string(utf16.Decode(units)), nil
}

// skipProperties skips the archive-properties list: (id, size, bytes)* End.
func skipProperties(reader *headerReader) error {
	for {
		id, err := reader.number()
		if err != nil {
			return err
		}
		if id == kEnd {
			return nil
		}
		size, err := reader.number()
		if err != nil {
			return err
		}
		if _, err := reader.bytes(int(size)); err != nil {
			return err
		}
	}
}
