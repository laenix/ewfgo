// Package sevenz reads 7-Zip archives.
//
// A 7z file is a 32-byte signature header pointing at a property tree.  The
// tree names packed streams, folders (coder chains), substreams, and files;
// the payloads sit between the signature header and the next header, in the
// folder order the tree declares.  When the header itself is compressed, the
// same streams machinery describes the compressed header and the decoded bytes
// hold the real tree.
//
// Supported coders: Copy, LZMA, LZMA2, Deflate, Bzip2, PPMd, Delta, the x86
// BCJ converter, the ARM/ARM-Thumb/ARM64/PowerPC/SPARC/IA-64/RISC-V branch
// converters, the Swap2/Swap4 byte swappers, chained by the folder's bind
// pairs (so a filter can sit on either side of the compressor), and the
// four-stream BCJ2 converter on top of any of them.  A folder is evaluated in
// whatever order its bind pairs allow: a coder runs as soon as every input is
// a packed stream or another coder's output, which covers both the single
// packed stream a compressor writes and the four streams BCJ2 splits a folder
// into.  Solid folders (several substreams in one folder) are decoded once and
// sliced.  Folder and substream CRC-32s are verified against the decoded
// bytes; a mismatch is reported on the entry but does not hide the bytes that
// were recovered.
//
// AES-256 folders and encoded headers are refused with source.ErrDecrypt:
// this port has no key provider, so ciphertext is never returned as content.
// Deflate64 and the Alpha branch converter are refused by name.  Multi-volume
// archives are not assembled here.
//
// Reader lists entries from the header alone; opening an entry decodes its
// folder on first read and caches the most recent folder, so a solid archive's
// members share one decode.
//
// This is a Go port of forensic-core's data/containers/sevenz.
package sevenz

import (
	"bytes"
	"compress/bzip2"
	"compress/flate"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/containers/lzma"
	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

// maxHeaderBytes bounds the bytes read for one header, compressed or plain.
//
// A header is metadata, not payload; an archive that points the reader at a
// multi-gigabyte "header" is treated as corrupt rather than decoded.
const maxHeaderBytes = 256 * 1024 * 1024

// ppmdMemoryLimit is the largest PPMd model this reader will allocate.  7-Zip
// allows up to 4 GiB; the default model is 16 MiB.  A header that asks for
// more than this is refused by name instead of being allocated.
const ppmdMemoryLimit = 1 << 30

// MatchesSignature reports whether head begins with the 7z signature.
func MatchesSignature(head []byte) bool {
	return len(head) >= len(signature) && bytes.Equal(head[:len(signature)], signature[:])
}

// Adapter registers 7z with the archive framework.
type Adapter struct{}

var (
	_ archive.Adapter = Adapter{}
	_ archive.Reader  = (*Reader)(nil)
)

// FormatID implements archive.Adapter.
func (Adapter) FormatID() string { return "7z" }

// Open parses an archive and applies the framework's resource budget to every
// member before exposing it.
func (a Adapter) Open(src source.ByteSource, limits archive.Limits) (archive.Reader, error) {
	return OpenAs(a.FormatID(), src, limits)
}

// Register adds the 7z adapter to registry.
func Register(registry *archive.Registry) error { return registry.Register(Adapter{}) }

// fileRecord is one listed file, plus where its bytes live.
type fileRecord struct {
	entry     archive.Entry
	hasStream bool
	folder    int
	sub       int
	anti      bool
}

// cachedFolder is one decoded folder plus the CRC verdict of each substream.
type cachedFolder struct {
	index   int
	bytes   []byte
	corrupt []bool
}

// volume holds the packed streams and folders shared by a reader and its entry
// sources.
type volume struct {
	source  source.ByteSource
	streams *streamsInfo
	packed  []packedRange
	limits  archive.Limits

	mu       sync.Mutex
	cached   *cachedFolder
	counters source.Counters
}

func (v *volume) folder(index int) (*folder, bool) {
	if index < 0 || index >= len(v.streams.folders) {
		return nil, false
	}
	return &v.streams.folders[index], true
}

// folderBytes decodes one folder (once) and checks every recorded CRC.
func (v *volume) folderBytes(index int) (*cachedFolder, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.cached != nil && v.cached.index == index {
		v.counters.AddCacheHit()
		return v.cached, nil
	}
	v.counters.AddCacheMiss()

	target, ok := v.folder(index)
	if !ok {
		return nil, source.NewCorrupt(0, fmt.Sprintf(
			"7z file names folder %d, which the header lacks", index))
	}
	// A wrong passphrase decrypts to noise indistinguishable from plaintext
	// except by its CRC.  This port has no key provider at all, so every
	// encrypted folder is refused before any bytes are handled.
	if target.encryption() != nil {
		return nil, decryptError(0,
			"7z folder is encrypted with AES-256 and this reader has no key provider")
	}
	if target.unpackSize() > v.limits.MaxTotalExpanded {
		return nil, source.NewCorrupt(0, fmt.Sprintf(
			"7z folder unpacks to %d bytes, past the configured %d-byte budget",
			target.unpackSize(), v.limits.MaxTotalExpanded))
	}

	decoded, err := v.decode(target)
	if err != nil {
		return nil, err
	}
	unpack := target.unpackSize()

	corrupt := make([]bool, target.numSubstreams)
	whole := uint64(len(decoded)) != unpack
	if target.crc != nil && foundation.CRC32(decoded) != *target.crc {
		whole = true
	}
	start := 0
	for sub, size := range target.subSizes {
		end := start + int(minU64(size, uint64(math.MaxInt-start)))
		if sub < len(target.subCRCs) && target.subCRCs[sub] != nil {
			expected := *target.subCRCs[sub]
			if end > len(decoded) || uint64(end-start) != size ||
				foundation.CRC32(decoded[start:end]) != expected {
				if sub < len(corrupt) {
					corrupt[sub] = true
				}
			}
		}
		start = end
	}
	if whole {
		for index := range corrupt {
			corrupt[index] = true
		}
	}
	cached := &cachedFolder{index: index, bytes: decoded, corrupt: corrupt}
	v.cached = cached
	return cached, nil
}

func (v *volume) decode(target *folder) ([]byte, error) {
	if chain, ok := target.chain(); ok {
		return v.decodeChain(target, chain)
	}
	return v.decodeMulti(target)
}

func (v *volume) decodeChain(target *folder, chain []int) ([]byte, error) {
	if target.firstPackStream < 0 || target.firstPackStream >= len(v.packed) {
		return nil, source.NewCorrupt(0, "7z folder names a packed stream the archive does not hold")
	}
	packed := v.packed[target.firstPackStream]
	offset := packed.offset
	stored, err := source.ReadVecAt(v.source, packed.offset, packed.size)
	if err != nil {
		return nil, err
	}
	// Coders run in the order the bind pairs chain them: the packed stream
	// feeds the first, and each coder's output is the next one's input.
	for _, index := range chain {
		if index < 0 || index >= len(target.coders) {
			return nil, source.NewCorrupt(offset, "7z folder names a coder it does not hold")
		}
		coder := &target.coders[index]
		unpack := uint64(0)
		if index < len(target.unpackSizes) {
			unpack = target.unpackSizes[index]
		}
		stored, err = v.applyCoder(offset, coder, stored, unpack)
		if err != nil {
			return nil, err
		}
	}
	v.counters.AddDecompressed(uint64(len(stored)))
	expected := target.unpackSize()
	if uint64(len(stored)) != expected {
		return nil, source.NewCorrupt(offset, fmt.Sprintf(
			"7z folder decoded %d bytes but declares %d", len(stored), expected))
	}
	return stored, nil
}

// decodeMulti decodes a folder whose coders take more than one input stream --
// the BCJ2 converter, alone or behind a compressor.
//
// Coders run in whatever order the bind pairs allow: a coder starts as soon as
// every one of its inputs is either a packed stream or another coder's output.
// Every coder must produce exactly one output stream, and each output feeds
// exactly one input, so a pass that makes no progress means the bind pairs
// form a cycle.
func (v *volume) decodeMulti(target *folder) ([]byte, error) {
	if target.firstPackStream < 0 ||
		target.firstPackStream+target.packedCount > len(v.packed) {
		return nil, source.NewCorrupt(0, "7z folder names a packed stream the archive does not hold")
	}
	offset := v.packed[target.firstPackStream].offset

	inCount := int(target.totalIn)
	outCount := int(target.totalOut)
	inputBase := make([]int, len(target.coders))
	outputBase := make([]int, len(target.coders))
	inputs, outputs := 0, 0
	for index := range target.coders {
		coder := &target.coders[index]
		if coder.numOut != 1 {
			return nil, source.NewCorrupt(offset, fmt.Sprintf(
				"folder coder %s has %d output streams",
				coderLabel(coder.id), coder.numOut))
		}
		inputBase[index] = inputs
		inputs += int(coder.numIn)
		outputBase[index] = outputs
		outputs++
	}
	if inputs != inCount || outputs != outCount {
		return nil, source.NewCorrupt(offset, "7z folder stream counts disagree with its coders")
	}

	// Each input stream is fed by exactly one output or one packed stream, and
	// each output feeds at most one input.
	fedBy := make([]int, inCount)
	for index := range fedBy {
		fedBy[index] = -1
	}
	usedOutput := make([]bool, outCount)
	for _, pair := range target.bindPairs {
		if pair.input >= uint64(inCount) || pair.output >= uint64(outCount) ||
			fedBy[pair.input] >= 0 || usedOutput[pair.output] {
			return nil, source.NewCorrupt(offset, "7z bind pair names a stream that is already bound")
		}
		fedBy[pair.input] = int(pair.output)
		usedOutput[pair.output] = true
	}
	packed := make([][]byte, inCount)
	packedSet := make([]bool, inCount)
	if len(target.packedInputs) != target.packedCount {
		return nil, source.NewCorrupt(offset, "7z folder does not say where its packed streams go")
	}
	for index, input := range target.packedInputs {
		if input < 0 || input >= inCount || packedSet[input] {
			return nil, source.NewCorrupt(offset, "7z packed stream feeds an unknown input")
		}
		rng := v.packed[target.firstPackStream+index]
		data, err := source.ReadVecAt(v.source, rng.offset, rng.size)
		if err != nil {
			return nil, err
		}
		packed[input] = data
		packedSet[input] = true
	}

	produced := make([][]byte, outCount)
	producedSet := make([]bool, outCount)
	pending := make([]int, len(target.coders))
	for index := range pending {
		pending[index] = index
	}
	for len(pending) > 0 {
		progressed := false
		waiting := make([]int, 0, len(pending))
		for _, coderIndex := range pending {
			coder := &target.coders[coderIndex]
			start := inputBase[coderIndex]
			end := start + int(coder.numIn)
			ready := true
			for input := start; input < end; input++ {
				if packedSet[input] {
					continue
				}
				if fedBy[input] >= 0 && producedSet[fedBy[input]] {
					continue
				}
				ready = false
				break
			}
			if !ready {
				waiting = append(waiting, coderIndex)
				continue
			}
			coderInputs := make([][]byte, 0, end-start)
			for input := start; input < end; input++ {
				if packedSet[input] {
					coderInputs = append(coderInputs, packed[input])
					packed[input] = nil
					packedSet[input] = false
				} else {
					output := fedBy[input]
					coderInputs = append(coderInputs, produced[output])
					produced[output] = nil
					producedSet[output] = false
				}
			}
			unpack := uint64(0)
			if outputBase[coderIndex] < len(target.unpackSizes) {
				unpack = target.unpackSizes[outputBase[coderIndex]]
			}
			result, err := v.applyCoderInputs(offset, coder, coderInputs, unpack)
			if err != nil {
				return nil, err
			}
			produced[outputBase[coderIndex]] = result
			producedSet[outputBase[coderIndex]] = true
			progressed = true
		}
		if !progressed {
			return nil, source.NewCorrupt(offset, "7z folder bind pairs form a cycle")
		}
		pending = waiting
	}

	finalOutput := -1
	for output := 0; output < outCount; output++ {
		bound := false
		for _, pair := range target.bindPairs {
			if pair.output == uint64(output) {
				bound = true
				break
			}
		}
		if !bound {
			finalOutput = output
			break
		}
	}
	if finalOutput < 0 {
		return nil, source.NewCorrupt(offset, "7z folder has no unbound output stream")
	}
	decoded := produced[finalOutput]
	if decoded == nil {
		return nil, source.NewCorrupt(offset, "7z folder produced no output")
	}
	v.counters.AddDecompressed(uint64(len(decoded)))
	expected := target.unpackSize()
	if uint64(len(decoded)) != expected {
		return nil, source.NewCorrupt(offset, fmt.Sprintf(
			"7z folder decoded %d bytes but declares %d", len(decoded), expected))
	}
	return decoded, nil
}

// applyCoderInputs runs one coder over its decoded input streams.
func (v *volume) applyCoderInputs(offset uint64, target *coder, inputs [][]byte, unpack uint64) ([]byte, error) {
	if target.is(idBCJ2) {
		if target.numIn != 4 || len(target.props) != 0 {
			return nil, source.NewCorrupt(offset, fmt.Sprintf(
				"7z BCJ2 coder has %d inputs and %d property bytes",
				target.numIn, len(target.props)))
		}
		if len(inputs) != 4 {
			return nil, source.NewCorrupt(offset, "7z BCJ2 coder was given the wrong number of streams")
		}
		decoded, reason := decodeBCJ2(inputs[0], inputs[1], inputs[2], inputs[3])
		if reason != "" {
			return nil, source.NewCorrupt(offset, fmt.Sprintf("7z BCJ2 stream: %s", reason))
		}
		if uint64(len(decoded)) != unpack {
			return nil, source.NewCorrupt(offset, fmt.Sprintf(
				"7z BCJ2 streams hold %d bytes but the folder unpacks to %d",
				len(decoded), unpack))
		}
		return decoded, nil
	}
	if len(inputs) != 1 {
		return nil, unsupportedError(fmt.Sprintf(
			"%s coder with %d input streams", coderLabel(target.id), len(inputs)))
	}
	return v.applyCoder(offset, target, inputs[0], unpack)
}

// filterShape checks an in-place byte filter: no properties, and the stream it
// consumes is exactly as long as the stream it produces.
func filterShape(offset uint64, target *coder, stored []byte, unpack uint64, name string) error {
	if len(target.props) != 0 {
		return source.NewCorrupt(offset, fmt.Sprintf(
			"7z %s coder has %d property bytes", name, len(target.props)))
	}
	if uint64(len(stored)) != unpack {
		return source.NewCorrupt(offset, fmt.Sprintf(
			"7z %s stream holds %d bytes but the folder unpacks to %d",
			name, len(stored), unpack))
	}
	return nil
}

// applyCoder runs one non-AES coder over stored, bounding the output by
// unpack.
func (v *volume) applyCoder(offset uint64, target *coder, stored []byte, unpack uint64) ([]byte, error) {
	if unpack > uint64(maxInt()) {
		return nil, unsupportedError(fmt.Sprintf(
			"folder unpacking to %d bytes on this platform", unpack))
	}
	if unpack > v.limits.MaxTotalExpanded {
		return nil, source.NewCorrupt(offset, fmt.Sprintf(
			"7z coder output of %d bytes is past the configured %d-byte budget",
			unpack, v.limits.MaxTotalExpanded))
	}
	switch {
	case target.is(idCopy):
		if uint64(len(stored)) != unpack {
			return nil, source.NewCorrupt(offset, fmt.Sprintf(
				"7z Copy stream holds %d bytes but the folder unpacks to %d",
				len(stored), unpack))
		}
		return stored, nil
	case target.is(idLZMA):
		return decodeLZMAStream(offset, target.props, stored, unpack)
	case target.is(idLZMA2):
		if len(target.props) != 1 {
			return nil, source.NewCorrupt(offset, fmt.Sprintf(
				"7z LZMA2 coder has %d property bytes, not 1", len(target.props)))
		}
		return decodeLZMA2Folder(offset, target.props[0], stored, unpack, v.limits.MaxTotalExpanded)
	case target.is(idDeflate):
		return decodeFlate(offset, stored, unpack)
	case target.is(idBzip2):
		return decodeBzip2(offset, stored, unpack)
	case target.is(idPPMd):
		return decodePPMdFolder(offset, target.props, stored, unpack)
	case target.is(idDelta):
		if len(target.props) != 1 {
			return nil, source.NewCorrupt(offset, fmt.Sprintf(
				"7z Delta coder has %d property bytes, not 1", len(target.props)))
		}
		distance := int(target.props[0]) + 1
		if uint64(len(stored)) != unpack {
			return nil, source.NewCorrupt(offset, fmt.Sprintf(
				"7z Delta stream holds %d bytes but the folder unpacks to %d",
				len(stored), unpack))
		}
		deltaDecode(stored, distance)
		return stored, nil
	case target.is(idBCJX86):
		if err := filterShape(offset, target, stored, unpack, "BCJ"); err != nil {
			return nil, err
		}
		bcjX86(stored, 0, false)
		return stored, nil
	case target.is(idBCJPPC):
		if err := filterShape(offset, target, stored, unpack, "BCJ PPC"); err != nil {
			return nil, err
		}
		branchPPC(stored, 0)
		return stored, nil
	case target.is(idBCJIA64):
		if err := filterShape(offset, target, stored, unpack, "BCJ IA-64"); err != nil {
			return nil, err
		}
		branchIA64(stored, 0)
		return stored, nil
	case target.is(idBCJARM):
		if err := filterShape(offset, target, stored, unpack, "BCJ ARM"); err != nil {
			return nil, err
		}
		branchARM(stored, 0)
		return stored, nil
	case target.is(idBCJARMT):
		if err := filterShape(offset, target, stored, unpack, "BCJ ARM-Thumb"); err != nil {
			return nil, err
		}
		branchARMThumb(stored, 0)
		return stored, nil
	case target.is(idBCJSPARC):
		if err := filterShape(offset, target, stored, unpack, "BCJ SPARC"); err != nil {
			return nil, err
		}
		branchSPARC(stored, 0)
		return stored, nil
	case target.is(idBCJARM64):
		if err := filterShape(offset, target, stored, unpack, "BCJ ARM64"); err != nil {
			return nil, err
		}
		branchARM64(stored, 0)
		return stored, nil
	case target.is(idBCJRISCV):
		if err := filterShape(offset, target, stored, unpack, "BCJ RISC-V"); err != nil {
			return nil, err
		}
		branchRISCV(stored, 0)
		return stored, nil
	case target.is(idSwap2):
		if err := filterShape(offset, target, stored, unpack, "Swap2"); err != nil {
			return nil, err
		}
		swap2(stored)
		return stored, nil
	case target.is(idSwap4):
		if err := filterShape(offset, target, stored, unpack, "Swap4"); err != nil {
			return nil, err
		}
		swap4(stored)
		return stored, nil
	default:
		return nil, unsupportedError(fmt.Sprintf("%s coder", coderLabel(target.id)))
	}
}

// decodeLZMAStream decodes a 7z LZMA coder.
//
// 7-Zip normally writes no end marker when the unpacked size is known, but
// some encoders (and raw liblzma streams) leave the marker in place.  The
// decoder first tries the stream as an end-marked stream and falls back to the
// known-size form, accepting either only when it yields exactly the declared
// bytes.
func decodeLZMAStream(offset uint64, props, stored []byte, unpack uint64) ([]byte, error) {
	if len(props) != 5 {
		return nil, source.NewCorrupt(offset, fmt.Sprintf(
			"7z LZMA coder has %d property bytes, not 5", len(props)))
	}
	limits := lzma.Limits{
		MaxDecodedBytes:    maxU64(unpack, 1),
		MaxCompressedBytes: uint64(len(stored)) + 13,
	}

	unknown := make([]byte, 0, 13+len(stored))
	unknown = append(unknown, props...)
	for index := 0; index < 8; index++ {
		unknown = append(unknown, 0xFF)
	}
	unknown = append(unknown, stored...)
	decoded, err := lzma.Decode(unknown, limits)
	if err == nil && uint64(len(decoded)) == unpack {
		return decoded, nil
	}

	known := make([]byte, 0, 13+len(stored))
	known = append(known, props...)
	known = appendUint64LE(known, unpack)
	known = append(known, stored...)
	decoded, knownErr := lzma.Decode(known, limits)
	if knownErr != nil {
		if err != nil {
			return nil, source.NewCorrupt(offset, fmt.Sprintf(
				"7z LZMA stream: %v (also tried the known-size form: %v)", err, knownErr))
		}
		return nil, source.NewCorrupt(offset, fmt.Sprintf("7z LZMA stream: %v", knownErr))
	}
	if uint64(len(decoded)) != unpack {
		return nil, source.NewCorrupt(offset, fmt.Sprintf(
			"7z LZMA stream decoded %d bytes but the folder declares %d",
			len(decoded), unpack))
	}
	return decoded, nil
}

func decodeFlate(offset uint64, stored []byte, unpack uint64) ([]byte, error) {
	reader := flate.NewReader(bytes.NewReader(stored))
	defer reader.Close()
	decoded, err := readBounded(reader, unpack)
	if err != nil {
		return nil, source.NewCorrupt(offset, fmt.Sprintf("7z Deflate stream: %v", err))
	}
	return decoded, nil
}

func decodeBzip2(offset uint64, stored []byte, unpack uint64) ([]byte, error) {
	decoded, err := readBounded(bzip2.NewReader(bytes.NewReader(stored)), unpack)
	if err != nil {
		return nil, source.NewCorrupt(offset, fmt.Sprintf("7z Bzip2 stream: %v", err))
	}
	return decoded, nil
}

// readBounded reads at most unpack+1 bytes: enough to detect a lying header
// without letting a decompression bomb grow the buffer.
func readBounded(reader io.Reader, unpack uint64) ([]byte, error) {
	limit := unpack
	if limit < math.MaxUint64 {
		limit++
	}
	if limit > uint64(math.MaxInt64) {
		return nil, fmt.Errorf("declared size %d is too large to decode", unpack)
	}
	decoded, err := io.ReadAll(io.LimitReader(reader, int64(limit)))
	if err != nil {
		return nil, err
	}
	if uint64(len(decoded)) > unpack {
		return nil, fmt.Errorf("the stream decodes past the %d bytes the header declares", unpack)
	}
	if uint64(len(decoded)) != unpack {
		return nil, fmt.Errorf("the stream decoded %d bytes, not the %d the header declares",
			len(decoded), unpack)
	}
	return decoded, nil
}

// Reader is a read-only 7z archive.
type Reader struct {
	formatID string
	source   source.ByteSource
	volume   *volume
	entries  []archive.Entry
	files    []fileRecord
	byPath   map[string]int
	limits   archive.Limits
}

// Open opens a 7z archive.
func Open(src source.ByteSource, limits archive.Limits) (*Reader, error) {
	return OpenAs("7z", src, limits)
}

// OpenAs opens a 7z archive reporting formatID.
func OpenAs(formatID string, src source.ByteSource, limits archive.Limits) (*Reader, error) {
	header, err := readHeader(src, limits)
	if err != nil {
		return nil, err
	}
	vol := buildVolume(src, &header.streams, limits)
	if err := validatePackedRanges(vol); err != nil {
		return nil, err
	}
	entries, files, err := buildFiles(header.files, vol, limits)
	if err != nil {
		return nil, err
	}
	byPath := make(map[string]int, len(entries))
	for index := range entries {
		if _, exists := byPath[entries[index].Path]; !exists {
			byPath[entries[index].Path] = index
		}
	}
	return &Reader{
		formatID: formatID,
		source:   src,
		volume:   vol,
		entries:  entries,
		files:    files,
		byPath:   byPath,
		limits:   limits,
	}, nil
}

func readHeader(src source.ByteSource, limits archive.Limits) (*parsedHeader, error) {
	length := src.Len()
	if length < signatureHeaderLen {
		return nil, archive.Invalidf(
			"7z file is too short for its signature header: %d bytes", length)
	}
	head, err := source.ReadVecAt(src, 0, signatureHeaderLen)
	if err != nil {
		return nil, err
	}
	sig, err := parseSignature(head)
	if err != nil {
		return nil, err
	}
	if sig.nextSize > maxHeaderBytes {
		return nil, archive.Limitf("7z next header declares %d bytes", sig.nextSize)
	}
	offset := uint64(signatureHeaderLen) + sig.nextOffset
	if offset < uint64(signatureHeaderLen) {
		return nil, archive.Invalidf("7z next-header offset overflows")
	}
	end := offset + sig.nextSize
	if end < offset || end > length {
		return nil, archive.Invalidf(
			"7z next header [%d, +%d) is past the %d bytes the file holds",
			offset, sig.nextSize, length)
	}
	data, err := source.ReadVecAt(src, offset, sig.nextSize)
	if err != nil {
		return nil, err
	}
	if !verifyNextCRC(data, sig.nextCRC) {
		return nil, archive.Invalidf("7z next-header CRC does not match")
	}
	next, err := parseNextHeader(data)
	if err != nil {
		return nil, err
	}
	if next.plain != nil {
		return next.plain, nil
	}
	return decodeEncodedHeader(src, next.encoded, limits)
}

// decodeEncodedHeader decodes a compressed header through the same folder
// machinery as payloads.
func decodeEncodedHeader(src source.ByteSource, streams *streamsInfo, limits archive.Limits) (*parsedHeader, error) {
	if len(streams.folders) != 1 {
		return nil, archive.Unsupportedf(
			"7z encoded header with %d folders", len(streams.folders))
	}
	target := &streams.folders[0]
	if target.encryption() != nil {
		return nil, decryptError(0,
			"7z header is encrypted with AES-256 and this reader has no key provider")
	}
	if target.numSubstreams != 1 {
		return nil, archive.Unsupportedf(
			"7z encoded header with %d substreams", target.numSubstreams)
	}
	if target.unpackSize() > maxHeaderBytes {
		return nil, archive.Limitf(
			"7z encoded header unpacks to %d bytes", target.unpackSize())
	}
	if target.unpackSize() > limits.MaxTotalExpanded {
		return nil, archive.Limitf(
			"7z encoded header unpacks to %d bytes, past the configured archive budget",
			target.unpackSize())
	}
	vol := buildVolume(src, streams, limits)
	if err := validatePackedRanges(vol); err != nil {
		return nil, err
	}
	cached, err := vol.folderBytes(0)
	if err != nil {
		switch {
		case isKind(err, source.ErrDecrypt):
			return nil, err
		case isKind(err, source.ErrUnsupported):
			return nil, archive.Unsupportedf("%v", err)
		default:
			return nil, archive.Invalidf("7z encoded header: %v", err)
		}
	}
	if len(cached.corrupt) > 0 && cached.corrupt[0] {
		return nil, archive.Invalidf("7z encoded header fails its CRC-32 check")
	}
	return parsePlainHeader(cached.bytes)
}

func buildVolume(src source.ByteSource, streams *streamsInfo, limits archive.Limits) *volume {
	return &volume{
		source:  src,
		streams: streams,
		packed:  streams.packedRanges(),
		limits:  limits,
	}
}

func validatePackedRanges(vol *volume) error {
	length := vol.source.Len()
	for _, rng := range vol.packed {
		end := rng.offset + rng.size
		if end < rng.offset {
			return archive.Invalidf("7z packed stream range overflows")
		}
		if end > length {
			return archive.Invalidf(
				"7z packed stream [%d, +%d) is past the %d bytes the file holds",
				rng.offset, rng.size, length)
		}
	}
	return nil
}

// buildFiles turns raw header files into listed entries, applying the archive
// budget.
func buildFiles(raw []rawFile, vol *volume, limits archive.Limits) ([]archive.Entry, []fileRecord, error) {
	budget := archive.NewBudget(limits)
	entries := make([]archive.Entry, 0, len(raw))
	files := make([]fileRecord, 0, len(raw))
	for index := range raw {
		record := &raw[index]
		kind := archive.KindFile
		if record.isDir {
			kind = archive.KindDirectory
		} else if record.anti {
			kind = archive.KindOther
		}
		entry, err := archive.NewEntry(record.name, kind, record.size)
		if err != nil {
			return nil, nil, err
		}
		entry.Modified = record.modified
		entry.CRC32 = record.crc
		if record.hasStream {
			target, ok := vol.folder(record.folder)
			if !ok {
				return nil, nil, archive.Invalidf(
					"7z file %s names folder %d", record.name, record.folder)
			}
			entry.Encrypted = target.encryption() != nil
			if target.numSubstreams == 1 {
				start := target.firstPackStream
				end := start + target.packedCount
				if start >= 0 && end <= len(vol.packed) {
					var total uint64
					for _, rng := range vol.packed[start:end] {
						total += rng.size
					}
					stored := total
					entry.CompressedSize = &stored
				}
			}
		}
		if err := budget.Admit(entry); err != nil {
			return nil, nil, err
		}
		entries = append(entries, entry)
		files = append(files, fileRecord{
			entry:     entry,
			hasStream: record.hasStream,
			folder:    record.folder,
			sub:       record.sub,
			anti:      record.anti,
		})
	}
	return entries, files, nil
}

// FormatID implements archive.Reader.
func (r *Reader) FormatID() string { return r.formatID }

// Limits returns the limits used while listing.
func (r *Reader) Limits() archive.Limits { return r.limits }

// Stats returns the volume's decode counters.
func (r *Reader) Stats() source.Stats { return r.volume.counters.Snapshot() }

// Entries implements archive.Reader.
func (r *Reader) Entries() ([]archive.Entry, error) {
	return append([]archive.Entry(nil), r.entries...), nil
}

// FindEntry implements archive.Reader.
func (r *Reader) FindEntry(path string) (archive.Entry, bool, error) {
	index, ok := r.byPath[path]
	if !ok {
		return archive.Entry{}, false, nil
	}
	return r.entries[index], true, nil
}

// OpenEntry implements archive.Reader.
func (r *Reader) OpenEntry(path string, sourceID source.ID) (source.ByteSource, error) {
	entry, err := r.OpenEntrySource(path, sourceID)
	if err != nil {
		return nil, err
	}
	return entry, nil
}

// OpenEntrySource opens one entry with its concrete source type.
func (r *Reader) OpenEntrySource(path string, sourceID source.ID) (*EntrySource, error) {
	index, ok := r.byPath[path]
	if !ok {
		return nil, archive.Invalidf("7z has no entry named %s", path)
	}
	file := &r.files[index]
	if file.entry.IsDir() {
		return nil, archive.Invalidf("7z entry %s is a directory", file.entry.Path)
	}
	if file.anti {
		return nil, archive.Invalidf("7z entry %s is an anti-file record, not data", file.entry.Path)
	}
	if file.entry.Encrypted {
		return nil, decryptError(0, fmt.Sprintf(
			"7z entry %s is encrypted with AES-256 and this reader has no key provider",
			file.entry.Path))
	}
	if !file.hasStream {
		return &EntrySource{
			id:     sourceID,
			parent: r.source,
			entry:  file.entry,
			folder: -1,
			sub:    -1,
		}, nil
	}
	target, ok := r.volume.folder(file.folder)
	if !ok {
		return nil, archive.Invalidf("7z has no folder %d", file.folder)
	}
	// Refuse an entry whose folder needs a coder this port cannot run before
	// handing the caller a source.  Reading late would still refuse, but the
	// failure belongs to opening: no range of this entry can ever be served.
	if target.encryption() != nil {
		return nil, decryptError(0, fmt.Sprintf(
			"7z entry %s is encrypted with AES-256 and this reader has no key provider",
			file.entry.Path))
	}
	for index := range target.coders {
		if !coderSupported(target.coders[index].id) {
			return nil, unsupportedError(fmt.Sprintf(
				"%s coder", coderLabel(target.coders[index].id)))
		}
	}
	var offset uint64
	for sub := 0; sub < file.sub && sub < len(target.subSizes); sub++ {
		offset += target.subSizes[sub]
	}
	length := uint64(0)
	if file.sub < len(target.subSizes) {
		length = target.subSizes[file.sub]
	}
	return &EntrySource{
		id:     sourceID,
		parent: r.source,
		volume: r.volume,
		entry:  file.entry,
		folder: file.folder,
		sub:    file.sub,
		offset: offset,
		length: length,
	}, nil
}

func decryptError(offset uint64, reason string) error {
	return &source.Error{Kind: source.ErrDecrypt, Offset: offset, Reason: reason}
}

func unsupportedError(reason string) error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: reason}
}

func isKind(err error, kind error) bool {
	return err != nil && errors.Is(err, kind)
}

func appendUint64LE(dst []byte, value uint64) []byte {
	return append(dst,
		byte(value), byte(value>>8), byte(value>>16), byte(value>>24),
		byte(value>>32), byte(value>>40), byte(value>>48), byte(value>>56))
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func maxInt() int { return int(^uint(0) >> 1) }
