// PDF stream filters.
//
// A PDF stream stores bytes behind a chain of named filters. This module
// implements the general-purpose filters (Flate, LZW, ASCIIHex, ASCII85,
// RunLength) with the PNG and TIFF predictors the cross-reference stream
// depends on, and refuses image and encryption filters by name.
//
// Rules:
//
//   - decoding is bounded: a stream that expands past the caller's limit is a
//     refusal, not a partly decoded answer;
//   - a filter chain is applied in the order the dictionary lists it, and one
//     refused filter refuses the whole stream;
//   - a stream with no /Filter is not "already decoded": it is copied, and
//     that copy is still bounded.

package pdf

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"io"
)

// DefaultMaxDecodedBytes is the largest decoded stream the reader materialises
// by default (64 MiB).
const DefaultMaxDecodedBytes = 64 * 1024 * 1024

// DecodedStream is a decoded stream.
type DecodedStream struct {
	Bytes []byte
	// Filters lists the filter names applied, in order.
	Filters []string
	// Note records a tolerant decision, such as a Flate stream written without
	// its zlib wrapper.
	Note string
}

type filterSpec struct {
	name  []byte
	parms *Dict
}

func filterSpecs(dict *Dict) ([]filterSpec, error) {
	filter, ok := dict.Get([]byte("Filter"))
	if !ok {
		return nil, nil
	}
	var names []Value
	switch filter.Kind() {
	case KindName:
		names = []Value{filter}
	case KindArray:
		values, _ := filter.AsArray()
		names = values
	default:
		return nil, corrupt(0, "PDF /Filter is neither a name nor an array: %s", filter)
	}
	var parms []*Dict
	parmValue, hasParms := dict.Get([]byte("DecodeParms"))
	if !hasParms {
		parmValue, hasParms = dict.Get([]byte("DP"))
	}
	if hasParms {
		switch parmValue.Kind() {
		case KindNull:
		case KindDictionary:
			d, _ := parmValue.AsDict()
			parms = append(parms, d)
		case KindArray:
			values, _ := parmValue.AsArray()
			for _, value := range values {
				switch value.Kind() {
				case KindDictionary:
					d, _ := value.AsDict()
					parms = append(parms, d)
				case KindNull:
					parms = append(parms, nil)
				default:
					return nil, corrupt(0, "PDF /DecodeParms contains %s", value)
				}
			}
		default:
			return nil, corrupt(0, "PDF /DecodeParms is neither a dictionary nor an array: %s", parmValue)
		}
	}
	specs := make([]filterSpec, 0, len(names))
	for index, value := range names {
		name, ok := value.AsName()
		if !ok {
			return nil, corrupt(0, "PDF /Filter holds a non-name")
		}
		var specParms *Dict
		if index < len(parms) {
			specParms = parms[index]
		}
		specs = append(specs, filterSpec{name: append([]byte(nil), name...), parms: specParms})
	}
	if len(parms) > len(specs) {
		return nil, corrupt(0, "PDF /DecodeParms has %d entries for %d filters", len(parms), len(specs))
	}
	return specs, nil
}

// FilterNames returns the filter names a stream dictionary declares, without
// decoding.
func FilterNames(dict *Dict) ([]string, error) {
	specs, err := filterSpecs(dict)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(specs))
	for i, spec := range specs {
		names[i] = lossyUTF8(spec.name)
	}
	return names, nil
}

// DecodeStream decodes a stream whose dictionary carries /Filter and
// /DecodeParms. raw is the stored stream body, exactly /Length bytes (or the
// bytes the reader could find before endstream).
func DecodeStream(dict *Dict, raw []byte, limit int) (*DecodedStream, error) {
	specs, err := filterSpecs(dict)
	if err != nil {
		return nil, err
	}
	if len(specs) == 0 {
		if len(raw) > limit {
			return nil, limitError("PDF stream of %d bytes exceeds the %d byte decode limit", len(raw), limit)
		}
		return &DecodedStream{Bytes: append([]byte(nil), raw...)}, nil
	}
	bytesValue := append([]byte(nil), raw...)
	labels := make([]string, 0, len(specs))
	var notes []string
	for _, spec := range specs {
		label := lossyUTF8(spec.name)
		decoded, note, err := applyFilter(spec, bytesValue, limit)
		if err != nil {
			return nil, err
		}
		if note != "" {
			notes = append(notes, note)
		}
		bytesValue = decoded
		labels = append(labels, label)
	}
	out := &DecodedStream{Bytes: bytesValue, Filters: labels}
	if len(notes) > 0 {
		out.Note = joinNotes(notes)
	}
	return out, nil
}

func applyFilter(spec filterSpec, input []byte, limit int) ([]byte, string, error) {
	switch string(spec.name) {
	case "FlateDecode", "Fl":
		predictor, err := newPredictor(spec.parms)
		if err != nil {
			return nil, "", err
		}
		return decodeFlate(input, limit, predictor)
	case "LZWDecode", "LZW":
		early := true
		if spec.parms != nil {
			if value, ok := spec.parms.GetInt([]byte("EarlyChange")); ok {
				early = value != 0
			}
		}
		decoded, err := decodeLZW(input, early, limit)
		if err != nil {
			return nil, "", err
		}
		predictor, err := newPredictor(spec.parms)
		if err != nil {
			return nil, "", err
		}
		decoded, err = predictor.apply(decoded)
		if err != nil {
			return nil, "", err
		}
		return decoded, "", nil
	case "ASCIIHexDecode", "AHx":
		return decodeASCIIHex(input, limit)
	case "ASCII85Decode", "A85":
		return decodeASCII85(input, limit)
	case "RunLengthDecode", "RL":
		return decodeRunLength(input, limit)
	case "CCITTFaxDecode", "CCF", "DCTDecode", "DCT", "JBIG2Decode", "JPXDecode":
		return nil, "", unsupportedFilter(spec.name)
	case "Crypt":
		return nil, "", unsupported("PDF /Crypt stream filter: the document is encrypted")
	default:
		return nil, "", unsupportedFilter(spec.name)
	}
}

func unsupportedFilter(name []byte) error {
	return unsupported("PDF stream filter %s", lossyUTF8(name))
}

func checkLimit(length, limit int, filter string) error {
	if length > limit {
		return limitError("PDF %s output of %d bytes exceeds the %d byte decode limit", filter, length, limit)
	}
	return nil
}

// decodeFlate accepts either a zlib stream or a raw deflate stream. Several
// writers omit the two-byte zlib header; the raw form is accepted with a note.
func decodeFlate(input []byte, limit int, predictor predictorState) ([]byte, string, error) {
	zreader, err := zlib.NewReader(bytes.NewReader(input))
	if err == nil {
		decoded, readErr := readAllBounded(zreader, limit)
		closeErr := zreader.Close()
		if readErr == nil && closeErr == nil {
			if err := checkLimit(len(decoded), limit, "FlateDecode"); err != nil {
				return nil, "", err
			}
			decoded, err = predictor.apply(decoded)
			if err != nil {
				return nil, "", err
			}
			return decoded, "", nil
		}
		if readErr != nil {
			if isLimitError(readErr) {
				return nil, "", limitError("PDF FlateDecode output exceeds the %d byte decode limit", limit)
			}
			return nil, "", corrupt(0, "PDF FlateDecode stream could not be decoded: %v", readErr)
		}
		if closeErr != nil {
			return nil, "", corrupt(0, "PDF FlateDecode stream could not be decoded: %v", closeErr)
		}
	}
	reader := flate.NewReader(bytes.NewReader(input))
	decoded, readErr := readAllBounded(reader, limit)
	closeErr := reader.Close()
	if readErr != nil {
		if isLimitError(readErr) {
			return nil, "", limitError("PDF FlateDecode output exceeds the %d byte decode limit", limit)
		}
		return nil, "", corrupt(0, "PDF FlateDecode stream could not be decoded: %v", readErr)
	}
	if closeErr != nil {
		return nil, "", corrupt(0, "PDF FlateDecode stream could not be decoded: %v", closeErr)
	}
	if err := checkLimit(len(decoded), limit, "FlateDecode"); err != nil {
		return nil, "", err
	}
	decoded, err = predictor.apply(decoded)
	if err != nil {
		return nil, "", err
	}
	return decoded, "Flate stream carries no zlib header", nil
}

type limitReadError struct{}

func (limitReadError) Error() string { return "decode limit exceeded" }

func isLimitError(err error) bool {
	_, ok := err.(limitReadError)
	return ok
}

func readAllBounded(reader io.Reader, limit int) ([]byte, error) {
	if limit < 0 {
		limit = 0
	}
	out, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(out) > limit {
		return nil, limitReadError{}
	}
	return out, nil
}

// predictorKind is how a decoded stream is de-differenced before it is used.
type predictorKind uint8

const (
	predictorNone predictorKind = iota
	predictorTiff
	predictorPNG
)

type predictorState struct {
	kind    predictorKind
	colors  int
	bits    int
	columns int
}

func nonePredictor() predictorState {
	return predictorState{kind: predictorNone, colors: 1, bits: 8, columns: 1}
}

// pixelBytes is the bytes per pixel, at least one so a sub-byte image still
// advances.
func (p predictorState) pixelBytes() int {
	bits := p.colors * p.bits
	value := (bits + 7) / 8
	if value < 1 {
		return 1
	}
	return value
}

// rowBytes is the bytes in one row, excluding the PNG filter byte.
func (p predictorState) rowBytes() (int, error) {
	bits := p.colors * p.bits
	if p.colors != 0 && bits/p.colors != p.bits {
		return 0, limitError("PDF predictor row is too wide to represent")
	}
	if p.columns != 0 && bits > int(^uint(0)>>1)/p.columns {
		return 0, limitError("PDF predictor row is too wide to represent")
	}
	bits *= p.columns
	return (bits + 7) / 8, nil
}

func (p predictorState) apply(bytesValue []byte) ([]byte, error) {
	switch p.kind {
	case predictorNone:
		return bytesValue, nil
	case predictorTiff:
		return p.applyTiff(bytesValue)
	case predictorPNG:
		return p.applyPNG(bytesValue)
	}
	return bytesValue, nil
}

func (p predictorState) applyTiff(bytesValue []byte) ([]byte, error) {
	if p.bits != 8 {
		return nil, unsupported("PDF TIFF predictor with %d bits per component", p.bits)
	}
	row, err := p.rowBytes()
	if err != nil {
		return nil, err
	}
	if row == 0 || len(bytesValue)%row != 0 {
		return nil, corrupt(0, "PDF TIFF predictor stream of %d bytes is not a whole number of %d-byte rows",
			len(bytesValue), row)
	}
	for start := 0; start < len(bytesValue); start += row {
		chunk := bytesValue[start : start+row]
		for index := p.colors; index < len(chunk); index++ {
			chunk[index] += chunk[index-p.colors]
		}
	}
	return bytesValue, nil
}

func (p predictorState) applyPNG(bytesValue []byte) ([]byte, error) {
	row, err := p.rowBytes()
	if err != nil {
		return nil, err
	}
	if row != 0 && len(bytesValue) > int(^uint(0)>>1)-row {
		return nil, limitError("PDF predictor row is too wide")
	}
	stride := row + 1
	if row == 0 || len(bytesValue)%stride != 0 {
		return nil, corrupt(0, "PDF PNG predictor stream of %d bytes is not a whole number of %d-byte rows with a filter byte",
			len(bytesValue), row)
	}
	pixel := p.pixelBytes()
	if pixel > row {
		pixel = row
	}
	rows := len(bytesValue) / stride
	out := make([]byte, 0, rows*row)
	previous := make([]byte, row)
	current := make([]byte, row)
	for index := 0; index < rows; index++ {
		chunk := bytesValue[index*stride : (index+1)*stride]
		filter := chunk[0]
		copy(current, chunk[1:])
		switch filter {
		case 0:
		case 1:
			for position := pixel; position < row; position++ {
				current[position] += current[position-pixel]
			}
		case 2:
			for position := 0; position < row; position++ {
				current[position] += previous[position]
			}
		case 3:
			for position := 0; position < row; position++ {
				left := 0
				if position >= pixel {
					left = int(current[position-pixel])
				}
				up := int(previous[position])
				current[position] += byte((left + up) / 2)
			}
		case 4:
			for position := 0; position < row; position++ {
				left, upLeft := 0, 0
				if position >= pixel {
					left = int(current[position-pixel])
					upLeft = int(previous[position-pixel])
				}
				up := int(previous[position])
				current[position] += paeth(left, up, upLeft)
			}
		default:
			return nil, corrupt(0, "PDF PNG predictor row %d uses filter type %d", index, filter)
		}
		out = append(out, current...)
		previous, current = current, previous
	}
	return out, nil
}

func paeth(left, up, upLeft int) byte {
	estimate := left + up - upLeft
	distanceLeft := abs(estimate - left)
	distanceUp := abs(estimate - up)
	distanceUpLeft := abs(estimate - upLeft)
	if distanceLeft <= distanceUp && distanceLeft <= distanceUpLeft {
		return byte(left)
	}
	if distanceUp <= distanceUpLeft {
		return byte(up)
	}
	return byte(upLeft)
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func newPredictor(parms *Dict) (predictorState, error) {
	if parms == nil {
		return nonePredictor(), nil
	}
	value := int64(1)
	if v, ok := parms.GetInt([]byte("Predictor")); ok {
		value = v
	}
	var kind predictorKind
	switch {
	case value == 1:
		return nonePredictor(), nil
	case value == 2:
		kind = predictorTiff
	case value >= 10 && value <= 15:
		kind = predictorPNG
	default:
		return predictorState{}, unsupported("PDF predictor %d", value)
	}
	colors := int64(1)
	if v, ok := parms.GetInt([]byte("Colors")); ok {
		colors = v
	}
	if colors < 1 || colors > 64 {
		return predictorState{}, corrupt(0, "PDF predictor /Colors is outside 1..=64")
	}
	columns := int64(1)
	if v, ok := parms.GetInt([]byte("Columns")); ok {
		columns = v
	}
	if columns < 1 || columns > 1<<24 {
		return predictorState{}, corrupt(0, "PDF predictor /Columns is outside 1..=16777216")
	}
	bits := int64(8)
	if v, ok := parms.GetInt([]byte("BitsPerComponent")); ok {
		bits = v
	}
	switch bits {
	case 1, 2, 4, 8, 16:
	default:
		return predictorState{}, unsupported("PDF predictor with %d bits per component", bits)
	}
	return predictorState{kind: kind, colors: int(colors), bits: int(bits), columns: int(columns)}, nil
}

func decodeASCIIHex(input []byte, limit int) ([]byte, string, error) {
	var out []byte
	high := -1
	terminated := false
	for index, b := range input {
		if b == '>' {
			terminated = true
			break
		}
		if isWhitespace(b) {
			continue
		}
		digit, ok := hexValue(b)
		if !ok {
			return nil, "", corrupt(0, "PDF ASCIIHexDecode input byte %d is 0x%02x, not a hex digit", index, b)
		}
		if high >= 0 {
			out = append(out, byte(high)<<4|digit)
			if err := checkLimit(len(out), limit, "ASCIIHexDecode"); err != nil {
				return nil, "", err
			}
			high = -1
		} else {
			high = int(digit)
		}
	}
	if high >= 0 {
		out = append(out, byte(high)<<4)
	}
	if err := checkLimit(len(out), limit, "ASCIIHexDecode"); err != nil {
		return nil, "", err
	}
	note := ""
	if !terminated {
		note = "ASCIIHex stream has no > end marker"
	}
	return out, note, nil
}

func decodeASCII85(input []byte, limit int) ([]byte, string, error) {
	var out []byte
	group := make([]byte, 0, 5)
	terminated := false
	index := 0
	if bytes.HasPrefix(input, []byte("<~")) {
		index = 2
	}
	for index < len(input) {
		b := input[index]
		index++
		if isWhitespace(b) {
			continue
		}
		if b == '~' && index < len(input) && input[index] == '>' {
			terminated = true
			break
		}
		switch {
		case b == 'z' && len(group) == 0:
			out = append(out, 0, 0, 0, 0)
			if err := checkLimit(len(out), limit, "ASCII85Decode"); err != nil {
				return nil, "", err
			}
		case b >= '!' && b <= 'u':
			group = append(group, b-'!')
			if len(group) == 5 {
				if err := emitASCII85Group(group, 4, &out, limit); err != nil {
					return nil, "", err
				}
				group = group[:0]
			}
		default:
			return nil, "", corrupt(0, "PDF ASCII85Decode input byte %d is 0x%02x", index, b)
		}
	}
	if len(group) > 0 {
		if len(group) == 1 {
			return nil, "", corrupt(0, "PDF ASCII85Decode ends with a one-character group")
		}
		count := len(group) - 1
		for len(group) < 5 {
			group = append(group, 84)
		}
		if err := emitASCII85Group(group, count, &out, limit); err != nil {
			return nil, "", err
		}
	}
	note := ""
	if !terminated {
		note = "ASCII85 stream has no ~> end marker"
	}
	return out, note, nil
}

func emitASCII85Group(group []byte, count int, out *[]byte, limit int) error {
	var value uint64
	for _, digit := range group {
		value = value*85 + uint64(digit)
	}
	if value > 0xFFFFFFFF {
		return corrupt(0, "PDF ASCII85Decode group %v exceeds 32 bits", group)
	}
	encoded := []byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}
	*out = append(*out, encoded[:count]...)
	return checkLimit(len(*out), limit, "ASCII85Decode")
}

func decodeRunLength(input []byte, limit int) ([]byte, string, error) {
	var out []byte
	index := 0
	terminated := false
	for index < len(input) {
		control := input[index]
		index++
		if control == 128 {
			terminated = true
			break
		}
		if control < 128 {
			count := int(control) + 1
			end := index + count
			if end > len(input) {
				return nil, "", corrupt(0, "PDF RunLengthDecode literal run of %d bytes runs past the stream", count)
			}
			out = append(out, input[index:end]...)
			index = end
		} else {
			if index >= len(input) {
				return nil, "", corrupt(0, "PDF RunLengthDecode repeat run has no byte to repeat")
			}
			value := input[index]
			index++
			count := 257 - int(control)
			for i := 0; i < count; i++ {
				out = append(out, value)
			}
		}
		if err := checkLimit(len(out), limit, "RunLengthDecode"); err != nil {
			return nil, "", err
		}
	}
	note := ""
	if !terminated {
		note = "RunLength stream has no 128 end marker"
	}
	return out, note, nil
}

// LZW as PDF defines it: 9-bit codes growing to 12, clear code 256, end code
// 257, and an EarlyChange parameter that moves the width step one code earlier
// (the default) or leaves it at the table boundary.
const (
	lzwClear     uint16 = 256
	lzwEnd       uint16 = 257
	lzwFirstFree uint16 = 258
	lzwMaxCode          = 4096
)

func decodeLZW(input []byte, earlyChange bool, limit int) ([]byte, error) {
	reader := bitReader{bytes: input}
	width := uint32(9)
	nextCode := lzwFirstFree
	var prefix [lzwMaxCode]uint16
	var suffix [lzwMaxCode]byte
	var out []byte
	previous := -1

	for {
		code, ok := reader.read(width)
		if !ok {
			break
		}
		if code == lzwClear {
			width = 9
			nextCode = lzwFirstFree
			previous = -1
			continue
		}
		if code == lzwEnd {
			break
		}
		if code < nextCode {
			if err := lzwExpand(code, &prefix, &suffix, &out, limit); err != nil {
				return nil, err
			}
			if previous >= 0 {
				if int(nextCode) < lzwMaxCode {
					first, err := lzwFirstByte(uint16(previous), &prefix)
					if err != nil {
						return nil, err
					}
					prefix[nextCode] = uint16(previous)
					suffix[nextCode] = first
					nextCode++
					width = grownWidth(width, nextCode, earlyChange)
				}
			}
			previous = int(code)
		} else if code == nextCode && previous >= 0 {
			// The KwKwK case: the code names the entry this step is about to
			// define, so it is the previous sequence plus its own first byte.
			if err := lzwExpand(uint16(previous), &prefix, &suffix, &out, limit); err != nil {
				return nil, err
			}
			first, err := lzwFirstByte(uint16(previous), &prefix)
			if err != nil {
				return nil, err
			}
			out = append(out, first)
			if err := checkLimit(len(out), limit, "LZWDecode"); err != nil {
				return nil, err
			}
			if int(nextCode) < lzwMaxCode {
				prefix[nextCode] = uint16(previous)
				suffix[nextCode] = first
				nextCode++
				width = grownWidth(width, nextCode, earlyChange)
			}
			previous = int(code)
		} else {
			return nil, corrupt(0, "PDF LZW code %d is beyond the next dictionary entry %d", code, nextCode)
		}
	}
	return out, nil
}

func grownWidth(width uint32, nextCode uint16, earlyChange bool) uint32 {
	early := 0
	if earlyChange {
		early = 1
	}
	if width < 12 && int(nextCode)+early == 1<<width {
		return width + 1
	}
	return width
}

func lzwExpand(code uint16, prefix *[lzwMaxCode]uint16, suffix *[lzwMaxCode]byte, out *[]byte, limit int) error {
	var chain []byte
	current := code
	for current >= 258 {
		chain = append(chain, suffix[current])
		if len(chain) > lzwMaxCode {
			return corrupt(0, "PDF LZW dictionary contains a cycle")
		}
		current = prefix[current]
	}
	if current > 255 {
		return corrupt(0, "PDF LZW code %d does not reach a literal byte", code)
	}
	chain = append(chain, byte(current))
	for i := len(chain) - 1; i >= 0; i-- {
		*out = append(*out, chain[i])
	}
	return checkLimit(len(*out), limit, "LZWDecode")
}

func lzwFirstByte(code uint16, prefix *[lzwMaxCode]uint16) (byte, error) {
	current := code
	steps := 0
	for current >= 258 {
		current = prefix[current]
		steps++
		if steps > lzwMaxCode {
			return 0, corrupt(0, "PDF LZW dictionary contains a cycle")
		}
	}
	if current > 255 {
		return 0, corrupt(0, "PDF LZW code %d does not reach a literal byte", code)
	}
	return byte(current), nil
}

// bitReader is an MSB-first bit reader for LZW codes.
type bitReader struct {
	bytes []byte
	bit   int
}

func (r *bitReader) read(width uint32) (uint16, bool) {
	bits := int(width)
	if r.bit+bits > len(r.bytes)*8 {
		return 0, false
	}
	var value uint16
	for i := 0; i < bits; i++ {
		b := r.bytes[r.bit/8]
		bit := (b >> (7 - uint(r.bit%8))) & 1
		value = value<<1 | uint16(bit)
		r.bit++
	}
	return value, true
}

func joinNotes(notes []string) string {
	out := ""
	for i, note := range notes {
		if i > 0 {
			out += "; "
		}
		out += note
	}
	return out
}
