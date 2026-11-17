// Compressed RTF: PidTagRtfCompressed (0x1009), the LZFu stream [MS-OXRTFCP]
// defines.
//
// The stored value begins with a 16-byte header: the compressed size (which
// counts the 12 header bytes before the CRC), the uncompressed size, the
// compression type (LZFu, or MELA for stored bytes) and a CRC-32 over the
// token stream (reflected polynomial, initial value 0, no final XOR, the same
// form the PST header uses).  LZFu then encodes a 4096-byte circular window
// whose first 207 bytes are a fixed RTF dictionary; a control byte carries
// eight tokens least-significant bit first, a clear bit is one literal byte,
// and a set bit is a big-endian 16-bit reference of a 12-bit window offset and
// a four-bit length minus two.  A reference whose offset equals the next write
// position ends the stream.  The dictionary is fixed rather than stored, so a
// stream is essentially never plain RTF even for a plain-text body.
//
// Decompression is bounded by the caller's limit; a stream that declares more
// is marked truncated rather than expanded in full.  Structural damage is a
// named refusal, never a partial body presented as complete.
package pst

// initialRTFDictionary is the fixed initial window [MS-OXRTFCP] specifies:
// 207 bytes of RTF markup.
const initialRTFDictionary = "{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil \\froman \\fswiss \\fmodern \\fscript \\fdecor MS Sans SerifSymbolArialTimes New RomanCourier{\\colortbl\\red0\\green0\\blue0\r\n\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx"

const (
	rtfWindowBytes = 4096
	rtfHeaderBytes = 16
)

var (
	rtfMagicLZFu = [4]byte{'L', 'Z', 'F', 'u'}
	rtfMagicMELA = [4]byte{'M', 'E', 'L', 'A'}
)

// Rtf is a decoded compressed RTF body.
type Rtf struct {
	// Markup is the decompressed RTF markup, at most the caller's limit.
	Markup []byte
	// Truncated is true when the limit stopped decompression before the
	// stream ended.
	Truncated bool
	// CRCMismatch is true when the header's CRC-32 disagrees with the token
	// stream (or, for MELA, when a nonzero CRC was stored); the bytes were
	// still decoded.
	CRCMismatch bool
}

// DecompressRTF decompresses a PidTagRtfCompressed value, keeping at most
// limit bytes.
//
// The header's compressed size fixes how many bytes the token stream has;
// trailing bytes in the value are not decoded.  A short header, an unknown
// compression type, a stream shorter than its declared size, a reference or
// literal cut off by the end of the tokens, a stream without its end marker,
// and a decoded length that disagrees with the declared uncompressed size are
// all named refusals.
func DecompressRTF(stream []byte, limit int) (Rtf, error) {
	if len(stream) < rtfHeaderBytes {
		return Rtf{}, corruptf("the compressed RTF value is %d byte(s), shorter than its %d-byte header", len(stream), rtfHeaderBytes)
	}
	compressed := uint64(leU32(stream, 0))
	declared := leU32(stream, 4)
	magic := [4]byte{stream[8], stream[9], stream[10], stream[11]}
	storedCRC := leU32(stream, 12)
	if compressed < 12 {
		return Rtf{}, corruptf("the header declares %d compressed byte(s), fewer than the 12 header bytes it counts", compressed)
	}
	tokensLen := compressed - 12
	if uint64(len(stream)-rtfHeaderBytes) < tokensLen {
		return Rtf{}, corruptf("the header declares %d token byte(s) but the value holds %d after the header", tokensLen, len(stream)-rtfHeaderBytes)
	}
	if limit < 0 {
		limit = 0
	}
	tokens := stream[rtfHeaderBytes : rtfHeaderBytes+int(tokensLen)]

	if magic == rtfMagicMELA {
		markup := append([]byte(nil), tokens...)
		truncated := len(markup) > limit
		if truncated {
			markup = markup[:limit]
		}
		return Rtf{Markup: markup, Truncated: truncated, CRCMismatch: storedCRC != 0}, nil
	}
	if magic != rtfMagicLZFu {
		return Rtf{}, corruptf("the RTF compression type is %q, neither LZFu nor MELA", string(magic[:]))
	}
	crcMismatch := crc32PST(tokens) != storedCRC

	var window [rtfWindowBytes]byte
	for index := range window {
		window[index] = ' '
	}
	copy(window[:], initialRTFDictionary)
	write := len(initialRTFDictionary)
	markup := make([]byte, 0, min(limit, len(tokens)*8))
	truncated := false
	ended := false
	at := 0
	for at < len(tokens) && !ended {
		control := tokens[at]
		at++
		for bit := 0; bit < 8; bit++ {
			if len(markup) >= limit {
				truncated = true
				break
			}
			if control&(1<<bit) == 0 {
				if at >= len(tokens) {
					return Rtf{}, corruptf("the LZFu token stream ends in the middle of a literal")
				}
				value := tokens[at]
				at++
				window[write] = value
				write = (write + 1) % rtfWindowBytes
				markup = append(markup, value)
				continue
			}
			if at+2 > len(tokens) {
				return Rtf{}, corruptf("the LZFu token stream ends in the middle of a reference")
			}
			token := uint16(tokens[at])<<8 | uint16(tokens[at+1])
			at += 2
			offset := int((token >> 4) & 0x0FFF)
			if offset == write {
				ended = true
				break
			}
			length := int(token&0x000F) + 2
			for step := 0; step < length; step++ {
				if len(markup) >= limit {
					truncated = true
					break
				}
				value := window[(offset+step)%rtfWindowBytes]
				window[write] = value
				write = (write + 1) % rtfWindowBytes
				markup = append(markup, value)
			}
			if truncated {
				break
			}
		}
	}
	if truncated {
		return Rtf{Markup: markup, Truncated: true, CRCMismatch: crcMismatch}, nil
	}
	if !ended {
		return Rtf{}, corruptf("the LZFu token stream ends without its end marker")
	}
	if uint64(len(markup)) != uint64(declared) {
		return Rtf{}, corruptf("the header declares %d uncompressed byte(s) but the token stream decodes to %d", declared, len(markup))
	}
	return Rtf{Markup: markup, Truncated: false, CRCMismatch: crcMismatch}, nil
}
