package iso9660

import "encoding/binary"

// RockRidge is what one record's system use area says.
type RockRidge struct {
	Name        string
	HasName     bool
	Mode        uint32
	HasMode     bool
	Links       uint32
	HasLinks    bool
	UID         uint32
	HasUID      bool
	GID         uint32
	HasGID      bool
	Created     IsoTime
	HasCreated  bool
	Modified    IsoTime
	HasModified bool
	Accessed    IsoTime
	HasAccessed bool
	Attributes  IsoTime
	HasAttrs    bool
	Symlink     string
	HasSymlink  bool

	// ChildLink is the block a CL entry names: where a relocated directory's
	// records actually live.
	ChildLink    uint32
	HasChildLink bool
	// ParentLink is the block a PL entry names.
	ParentLink    uint32
	HasParentLink bool
	// Relocated is the RE entry: this area belongs to a relocated directory.
	Relocated bool
	// LinkMismatch reports a CL/PL entry whose byte orders disagree.
	LinkMismatch bool
	// Continuation is a CE area holding more entries.
	Continuation    continuation
	HasContinuation bool
	// Sharing reports the SP entry.
	Sharing bool
	// Extension is the identifier from an ER entry.
	Extension string
	// Zisofs is a ZF entry: this file's data is zisofs-compressed.
	Zisofs  *ZisofsMark
	Present bool
}

type continuation struct {
	block  uint32
	offset uint32
	length uint32
}

// parseSUSP parses the entries in one system use area.
func parseSUSP(bytes []byte) RockRidge {
	var out RockRidge
	parseSUSPInto(bytes, &out, 0)
	return out
}

func parseSUSPInto(bytes []byte, out *RockRidge, depth uint8) {
	if depth > 2 {
		return
	}
	at := 0
	for at+4 <= len(bytes) {
		signature := string(bytes[at : at+2])
		length := int(bytes[at+2])
		if length < 4 || at+length > len(bytes) {
			break
		}
		data := bytes[at+4 : at+length]
		out.Present = true
		switch signature {
		case "ST":
			return
		case "SP":
			if len(data) >= 2 && data[0] == 0xBE && data[1] == 0xEF {
				out.Sharing = true
			}
		case "NM":
			if len(data) >= 1 {
				flags := data[0]
				name := data[1:]
				switch flags & 0x06 {
				case 0x02:
					out.Name, out.HasName = ".", true
				case 0x04:
					out.Name, out.HasName = "..", true
				default:
					if flags&0x08 != 0 {
						out.Name, out.HasName = "/", true
					} else {
						text := latin1String(name)
						if out.HasName {
							out.Name += text
						} else {
							out.Name, out.HasName = text, true
						}
					}
				}
			}
		case "PX":
			if len(data) >= 16 {
				out.Mode, out.HasMode = binary.BigEndian.Uint32(data[0:]), true
				out.Links, out.HasLinks = binary.BigEndian.Uint32(data[4:]), true
				out.UID, out.HasUID = binary.BigEndian.Uint32(data[8:]), true
				out.GID, out.HasGID = binary.BigEndian.Uint32(data[12:]), true
			}
		case "TF":
			parseSUSPTimes(data, out)
		case "SL":
			parseSUSPSymlink(data, out)
		case "CL":
			if len(data) >= 8 {
				block, agrees := suspLocation(data)
				out.ChildLink, out.HasChildLink = block, true
				out.LinkMismatch = out.LinkMismatch || !agrees
			}
		case "PL":
			if len(data) >= 8 {
				block, agrees := suspLocation(data)
				out.ParentLink, out.HasParentLink = block, true
				out.LinkMismatch = out.LinkMismatch || !agrees
			}
		case "RE":
			out.Relocated = true
		case "ZF":
			if len(data) >= 12 {
				uncompressed := binary.LittleEndian.Uint32(data[4:])
				big := binary.BigEndian.Uint32(data[8:])
				out.Zisofs = &ZisofsMark{
					Algorithm:       [2]byte{data[0], data[1]},
					HeaderSize:      data[2],
					BlockShift:      data[3],
					UncompressedLen: uncompressed,
					SizeAgrees:      uncompressed == big,
				}
			}
		case "CE":
			if len(data) >= 12 {
				out.Continuation = continuation{
					block:  binary.BigEndian.Uint32(data[0:]),
					offset: binary.BigEndian.Uint32(data[4:]),
					length: binary.BigEndian.Uint32(data[8:]),
				}
				out.HasContinuation = true
			}
		case "ER":
			if len(data) >= 4 {
				idLen := int(data[0])
				if 4+idLen <= len(data) {
					out.Extension = latin1String(data[4 : 4+idLen])
				}
			}
		}
		at += length
	}
}

func parseSUSPTimes(data []byte, out *RockRidge) {
	if len(data) == 0 {
		return
	}
	flags := data[0]
	long := flags&0x80 != 0
	width := 7
	if long {
		width = 17
	}
	at := 1
	next := func(set uint8) (IsoTime, bool) {
		if flags&set == 0 {
			return IsoTime{}, false
		}
		if at+width > len(data) {
			at += width
			return IsoTime{}, false
		}
		slice := data[at : at+width]
		at += width
		if long {
			return isoTimeFromASCII(slice)
		}
		return isoTimeFromRecording(slice)
	}
	if t, ok := next(0x01); ok {
		out.Created, out.HasCreated = t, true
	}
	if t, ok := next(0x02); ok {
		out.Modified, out.HasModified = t, true
	}
	if t, ok := next(0x04); ok {
		out.Accessed, out.HasAccessed = t, true
	}
	if t, ok := next(0x08); ok {
		out.Attributes, out.HasAttrs = t, true
	}
	next(0x10)
	next(0x20)
	next(0x40)
}

func parseSUSPSymlink(data []byte, out *RockRidge) {
	if len(data) == 0 {
		return
	}
	target := out.Symlink
	first := len(target) == 0
	at := 1
	for at+2 <= len(data) {
		componentFlags := data[at]
		length := int(data[at+1])
		if at+2+length > len(data) {
			break
		}
		component := data[at+2 : at+2+length]
		var text string
		switch {
		case componentFlags&0x02 != 0:
			text = "."
		case componentFlags&0x04 != 0:
			text = ".."
		case componentFlags&0x08 != 0:
			text = ""
		default:
			text = latin1String(component)
		}
		if componentFlags&0x08 != 0 {
			target += "/"
			first = false
		} else {
			if !first && len(target) > 0 && target[len(target)-1] != '/' {
				target += "/"
			}
			target += text
			first = false
		}
		at += 2 + length
	}
	if len(target) > 0 {
		out.Symlink, out.HasSymlink = target, true
	}
}

// suspLocation reads a CL/PL location: little-endian first, then the same
// value in big-endian. The little-endian copy is what readers trust.
func suspLocation(data []byte) (uint32, bool) {
	little := binary.LittleEndian.Uint32(data[0:])
	big := binary.BigEndian.Uint32(data[4:])
	return little, little == big
}

func latin1String(bytes []byte) string {
	out := make([]rune, len(bytes))
	for i, b := range bytes {
		out[i] = rune(b)
	}
	return string(out)
}
