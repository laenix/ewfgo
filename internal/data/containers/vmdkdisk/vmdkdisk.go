// Package vmdkdisk assembles VMware split/flat VMDK descriptors. It parses a
// descriptor document and joins FLAT, SPARSE and ZERO extents into one logical
// ByteSource. It is a pure-Go port of forensic-core's vmdk_split.rs, starting
// with base (non-differencing) disks.
package vmdkdisk

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/laenix/ewfgo/internal/data/containers/vmdk"
	"github.com/laenix/ewfgo/internal/data/source"
)

// DescriptorSignature is the first line of a disk descriptor.
const DescriptorSignature = "# Disk DescriptorFile"

// DescriptorVersion is the only descriptor version this build reads.
const DescriptorVersion = 1

// Access is an extent access mode.
type Access uint8

const (
	AccessReadWrite Access = iota
	AccessReadOnly
	AccessNoAccess
)

// Label returns "RW", "RDONLY" or "NOACCESS".
func (a Access) Label() string {
	switch a {
	case AccessReadWrite:
		return "RW"
	case AccessReadOnly:
		return "RDONLY"
	default:
		return "NOACCESS"
	}
}

func (a Access) suppliesBytes() bool { return a != AccessNoAccess }

// Kind is an extent storage kind.
type Kind uint8

const (
	KindFlat Kind = iota
	KindSparse
	KindZero
)

// Label returns "FLAT", "SPARSE" or "ZERO".
func (k Kind) Label() string {
	switch k {
	case KindFlat:
		return "FLAT"
	case KindSparse:
		return "SPARSE"
	default:
		return "ZERO"
	}
}

// Extent is one descriptor extent line.
type Extent struct {
	Access  Access
	Sectors uint64
	Kind    Kind
	File    string
	HasFile bool
	Offset  uint64 // sectors, meaningful for FLAT
}

// LenBytes returns the extent length in bytes.
func (e Extent) LenBytes() uint64 { return e.Sectors * 512 }

// FileOffsetBytes returns the FLAT file offset in bytes.
func (e Extent) FileOffsetBytes() uint64 { return e.Offset * 512 }

// KV is an uninterpreted descriptor option.
type KV struct {
	Key   string
	Value string
}

// Descriptor is a parsed split VMDK descriptor.
type Descriptor struct {
	Version        uint32
	Encoding       string
	CID            string
	ParentCID      string
	CreateType     string
	ParentFileHint string
	Extents        []Extent
	Options        []KV
}

// DeclaresParent reports whether the descriptor names a parent.
func (d *Descriptor) DeclaresParent() bool {
	if d.ParentFileHint != "" {
		return true
	}
	return d.ParentCID != "" && !strings.EqualFold(d.ParentCID, "ffffffff")
}

// MatchesDescriptor reports whether head starts with the descriptor signature,
// tolerating a UTF-8 BOM and leading whitespace.
func MatchesDescriptor(head []byte) bool {
	head = stripBOM(head)
	line := head
	if at := indexByte(head, '\n'); at >= 0 {
		line = head[:at]
	}
	return strings.EqualFold(strings.TrimSpace(string(line)), DescriptorSignature)
}

// DescriptorSupportsAssembly reports whether head is a descriptor this build
// can parse.
func DescriptorSupportsAssembly(head []byte) bool {
	if !MatchesDescriptor(head) {
		return false
	}
	_, err := ParseDescriptor(head)
	return err == nil
}

// ParseDescriptor parses descriptor text. An extent line this parser cannot
// read is an error: dropping it would silently misrepresent the disk.
func ParseDescriptor(text []byte) (*Descriptor, error) {
	text = stripBOM(text)
	lines := strings.Split(string(text), "\n")
	if len(lines) == 0 || !strings.EqualFold(strings.TrimSpace(lines[0]), DescriptorSignature) {
		return nil, unsupported(fmt.Sprintf("a disk descriptor (the first line is not `%s`)", DescriptorSignature))
	}
	descriptor := &Descriptor{}
	for index, raw := range lines[1:] {
		number := index + 2
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tokens := tokenize(line)
		if len(tokens) > 0 {
			if _, ok := parseAccess(tokens[0]); ok {
				extent, err := parseExtent(tokens, number)
				if err != nil {
					return nil, err
				}
				descriptor.Extents = append(descriptor.Extents, extent)
				continue
			}
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, corrupt(uint64(number), fmt.Sprintf("line %d is neither an extent nor a key = value line", number))
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, corrupt(uint64(number), fmt.Sprintf("line %d has a value but no key", number))
		}
		value = unquote(strings.TrimSpace(value))
		switch strings.ToLower(key) {
		case "version":
			var version uint32
			if _, err := fmt.Sscanf(value, "%d", &version); err != nil {
				return nil, corrupt(uint64(number), fmt.Sprintf("version `%s` is not a number", value))
			}
			descriptor.Version = version
		case "encoding":
			descriptor.Encoding = value
		case "cid":
			descriptor.CID = value
		case "parentcid":
			descriptor.ParentCID = value
		case "createtype":
			descriptor.CreateType = value
		case "parentfilenamehint":
			descriptor.ParentFileHint = value
		default:
			descriptor.Options = append(descriptor.Options, KV{Key: key, Value: value})
		}
	}
	if descriptor.Version != DescriptorVersion {
		return nil, unsupported(fmt.Sprintf("descriptor version %d (only 1 is read)", descriptor.Version))
	}
	if len(descriptor.Extents) == 0 {
		return nil, corrupt(0, "descriptor declares no extent")
	}
	return descriptor, nil
}

func parseExtent(tokens []string, line int) (Extent, error) {
	if len(tokens) < 3 {
		return Extent{}, corrupt(uint64(line), fmt.Sprintf("line %d has an incomplete extent", line))
	}
	access, _ := parseAccess(tokens[0])
	var sectors uint64
	if _, err := fmt.Sscanf(tokens[1], "%d", &sectors); err != nil || sectors == 0 {
		return Extent{}, corrupt(uint64(line), fmt.Sprintf("extent sector count `%s` is not a positive number", tokens[1]))
	}
	kind, err := parseKind(tokens[2])
	if err != nil {
		return Extent{}, unsupported(err.Error())
	}
	extent := Extent{Access: access, Sectors: sectors, Kind: kind}
	rest := tokens[3:]
	if len(rest) > 0 {
		if !looksNumeric(rest[0]) {
			extent.File = rest[0]
			extent.HasFile = true
			rest = rest[1:]
		}
	}
	if len(rest) > 0 {
		if _, err := fmt.Sscanf(rest[0], "%d", &extent.Offset); err != nil {
			return Extent{}, corrupt(uint64(line), fmt.Sprintf("extent offset `%s` is not a number", rest[0]))
		}
		rest = rest[1:]
	}
	if len(rest) > 0 {
		return Extent{}, corrupt(uint64(line), fmt.Sprintf("line %d has trailing extent tokens", line))
	}
	if kind != KindZero && !extent.HasFile {
		return Extent{}, corrupt(uint64(line), fmt.Sprintf("%s extent has no file name", kind.Label()))
	}
	if extent.HasFile && !safePath(extent.File) {
		return Extent{}, corrupt(uint64(line), fmt.Sprintf("extent path `%s` is absolute or escapes the descriptor directory", extent.File))
	}
	if access == AccessNoAccess && kind != KindZero {
		return Extent{}, unsupported(fmt.Sprintf("%s extent with access NOACCESS", kind.Label()))
	}
	return extent, nil
}

func parseAccess(token string) (Access, bool) {
	switch strings.ToUpper(token) {
	case "RW":
		return AccessReadWrite, true
	case "RDONLY":
		return AccessReadOnly, true
	case "NOACCESS":
		return AccessNoAccess, true
	default:
		return 0, false
	}
}

func parseKind(token string) (Kind, error) {
	switch strings.ToUpper(token) {
	case "FLAT":
		return KindFlat, nil
	case "SPARSE":
		return KindSparse, nil
	case "ZERO":
		return KindZero, nil
	default:
		return 0, fmt.Errorf("extent type `%s` is not one this build assembles (only FLAT, SPARSE and ZERO)", token)
	}
}

func tokenize(line string) []string {
	var out []string
	var current strings.Builder
	inQuote := false
	for _, r := range line {
		switch {
		case r == '"':
			inQuote = !inQuote
		case unicode.IsSpace(r) && !inQuote:
			if current.Len() > 0 {
				out = append(out, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		out = append(out, current.String())
	}
	return out
}

func looksNumeric(text string) bool {
	if text == "" {
		return false
	}
	for _, r := range text {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func unquote(text string) string {
	if len(text) >= 2 && text[0] == '"' && text[len(text)-1] == '"' {
		return text[1 : len(text)-1]
	}
	return text
}

func safePath(name string) bool {
	name = strings.ReplaceAll(name, "\\", "/")
	if name == "" || strings.HasPrefix(name, "/") {
		return false
	}
	if len(name) >= 2 && name[1] == ':' {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return false
		}
	}
	return true
}

func stripBOM(bytes []byte) []byte {
	if len(bytes) >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF {
		return bytes[3:]
	}
	return bytes
}

func indexByte(bytes []byte, b byte) int {
	for i, value := range bytes {
		if value == b {
			return i
		}
	}
	return -1
}

// Resolver returns the byte source for an extent file name.
type Resolver func(name string) (source.ByteSource, error)

type extentSource struct {
	start  uint64
	length uint64
	src    source.ByteSource
}

// Source is a logical disk assembled from descriptor extents.
type Source struct {
	id        source.ID
	imageID   source.ImageID
	length    uint64
	cid       string
	parentCID string
	extents   []extentSource
	counters  source.Counters
}

// CID returns the descriptor's content id.
func (s *Source) CID() string { return s.cid }

// ParentCID returns the parent content id the descriptor declares.
func (s *Source) ParentCID() string { return s.parentCID }

// Assemble joins descriptor extents over the files resolver provides. Extent
// source ids are assigned from `uint64(id)+1` upward.
func Assemble(id source.ID, descriptor *Descriptor, resolver Resolver) (*Source, error) {
	return assemble(id, descriptor, resolver, nil)
}

// AssembleWithParent joins a split differencing disk over an already-assembled
// parent disk. The descriptor's parentCID and logical size are checked before
// any extent is opened; unwritten sparse grains read the parent at the same
// logical offset through a window.
func AssembleWithParent(id source.ID, descriptor *Descriptor, resolver Resolver, parent *Source) (*Source, error) {
	return assemble(id, descriptor, resolver, parent)
}

func assemble(id source.ID, descriptor *Descriptor, resolver Resolver, parent *Source) (*Source, error) {
	declaresParent := descriptor.DeclaresParent()
	if declaresParent && parent == nil {
		return nil, unsupported("a differencing split VMDK: supply the parent disk")
	}
	if !declaresParent && parent != nil {
		return nil, unsupported("parent supplied for a split VMDK that does not declare one")
	}
	if parent != nil {
		childCID, ok := parseCID(descriptor.ParentCID)
		if !ok {
			return nil, unsupported(fmt.Sprintf("differencing parentCID %q is not a content id", descriptor.ParentCID))
		}
		parentCID, ok := parseCID(parent.cid)
		if !ok {
			return nil, unsupported("the supplied parent descriptor declares no usable CID")
		}
		if childCID != parentCID {
			return nil, unsupported(fmt.Sprintf("differencing parentCID %#010x does not match the parent descriptor's CID %#010x", childCID, parentCID))
		}
		var total uint64
		for _, extent := range descriptor.Extents {
			total += extent.LenBytes()
		}
		if total != parent.length {
			return nil, unsupported(fmt.Sprintf("differencing child capacity %d does not match the parent's %d", total, parent.length))
		}
	}
	disk := &Source{id: id, cid: descriptor.CID, parentCID: descriptor.ParentCID}
	var logical uint64
	seen := make(map[string]bool)
	nextID := uint64(id) + 1
	for _, extent := range descriptor.Extents {
		length := extent.LenBytes()
		if length/512 != extent.Sectors {
			return nil, unsupported("extent length overflows")
		}
		var src source.ByteSource
		switch extent.Kind {
		case KindZero:
			src = &zeroSource{id: source.ID(nextID), length: length}
			nextID++
		case KindFlat:
			if seen[extent.File] {
				return nil, unsupported(fmt.Sprintf("extent file `%s` appears twice", extent.File))
			}
			seen[extent.File] = true
			file, err := resolver(extent.File)
			if err != nil {
				return nil, err
			}
			offset := extent.FileOffsetBytes()
			if offset > file.Len() || length > file.Len()-offset {
				return nil, corrupt(logical, fmt.Sprintf("flat extent `%s` [%d, +%d) does not fit the %d byte file",
					extent.File, offset, length, file.Len()))
			}
			sub, err := source.NewSubSource(source.ID(nextID), file, offset, length)
			if err != nil {
				return nil, err
			}
			src = sub
			nextID++
		case KindSparse:
			if seen[extent.File] {
				return nil, unsupported(fmt.Sprintf("extent file `%s` appears twice", extent.File))
			}
			seen[extent.File] = true
			file, err := resolver(extent.File)
			if err != nil {
				return nil, err
			}
			sparseID := source.ID(nextID)
			nextID++
			var sparse *vmdk.Source
			if parent != nil {
				windowID := source.ID(nextID)
				nextID++
				window, err := source.NewSubSource(windowID, parent, logical, length)
				if err != nil {
					return nil, err
				}
				sparse, err = vmdk.OpenExtent(sparseID, file, window)
			} else {
				sparse, err = vmdk.Open(sparseID, file)
			}
			if err != nil {
				return nil, err
			}
			if sparse.Len() != length {
				return nil, corrupt(logical, fmt.Sprintf("sparse extent `%s` capacity %d does not match its descriptor slice %d",
					extent.File, sparse.Len(), length))
			}
			src = sparse
		}
		if disk.imageID == 0 {
			disk.imageID = src.ImageID()
		}
		disk.extents = append(disk.extents, extentSource{start: logical, length: length, src: src})
		logical += length
	}
	disk.length = logical
	return disk, nil
}

func (s *Source) SourceID() source.ID     { return s.id }
func (s *Source) Len() uint64             { return s.length }
func (s *Source) ImageID() source.ImageID { return s.imageID }
func (s *Source) SectorSize() uint32      { return 512 }
func (s *Source) IsEmpty() bool           { return s.length == 0 }
func (s *Source) Stats() source.Stats     { return s.counters.Snapshot() }

func (s *Source) ReadAt(offset uint64, buf []byte) (int, error) {
	return s.readInto(offset, buf, false)
}

func (s *Source) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	return s.readInto(offset, buf, true)
}

func (s *Source) readInto(offset uint64, buf []byte, lossy bool) (int, error) {
	if len(buf) == 0 {
		s.counters.AddRead(0)
		return 0, nil
	}
	if offset >= s.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), s.length)
	}
	want := int(minU64(s.length-offset, uint64(len(buf))))
	done := 0
	for done < want {
		position := offset + uint64(done)
		extent, local, ok := s.locate(position)
		if !ok {
			return 0, source.NewOutOfRange(position, uint64(want-done), s.length)
		}
		chunk := int(minU64(extent.length-local, uint64(want-done)))
		target := buf[done : done+chunk]
		var (
			n   int
			err error
		)
		if lossy {
			n, err = extent.src.ReadAtLossy(local, target)
		} else {
			n, err = extent.src.ReadAt(local, target)
		}
		if err != nil {
			return 0, err
		}
		done += n
		if n < chunk {
			break
		}
	}
	s.counters.AddRead(done)
	return done, nil
}

func (s *Source) locate(position uint64) (*extentSource, uint64, bool) {
	for i := range s.extents {
		extent := &s.extents[i]
		if position >= extent.start && position < extent.start+extent.length {
			return extent, position - extent.start, true
		}
	}
	return nil, 0, false
}

func (s *Source) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > s.length || length > s.length-offset {
		return out, source.NewOutOfRange(offset, length, s.length)
	}
	cursor := offset
	end := offset + length
	for cursor < end {
		extent, local, ok := s.locate(cursor)
		if !ok {
			return out, source.NewOutOfRange(cursor, end-cursor, s.length)
		}
		chunk := minU64(extent.length-local, end-cursor)
		inner, err := extent.src.Extents(local, chunk)
		if err != nil {
			return out, err
		}
		out = append(out, inner...)
		cursor += chunk
	}
	return out, nil
}

func (s *Source) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return s.ExtentsInto(offset, length, nil)
}

func (s *Source) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	if offset > s.length || length > s.length-offset {
		return nil, source.NewOutOfRange(offset, length, s.length)
	}
	var out []source.ImageRange
	cursor := offset
	end := offset + length
	for cursor < end {
		extent, local, ok := s.locate(cursor)
		if !ok {
			return nil, source.NewOutOfRange(cursor, end-cursor, s.length)
		}
		chunk := minU64(extent.length-local, end-cursor)
		inner, err := extent.src.MapToImage(local, chunk)
		if err != nil {
			return nil, err
		}
		out = append(out, inner...)
		cursor += chunk
	}
	return out, nil
}

var _ source.ByteSource = (*Source)(nil)

type zeroSource struct {
	id     source.ID
	length uint64
}

func (z *zeroSource) SourceID() source.ID     { return z.id }
func (z *zeroSource) Len() uint64             { return z.length }
func (z *zeroSource) ImageID() source.ImageID { return 0 }
func (z *zeroSource) SectorSize() uint32      { return 512 }
func (z *zeroSource) IsEmpty() bool           { return z.length == 0 }
func (z *zeroSource) Stats() source.Stats     { return source.Stats{} }

func (z *zeroSource) ReadAt(offset uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if offset >= z.length {
		return 0, source.NewOutOfRange(offset, uint64(len(buf)), z.length)
	}
	n := int(minU64(z.length-offset, uint64(len(buf))))
	clear(buf[:n])
	return n, nil
}

func (z *zeroSource) ReadAtLossy(offset uint64, buf []byte) (int, error) {
	return z.ReadAt(offset, buf)
}

func (z *zeroSource) ExtentsInto(offset, length uint64, out []source.ParentRange) ([]source.ParentRange, error) {
	if offset > z.length || length > z.length-offset {
		return out, source.NewOutOfRange(offset, length, z.length)
	}
	if length > 0 {
		out = append(out, source.ParentRange{Parent: z.id, ParentOffset: 0, Len: length, Kind: source.RangeZero})
	}
	return out, nil
}

func (z *zeroSource) Extents(offset, length uint64) ([]source.ParentRange, error) {
	return z.ExtentsInto(offset, length, nil)
}

func (z *zeroSource) MapToImage(offset, length uint64) ([]source.ImageRange, error) {
	if offset > z.length || length > z.length-offset {
		return nil, source.NewOutOfRange(offset, length, z.length)
	}
	if length == 0 {
		return nil, nil
	}
	return []source.ImageRange{{ImageID: 0, ImageOffset: 0, Len: length, Kind: source.RangeZero}}, nil
}

func parseCID(text string) (uint32, bool) {
	text = strings.TrimSpace(text)
	text = strings.TrimPrefix(text, "0x")
	if text == "" {
		return 0, false
	}
	var value uint32
	for i := 0; i < len(text); i++ {
		c := text[i]
		var digit uint32
		switch {
		case c >= '0' && c <= '9':
			digit = uint32(c - '0')
		case c >= 'a' && c <= 'f':
			digit = uint32(c-'a') + 10
		case c >= 'A' && c <= 'F':
			digit = uint32(c-'A') + 10
		default:
			return 0, false
		}
		next := value<<4 | digit
		if next>>4 != value {
			return 0, false
		}
		value = next
	}
	return value, true
}

func corrupt(offset uint64, reason string) error {
	return &source.Error{Kind: source.ErrCorrupt, Offset: offset, Reason: reason}
}

func unsupported(reason string) error {
	return &source.Error{Kind: source.ErrUnsupported, Reason: reason}
}

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
