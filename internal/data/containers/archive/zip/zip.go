// Package zip reads ZIP / Zip64 archives as the archive framework's Reader.
//
// The reader parses the end-of-central-directory record, the optional Zip64
// records, and every central-directory entry.  It never trusts local headers
// for sizes: the central directory is authoritative, as it is for every ZIP
// tool.  Local headers are re-read only to find the payload offset.
//
// Supported payload methods are stored (0) and deflated (8), decoded lazily
// with the Go standard library.  Encrypted entries are listed but refused by
// Open with an explicit ErrEncrypted error; this port has no key provider.
// Other methods are refused with ErrUnsupported.  CRC-32 mismatches are
// counted as corrupt bytes but the decoded bytes remain readable, so evidence
// is never hidden.
package zip

import (
	"strings"
	"unicode/utf8"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	eocdLen         = 22
	zip64LocatorLen = 20
	zip64EOCDLen    = 56
	centralLen      = 46
	localLen        = 30

	methodStored   uint16 = 0
	methodDeflated uint16 = 8
	methodAES      uint16 = 99

	gpEncrypted       uint16 = 0x0001
	gpStrongEncrypted uint16 = 0x0040
	gpDataDescriptor  uint16 = 0x0008
	gpUTF8            uint16 = 0x0800
)

var (
	eocdSig         = [4]byte{0x50, 0x4b, 0x05, 0x06}
	zip64LocatorSig = [4]byte{0x50, 0x4b, 0x06, 0x07}
	zip64EOCDSig    = [4]byte{0x50, 0x4b, 0x06, 0x06}
	centralSig      = [4]byte{0x50, 0x4b, 0x01, 0x02}
	localSig        = [4]byte{0x50, 0x4b, 0x03, 0x04}
)

func u16At(buf []byte, offset int) uint16 {
	return uint16(buf[offset]) | uint16(buf[offset+1])<<8
}

func u32At(buf []byte, offset int) uint32 {
	return uint32(buf[offset]) | uint32(buf[offset+1])<<8 |
		uint32(buf[offset+2])<<16 | uint32(buf[offset+3])<<24
}

func u64At(buf []byte, offset int) uint64 {
	return uint64(u32At(buf, offset)) | uint64(u32At(buf, offset+4))<<32
}

// Adapter opens ZIP-shaped archives.  One adapter instance serves one format
// id so an APK routed as "apk" still reports "apk" from Reader.FormatID.
type Adapter struct {
	formatID string
}

// NewAdapter creates an adapter for one format id.
func NewAdapter(formatID string) Adapter { return Adapter{formatID: formatID} }

// ZipAdapter returns an adapter for the generic "zip" format id.
func ZipAdapter() Adapter { return Adapter{formatID: "zip"} }

// FormatID implements archive.Adapter.
func (a Adapter) FormatID() string { return a.formatID }

// Open implements archive.Adapter.
func (a Adapter) Open(src source.ByteSource, limits archive.Limits) (archive.Reader, error) {
	return OpenAs(a.formatID, src, limits)
}

// Register adds the ZIP parser for generic ZIP, APK, and JAR content.
func Register(registry *archive.Registry) error {
	for _, formatID := range []string{"zip", "apk", "jar"} {
		if err := registry.Register(NewAdapter(formatID)); err != nil {
			return err
		}
	}
	return nil
}

type zipEntry struct {
	entry             archive.Entry
	method            uint16
	compressedSize    uint64
	localHeaderOffset uint64
}

// Reader is a read-only ZIP archive.
type Reader struct {
	formatID string
	source   source.ByteSource
	entries  []archive.Entry
	raw      []zipEntry
	byPath   map[string]int
	limits   archive.Limits
}

// Open opens a generic ZIP archive.
func Open(src source.ByteSource, limits archive.Limits) (*Reader, error) {
	return OpenAs("zip", src, limits)
}

// OpenAs opens a ZIP-shaped archive reporting formatID.
func OpenAs(formatID string, src source.ByteSource, limits archive.Limits) (*Reader, error) {
	directory, err := parseDirectory(src)
	if err != nil {
		return nil, err
	}
	entries, raw, err := parseEntries(src, directory, limits)
	if err != nil {
		return nil, err
	}
	byPath := make(map[string]int, len(entries))
	for index, entry := range entries {
		if _, exists := byPath[entry.Path]; !exists {
			byPath[entry.Path] = index
		}
	}
	return &Reader{
		formatID: formatID,
		source:   src,
		entries:  entries,
		raw:      raw,
		byPath:   byPath,
		limits:   limits,
	}, nil
}

// FormatID implements archive.Reader.
func (r *Reader) FormatID() string { return r.formatID }

// Limits returns the limits used while listing.
func (r *Reader) Limits() archive.Limits { return r.limits }

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
	index, ok := r.byPath[path]
	if !ok {
		return nil, archive.Invalidf("ZIP has no entry named %s", path)
	}
	entry := r.raw[index]

	if entry.entry.IsDir() {
		return nil, archive.Invalidf("ZIP entry %s is a directory", entry.entry.Path)
	}
	if !isSupported(entry.method) {
		return nil, archive.Unsupportedf("ZIP entry %s uses compression method %d", entry.entry.Path, entry.method)
	}
	if entry.compressedSize > r.limits.MaxEntrySize {
		return nil, archive.Limitf("ZIP entry %s is larger than the configured limit", entry.entry.Path)
	}

	dataOffset, err := localDataOffset(r.source, entry.localHeaderOffset, entry.compressedSize)
	if err != nil {
		return nil, err
	}
	if entry.entry.Encrypted {
		return nil, archive.Encryptedf("ZIP entry %s is encrypted and this reader has no key provider", entry.entry.Path)
	}

	return newEntrySource(sourceID, r.source, entry.entry, dataOffset, entry.compressedSize, entry.method), nil
}

func isSupported(method uint16) bool {
	return method == methodStored || method == methodDeflated
}

type directory struct {
	entries  uint64
	cdOffset uint64
	cdSize   uint64
}

func parseDirectory(src source.ByteSource) (directory, error) {
	length := src.Len()
	if length < eocdLen {
		return directory{}, archive.Invalidf("ZIP is too short for an end-of-central-directory record: %d bytes", length)
	}

	tailLen := length
	if tailLen > uint64(eocdLen+0xFFFF) {
		tailLen = uint64(eocdLen + 0xFFFF)
	}
	tailOffset := length - tailLen
	tail, err := source.ReadVecAt(src, tailOffset, tailLen)
	if err != nil {
		return directory{}, err
	}

	eocdIndex := -1
	for index := len(tail) - eocdLen; index >= 0; index-- {
		if [4]byte(tail[index:index+4]) != eocdSig {
			continue
		}
		commentLen := int(u16At(tail, index+20))
		if index+eocdLen+commentLen == len(tail) {
			eocdIndex = index
			break
		}
	}
	if eocdIndex < 0 {
		return directory{}, archive.Invalidf("ZIP end-of-central-directory record not found")
	}
	eocdOffset := tailOffset + uint64(eocdIndex)

	classicDisk := u16At(tail, eocdIndex+4)
	classicCDDisk := u16At(tail, eocdIndex+6)
	classicEntriesDisk := u16At(tail, eocdIndex+8)
	classicEntries := u16At(tail, eocdIndex+10)
	classicCDSize := u32At(tail, eocdIndex+12)
	classicCDOffset := u32At(tail, eocdIndex+16)

	// A Zip64 locator sits immediately before the classic EOCD record.  Its
	// presence is authoritative even when the classic fields were not filled
	// with sentinels.
	if eocdOffset >= zip64LocatorLen {
		locatorOffset := eocdOffset - zip64LocatorLen
		if locatorOffset+zip64LocatorLen <= length {
			locator, err := source.ReadVecAt(src, locatorOffset, zip64LocatorLen)
			if err != nil {
				return directory{}, err
			}
			if [4]byte(locator[0:4]) == zip64LocatorSig {
				zip64Offset := u64At(locator, 8)
				totalDisks := u32At(locator, 16)
				if totalDisks != 1 {
					return directory{}, archive.Unsupportedf("multi-disk ZIP64 archive (%d disks)", totalDisks)
				}
				if zip64Offset > length || zip64EOCDLen > length-zip64Offset {
					return directory{}, archive.Invalidf("ZIP64 locator points outside the file")
				}
				record, err := source.ReadVecAt(src, zip64Offset, zip64EOCDLen)
				if err != nil {
					return directory{}, err
				}
				if [4]byte(record[0:4]) != zip64EOCDSig {
					return directory{}, archive.Invalidf("ZIP64 locator points to a missing Zip64 record")
				}
				if u64At(record, 4) < 44 {
					return directory{}, archive.Invalidf("ZIP64 end-of-central-directory record is too short")
				}

				disk := u32At(record, 16)
				cdDisk := u32At(record, 20)
				entriesDisk := u64At(record, 24)
				entries := u64At(record, 32)
				cdSize := u64At(record, 40)
				cdOffset := u64At(record, 48)

				if disk != 0 || cdDisk != 0 {
					return directory{}, archive.Unsupportedf("multi-disk ZIP64 archive")
				}
				if entriesDisk != entries {
					return directory{}, archive.Unsupportedf("ZIP64 archive splits entries across disks")
				}
				return validateDirectory(src, entries, cdOffset, cdSize)
			}
		}
	}

	if classicDisk != 0 || classicCDDisk != 0 {
		return directory{}, archive.Unsupportedf("multi-disk ZIP archive")
	}
	if classicEntries == 0xFFFF || classicEntriesDisk == 0xFFFF ||
		classicCDSize == 0xFFFFFFFF || classicCDOffset == 0xFFFFFFFF {
		return directory{}, archive.Invalidf("ZIP uses Zip64 sentinel values without a Zip64 record")
	}
	if classicEntriesDisk != classicEntries {
		return directory{}, archive.Unsupportedf("ZIP archive splits entries across disks")
	}

	return validateDirectory(src, uint64(classicEntries), uint64(classicCDOffset), uint64(classicCDSize))
}

func validateDirectory(src source.ByteSource, entries, cdOffset, cdSize uint64) (directory, error) {
	length := src.Len()
	if cdOffset > length || cdSize > length-cdOffset {
		return directory{}, archive.Invalidf("ZIP central directory [%d, +%d) is outside the file (%d bytes)", cdOffset, cdSize, length)
	}
	// Every entry needs at least a 46-byte header.  Rejecting an impossible
	// count here bounds the loop before any per-entry allocation.
	if entries > cdSize/centralLen {
		return directory{}, archive.Invalidf("ZIP declares %d entries but its central directory holds at most %d", entries, cdSize/centralLen)
	}
	return directory{entries: entries, cdOffset: cdOffset, cdSize: cdSize}, nil
}

type centralHeader struct {
	versionMade      uint16
	flags            uint16
	method           uint16
	modifiedTime     uint16
	modifiedDate     uint16
	crc32            uint32
	compressedSize   uint32
	uncompressedSize uint32
	nameLen          int
	extraLen         int
	commentLen       int
	diskStart        uint16
	externalAttrs    uint32
	localOffset      uint32
}

func parseCentralHeader(fixed []byte) centralHeader {
	return centralHeader{
		versionMade:      u16At(fixed, 4),
		flags:            u16At(fixed, 8),
		method:           u16At(fixed, 10),
		modifiedTime:     u16At(fixed, 12),
		modifiedDate:     u16At(fixed, 14),
		crc32:            u32At(fixed, 16),
		compressedSize:   u32At(fixed, 20),
		uncompressedSize: u32At(fixed, 24),
		nameLen:          int(u16At(fixed, 28)),
		extraLen:         int(u16At(fixed, 30)),
		commentLen:       int(u16At(fixed, 32)),
		diskStart:        u16At(fixed, 34),
		externalAttrs:    u32At(fixed, 38),
		localOffset:      u32At(fixed, 42),
	}
}

func parseEntries(src source.ByteSource, dir directory, limits archive.Limits) ([]archive.Entry, []zipEntry, error) {
	if dir.entries > uint64(limits.MaxEntries) {
		return nil, nil, archive.Limitf("ZIP has %d entries, limit is %d", dir.entries, limits.MaxEntries)
	}
	maxInt := uint64(^uint(0) >> 1)
	if dir.entries > maxInt {
		return nil, nil, archive.Limitf("ZIP entry count %d does not fit in memory", dir.entries)
	}

	total := int(dir.entries)
	cdEnd := dir.cdOffset + dir.cdSize
	budget := archive.NewBudget(limits)
	entries := make([]archive.Entry, 0, min(total, 4096))
	raw := make([]zipEntry, 0, min(total, 4096))
	position := dir.cdOffset

	for index := 0; index < total; index++ {
		if position > cdEnd || cdEnd-position < centralLen {
			return nil, nil, archive.Invalidf("ZIP central directory ends inside entry %d", index)
		}
		fixed, err := source.ReadVecAt(src, position, centralLen)
		if err != nil {
			return nil, nil, err
		}
		if [4]byte(fixed[0:4]) != centralSig {
			return nil, nil, archive.Invalidf("bad central-directory signature at offset %d", position)
		}
		header := parseCentralHeader(fixed)

		variableLen := uint64(header.nameLen + header.extraLen + header.commentLen)
		if position+centralLen > cdEnd || variableLen > cdEnd-(position+centralLen) {
			return nil, nil, archive.Invalidf("ZIP central-directory entry %d extends past the directory", index)
		}
		var variable []byte
		if variableLen > 0 {
			variable, err = source.ReadVecAt(src, position+centralLen, variableLen)
			if err != nil {
				return nil, nil, err
			}
		}
		position += centralLen + variableLen

		nameRaw := variable[:header.nameLen]
		extraBytes := variable[header.nameLen : header.nameLen+header.extraLen]

		extra, err := parseExtra(extraBytes, header)
		if err != nil {
			return nil, nil, err
		}
		uncompressedSize, err := resolve(header.uncompressedSize, extra.uncompressedSize, "uncompressed size", index)
		if err != nil {
			return nil, nil, err
		}
		compressedSize, err := resolve(header.compressedSize, extra.compressedSize, "compressed size", index)
		if err != nil {
			return nil, nil, err
		}
		localOffset, err := resolve(header.localOffset, extra.localOffset, "local header offset", index)
		if err != nil {
			return nil, nil, err
		}
		if localOffset > src.Len() || localLen > src.Len()-localOffset {
			return nil, nil, archive.Invalidf("ZIP entry %d points to local header %d, outside the file", index, localOffset)
		}

		name, err := decodeName(nameRaw, header.flags&gpUTF8 != 0)
		if err != nil {
			return nil, nil, err
		}
		kind := entryKind(name, header.versionMade, header.externalAttrs)

		if header.method == methodAES && extra.aes == nil {
			return nil, nil, archive.Invalidf("ZIP entry %d uses method 99 but has no 0x9901 AES extra field", index)
		}
		// The central directory is authoritative, so the AES extra field names
		// the real compression method.
		method := header.method
		if extra.aes != nil {
			method = extra.aes.method
		}
		encrypted := header.flags&(gpEncrypted|gpStrongEncrypted) != 0 ||
			header.method == methodAES || extra.aes != nil || extra.strong

		modified := extra.mtime
		if modified == nil {
			modified = dosDateTime(header.modifiedDate, header.modifiedTime)
		}

		entry, err := archive.NewEntry(name, kind, uncompressedSize)
		if err != nil {
			return nil, nil, err
		}
		entry.CompressedSize = &compressedSize
		entry.Modified = modified
		crc := header.crc32
		entry.CRC32 = &crc
		entry.Encrypted = encrypted
		if err := budget.Admit(entry); err != nil {
			return nil, nil, err
		}

		entries = append(entries, entry)
		raw = append(raw, zipEntry{
			entry:             entry,
			method:            method,
			compressedSize:    compressedSize,
			localHeaderOffset: localOffset,
		})
	}
	return entries, raw, nil
}

func resolve(value uint32, zip64 *uint64, field string, index int) (uint64, error) {
	if value == 0xFFFFFFFF {
		if zip64 == nil {
			return 0, archive.Invalidf("ZIP entry %d needs a Zip64 %s but has no Zip64 extra field", index, field)
		}
		return *zip64, nil
	}
	return uint64(value), nil
}

type aesExtra struct {
	version  uint16
	strength byte
	method   uint16
}

type extraInfo struct {
	uncompressedSize *uint64
	compressedSize   *uint64
	localOffset      *uint64
	mtime            *int64
	aes              *aesExtra
	strong           bool
}

func parseExtra(extra []byte, header centralHeader) (extraInfo, error) {
	var info extraInfo
	position := 0
	for position+4 <= len(extra) {
		id := u16At(extra, position)
		size := int(u16At(extra, position+2))
		position += 4
		if position+size > len(extra) {
			return info, archive.Invalidf("ZIP extra field extends past the central-directory entry")
		}
		data := extra[position : position+size]
		position += size

		switch id {
		case 0x0001:
			cursor := 0
			if header.uncompressedSize == 0xFFFFFFFF {
				value, err := takeU64(data, &cursor, id)
				if err != nil {
					return info, err
				}
				info.uncompressedSize = &value
			}
			if header.compressedSize == 0xFFFFFFFF {
				value, err := takeU64(data, &cursor, id)
				if err != nil {
					return info, err
				}
				info.compressedSize = &value
			}
			if header.localOffset == 0xFFFFFFFF {
				value, err := takeU64(data, &cursor, id)
				if err != nil {
					return info, err
				}
				info.localOffset = &value
			}
			if header.diskStart == 0xFFFF {
				if cursor+4 > len(data) {
					return info, archive.Invalidf("Zip64 extra field is missing the disk-start value")
				}
				if u32At(data, cursor) != 0 {
					return info, archive.Unsupportedf("ZIP entry starts on another disk")
				}
			}
		case 0x5455:
			// Extended timestamp: the local-time flag is followed by the
			// modification time (UTC) when bit 0 is set.
			if len(data) >= 5 && data[0]&1 != 0 {
				mtime := int64(u32At(data, 1))
				info.mtime = &mtime
			}
		case 0x9901:
			aes, err := parseAESExtra(data)
			if err != nil {
				return info, err
			}
			info.aes = aes
		case 0x0017:
			// PKWARE strong encryption.  This port only needs to recognize the
			// entry as encrypted; it does not decrypt.
			info.strong = true
		}
	}

	if header.diskStart != 0xFFFF && header.diskStart != 0 {
		return info, archive.Unsupportedf("ZIP entry starts on another disk")
	}
	return info, nil
}

func takeU64(data []byte, cursor *int, extraID uint16) (uint64, error) {
	if *cursor+8 > len(data) {
		return 0, archive.Invalidf("Zip64 extra field 0x%04X is truncated", extraID)
	}
	value := u64At(data, *cursor)
	*cursor += 8
	return value, nil
}

func parseAESExtra(data []byte) (*aesExtra, error) {
	if len(data) < 7 {
		return nil, archive.Invalidf("ZIP AES extra field is %d bytes; seven are required", len(data))
	}
	version := u16At(data, 0)
	if version != 1 && version != 2 {
		return nil, archive.Unsupportedf("ZIP AES extra field version %d (only AE-1 and AE-2 are defined)", version)
	}
	if data[2] != 'A' || data[3] != 'E' {
		return nil, archive.Invalidf("ZIP AES extra field does not carry the AE vendor id")
	}
	if data[4] < 1 || data[4] > 3 {
		return nil, archive.Unsupportedf("ZIP AES strength code %d", data[4])
	}
	return &aesExtra{version: version, strength: data[4], method: u16At(data, 5)}, nil
}

func entryKind(name string, versionMade uint16, externalAttrs uint32) archive.Kind {
	host := byte(versionMade >> 8)
	unixMode := externalAttrs >> 16
	if strings.HasSuffix(name, "/") || externalAttrs&0x10 != 0 || (host == 3 && unixMode&0o170000 == 0o040000) {
		return archive.KindDirectory
	}
	if host == 3 && unixMode&0o170000 == 0o120000 {
		return archive.KindSymlink
	}
	return archive.KindFile
}

func localDataOffset(src source.ByteSource, localOffset, compressedSize uint64) (uint64, error) {
	if localOffset > src.Len() || localLen > src.Len()-localOffset {
		return 0, archive.Invalidf("ZIP local header at offset %d is outside the file", localOffset)
	}
	fixed, err := source.ReadVecAt(src, localOffset, localLen)
	if err != nil {
		return 0, err
	}
	if [4]byte(fixed[0:4]) != localSig {
		return 0, archive.Invalidf("bad local-header signature at offset %d", localOffset)
	}
	nameLen := uint64(u16At(fixed, 26))
	extraLen := uint64(u16At(fixed, 28))
	dataOffset := localOffset + localLen
	if dataOffset+nameLen < dataOffset {
		return 0, archive.Invalidf("ZIP local header offset overflows")
	}
	dataOffset += nameLen
	if dataOffset+extraLen < dataOffset {
		return 0, archive.Invalidf("ZIP local header offset overflows")
	}
	dataOffset += extraLen

	if dataOffset > src.Len() || compressedSize > src.Len()-dataOffset {
		return 0, archive.Invalidf("ZIP entry payload [%d, +%d) is outside the file", dataOffset, compressedSize)
	}
	return dataOffset, nil
}

func decodeName(raw []byte, utf8Flag bool) (string, error) {
	if utf8Flag {
		if !utf8.Valid(raw) {
			return "", archive.Invalidf("ZIP entry name is flagged UTF-8 but is not valid UTF-8")
		}
		return string(raw), nil
	}
	// Many tools write UTF-8 without setting the flag.  Accept it when valid;
	// otherwise fall back to the encoding the specification mandates.
	if utf8.Valid(raw) {
		return string(raw), nil
	}
	runes := make([]rune, 0, len(raw))
	for _, b := range raw {
		runes = append(runes, cp437(b))
	}
	return string(runes), nil
}

// Upper half of code page 437, in byte order 0x80..=0xFF.
var cp437Runes = []rune("ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ ")

func cp437(b byte) rune {
	if b < 0x80 {
		return rune(b)
	}
	index := int(b - 0x80)
	if index >= len(cp437Runes) {
		return '�'
	}
	return cp437Runes[index]
}

func dosDateTime(date, time uint16) *int64 {
	year := int64(1980 + (date>>9)&0x7f)
	month := int64((date >> 5) & 0x0f)
	day := int64(date & 0x1f)
	hour := int64((time >> 11) & 0x1f)
	minute := int64((time >> 5) & 0x3f)
	second := int64((time & 0x1f) * 2)

	if month == 0 || month > 12 || day == 0 || day > 31 || hour > 23 || minute > 59 || second > 59 {
		return nil
	}
	days := daysFromCivil(year, month, day)
	value := days*86_400 + hour*3_600 + minute*60 + second
	return &value
}

// daysFromCivil returns days since 1970-01-01 for a proleptic Gregorian date
// (Howard Hinnant's days_from_civil).
func daysFromCivil(year, month, day int64) int64 {
	if month <= 2 {
		year--
	}
	var era int64
	if year >= 0 {
		era = year / 400
	} else {
		era = (year - 399) / 400
	}
	yearOfEra := year - era*400
	monthPrime := (month + 9) % 12
	dayOfYear := (153*monthPrime+2)/5 + day - 1
	dayOfEra := yearOfEra*365 + yearOfEra/4 - yearOfEra/100 + dayOfYear
	return era*146_097 + dayOfEra - 719_468
}
