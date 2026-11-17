package l01

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
)

// catalogLine is one line of the ltree UTF-16 text. raw is set only when the
// line is not well-formed UTF-16; text then carries the lossy decoding.
type catalogLine struct {
	text string
	raw  []uint16
}

// catalog is the parsed ltree payload.
type catalog struct {
	entries      []Entry
	root         int
	dataSize     uint64
	dataSizeSet  bool
	md5Present   bool
	md5OK        bool
	adlerPresent bool
	adlerOK      bool
	sources      []SourceRecord
	subjects     []Subject
}

func parseLTree(data []byte, limits Limits, warnings *[]string) (catalog, error) {
	var result catalog
	if len(data) < LTreeHeaderBytes {
		return result, corrupt(0, fmt.Sprintf(
			"ltree section is truncated: %d bytes, needs at least %d", len(data), LTreeHeaderBytes))
	}

	var storedMD5 [16]byte
	copy(storedMD5[:], data[:16])
	textSize := binary.LittleEndian.Uint64(data[ltreeTextSizeFieldOffset:])
	if textSize > limits.MaxLTreeBytes {
		return result, unsupported(fmt.Sprintf(
			"ltree text of %d bytes exceeds the configured bound %d", textSize, limits.MaxLTreeBytes))
	}
	textEnd, ok := checkedAdd(LTreeHeaderBytes, textSize)
	if !ok {
		return result, corrupt(16, "ltree text size overflows")
	}
	if textEnd > uint64(len(data)) {
		return result, corrupt(LTreeHeaderBytes, fmt.Sprintf(
			"ltree text of %d bytes is truncated: section payload is %d bytes", textSize, len(data)))
	}

	storedAdler := binary.LittleEndian.Uint32(data[ltreeAdlerFieldOffset:])
	if storedAdler != 0 {
		header := append([]byte(nil), data[:LTreeHeaderBytes]...)
		clear(header[24:28])
		computed := adler32Checksum(header)
		if computed != storedAdler {
			return result, corrupt(24, fmt.Sprintf(
				"ltree header Adler-32 mismatch: stored %08x, computed %08x", storedAdler, computed))
		}
		result.adlerPresent = true
		result.adlerOK = true
	}

	textBytes := data[LTreeHeaderBytes:textEnd]
	allZero := true
	for _, value := range storedMD5 {
		if value != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		computed := md5.Sum(textBytes)
		if computed != storedMD5 {
			return result, corrupt(0, "ltree text MD5 does not match the integrity hash in its header")
		}
		result.md5Present = true
		result.md5OK = true
	}

	lines, err := decodeLines(textBytes)
	if err != nil {
		return result, err
	}
	if len(lines) == 0 || lines[0].text != "5" {
		return result, corrupt(0, "ltree catalog has an unsupported category count (expected the text `5`)")
	}

	index := 1
	dataSize, dataSizeSet, next, err := parseRecordCategory(lines, index)
	if err != nil {
		return result, err
	}
	result.dataSize = dataSize
	result.dataSizeSet = dataSizeSet
	index = next

	index, err = parseFlatCategory(lines, index, "perm", limits, warnings, nil)
	if err != nil {
		return result, err
	}
	index, err = parseFlatCategory(lines, index, "srce", limits, warnings,
		func(types []string, line catalogLine, lineNumber int) {
			if record, ok := parseSourceRow(types, line, lineNumber, warnings); ok {
				result.sources = append(result.sources, record)
			}
		})
	if err != nil {
		return result, err
	}
	index, err = parseFlatCategory(lines, index, "sub", limits, warnings,
		func(types []string, line catalogLine, lineNumber int) {
			if record, ok := parseSubjectRow(types, line, lineNumber, warnings); ok {
				result.subjects = append(result.subjects, record)
			}
		})
	if err != nil {
		return result, err
	}

	entries, root, _, err := parseEntryCategory(lines, index, limits, warnings)
	if err != nil {
		return result, err
	}
	result.entries = entries
	result.root = root
	return result, nil
}

func decodeLines(data []byte) ([]catalogLine, error) {
	if len(data)%2 != 0 {
		return nil, corrupt(0, fmt.Sprintf("ltree text has an odd UTF-16 byte size (%d)", len(data)))
	}
	units := make([]uint16, len(data)/2)
	for index := range units {
		units[index] = binary.LittleEndian.Uint16(data[index*2:])
	}
	if len(units) > 0 && units[0] == 0xfeff {
		units = units[1:]
	}
	parts := splitUnits(units, '\n')
	lines := make([]catalogLine, 0, len(parts))
	for _, part := range parts {
		if len(part) > 0 && part[len(part)-1] == '\r' {
			part = part[:len(part)-1]
		}
		line := catalogLine{text: string(utf16.Decode(part))}
		if !validUTF16(part) {
			line.raw = append([]uint16(nil), part...)
		}
		lines = append(lines, line)
	}
	return lines, nil
}

func splitUnits(units []uint16, separator uint16) [][]uint16 {
	parts := make([][]uint16, 0, 8)
	start := 0
	for index, unit := range units {
		if unit == separator {
			parts = append(parts, units[start:index])
			start = index + 1
		}
	}
	return append(parts, units[start:])
}

func validUTF16(units []uint16) bool {
	for index := 0; index < len(units); index++ {
		unit := units[index]
		switch {
		case unit >= 0xd800 && unit <= 0xdbff:
			if index+1 >= len(units) {
				return false
			}
			next := units[index+1]
			if next < 0xdc00 || next > 0xdfff {
				return false
			}
			index++
		case unit >= 0xdc00 && unit <= 0xdfff:
			return false
		}
	}
	return true
}

func parseRecordCategory(lines []catalogLine, index int) (uint64, bool, int, error) {
	if err := requireCategory(lines, index, "rec"); err != nil {
		return 0, false, 0, err
	}
	typesLine, err := lineAt(lines, index+1, "record type line")
	if err != nil {
		return 0, false, 0, err
	}
	types, err := parseTypeLine(typesLine, "rec")
	if err != nil {
		return 0, false, 0, err
	}
	valuesLine, err := lineAt(lines, index+2, "record value line")
	if err != nil {
		return 0, false, 0, err
	}
	if err := requireEmpty(lines, index+3, "record category terminator"); err != nil {
		return 0, false, 0, err
	}
	values := strings.Split(valuesLine.text, "\t")
	for position, kind := range types {
		if kind != "tb" {
			continue
		}
		if position >= len(values) || values[position] == "" {
			return 0, false, index + 4, nil
		}
		size, err := parseU64(values[position], "record data size", index+2)
		if err != nil {
			return 0, false, 0, err
		}
		return size, true, index + 4, nil
	}
	return 0, false, index + 4, nil
}

// parseFlatCategory validates a perm/srce/sub style category. rowFn is called
// for the category root and every group/child row; it may be nil to skip them.
func parseFlatCategory(lines []catalogLine, index int, name string, limits Limits, warnings *[]string,
	rowFn func(types []string, line catalogLine, lineNumber int)) (int, error) {

	if err := requireCategory(lines, index, name); err != nil {
		return 0, err
	}
	countLine, err := lineAt(lines, index+1, name+" count line")
	if err != nil {
		return 0, err
	}
	entryCount, marker, err := parsePair(countLine, name+" count line", index+1)
	if err != nil {
		return 0, err
	}
	if marker != 1 {
		*warnings = append(*warnings, fmt.Sprintf(
			"ltree `%s` category line %d has %d where 1 was expected", name, index+1, marker))
	}
	if entryCount > uint64(limits.MaxEntries) {
		return 0, unsupported(fmt.Sprintf(
			"ltree `%s` category declares %d entries, above the configured bound %d",
			name, entryCount, limits.MaxEntries))
	}

	typesLine, err := lineAt(lines, index+2, name+" type line")
	if err != nil {
		return 0, err
	}
	types, err := parseTypeLine(typesLine, name)
	if err != nil {
		return 0, err
	}

	rootCountLine, err := lineAt(lines, index+3, name+" category root count")
	if err != nil {
		return 0, err
	}
	zero, copyCount, err := parsePair(rootCountLine, name+" category root count", index+3)
	if err != nil {
		return 0, err
	}
	if zero != 0 {
		*warnings = append(*warnings, fmt.Sprintf(
			"ltree `%s` category root count at line %d starts with %d, expected 0", name, index+3, zero))
	}
	if copyCount != entryCount {
		*warnings = append(*warnings, fmt.Sprintf(
			"ltree `%s` category declares %d entries but its root records %d", name, entryCount, copyCount))
	}

	cursor := index + 4
	rootLine, err := lineAt(lines, cursor, name+" category root row")
	if err != nil {
		return 0, err
	}
	if rowFn != nil {
		rowFn(types, rootLine, cursor)
	}
	cursor++

	for group := uint64(0); group < entryCount; group++ {
		groupCount, err := lineAt(lines, cursor, fmt.Sprintf("%s group %d count", name, group))
		if err != nil {
			return 0, err
		}
		parent, children, err := parsePair(groupCount, fmt.Sprintf("%s group %d count", name, group), cursor)
		if err != nil {
			return 0, err
		}
		if parent != 0 {
			*warnings = append(*warnings, fmt.Sprintf(
				"ltree `%s` group %d count line %d starts with %d, expected 0", name, group, cursor, parent))
		}
		cursor++
		groupLine, err := lineAt(lines, cursor, fmt.Sprintf("%s group %d row", name, group))
		if err != nil {
			return 0, err
		}
		if rowFn != nil {
			rowFn(types, groupLine, cursor)
		}
		cursor++
		if children > uint64(limits.MaxEntries) {
			return 0, unsupported(fmt.Sprintf(
				"ltree `%s` group %d declares %d children, above the configured bound %d",
				name, group, children, limits.MaxEntries))
		}
		for child := uint64(0); child < children; child++ {
			childCount, err := lineAt(lines, cursor, fmt.Sprintf("%s group %d child %d count", name, group, child))
			if err != nil {
				return 0, err
			}
			childParent, childChildren, err := parsePair(childCount,
				fmt.Sprintf("%s group %d child %d count", name, group, child), cursor)
			if err != nil {
				return 0, err
			}
			if childParent != 0 || childChildren != 0 {
				return 0, corrupt(0, fmt.Sprintf(
					"ltree `%s` group %d child %d count line %d is `%d\\t%d`, expected `0\\t0`",
					name, group, child, cursor, childParent, childChildren))
			}
			cursor++
			childLine, err := lineAt(lines, cursor, fmt.Sprintf("%s group %d child %d row", name, group, child))
			if err != nil {
				return 0, err
			}
			if rowFn != nil {
				rowFn(types, childLine, cursor)
			}
			cursor++
		}
	}
	if err := requireEmpty(lines, cursor, fmt.Sprintf("%s category terminator", name)); err != nil {
		return 0, err
	}
	return cursor + 1, nil
}

func parseEntryCategory(lines []catalogLine, index int, limits Limits, warnings *[]string) ([]Entry, int, int, error) {
	if err := requireCategory(lines, index, "entry"); err != nil {
		return nil, 0, 0, err
	}
	countLine, err := lineAt(lines, index+1, "entry count line")
	if err != nil {
		return nil, 0, 0, err
	}
	first, marker, err := parsePair(countLine, "entry count line", index+1)
	if err != nil {
		return nil, 0, 0, err
	}
	if marker != 1 {
		*warnings = append(*warnings, fmt.Sprintf(
			"ltree `entry` category line %d has %d where 1 was expected", index+1, marker))
	}
	if first > uint64(limits.MaxEntries) {
		return nil, 0, 0, unsupported(fmt.Sprintf(
			"ltree `entry` category declares %d entries, above the configured bound %d", first, limits.MaxEntries))
	}
	typesLine, err := lineAt(lines, index+2, "entry type line")
	if err != nil {
		return nil, 0, 0, err
	}
	types, err := parseTypeLine(typesLine, "entry")
	if err != nil {
		return nil, 0, 0, err
	}

	cursor := index + 3
	rootLine, err := lineAt(lines, cursor, "entry root")
	if err != nil {
		return nil, 0, 0, err
	}
	if rootLine.text == "" {
		return nil, 0, 0, corrupt(0, fmt.Sprintf(
			"ltree entry category has no root entry (line %d is empty)", cursor))
	}

	entries := make([]Entry, 0, 8)
	root, err := parseEntry(lines, types, &cursor, -1, 0, limits, &entries, warnings)
	if err != nil {
		return nil, 0, 0, err
	}
	if cursor < len(lines) && lines[cursor].text == "" {
		cursor++
	} else if cursor < len(lines) {
		*warnings = append(*warnings, fmt.Sprintf(
			"ltree entry category has trailing content at line %d", cursor))
	}
	return entries, root, cursor, nil
}

func parseEntry(lines []catalogLine, types []string, cursor *int, parent, depth int,
	limits Limits, entries *[]Entry, warnings *[]string) (int, error) {

	if depth > limits.MaxDepth {
		return 0, unsupported(fmt.Sprintf(
			"catalog entry nesting depth %d exceeds the configured bound %d", depth, limits.MaxDepth))
	}
	if len(*entries) >= limits.MaxEntries {
		return 0, unsupported(fmt.Sprintf(
			"catalog entry count exceeds the configured bound %d", limits.MaxEntries))
	}

	countLineIndex := *cursor
	countLine, err := lineAt(lines, *cursor, "entry child count")
	if err != nil {
		return 0, err
	}
	parentMarker, childCount, err := parsePair(countLine, "entry child count", *cursor)
	if err != nil {
		return 0, err
	}
	if parentMarker != 0 && parentMarker != 26 {
		*warnings = append(*warnings, fmt.Sprintf(
			"ltree entry at line %d has parent marker %d, expected 0 or 26", countLineIndex, parentMarker))
	}
	*cursor++
	if childCount > uint64(limits.MaxEntries) {
		return 0, unsupported(fmt.Sprintf(
			"catalog entry at line %d declares %d children, above the configured bound %d",
			countLineIndex, childCount, limits.MaxEntries))
	}

	rowLineIndex := *cursor
	rowLine, err := lineAt(lines, *cursor, "entry value row")
	if err != nil {
		return 0, err
	}
	*cursor++

	index := len(*entries)
	entry, err := parseEntryRow(types, rowLine, index, parent, depth, rowLineIndex, warnings)
	if err != nil {
		return 0, err
	}
	*entries = append(*entries, entry)

	for child := uint64(0); child < childCount; child++ {
		childIndex, err := parseEntry(lines, types, cursor, index, depth+1, limits, entries, warnings)
		if err != nil {
			return 0, err
		}
		(*entries)[index].Children = append((*entries)[index].Children, childIndex)
	}
	return index, nil
}

func parseEntryRow(types []string, line catalogLine, index, parent, depth, lineNumber int,
	warnings *[]string) (Entry, error) {

	entry := Entry{Index: index, Parent: parent, Depth: depth}
	textValues := strings.Split(line.text, "\t")
	var rawValues [][]uint16
	if line.raw != nil {
		rawValues = splitUnits(line.raw, '\t')
	}
	if len(textValues) > len(types) {
		extraNonEmpty := false
		for _, value := range textValues[len(types):] {
			if value != "" {
				extraNonEmpty = true
				break
			}
		}
		if extraNonEmpty {
			*warnings = append(*warnings, fmt.Sprintf(
				"ltree entry row %d has %d values for %d type indicators",
				lineNumber, len(textValues), len(types)))
		}
	}

	for position, kind := range types {
		value := ""
		if position < len(textValues) {
			value = textValues[position]
		}
		if rawValues != nil && position < len(rawValues) && !validUTF16(rawValues[position]) {
			if kind == "n" {
				entry.NameUTF16 = append([]uint16(nil), rawValues[position]...)
			} else {
				return Entry{}, corrupt(0, fmt.Sprintf(
					"ltree entry row %d field `%s` is not valid UTF-16", lineNumber, kind))
			}
		}
		if value == "" {
			if kind == "p" {
				entry.Kind = KindFile
			}
			continue
		}
		switch kind {
		case "id":
			parsed, err := parseU64(value, "identifier", lineNumber)
			if err != nil {
				return Entry{}, err
			}
			entry.ID = &parsed
		case "p":
			switch value {
			case "1", "d", "D":
				entry.Kind = KindDirectory
			case "0", "f", "F":
				entry.Kind = KindFile
			default:
				*warnings = append(*warnings, fmt.Sprintf(
					"ltree entry row %d has undefined `p` value `%s`", lineNumber, value))
				entry.Kind = KindUnknown
			}
		case "n":
			if entry.Name == "" {
				entry.Name = value
			}
		case "ls":
			parsed, err := parseU64(value, "file size", lineNumber)
			if err != nil {
				return Entry{}, err
			}
			entry.Size = &parsed
		case "lo":
			parsed, err := parseI64(value, "logical offset", lineNumber)
			if err != nil {
				return Entry{}, err
			}
			entry.LogicalOffset = &parsed
		case "po":
			parsed, err := parseI64(value, "physical offset", lineNumber)
			if err != nil {
				return Entry{}, err
			}
			entry.PhysicalOffset = &parsed
		case "du":
			parsed, err := parseI64(value, "duplicate data offset", lineNumber)
			if err != nil {
				return Entry{}, err
			}
			entry.DuplicateDataOffset = &parsed
		case "src":
			parsed, err := parseI64(value, "source identifier", lineNumber)
			if err != nil {
				return Entry{}, err
			}
			if parsed < 0 || parsed > 2147483647 {
				return Entry{}, corrupt(0, fmt.Sprintf(
					"ltree entry row %d source identifier %d is outside i32", lineNumber, parsed))
			}
			converted := int32(parsed)
			entry.SourceID = &converted
		case "sub":
			parsed, err := parseU32(value, "subject identifier", lineNumber)
			if err != nil {
				return Entry{}, err
			}
			entry.SubjectID = &parsed
		case "pm":
			parsed, err := parseI32(value, "permission group index", lineNumber)
			if err != nil {
				return Entry{}, err
			}
			entry.PermissionGroup = &parsed
		case "cid":
			parsed, err := parseU32(value, "record type", lineNumber)
			if err != nil {
				return Entry{}, err
			}
			entry.RecordType = &parsed
		case "opr":
			parsed, err := parseU32(value, "entry flags", lineNumber)
			if err != nil {
				return Entry{}, err
			}
			entry.Flags = &parsed
		case "be":
			parsed, err := parseExtents(value, lineNumber)
			if err != nil {
				return Entry{}, err
			}
			entry.Extents = parsed
		case "ha":
			parsed, err := parseHash(value, "MD5", 32, lineNumber)
			if err != nil {
				return Entry{}, err
			}
			entry.MD5 = parsed
		case "sha":
			parsed, err := parseHash(value, "SHA-1", 40, lineNumber)
			if err != nil {
				return Entry{}, err
			}
			entry.SHA1 = parsed
		case "snh":
			parsed, err := parseShortName(value, lineNumber)
			if err != nil {
				return Entry{}, err
			}
			entry.ShortName = parsed
		case "cr":
			parsed, err := parseI64(value, "creation time", lineNumber)
			if err != nil {
				return Entry{}, err
			}
			entry.CreationTime = &parsed
		case "wr":
			parsed, err := parseI64(value, "modification time", lineNumber)
			if err != nil {
				return Entry{}, err
			}
			entry.ModificationTime = &parsed
		case "ac":
			parsed, err := parseI64(value, "access time", lineNumber)
			if err != nil {
				return Entry{}, err
			}
			entry.AccessTime = &parsed
		case "mo":
			parsed, err := parseI64(value, "entry modification time", lineNumber)
			if err != nil {
				return Entry{}, err
			}
			entry.EntryModificationTime = &parsed
		case "dl":
			parsed, err := parseI64(value, "deletion time", lineNumber)
			if err != nil {
				return Entry{}, err
			}
			entry.DeletionTime = &parsed
		default:
			// `ea`, `mid` and future indicators are not interpreted.
		}
	}
	return entry, nil
}

func parseExtents(value string, lineNumber int) ([]Extent, error) {
	parts := strings.Fields(value)
	if len(parts) == 0 {
		return nil, corrupt(0, fmt.Sprintf(
			"ltree entry row %d `be` value has no extent count", lineNumber))
	}
	count, err := strconv.ParseUint(parts[0], 16, 64)
	if err != nil {
		return nil, corrupt(0, fmt.Sprintf(
			"ltree entry row %d `be` extent count `%s` is not hex", lineNumber, parts[0]))
	}
	if count > maxExtentCountPerEntry {
		return nil, unsupported(fmt.Sprintf(
			"ltree entry row %d declares %d extents, above the reader bound", lineNumber, count))
	}
	extents := make([]Extent, 0, count)
	position := 1
	for position < len(parts) {
		sparse := false
		if parts[position] == "S" {
			sparse = true
			position++
		}
		if position+1 >= len(parts) {
			return nil, corrupt(0, fmt.Sprintf(
				"ltree entry row %d extent is missing its offset or size", lineNumber))
		}
		offset, err := strconv.ParseUint(parts[position], 16, 64)
		if err != nil {
			return nil, corrupt(0, fmt.Sprintf(
				"ltree entry row %d extent offset `%s` is not hex", lineNumber, parts[position]))
		}
		size, err := strconv.ParseUint(parts[position+1], 16, 64)
		if err != nil {
			return nil, corrupt(0, fmt.Sprintf(
				"ltree entry row %d extent size `%s` is not hex", lineNumber, parts[position+1]))
		}
		position += 2
		extents = append(extents, Extent{Offset: offset, Size: size, Sparse: sparse})
		if uint64(len(extents)) > count {
			return nil, corrupt(0, fmt.Sprintf(
				"ltree entry row %d has more extents than its declared %d", lineNumber, count))
		}
	}
	if uint64(len(extents)) != count {
		return nil, corrupt(0, fmt.Sprintf(
			"ltree entry row %d declares %d extents but carries %d", lineNumber, count, len(extents)))
	}
	return extents, nil
}

func parseHash(value, label string, expectedLength, lineNumber int) (string, error) {
	if !isHexString(value) {
		return "", corrupt(0, fmt.Sprintf(
			"ltree entry row %d %s value is not hexadecimal", lineNumber, label))
	}
	if len(value) != expectedLength {
		return "", corrupt(0, fmt.Sprintf(
			"ltree entry row %d %s value has %d hex digits, expected %d",
			lineNumber, label, len(value), expectedLength))
	}
	allZero := true
	for index := 0; index < len(value); index++ {
		if value[index] != '0' {
			allZero = false
			break
		}
	}
	if allZero {
		return "", nil
	}
	return strings.ToLower(value), nil
}

func parseShortName(value string, lineNumber int) (string, error) {
	parts := strings.Split(value, " ")
	if len(parts) != 2 {
		if len(parts) < 2 {
			return "", corrupt(0, fmt.Sprintf(
				"ltree entry row %d short name has no value", lineNumber))
		}
		return "", corrupt(0, fmt.Sprintf(
			"ltree entry row %d short name has too many values", lineNumber))
	}
	declared, err := parseU64(parts[0], "short name size", lineNumber)
	if err != nil {
		return "", err
	}
	actual := uint64(len(parts[1]) + 1)
	if declared != actual {
		return "", corrupt(0, fmt.Sprintf(
			"ltree entry row %d short name declares %d bytes but is %d",
			lineNumber, declared, actual))
	}
	return parts[1], nil
}

func parseSourceRow(types []string, line catalogLine, lineNumber int, warnings *[]string) (SourceRecord, bool) {
	if line.text == "" {
		return SourceRecord{}, false
	}
	values := strings.Split(line.text, "\t")
	record := SourceRecord{}
	nonEmpty := false
	for position, kind := range types {
		if position >= len(values) {
			break
		}
		value := values[position]
		if value == "" {
			continue
		}
		nonEmpty = true
		switch kind {
		case "id":
			parsed, err := parseI32(value, "source identifier", lineNumber)
			if err != nil || parsed < 0 {
				appendSourceWarning(warnings, lineNumber, kind)
				continue
			}
			record.Identifier = &parsed
		case "n":
			record.Name = value
		case "ev":
			record.EvidenceNumber = value
		case "loc":
			record.Location = value
		case "gu":
			record.DeviceGUID = parseHexString(value, warnings, lineNumber, kind)
		case "pgu":
			record.PrimaryDeviceGUID = parseHexString(value, warnings, lineNumber, kind)
		case "dt":
			record.DriveType = value
		case "mfr":
			record.Manufacturer = value
		case "mo":
			record.Model = value
		case "se":
			record.SerialNumber = value
		case "do":
			record.Domain = value
		case "ip":
			record.IPAddress = value
		case "ma":
			record.MACAddress = parseHexString(value, warnings, lineNumber, kind)
		case "tb":
			parsed, err := parseU64(value, "source size", lineNumber)
			if err != nil {
				appendSourceWarning(warnings, lineNumber, kind)
				continue
			}
			record.Size = &parsed
		case "lo":
			parsed, err := parseI64(value, "source logical offset", lineNumber)
			if err != nil {
				appendSourceWarning(warnings, lineNumber, kind)
				continue
			}
			record.LogicalOffset = &parsed
		case "po":
			parsed, err := parseI64(value, "source physical offset", lineNumber)
			if err != nil {
				appendSourceWarning(warnings, lineNumber, kind)
				continue
			}
			record.PhysicalOffset = &parsed
		case "aq":
			parsed, err := parseI64(value, "source acquisition time", lineNumber)
			if err != nil {
				appendSourceWarning(warnings, lineNumber, kind)
				continue
			}
			record.AcquisitionTime = &parsed
		case "ah":
			record.MD5 = parseHexString(value, warnings, lineNumber, kind)
		case "sh":
			record.SHA1 = parseHexString(value, warnings, lineNumber, kind)
		}
	}
	return record, nonEmpty
}

func parseSubjectRow(types []string, line catalogLine, lineNumber int, warnings *[]string) (Subject, bool) {
	if line.text == "" {
		return Subject{}, false
	}
	values := strings.Split(line.text, "\t")
	record := Subject{}
	nonEmpty := false
	for position, kind := range types {
		if position >= len(values) {
			break
		}
		value := values[position]
		if value == "" {
			continue
		}
		nonEmpty = true
		switch kind {
		case "id":
			parsed, err := parseU32(value, "subject identifier", lineNumber)
			if err != nil {
				*warnings = append(*warnings, fmt.Sprintf(
					"ltree subject row %d field `id` is not a u32", lineNumber))
				continue
			}
			record.Identifier = &parsed
		case "n":
			record.Name = value
		}
	}
	return record, nonEmpty
}

func parseHexString(value string, warnings *[]string, lineNumber int, kind string) string {
	if !isHexString(value) {
		*warnings = append(*warnings, fmt.Sprintf(
			"ltree source row %d field `%s` is not hexadecimal", lineNumber, kind))
		return ""
	}
	allZero := true
	for index := 0; index < len(value); index++ {
		if value[index] != '0' {
			allZero = false
			break
		}
	}
	if allZero {
		return ""
	}
	return strings.ToLower(value)
}

func appendSourceWarning(warnings *[]string, lineNumber int, kind string) {
	*warnings = append(*warnings, fmt.Sprintf(
		"ltree source row %d field `%s` could not be parsed and was ignored", lineNumber, kind))
}

func isHexString(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') &&
			(character < 'A' || character > 'F') {
			return false
		}
	}
	return true
}

func requireCategory(lines []catalogLine, index int, expected string) error {
	line, err := lineAt(lines, index, "category")
	if err != nil {
		return err
	}
	if line.text != expected {
		return corrupt(0, fmt.Sprintf(
			"ltree catalog is missing the `%s` category at line %d (found `%s`)", expected, index, line.text))
	}
	return nil
}

func lineAt(lines []catalogLine, index int, what string) (catalogLine, error) {
	if index < 0 || index >= len(lines) {
		return catalogLine{}, corrupt(0, fmt.Sprintf(
			"ltree catalog is truncated: %s is missing at line %d", what, index))
	}
	return lines[index], nil
}

func requireEmpty(lines []catalogLine, index int, what string) error {
	line, err := lineAt(lines, index, what)
	if err != nil {
		return err
	}
	if line.text != "" {
		return corrupt(0, fmt.Sprintf(
			"%s at line %d is not an empty line (found `%s`)", what, index, line.text))
	}
	return nil
}

func parseTypeLine(line catalogLine, label string) ([]string, error) {
	types := strings.Split(line.text, "\t")
	if len(types) == 0 {
		return nil, corrupt(0, fmt.Sprintf(
			"ltree `%s` type line contains an empty type indicator", label))
	}
	for _, value := range types {
		if value == "" {
			return nil, corrupt(0, fmt.Sprintf(
				"ltree `%s` type line contains an empty type indicator", label))
		}
	}
	if len(types) > maxCatalogTypeIndicators {
		return nil, unsupported(fmt.Sprintf(
			"ltree `%s` type line has %d indicators, above the reader bound 256", label, len(types)))
	}
	return types, nil
}

func parsePair(line catalogLine, label string, lineNumber int) (uint64, uint64, error) {
	parts := strings.Split(line.text, "\t")
	if len(parts) < 2 {
		return 0, 0, corrupt(0, fmt.Sprintf(
			"ltree %s at line %d has only one value", label, lineNumber))
	}
	if len(parts) > 2 {
		return 0, 0, corrupt(0, fmt.Sprintf(
			"ltree %s at line %d has more than two values", label, lineNumber))
	}
	first, err := parseU64(parts[0], label, lineNumber)
	if err != nil {
		return 0, 0, err
	}
	second, err := parseU64(parts[1], label, lineNumber)
	if err != nil {
		return 0, 0, err
	}
	return first, second, nil
}

func parseU64(value, label string, lineNumber int) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, corrupt(0, fmt.Sprintf(
			"ltree %s at line %d is not an unsigned integer: `%s`", label, lineNumber, value))
	}
	return parsed, nil
}

func parseU32(value, label string, lineNumber int) (uint32, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, corrupt(0, fmt.Sprintf(
			"ltree %s at line %d does not fit u32: %s", label, lineNumber, value))
	}
	return uint32(parsed), nil
}

func parseI64(value, label string, lineNumber int) (int64, error) {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, corrupt(0, fmt.Sprintf(
			"ltree %s at line %d is not a signed integer: `%s`", label, lineNumber, value))
	}
	return parsed, nil
}

func parseI32(value, label string, lineNumber int) (int32, error) {
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return 0, corrupt(0, fmt.Sprintf(
			"ltree %s at line %d does not fit i32: %s", label, lineNumber, value))
	}
	return int32(parsed), nil
}
