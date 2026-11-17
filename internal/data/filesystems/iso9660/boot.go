package iso9660

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	bootEntryBytes  = 32
	maxCatalogBytes = 32 * 1024
)

// BootEntry is one bootable (or explicitly non-bootable) image entry.
type BootEntry struct {
	Section     int
	Index       int
	Bootable    bool
	Media       uint8
	MediaLabel  string
	LoadSegment uint16
	SystemType  uint8
	SectorCount uint16
	LoadRBA     uint32
}

// BootSection is a section header and how many entries it declares.
type BootSection struct {
	Platform      uint8
	PlatformLabel string
	Name          string
	Declared      int
	FinalSection  bool
}

// BootCatalog is a decoded El Torito boot catalog.
type BootCatalog struct {
	Platform      uint8
	PlatformLabel string
	ID            string
	ChecksumOK    bool
	KeyOK         bool
	Initial       *BootEntry
	Entries       []BootEntry
	Sections      []BootSection
	Extensions    int
	Warnings      []string
}

// BootableEntries returns the bootable images the catalog lists.
func (c *BootCatalog) BootableEntries() int {
	count := 0
	if c.Initial != nil && c.Initial.Bootable {
		count++
	}
	for i := range c.Entries {
		if c.Entries[i].Bootable {
			count++
		}
	}
	return count
}

func bootPlatformLabel(platform uint8) string {
	switch platform {
	case 0x00:
		return "x86"
	case 0x01:
		return "PowerPC"
	case 0x02:
		return "Mac"
	case 0xEF:
		return "EFI"
	default:
		return "unknown"
	}
}

func bootMediaLabel(media uint8) string {
	switch media {
	case 0:
		return "no emulation"
	case 1:
		return "1.2 MB floppy"
	case 2:
		return "1.44 MB floppy"
	case 3:
		return "2.88 MB floppy"
	case 4:
		return "hard disk"
	default:
		return "unknown"
	}
}

// parseBootCatalog parses a catalog sector (or the leading sectors of one).
func parseBootCatalog(bytes []byte) (*BootCatalog, error) {
	if len(bytes) < 2*bootEntryBytes {
		return nil, fmt.Errorf("the boot catalog is %d bytes, shorter than its validation and initial entries", len(bytes))
	}
	if bytes[0] != 0x01 {
		return nil, fmt.Errorf("boot catalog validation entry starts with 0x%02x, not 0x01", bytes[0])
	}
	var warnings []string
	platform := bytes[1]
	id := trimBootText(bytes[4:28])
	checksumOK := bootChecksum(bytes[:bootEntryBytes]) == 0
	if !checksumOK {
		warnings = append(warnings, "validation entry checksum does not sum to zero")
	}
	keyOK := bytes[30] == 0x55 && bytes[31] == 0xAA
	if !keyOK {
		warnings = append(warnings, "validation entry key is not 0x55 0xAA")
	}
	initial := bootEntry(bytes[bootEntryBytes:2*bootEntryBytes], 0, 0)

	var entries []BootEntry
	var sections []BootSection
	extensions := 0
	at := 2 * bootEntryBytes
	for at+bootEntryBytes <= len(bytes) {
		header := bytes[at : at+bootEntryBytes]
		indicator := header[0]
		if indicator != 0x90 && indicator != 0x91 {
			warnings = append(warnings, fmt.Sprintf("unsupported catalog record 0x%02x at catalog offset %d", indicator, at))
			break
		}
		sectionPlatform := header[1]
		declared := int(binary.LittleEndian.Uint16(header[2:4]))
		sections = append(sections, BootSection{
			Platform:      sectionPlatform,
			PlatformLabel: bootPlatformLabel(sectionPlatform),
			Name:          trimBootText(header[4:bootEntryBytes]),
			Declared:      declared,
			FinalSection:  indicator == 0x90,
		})
		section := len(sections)
		at += bootEntryBytes
		index := 0
		for index < declared {
			if at+bootEntryBytes > len(bytes) {
				warnings = append(warnings, fmt.Sprintf(
					"catalog section %d declares %d entries but the catalog ends after %d",
					section, declared, index))
				at = len(bytes)
				break
			}
			raw := bytes[at : at+bootEntryBytes]
			if raw[0] == 0x88 || raw[0] == 0x00 {
				entries = append(entries, bootEntry(raw, section, index))
			} else {
				extensions++
			}
			index++
			at += bootEntryBytes
		}
		if indicator == 0x90 {
			break
		}
	}
	return &BootCatalog{
		Platform:      platform,
		PlatformLabel: bootPlatformLabel(platform),
		ID:            id,
		ChecksumOK:    checksumOK,
		KeyOK:         keyOK,
		Initial:       &initial,
		Entries:       entries,
		Sections:      sections,
		Extensions:    extensions,
		Warnings:      warnings,
	}, nil
}

func bootEntry(raw []byte, section, index int) BootEntry {
	media := raw[1]
	return BootEntry{
		Section:     section,
		Index:       index,
		Bootable:    raw[0] == 0x88,
		Media:       media,
		MediaLabel:  bootMediaLabel(media),
		LoadSegment: binary.LittleEndian.Uint16(raw[2:4]),
		SystemType:  raw[4],
		SectorCount: binary.LittleEndian.Uint16(raw[6:8]),
		LoadRBA:     binary.LittleEndian.Uint32(raw[8:12]),
	}
}

func bootChecksum(bytes []byte) uint16 {
	var sum uint16
	for i := 0; i+2 <= len(bytes); i += 2 {
		sum += binary.LittleEndian.Uint16(bytes[i:])
	}
	return sum
}

func trimBootText(bytes []byte) string {
	end := 0
	for end < len(bytes) && bytes[end] != 0 {
		end++
	}
	return strings.TrimSpace(latin1String(bytes[:end]))
}
