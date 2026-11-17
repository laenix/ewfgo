package partition

import (
	"fmt"
	"hash/crc32"
	"unicode/utf16"

	"github.com/laenix/ewfgo/internal/data/source"
)

// GPTSignature is the eight-byte header signature at LBA 1 and the last LBA.
const GPTSignature = "EFI PART"

const (
	gptZeroGUID      = "00000000-0000-0000-0000-000000000000"
	gptMinHeaderSize = 92
	gptMaxEntries    = 4096
	gptMaxEntrySize  = 4096
	gptMaxEntryBytes = 16 * 1024 * 1024
	gptMinEntrySize  = 128
)

// ParseGPT reads the primary GPT header and entry array at LBA 1.
func ParseGPT(src source.ByteSource, secSize uint64) (*GPTTable, error) {
	return parseGPTCopy(src, secSize, 1, CopyPrimary)
}

// ParseGPTBackup reads the backup header at the last LBA, if there is one.
//
// A nil table with a nil error means the last sector holds no GPT signature,
// which is normal for an MBR disk or an image truncated before its last
// sector. A header that is present but does not verify is an error: the caller
// decides whether the primary already said enough.
func ParseGPTBackup(src source.ByteSource, secSize uint64) (*GPTTable, error) {
	if secSize < 512 || secSize&(secSize-1) != 0 {
		return nil, invalid("invalid GPT sector size %d", secSize)
	}
	if src.Len() < secSize*2 {
		return nil, nil
	}
	lastLBA := src.Len()/secSize - 1
	if lastLBA < 2 {
		return nil, nil
	}
	signature, err := source.ReadVecAt(src, lastLBA*secSize, uint64(len(GPTSignature)))
	if err != nil {
		return nil, err
	}
	if string(signature) != GPTSignature {
		return nil, nil
	}
	return parseGPTCopy(src, secSize, lastLBA, CopyBackup)
}

// parseGPTCopy parses and verifies the header at headerLBA. The header is
// required to agree that it sits at that LBA: a header found elsewhere is
// stale, copied from another disk, or was moved, and its entry array does not
// describe the disk it was read from.
func parseGPTCopy(src source.ByteSource, secSize, headerLBA uint64, copy Copy) (*GPTTable, error) {
	if secSize < 512 || secSize&(secSize-1) != 0 {
		return nil, invalid("invalid GPT sector size %d", secSize)
	}

	headerOffset, ok := checkedMul(headerLBA, secSize)
	if !ok {
		return nil, invalid("GPT header offset overflows u64")
	}
	headerMin, err := source.ReadVecAt(src, headerOffset, gptMinHeaderSize)
	if err != nil {
		return nil, err
	}
	if string(headerMin[0:8]) != GPTSignature {
		return nil, invalid("missing GPT signature at LBA %d (%s)", headerLBA, copy.Label())
	}

	headerSize := le32(headerMin[12:16])
	if headerSize < gptMinHeaderSize || uint64(headerSize) > secSize {
		return nil, invalid("invalid GPT header size %d", headerSize)
	}

	header, err := source.ReadVecAt(src, headerOffset, uint64(headerSize))
	if err != nil {
		return nil, err
	}
	storedCRC := le32(header[16:20])
	crcInput := append([]byte(nil), header...)
	clear(crcInput[16:20])
	if computed := crc32.ChecksumIEEE(crcInput); computed != storedCRC {
		return nil, invalid("GPT header CRC mismatch: stored %08X, computed %08X", storedCRC, computed)
	}

	revision := le32(header[8:12])
	currentLBA := le64(header[24:32])
	backupLBA := le64(header[32:40])
	firstUsableLBA := le64(header[40:48])
	lastUsableLBA := le64(header[48:56])
	diskGUID := GUIDString(header[56:72])
	partitionEntryLBA := le64(header[72:80])
	numEntries := le32(header[80:84])
	entrySize := le32(header[84:88])
	entriesCRC32 := le32(header[88:92])

	if currentLBA != headerLBA {
		return nil, invalid("GPT %s header claims to sit at LBA %d, but was found at LBA %d",
			copy.Label(), currentLBA, headerLBA)
	}
	if numEntries > gptMaxEntries {
		return nil, invalid("GPT has %d partition entries, limit is %d", numEntries, gptMaxEntries)
	}
	if entrySize < gptMinEntrySize || entrySize > gptMaxEntrySize {
		return nil, invalid("invalid GPT partition entry size %d", entrySize)
	}

	entriesLen, ok := checkedMul(uint64(numEntries), uint64(entrySize))
	if !ok {
		return nil, invalid("GPT partition-entry array length overflows u64")
	}
	if entriesLen > gptMaxEntryBytes {
		return nil, invalid("GPT partition-entry array is %d bytes, limit is %d", entriesLen, gptMaxEntryBytes)
	}

	entriesOffset, ok := checkedMul(partitionEntryLBA, secSize)
	if !ok {
		return nil, invalid("GPT partition-entry offset overflows u64")
	}
	entries, err := source.ReadVecAt(src, entriesOffset, entriesLen)
	if err != nil {
		return nil, err
	}
	if computed := crc32.ChecksumIEEE(entries); computed != entriesCRC32 {
		return nil, invalid("GPT entry CRC mismatch: stored %08X, computed %08X", entriesCRC32, computed)
	}

	diskSectors := src.Len() / secSize
	partitions := make([]Partition, 0, numEntries)
	for i := 0; i < int(numEntries); i++ {
		start := i * int(entrySize)
		entry := entries[start : start+int(entrySize)]

		typeGUID := GUIDString(entry[0:16])
		if typeGUID == gptZeroGUID {
			continue
		}
		uniqueGUID := GUIDString(entry[16:32])
		firstLBA := le64(entry[32:40])
		lastLBA := le64(entry[40:48])

		if lastLBA < firstLBA {
			return nil, invalid("GPT partition %d has last_lba %d < first_lba %d", i, lastLBA, firstLBA)
		}
		end := lastLBA + 1
		if end < lastLBA {
			return nil, invalid("GPT partition %d end overflows u64", i)
		}
		if end > diskSectors {
			return nil, invalid("GPT partition %d ends at sector %d, disk has %d", i, end, diskSectors)
		}

		sectorCount := end - firstLBA
		offset, ok := checkedMul(firstLBA, secSize)
		if !ok {
			return nil, invalid("GPT partition %d offset overflows u64", i)
		}
		length, ok := checkedMul(sectorCount, secSize)
		if !ok {
			return nil, invalid("GPT partition %d length overflows u64", i)
		}

		partitions = append(partitions, Partition{
			Index:       len(partitions),
			Kind:        KindGPT,
			TypeGUID:    typeGUID,
			GUID:        uniqueGUID,
			Name:        utf16Name(entry[56:128]),
			StartLBA:    firstLBA,
			SectorCount: sectorCount,
			Offset:      offset,
			Len:         length,
		})
	}

	return &GPTTable{
		DiskGUID: diskGUID,
		Header: GPTHeader{
			Revision:              revision,
			HeaderSize:            headerSize,
			HeaderCRC32:           storedCRC,
			CurrentLBA:            currentLBA,
			BackupLBA:             backupLBA,
			FirstUsableLBA:        firstUsableLBA,
			LastUsableLBA:         lastUsableLBA,
			DiskGUID:              diskGUID,
			PartitionEntryLBA:     partitionEntryLBA,
			NumPartitionEntries:   numEntries,
			PartitionEntrySize:    entrySize,
			PartitionEntriesCRC32: entriesCRC32,
			Copy:                  copy,
		},
		Partitions: partitions,
	}, nil
}

// GUIDString formats a 16-byte GPT GUID. The first three fields are stored
// little-endian and the last two in network byte order.
func GUIDString(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	a := le32(b[0:4])
	c1 := le16(b[4:6])
	c2 := le16(b[6:8])
	return fmt.Sprintf("%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		a, c1, c2,
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

func utf16Name(b []byte) string {
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		unit := le16(b[i : i+2])
		if unit == 0 {
			break
		}
		units = append(units, unit)
	}
	return string(utf16.Decode(units))
}
