package partition

import (
	"strings"

	"github.com/laenix/ewfgo/internal/data/source"
)

// APM addresses storage in 512-byte blocks regardless of the device's logical
// sector size, and every field is big-endian.
const (
	// ApmBlockBytes is APM's fixed address unit.
	ApmBlockBytes = 512
	// ApmEntryBytes is one partition map entry.
	ApmEntryBytes = 512
	// ApmMaxMapBlocks caps a forged pmMapBlkCnt.
	ApmMaxMapBlocks = 4096
)

const (
	apmMapBlkCnt   = 4
	apmPartStart   = 8
	apmPartBlkCnt  = 12
	apmPartName    = 16
	apmParType     = 48
	apmPartStatus  = 88
	apmProcessor   = 120
	apmStringBytes = 32
)

// ApmDriverDescriptor is the driver descriptor record at block 0.
type ApmDriverDescriptor struct {
	BlockSize  uint16
	BlockCount uint32
	DeviceType uint16
	DeviceID   uint16
}

// ApmPartitionTable is a parsed Apple Partition Map.
type ApmPartitionTable struct {
	Driver     *ApmDriverDescriptor
	MapBlocks  uint32
	Skipped    int
	Partitions []Partition
}

// ParseAPM reads an Apple Partition Map. A nil table with a nil error means the
// source does not start with a map entry. Once the signature is there, a
// structurally broken map is an error: it is a table that cannot be read, not
// a disk without one.
func ParseAPM(src source.ByteSource) (*ApmPartitionTable, error) {
	if src.Len() < 2*ApmBlockBytes {
		return nil, nil
	}
	signature, err := source.ReadVecAt(src, ApmBlockBytes, 2)
	if err != nil {
		return nil, err
	}
	if string(signature) != "PM" {
		return nil, nil
	}

	first, err := source.ReadVecAt(src, ApmBlockBytes, ApmEntryBytes)
	if err != nil {
		return nil, err
	}
	mapBlocks := be32(first[apmMapBlkCnt : apmMapBlkCnt+4])
	totalBlocks := src.Len() / ApmBlockBytes
	if mapBlocks < 1 || mapBlocks > ApmMaxMapBlocks || uint64(mapBlocks) > totalBlocks {
		// The signature can occur inside a volume image that happens to sit at
		// offset zero; an impossible count is not a table.
		return nil, nil
	}

	driver, err := readApmDriver(src)
	if err != nil {
		return nil, err
	}

	table := &ApmPartitionTable{Driver: driver, MapBlocks: mapBlocks}
	for block := uint64(1); block <= uint64(mapBlocks); block++ {
		entry, err := source.ReadVecAt(src, block*ApmBlockBytes, ApmEntryBytes)
		if err != nil {
			return nil, err
		}
		if string(entry[0:2]) != "PM" {
			return nil, invalid("partition map entry %d is missing its `PM` signature", block)
		}
		if declared := be32(entry[apmMapBlkCnt : apmMapBlkCnt+4]); declared != mapBlocks {
			return nil, invalid("partition map entry %d declares %d map blocks, the first entry declares %d",
				block, declared, mapBlocks)
		}

		partType := fixedString(entry, apmParType, apmStringBytes)
		start := uint64(be32(entry[apmPartStart : apmPartStart+4]))
		count := uint64(be32(entry[apmPartBlkCnt : apmPartBlkCnt+4]))

		if partType == "Apple_partition_map" || partType == "Apple_Free" || count == 0 {
			table.Skipped++
			continue
		}

		end := start + count
		if end < start {
			return nil, invalid("partition end overflows u64")
		}
		if end > totalBlocks {
			return nil, invalid("partition %d ends at block %d, the image has %d", block, end, totalBlocks)
		}

		byteOffset, ok := checkedMul(start, ApmBlockBytes)
		if !ok {
			return nil, invalid("partition byte offset overflows u64")
		}
		length, ok := checkedMul(count, ApmBlockBytes)
		if !ok {
			return nil, invalid("partition byte length overflows u64")
		}

		name := fixedString(entry, apmPartName, apmStringBytes)
		processor := fixedString(entry, apmProcessor, 16)
		label := partType
		if processor != "" {
			label = partType + " (" + processor + ")"
		}

		table.Partitions = append(table.Partitions, Partition{
			Index:       len(table.Partitions),
			Kind:        KindAPM,
			TypeGUID:    label,
			Name:        name,
			StartLBA:    start,
			SectorCount: count,
			Offset:      byteOffset,
			Len:         length,
		})
	}

	return table, nil
}

func readApmDriver(src source.ByteSource) (*ApmDriverDescriptor, error) {
	block, err := source.ReadVecAt(src, 0, ApmEntryBytes)
	if err != nil {
		return nil, err
	}
	if string(block[0:2]) != "ER" {
		return nil, nil
	}
	return &ApmDriverDescriptor{
		BlockSize:  be16(block[2:4]),
		BlockCount: be32(block[4:8]),
		DeviceType: be16(block[8:10]),
		DeviceID:   be16(block[10:12]),
	}, nil
}

// fixedString decodes a fixed-width, NUL-padded string. Trailing spaces are
// trimmed because some writers pad with those instead of NULs. Invalid UTF-8
// is replaced rather than dropped, so a damaged name stays visible.
func fixedString(bytes []byte, offset, length int) string {
	raw := bytes[offset : offset+length]
	end := len(raw)
	for i, b := range raw {
		if b == 0 {
			end = i
			break
		}
	}
	return strings.TrimRight(strings.ToValidUTF8(string(raw[:end]), "�"), " \t\r\n")
}

// APMMatchesHead reports whether head starts with a driver descriptor and a
// partition map entry. A head shorter than two blocks cannot say either way.
func APMMatchesHead(head []byte) bool {
	return len(head) >= 514 && string(head[0:2]) == "ER" && string(head[512:514]) == "PM"
}
