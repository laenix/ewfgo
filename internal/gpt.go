package internal

import "encoding/binary"

// GPT is a parsed GUID Partition Table: the header plus up to 128 partition
// entries.
type GPT struct {
	GPTHeader         GPTHeader
	GPTPartitionTable [128]GPTPartitionTable
}

type GPTHeader struct {
	Signature         [8]byte
	Version           uint32
	HeaderSize        uint32
	HeaderCRC         uint32
	Reserved          uint32
	CurrentLBA        uint64
	BackupLBA         uint64
	FirstLBA          uint64
	LastLBA           uint64
	GUID              [16]byte
	PartitionStartLBA uint64
	PartitionNumber   uint32
	PartitionSize     uint32
	PartitionCRC      uint32
	Save              [420]byte
}

type GPTPartitionTable struct {
	PartitionTypeGUID [16]byte
	PartitionGUID     [16]byte
	StartLBA          uint64
	EndLBA            uint64
	AttributeFlag     [8]byte
	PartitionName     [72]byte
}

// ParseGPTHeader scans headerData in 512-byte strides for the "EFI PART"
// signature and, on a hit, fills the header fields the caller consumes.
// Fields the caller's inline parse never read (e.g. GUID, BackupLBA) are left
// zero, so the result is byte-identical to that parse. The 512-byte stride
// preserves the original multi-stride scan within a single large sector.
//
// Known boundary: CurrentLBA is filled but is NOT used as a validity criterion —
// a header is accepted on the signature alone, exactly as before. Deliberately
// not tightened; any change here would alter ScanFileSystems behavior.
//
// It returns ok=false when no signature is found. A header whose first 92 bytes
// (the parsed region) exceed the data is treated as not-found rather than
// panicking on a crafted short sector.
func ParseGPTHeader(headerData []byte) (GPTHeader, bool) {
	var hdr GPTHeader
	for offset := 0; offset < len(headerData)-8; offset += 512 {
		if string(headerData[offset:offset+8]) != "EFI PART" {
			continue
		}
		if offset+92 > len(headerData) {
			return GPTHeader{}, false
		}
		h := headerData[offset : offset+92]
		copy(hdr.Signature[:], h[:8])
		hdr.Version = binary.LittleEndian.Uint32(h[8:12])
		hdr.HeaderSize = binary.LittleEndian.Uint32(h[12:16])
		hdr.CurrentLBA = binary.LittleEndian.Uint64(h[24:32])
		hdr.FirstLBA = binary.LittleEndian.Uint64(h[40:48])
		hdr.LastLBA = binary.LittleEndian.Uint64(h[48:56])
		hdr.PartitionStartLBA = binary.LittleEndian.Uint64(h[72:80])
		hdr.PartitionNumber = binary.LittleEndian.Uint32(h[80:84])
		hdr.PartitionSize = binary.LittleEndian.Uint32(h[84:88])
		return hdr, true
	}
	return GPTHeader{}, false
}

// ParseGPTPartitions decodes the GPT partition entries from partData into gpt,
// mirroring the caller's semantics: entries are bounded by PartitionNumber
// (max 128), an entry beyond partData stops the scan, and an entry with
// StartLBA == 0 (or the all-ones value) is left empty. An entry whose declared
// size is too small to carry the parsed fields (name region ends at offset 80)
// is skipped rather than panicking on a crafted header.
func ParseGPTPartitions(gpt *GPT, partData []byte) {
	partSize := int(gpt.GPTHeader.PartitionSize)
	if partSize == 0 {
		partSize = 128 // Default entry size
	}
	for i := 0; i < int(gpt.GPTHeader.PartitionNumber) && i < 128; i++ {
		offset := i * partSize
		if offset+partSize > len(partData) {
			break
		}
		part := partData[offset : offset+partSize]
		if len(part) < 80 {
			continue
		}
		startLBA := binary.LittleEndian.Uint64(part[32:40])
		endLBA := binary.LittleEndian.Uint64(part[40:48])
		if startLBA > 0 && startLBA < 0xFFFFFFFFFFFFFFFF {
			gpt.GPTPartitionTable[i].StartLBA = startLBA
			gpt.GPTPartitionTable[i].EndLBA = endLBA
			copy(gpt.GPTPartitionTable[i].PartitionTypeGUID[:], part[0:16])
			copy(gpt.GPTPartitionTable[i].PartitionGUID[:], part[16:32])
			copy(gpt.GPTPartitionTable[i].PartitionName[:], part[48:80])
		}
	}
}
