package partition

import (
	"fmt"

	"github.com/laenix/ewfgo/internal/data/source"
)

// Detect identifies the disk's partition table.
//
// GPT is authoritative when its signature is present at LBA 1; the backup
// header at the last LBA is tried when the primary is absent or does not
// verify. A plain MBR with usable entries wins over an error about a GPT copy
// that is not there. A protective-only MBR (a single 0xEE entry) is reported
// only when no GPT copy answered, so a damaged GPT is not hidden behind it.
func Detect(src source.ByteSource) (*Table, error) {
	secSize, err := sectorSize(src)
	if err != nil {
		return nil, err
	}
	if src.Len() < 512 {
		return &Table{Kind: KindNone}, nil
	}

	mbrSector, err := source.ReadVecAt(src, 0, 512)
	if err != nil {
		return nil, err
	}
	hasMBRSignature := mbrSector[510] == 0x55 && mbrSector[511] == 0xAA

	var primaryIssue error
	if src.Len() >= secSize+8 {
		signature, err := source.ReadVecAt(src, secSize, uint64(len(GPTSignature)))
		if err != nil {
			return nil, err
		}
		if string(signature) == GPTSignature {
			table, err := ParseGPT(src, secSize)
			if err == nil {
				return &Table{Kind: KindGPT, GPT: table}, nil
			}
			primaryIssue = err
		}
	}

	var backupIssue error
	backup, err := ParseGPTBackup(src, secSize)
	if err != nil {
		backupIssue = err
	} else if backup != nil {
		return &Table{Kind: KindGPT, GPT: backup}, nil
	}

	// An MBR that still describes partitions is a better answer than an error
	// about a GPT copy that is not there. A sector with the 0x55AA signature
	// but no entries is a volume boot sector, not a partition table.
	var protectiveOnly *Table
	if hasMBRSignature {
		mbr, err := ParseMBR(src)
		if err != nil {
			return nil, err
		}
		switch {
		case len(mbr.Partitions) == 0:
			// Boot sector: fall through to the GPT issue/None result.
		case allProtective(mbr.Partitions):
			protectiveOnly = &Table{Kind: KindMBR, MBR: mbr}
		default:
			return &Table{Kind: KindMBR, MBR: mbr}, nil
		}
	}

	// Apple Partition Map: block 1 is the first map entry. An APM disk has no
	// 0x55AA in block 0, so the MBR path above never claims it.
	var apmIssue error
	apm, err := ParseAPM(src)
	if err != nil {
		apmIssue = err
	} else if apm != nil {
		return &Table{Kind: KindAPM, APM: apm}, nil
	}

	// BSD disklabel: the LABEL magic sits in sector 1 (byte 512 on 512-byte
	// disks, byte 4096 on 4 KiB disks), confirmed by d_magic2. A label disk
	// carries no 0x55AA in sector 0, so the MBR path never claims it.
	var bsdIssue error
	bsd, err := ParseBSD(src)
	if err != nil {
		bsdIssue = err
	} else if bsd != nil {
		return &Table{Kind: KindBSD, BSD: bsd}, nil
	}

	if apmIssue != nil {
		return nil, apmIssue
	}
	if bsdIssue != nil {
		return nil, bsdIssue
	}

	switch {
	case primaryIssue != nil && backupIssue != nil:
		return nil, fmt.Errorf("%w: %v; the backup header did not verify either: %v",
			ErrInvalid, primaryIssue, backupIssue)
	case primaryIssue != nil:
		return nil, fmt.Errorf("%w: %v; no backup header was found at the last sector",
			ErrInvalid, primaryIssue)
	case backupIssue != nil:
		return nil, backupIssue
	}

	if protectiveOnly != nil {
		return protectiveOnly, nil
	}
	return &Table{Kind: KindNone}, nil
}

func allProtective(partitions []Partition) bool {
	if len(partitions) == 0 {
		return false
	}
	for _, p := range partitions {
		if p.TypeID != 0xEE {
			return false
		}
	}
	return true
}
