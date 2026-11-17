package zfs

import (
	"fmt"
	"sort"
)

// The uberblock ring. Every label ends with 128 KiB holding 32 four-kilobyte
// slots. A sync writes the new uberblock into the next slot, wrapping around,
// so the ring holds a mix of recent and stale transaction groups. The highest
// txg is the newest state, but it is trusted only after its root block pointer
// reads and verifies.

// UberblockMagic marks a slot that holds an uberblock.
const UberblockMagic uint64 = 0x00bab10c

// UberblockShift is the log2 of the slot stride. Slots are four kilobytes
// apart, not one: a one-kilobyte stride finds the magic only every fourth
// slot.
const UberblockShift = 12

// UberblockSize is one slot.
const UberblockSize = 1 << UberblockShift

// UberblocksPerLabel is 128 KiB / 4 KiB.
const UberblocksPerLabel = UberblockRingSize / UberblockSize

// spaVersion is the current on-disk SPA version; feature flags are used above
// version 28.
const spaVersion uint64 = 5000

// Uberblock is one verified-or-candidate transaction group.
type Uberblock struct {
	// Label and Slot name the copy that was read.
	Label int
	Slot  int

	Version uint64
	TXG     uint64
	GUIDSum uint64
	// Timestamp is UTC seconds when the sync completed.
	Timestamp uint64
	Root      BlockPointer
	// SoftwareVersion is the userland that wrote the pool.
	SoftwareVersion uint64
}

func uberblockWord(slot []byte, offset int) uint64 {
	return leUint64(slot[offset : offset+8])
}

// parseUberblock parses one slot. It returns (nil, nil) when the slot does not
// hold an uberblock; a magic-bearing slot with an implausible version or
// transaction group is an error rather than a silent skip.
func parseUberblock(slot []byte, label, index int) (*Uberblock, error) {
	if len(slot) < 216 {
		return nil, corruptf("an uberblock slot shorter than its fixed fields")
	}
	if uberblockWord(slot, 0) != UberblockMagic {
		return nil, nil
	}
	version := uberblockWord(slot, 8)
	txg := uberblockWord(slot, 16)
	if version == 0 || version > spaVersion {
		return nil, unsupportedf("uberblock version %d; this reader knows up to %d", version, spaVersion)
	}
	if txg == 0 {
		return nil, corruptf("an uberblock with transaction group zero")
	}
	root, err := parseBlockPointer(slot[40:168])
	if err != nil {
		return nil, err
	}
	return &Uberblock{
		Label:           label,
		Slot:            index,
		Version:         version,
		TXG:             txg,
		GUIDSum:         uberblockWord(slot, 24),
		Timestamp:       uberblockWord(slot, 32),
		Root:            root,
		SoftwareVersion: uberblockWord(slot, 168),
	}, nil
}

// scanUberblockRing parses a whole 128 KiB ring into the slots that hold an
// uberblock, newest first. A slot that fails to parse does not hide the rest;
// its error is returned alongside the others as a problem string.
func scanUberblockRing(ring []byte, label int) ([]Uberblock, []string) {
	var found []Uberblock
	var problems []string
	for index := 0; index < UberblocksPerLabel; index++ {
		start := index * UberblockSize
		if start+UberblockSize > len(ring) {
			break
		}
		block, err := parseUberblock(ring[start:start+UberblockSize], label, index)
		switch {
		case err != nil:
			problems = append(problems, fmt.Sprintf("label %d slot %d: %v", label, index, err))
		case block != nil:
			found = append(found, *block)
		}
	}
	sort.SliceStable(found, func(i, j int) bool { return found[i].TXG > found[j].TXG })
	return found, problems
}
