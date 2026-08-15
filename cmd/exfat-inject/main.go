// Command exfat-inject injects a small fixture file (fixture.txt, content
// "fixture\n") into a fresh mkfs.exfat image so the committed exFAT forensic
// fixtures have a real, spec-conformant file for the parser tests to read.
//
// It is dev-time tooling only: scripts/gen_fs_fixtures.sh calls it after
// mkfs.exfat (mtools cannot write exFAT — mcopy fails "init :: non DOS media"),
// and the fixture E01s it produces are what the tests consume. It is never
// called by tests.
//
// The injected directory entry set follows the exFAT spec:
//
//	0x85 file directory (SecondaryCount=2, attributes=archive, SetChecksum)
//	0xC0 stream extension (AllocationPossible, NameLength, NameHash,
//	                      ValidDataLength=8, FirstCluster, DataLength=8)
//	0xC1 file name        ("fixture.txt" = 11 UTF-16LE units, one entry)
//
// The checksum and name hash are computed per the spec algorithms.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"unicode/utf16"
)

const (
	fixtureContent = "fixture\n"
	fixtureName    = "fixture.txt"
	fixtureNameLen = 11 // UTF-16 code units in "fixture.txt"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: exfat-inject <exfat-image>\n")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "exfat-inject: %v\n", err)
		os.Exit(1)
	}
}

func run(path string) error {
	img, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(img) < 512 {
		return fmt.Errorf("image too small")
	}
	if string(img[3:11]) != "EXFAT   " {
		return fmt.Errorf("not an exFAT image (bad signature)")
	}

	// Boot sector fields (spec offsets; same as internal/filesystem/exfat.go).
	bpsShift := img[108]
	spcShift := img[109]
	if bpsShift < 9 || bpsShift > 12 {
		return fmt.Errorf("invalid bytes-per-sector shift %d", bpsShift)
	}
	if spcShift > 25 {
		return fmt.Errorf("invalid sectors-per-cluster shift %d", spcShift)
	}
	sectorSize := int64(1) << bpsShift
	sectorsPerCluster := int64(1) << spcShift
	clusterSize := sectorSize * sectorsPerCluster
	fatOffset := int64(binary.LittleEndian.Uint32(img[80:84]))
	clusterHeapOffset := int64(binary.LittleEndian.Uint32(img[88:92]))
	clusterCount := uint32(binary.LittleEndian.Uint32(img[92:96]))
	rootCluster := uint32(binary.LittleEndian.Uint32(img[96:100]))

	// 1. Read the root directory cluster once: locate the allocation-bitmap
	//    entry (0x81, for marking our data cluster allocated) and the first
	//    0x00 end-of-directory entry (where the new entry set goes).
	rootOff := (clusterHeapOffset + int64(rootCluster-2)*sectorsPerCluster) * sectorSize
	if rootOff+clusterSize > int64(len(img)) {
		return fmt.Errorf("root directory cluster out of image bounds")
	}
	rootDir := img[rootOff : rootOff+clusterSize]
	insertAt := int64(-1)
	bitmapCluster := uint32(0)
	for off := int64(0); off+32 <= clusterSize; off += 32 {
		typ := rootDir[off]
		if typ == 0x00 {
			if insertAt < 0 {
				insertAt = off
			}
			break
		}
		if typ == 0x81 {
			bitmapCluster = binary.LittleEndian.Uint32(rootDir[off+20 : off+24])
		}
	}
	if insertAt < 0 {
		return fmt.Errorf("no end-of-directory (0x00) entry found in root directory")
	}
	if insertAt+int64(3*32) > clusterSize {
		return fmt.Errorf("root directory cluster has no room for 3 entries")
	}

	// 2. Allocate the first free heap cluster (FAT entry == 0).
	var alloc uint32
	for c := uint32(2); c <= clusterCount+1; c++ {
		off := fatOffset*sectorSize + int64(c)*4
		if off+4 > int64(len(img)) {
			return fmt.Errorf("FAT entry for cluster %d out of image bounds", c)
		}
		if binary.LittleEndian.Uint32(img[off:off+4]) == 0 {
			alloc = c
			break
		}
	}
	if alloc == 0 {
		return fmt.Errorf("no free cluster in FAT (clusterCount %d)", clusterCount)
	}

	// Write the file bytes zero-padded to the cluster size, then mark EOC.
	dataOff := (clusterHeapOffset + int64(alloc-2)*sectorsPerCluster) * sectorSize
	if dataOff+clusterSize > int64(len(img)) {
		return fmt.Errorf("data cluster %d out of image bounds", alloc)
	}
	cluster := img[dataOff : dataOff+clusterSize]
	for i := range cluster {
		cluster[i] = 0
	}
	copy(cluster, fixtureContent)
	fatOff := fatOffset*sectorSize + int64(alloc)*4
	binary.LittleEndian.PutUint32(img[fatOff:fatOff+4], 0xFFFFFFFF) // EOC

	// 2. Build the 3-entry directory set.
	nameUTF16 := utf16le(fixtureName)
	hash := nameHash(strings.ToUpper(fixtureName))

	entries := make([][]byte, 3)
	entries[0] = make([]byte, 32)
	entries[0][0] = 0x85 // file directory entry
	entries[0][1] = 2    // SecondaryCount: one stream + one name
	entries[0][4] = 0x20 // FileAttributes: archive
	// SetChecksum (bytes 2-3) filled in below, after the checksum is computed.

	entries[1] = make([]byte, 32)
	entries[1][0] = 0xC0 // stream extension
	entries[1][1] = 0x01 // GeneralSecondaryFlags: AllocationPossible
	entries[1][3] = fixtureNameLen
	binary.LittleEndian.PutUint16(entries[1][4:6], hash)
	binary.LittleEndian.PutUint64(entries[1][8:16], uint64(len(fixtureContent))) // ValidDataLength
	binary.LittleEndian.PutUint32(entries[1][20:24], alloc)                       // FirstCluster
	binary.LittleEndian.PutUint64(entries[1][24:32], uint64(len(fixtureContent))) // DataLength

	entries[2] = make([]byte, 32)
	entries[2][0] = 0xC1 // file name
	copy(entries[2][2:], nameUTF16) // name UTF-16LE at bytes 2-31 (real spec layout)

	binary.LittleEndian.PutUint16(entries[0][2:4], entrySetChecksum(entries))

	// 3. Mark the data cluster allocated in the allocation bitmap (bit N of the
	//    bitmap corresponds to cluster N+2), so the volume is self-consistent.
	if bitmapCluster >= 2 {
		bitmapOff := (clusterHeapOffset + int64(bitmapCluster-2)*sectorsPerCluster) * sectorSize
		bit := uint64(alloc) - 2
		byteOff := bitmapOff + int64(bit/8)
		if byteOff < int64(len(img)) {
			img[byteOff] |= 1 << (bit % 8)
		}
	}

	// 4. Append the set into the root directory cluster at the first 0x00
	//    end-of-directory entry (a fresh mkfs.exfat root is one cluster holding
	//    the volume-label/bitmap/up-case entries followed by 0x00 padding).
	for i, e := range entries {
		copy(img[rootOff+insertAt+int64(i*32):], e)
	}

	if err := os.WriteFile(path, img, 0o644); err != nil {
		return err
	}
	fmt.Printf("injected %s (%d bytes) -> cluster %d, root-dir entry offset %d\n",
		fixtureName, len(fixtureContent), alloc, insertAt)
	return nil
}

// utf16le encodes s as UTF-16LE bytes.
func utf16le(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(out[i*2:], u)
	}
	return out
}

// entrySetChecksum implements the exFAT entry-set checksum: a 16-bit fold over
// every byte of every entry in the set, skipping bytes 2-3 (the SetChecksum
// field) of the first (primary) entry. This is the algorithm the Linux kernel
// (exfat_calc_chksum16, type CS_DIR_ENTRY) and exfatprogs (exfat_calc_dentry_
// checksum) use to write and verify file-directory entry sets. (Task 13's brief
// quoted the 32-bit boot-region checksum for this field; the 16-bit form is the
// one the on-disk SetChecksum field and the tools that built the fixtures use.)
func entrySetChecksum(entries [][]byte) uint16 {
	var sum uint16
	for i, e := range entries {
		for j, b := range e {
			if i == 0 && (j == 2 || j == 3) {
				continue
			}
			sum = ((sum << 15) | (sum >> 1)) + uint16(b)
		}
	}
	return sum
}

// nameHash implements the exFAT spec's NameHash: a 16-bit fold over the
// uppercased UTF-16 name (rotating the accumulator right by one bit per byte).
func nameHash(name string) uint16 {
	var hash uint16
	for _, r := range name {
		c := uint16(r)
		hash = ((hash << 15) | (hash >> 1)) + (c & 0xff)
		hash = ((hash << 15) | (hash >> 1)) + (c >> 8)
	}
	return hash
}
