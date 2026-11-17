package ufs

import (
	"strings"
	"testing"

	"github.com/laenix/ewfgo/internal/data/foundation"
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	delRootFrag = 100
	delGoneFrag = 104
	delBusyFrag = 108
	delLiveFrag = 112
	delBitOff   = 168
	delFreeOff  = 176
)

func allBits(count int) []uint32 {
	out := make([]uint32, count)
	for index := range out {
		out[index] = uint32(index)
	}
	return out
}

// buildDeleted synthesises the Rust deleted-recovery fixture: inodes 0..3 are
// allocated, inode 4 and inode 5 are freed, and their names survive behind the
// grown record of live.txt. Fragment 108 is allocated, so inode 5's content
// cannot be exported.
func buildDeleted(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t, UFS2)
	f.installSuperblock()
	f.writeCylinderGroup(0, delBitOff, []uint32{0, 1, 2, 3}, []uint32{delBusyFrag})
	f.writeCylinderGroup(1, delBitOff, allBits(testInodesPerGrp), nil)

	chunk := make([]byte, 0, DirBlockSize)
	chunk = append(chunk, dirRecord(RootInode, ".", 12, DTDir)...)
	chunk = append(chunk, dirRecord(RootInode, "..", 12, DTDir)...)
	chunk = append(chunk, dirRecord(3, "live.txt", DirBlockSize-24, DTReg)...)
	copy(chunk[44:68], dirRecord(4, "gone.txt", 24, DTReg))
	copy(chunk[68:92], dirRecord(5, "busy.txt", 24, DTReg))
	f.writeFrag(delRootFrag, chunk)
	f.writeFrag(delGoneFrag, []byte("gone"))
	f.writeFrag(delBusyFrag, []byte("busy"))
	f.writeFrag(delLiveFrag, []byte("hello"))

	f.writeInode(RootInode, SIFDIR|0o755, 2, DirBlockSize, []int64{delRootFrag}, nil)
	f.writeInode(3, SIFREG|0o644, 1, 5, []int64{delLiveFrag}, nil)
	writeFreedInode(f, 4, 0, 4, delGoneFrag, 5)
	writeFreedInode(f, 5, 0, 4, delBusyFrag, 0)
	return f
}

func writeFreedInode(f *fixture, number uint32, links uint16, size uint64, fragment int64, freelink uint32) {
	f.t.Helper()
	raw := inodeBytes(UFS2, SIFREG|0o644, links, size, []int64{fragment}, nil)
	putU32(raw, 240, freelink)
	f.writeInodeBytes(number, raw)
}

func TestDeletedScanFindsCandidatesAndNames(t *testing.T) {
	volume := buildDeleted(t).open()
	scan, err := volume.DeletedScan(nil)
	if err != nil {
		t.Fatalf("DeletedScan: %v", err)
	}
	if scan.Stats.GroupsScanned != 2 || scan.Stats.FreeSlots != 60 {
		t.Fatalf("stats = %+v", scan.Stats)
	}
	if scan.Stats.Candidates != 2 || len(scan.Inodes) != 2 {
		t.Fatalf("candidates = %+v", scan.Inodes)
	}
	numbers := []uint32{scan.Inodes[0].Inode.Number, scan.Inodes[1].Inode.Number}
	if numbers[0] != 4 || numbers[1] != 5 {
		t.Fatalf("candidate numbers = %v", numbers)
	}
	gone := scan.Inode(4)
	if gone == nil || !gone.Inode.IsRegular() || !gone.Content.IsRecoverable() {
		t.Fatalf("gone = %+v", gone)
	}
	if gone.FreeListLink == nil || *gone.FreeListLink != 5 {
		t.Fatalf("freelink = %v", gone.FreeListLink)
	}
	if !gone.HasPath || gone.Path != "/gone.txt" {
		t.Fatalf("path = %q/%v", gone.Path, gone.HasPath)
	}
	if scan.Stats.FreeListMembers != 1 {
		t.Fatalf("free-list members = %d", scan.Stats.FreeListMembers)
	}
	if scan.Stats.NamesFreedRecords != 2 || scan.Stats.NamesStaleRecords != 0 {
		t.Fatalf("name stats = %+v", scan.Stats)
	}
	if len(scan.Entries) != 2 || scan.Stats.Entries != 2 {
		t.Fatalf("entries = %+v", scan.Entries)
	}
	for _, entry := range scan.Entries {
		if entry.State != EntryDeleted || entry.Source != NameSourceFreedRecord {
			t.Fatalf("entry = %+v", entry)
		}
		if entry.Parent != RootInode || !entry.HasPath || entry.Path != "/"+entry.Name {
			t.Fatalf("entry path = %+v", entry)
		}
	}
	if got := scan.DeletedEntries(); len(got) != 2 {
		t.Fatalf("DeletedEntries = %d", len(got))
	}
}

func TestDeletedContentStatesAndSource(t *testing.T) {
	volume := buildDeleted(t).open()
	scan, err := volume.DeletedScan(nil)
	if err != nil {
		t.Fatalf("DeletedScan: %v", err)
	}
	busy := scan.Inode(5)
	if busy == nil || busy.Content.IsRecoverable() {
		t.Fatalf("busy = %+v", busy)
	}
	reason := busy.Content.Reason()
	if !strings.Contains(reason, "does not mark free") {
		t.Fatalf("reason = %q", reason)
	}
	file, err := volume.DeletedFileSource(scan, 4)
	if err != nil {
		t.Fatalf("DeletedFileSource(4): %v", err)
	}
	if file.Len() != 4 {
		t.Fatalf("len = %d", file.Len())
	}
	buf := make([]byte, 4)
	if _, err := file.ReadAt(0, buf); err != nil || string(buf) != "gone" {
		t.Fatalf("read = %q/%v", buf, err)
	}
	if _, err := volume.DeletedFileSource(scan, 5); err == nil || !strings.Contains(err.Error(), "cannot be exported") {
		t.Fatalf("busy export error = %v", err)
	}
	if _, err := volume.DeletedFileSource(scan, 9); err == nil || !strings.Contains(err.Error(), "not one of the scan") {
		t.Fatalf("unknown candidate error = %v", err)
	}
}

func TestDeletedScanLimits(t *testing.T) {
	volume := buildDeleted(t).open()
	zero := DeletedOptions{ScanLimit: 0, MaxCandidates: 1, MaxRecords: 1 << 20}
	scan, err := volume.DeletedScan(&zero)
	if err != nil {
		t.Fatalf("DeletedScan: %v", err)
	}
	if scan.Stats.ScannedInodes != 0 || scan.Stats.CappedAt != ScanCapScanLimit || !scan.Stats.CapReached() {
		t.Fatalf("scan limit stats = %+v", scan.Stats)
	}

	options := DefaultDeletedOptions()
	options.MaxCandidates = 1
	scan, err = volume.DeletedScan(&options)
	if err != nil {
		t.Fatalf("DeletedScan: %v", err)
	}
	if scan.Stats.Candidates != 1 || scan.Stats.CappedAt != ScanCapCandidateLimit {
		t.Fatalf("candidate limit stats = %+v", scan.Stats)
	}

	options = DefaultDeletedOptions()
	options.MaxRecords = 0
	scan, err = volume.DeletedScan(&options)
	if err != nil {
		t.Fatalf("DeletedScan: %v", err)
	}
	if scan.Stats.CappedAt != ScanCapRecordLimit || len(scan.Entries) != 0 {
		t.Fatalf("record limit stats = %+v", scan.Stats)
	}
}

func TestDeletedScanRefusedGroup(t *testing.T) {
	f := buildDeleted(t)
	putU32(f.image, int(f.cgOffset(1))+92, 100)
	volume := f.open()
	scan, err := volume.DeletedScan(nil)
	if err != nil {
		t.Fatalf("DeletedScan: %v", err)
	}
	if len(scan.RefusedGroups) != 1 || !strings.Contains(scan.RefusedGroups[0], "cylinder group 1") {
		t.Fatalf("refused = %v", scan.RefusedGroups)
	}
	if scan.Stats.GroupsScanned != 1 || scan.Stats.FreeSlots != 60 {
		t.Fatalf("stats = %+v", scan.Stats)
	}
}

func TestDeletedNonZeroLinks(t *testing.T) {
	f := buildDeleted(t)
	writeFreedInode(f, 4, 2, 4, delGoneFrag, 5)
	volume := f.open()
	scan, err := volume.DeletedScan(nil)
	if err != nil {
		t.Fatalf("DeletedScan: %v", err)
	}
	if scan.Stats.NonZeroLinks != 1 {
		t.Fatalf("stats = %+v", scan.Stats)
	}
	if inode := scan.Inode(4); inode == nil || !inode.NonZeroLinks {
		t.Fatalf("inode = %+v", inode)
	}
}

func TestDeletedAmbiguousName(t *testing.T) {
	f := buildDeleted(t)
	writeFreedInode(f, 6, 0, 0, 0, 0)
	chunk := f.image[int(delRootFrag*testFSize) : int(delRootFrag*testFSize)+DirBlockSize]
	copy(chunk[92:104], dirRecord(4, "dup", 12, DTReg))
	copy(chunk[104:116], dirRecord(6, "dup", 12, DTReg))
	volume := f.open()
	scan, err := volume.DeletedScan(nil)
	if err != nil {
		t.Fatalf("DeletedScan: %v", err)
	}
	var ambiguous int
	for _, entry := range scan.Entries {
		if entry.Name == "dup" {
			ambiguous++
			if entry.State != EntryUnresolved || !strings.Contains(entry.Reason, "more than one inode") {
				t.Fatalf("entry = %+v", entry)
			}
			if entry.HasPath {
				t.Fatalf("an ambiguous name acquired a path: %+v", entry)
			}
		}
	}
	if ambiguous != 2 {
		t.Fatalf("ambiguous entries = %d", ambiguous)
	}
}

func TestDeletedHashGate(t *testing.T) {
	raw := inodeBytes(UFS2, SIFREG|0o644, 0, 4, []int64{delGoneFrag}, nil)
	sbRaw := superblockBytes(UFS2, LittleEndian, testUFS2Offset)
	putU32(sbRaw, 1308, CK_INODE)
	sb, err := ParseSuperblock(sbRaw, UFS2, LittleEndian, testUFS2Offset)
	if err != nil {
		t.Fatalf("ParseSuperblock: %v", err)
	}
	inode, err := ParseInode(4, raw, UFS2, LittleEndian)
	if err != nil {
		t.Fatalf("ParseInode: %v", err)
	}
	if inodeHashMatches(sb, inode, raw) {
		t.Fatal("a stored zero check hash was treated as a pass")
	}
	hashed := append([]byte(nil), raw...)
	clear(hashed[244:248])
	putU32(raw, 244, foundation.CRC32C(hashed))
	inode, _ = ParseInode(4, raw, UFS2, LittleEndian)
	if !inodeHashMatches(sb, inode, raw) {
		t.Fatal("a correct inode check hash was rejected")
	}
	raw[200] ^= 0xFF
	inode, _ = ParseInode(4, raw, UFS2, LittleEndian)
	if inodeHashMatches(sb, inode, raw) {
		t.Fatal("a damaged inode hash was accepted")
	}
}

func TestDeletedStructuralGate(t *testing.T) {
	sb := mustParseSuperblock(t, superblockBytes(UFS2, LittleEndian, testUFS2Offset))
	raw := inodeBytes(UFS2, SIFREG|0o644, 0, 8, []int64{99999}, nil)
	inode, _ := ParseInode(4, raw, UFS2, LittleEndian)
	if got := credibleInode(sb, inode, raw); got != credibilityBounds {
		t.Fatalf("out-of-range pointer credibility = %d", got)
	}
	cleared := make([]byte, 256)
	inode, _ = ParseInode(4, cleared, UFS2, LittleEndian)
	if got := credibleInode(sb, inode, cleared); got != credibilityCleared {
		t.Fatalf("cleared credibility = %d", got)
	}
	raw = inodeBytes(UFS2, SIFREG|0o644, 0, 4, nil, nil)
	inode, _ = ParseInode(4, raw, UFS2, LittleEndian)
	if got := credibleInode(sb, inode, raw); got != credibilityOK {
		t.Fatalf("credible inode = %d", got)
	}
	if kindAgrees(DTReg, InodeRegular) != true || kindAgrees(DTDir, InodeRegular) != false {
		t.Fatal("kind mapping is wrong")
	}
	pointers := sb.PointersPerBlock()
	want := (12 + pointers + pointers*pointers + pointers*pointers*pointers) * sb.BlockSize()
	if maxFileBytes(sb) != want {
		t.Fatalf("max file bytes = %d, want %d", maxFileBytes(sb), want)
	}
}

func TestFreeSpaceScan(t *testing.T) {
	volume := buildDeleted(t).open()
	free, err := volume.FreeSpace()
	if err != nil {
		t.Fatalf("FreeSpace: %v", err)
	}
	if free.Covered() != testVolumeLen {
		t.Fatalf("covered = %d", free.Covered())
	}
	if free.IsFree(delGoneFrag*testFSize, testFSize) != true {
		t.Fatal("the freed fragment is not free")
	}
	if free.IsFree(delBusyFrag*testFSize, testFSize) {
		t.Fatal("the allocated fragment reads as free")
	}
	if free.IsFree(testVolumeLen, testFSize) {
		t.Fatal("a range past the covered volume reads as free")
	}
	if len(free.Notes()) != 0 {
		t.Fatalf("notes = %v", free.Notes())
	}
	// Fragment 108 is allocated in group zero; every other fragment is free.
	if free.FreeBytes() != uint64(testBlocksPerGrp*testGroups-1)*testFSize {
		t.Fatalf("free bytes = %d", free.FreeBytes())
	}
}

func TestFreeSpaceShortImageNote(t *testing.T) {
	f := buildDeleted(t)
	short := source.NewMemorySource(1, f.image[:100000])
	free, err := freeSpace(short, mustParseSuperblock(t, f.image[testUFS2Offset:testUFS2Offset+SuperblockLen]))
	if err != nil {
		t.Fatalf("freeSpace: %v", err)
	}
	found := false
	for _, note := range free.Notes() {
		if strings.Contains(note, "only the present groups") {
			found = true
		}
	}
	if !found {
		t.Fatalf("notes = %v", free.Notes())
	}
	if free.IsFree(testVolumeLen-testFSize, testFSize) {
		t.Fatal("a fragment the image does not hold reads as free")
	}
}

func TestCylinderGroupCheckHash(t *testing.T) {
	f := newFixture(t, UFS2)
	f.installSuperblock()
	putU32(f.image, int(testUFS2Offset)+1308, CK_CYLGRP)
	header := f.image[int(f.cgOffset(0)) : int(f.cgOffset(0))+4096]
	putU32(header, CGCheckHashOffset, 0)
	putU32(header, CGCheckHashOffset, foundation.CRC32C(header))
	volume := f.open()
	group, err := volume.CylinderGroup(0)
	if err != nil || !group.CheckHashKnown || !group.CheckHashValid {
		t.Fatalf("group = %+v, err %v", group, err)
	}
	header[700] ^= 0xFF
	if _, err := ReadInodeBitmap(f.source(), volume.Superblock(), 0); err == nil || !strings.Contains(err.Error(), "check hash") {
		t.Fatalf("mismatched group hash error = %v", err)
	}
}

func mustParseSuperblock(t *testing.T, raw []byte) *Superblock {
	t.Helper()
	sb, err := ParseSuperblock(raw, UFS2, LittleEndian, testUFS2Offset)
	if err != nil {
		t.Fatalf("ParseSuperblock: %v", err)
	}
	return sb
}
