package exfat

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/laenix/ewfgo/internal/filesystem"
)

// exFAT filesystem implementation.
// Reference: https://docs.microsoft.com/en-us/windows/win32/fileio/exfat-specification
//
// Directory-entry type values (spec section 4.4; the InUse bit is 0x80 and the
// structure type code is the low 7 bits):
//
//	0x00 / 0x01  end of directory
//	0x20         reserved volume-GUID slot written by mkfs.exfat (in-use bit clear)
//	0x81         allocation bitmap
//	0x82         up-case table
//	0x83         volume label (label UTF-16LE at bytes 2.., CharacterCount at byte 1)
//	0x85         file directory entry (SecondaryCount at byte 1, SetChecksum at 2-3,
//	             FileAttributes at 4-5)
//	0xC0         stream extension (NameLength at byte 3, NameHash at 4-5,
//	             ValidDataLength at 8-15, FirstCluster at 20-23, DataLength at 24-31)
//	0xC1         file name (UTF-16LE name, up to 15 units, at bytes 2-31)
//
// Note: Task 13's brief listed 0x85/0x81/0x82/0x83 for label/file-dir/stream/name,
// but the real spec (and the real mkfs.exfat output used to build the fixtures)
// assigns 0x83 to the volume label, 0x85 to the file directory, 0xC0 to the
// stream extension and 0xC1 to the file name. The parser follows the real spec,
// otherwise GetVolumeLabel could not return "FIXTURE" and the bitmap/up-case
// entries in a fresh mkfs.exfat root would be misparsed as files.

// exFAT directory-entry type constants (in-use values).
const (
	exfatEndOfDir       = 0x00
	exfatEntryBitmap    = 0x81
	exfatEntryUpCase    = 0x82
	exfatEntryVolume    = 0x83
	exfatEntryFileDir   = 0x85
	exfatEntryStream    = 0xC0
	exfatEntryFileName  = 0xC1
	exfatVolumeLabelMax = 11 // max UTF-16 units in a volume label

	// exfatEOC marks the end of a FAT cluster chain.
	exfatEOC = 0xFFFFFFFF
	// exfatBadCluster marks a bad cluster in the exFAT FAT.
	exfatBadCluster = 0xFFFFFFF7
)

// exFAT file attribute bits (FileAttributes in the file-directory entry).
const (
	exfatAttrReadOnly = 0x0001
	exfatAttrHidden   = 0x0002
	exfatAttrSystem   = 0x0004
	exfatAttrDir      = 0x0010
	exfatAttrArchive  = 0x0020
)

// Parser safety limits. These mirror the parent filesystem package's private
// limits (fat32.go) with the same values; they live here because the subpackage
// cannot reference the parent's unexported identifiers.
const (
	// maxClusterChain bounds the number of clusters a single chain may span,
	// protecting against hostile/corrupt FAT tables.
	maxClusterChain = 1 << 22
	// maxSearchDepth bounds recursive directory traversal in SearchFiles.
	maxSearchDepth = 32
	// maxSearchCount bounds the number of results SearchFiles may return.
	maxSearchCount = 100000
	// maxDirBytes bounds how much directory data readDirectory will parse.
	maxDirBytes = uint64(1) << 30
)

// EXFAT handles exFAT filesystem operations.
type EXFAT struct {
	reader   filesystem.Reader
	startLBA uint64

	// Parsed boot sector values (spec section 3.1).
	partitionOffset    uint64
	volumeLength       uint64
	fatOffset          uint32
	fatLength          uint32
	clusterHeapOffset  uint32
	clusterCount       uint32
	firstClusterOfRoot uint32
	volumeSerialNumber uint32
	volumeLabel        string

	bytesPerSector    uint16
	sectorsPerCluster uint8
	clusterSize       uint64

	readFunc func(startLBA uint64, count uint64) ([]byte, error)
}

// NewEXFATHandler creates a new exFAT handler. reader is the absolute-LBA sector
// reader (see filesystem.Reader); startLBA is the partition's first sector.
func NewEXFATHandler(reader filesystem.Reader, startLBA uint64) (*EXFAT, error) {
	if reader == nil {
		return nil, fmt.Errorf("exFAT handler requires a reader")
	}
	h := &EXFAT{
		reader:   reader,
		startLBA: startLBA,
	}
	h.readFunc = reader.ReadSectors
	if err := h.readBootSector(); err != nil {
		return nil, err
	}
	// Volume label lives in the root directory (0x83 entry); read it
	// best-effort so GetVolumeLabel works without a prior ListDirectory.
	h.readVolumeLabel()
	return h, nil
}

// readSectors reads count sectors at an absolute LBA via the handler's reader.
func (exfat *EXFAT) readSectors(lba uint64, count uint64) ([]byte, error) {
	if exfat.readFunc == nil {
		return nil, fmt.Errorf("exFAT: handler has no reader")
	}
	data, err := exfat.readFunc(lba, count)
	if err != nil {
		return nil, err
	}
	want := count * uint64(exfat.bytesPerSector)
	if exfat.bytesPerSector == 0 {
		want = count * 512
	}
	if uint64(len(data)) < want {
		return nil, fmt.Errorf("exFAT: short read at LBA %d: got %d bytes, want %d", lba, len(data), want)
	}
	return data, nil
}

// parseBootSector validates and parses the exFAT boot sector at spec offsets.
func (exfat *EXFAT) parseBootSector(data []byte) error {
	if len(data) < 512 {
		return fmt.Errorf("exFAT: boot sector too small")
	}
	if string(data[3:11]) != "EXFAT   " {
		return fmt.Errorf("exFAT: invalid signature")
	}

	bpsShift := data[108]
	spcShift := data[109]
	if bpsShift < 9 || bpsShift > 12 {
		return fmt.Errorf("exFAT: invalid bytes-per-sector shift %d", bpsShift)
	}
	if spcShift > 25 {
		return fmt.Errorf("exFAT: invalid sectors-per-cluster shift %d", spcShift)
	}
	exfat.bytesPerSector = uint16(1) << bpsShift
	exfat.sectorsPerCluster = 1 << spcShift
	exfat.clusterSize = uint64(exfat.bytesPerSector) * uint64(exfat.sectorsPerCluster)

	exfat.partitionOffset = binary.LittleEndian.Uint64(data[64:72])
	exfat.volumeLength = binary.LittleEndian.Uint64(data[72:80])
	exfat.fatOffset = binary.LittleEndian.Uint32(data[80:84])
	exfat.fatLength = binary.LittleEndian.Uint32(data[84:88])
	exfat.clusterHeapOffset = binary.LittleEndian.Uint32(data[88:92])
	exfat.clusterCount = binary.LittleEndian.Uint32(data[92:96])
	exfat.firstClusterOfRoot = binary.LittleEndian.Uint32(data[96:100])
	exfat.volumeSerialNumber = binary.LittleEndian.Uint32(data[100:104])

	if exfat.firstClusterOfRoot < 2 {
		return fmt.Errorf("exFAT: invalid root cluster %d", exfat.firstClusterOfRoot)
	}
	if exfat.clusterCount == 0 {
		return fmt.Errorf("exFAT: invalid cluster count 0")
	}
	if exfat.clusterHeapOffset == 0 {
		return fmt.Errorf("exFAT: invalid cluster heap offset 0")
	}
	return nil
}

// readBootSector reads and parses the boot sector at the partition start.
func (exfat *EXFAT) readBootSector() error {
	data, err := exfat.readSectors(exfat.startLBA, 1)
	if err != nil {
		return fmt.Errorf("exFAT: failed to read boot sector: %w", err)
	}
	return exfat.parseBootSector(data)
}

// Type returns the filesystem type.
func (exfat *EXFAT) Type() filesystem.FileSystemType {
	return filesystem.FS_EXFAT
}

// Open initializes the filesystem from boot sector data (used by the detection
// path; real reads require a reader via NewEXFATHandler).
func (exfat *EXFAT) Open(sectorData []byte) error {
	return exfat.parseBootSector(sectorData)
}

// Close closes the filesystem handler.
func (exfat *EXFAT) Close() error { return nil }

// GetVolumeLabel returns the volume label stored in the root directory.
func (exfat *EXFAT) GetVolumeLabel() string {
	if exfat.volumeLabel == "" {
		exfat.readVolumeLabel()
	}
	return exfat.volumeLabel
}

// GetClusterSize returns the cluster size in bytes (0 when not parsed).
func (exfat *EXFAT) GetClusterSize() int {
	return int(exfat.clusterSize)
}

// clusterToLBA converts a cluster number to its absolute LBA.
func (exfat *EXFAT) clusterToLBA(cluster uint32) uint64 {
	return exfat.startLBA + uint64(exfat.clusterHeapOffset) + uint64(cluster-2)*uint64(exfat.sectorsPerCluster)
}

// fatEntry returns the 32-bit FAT entry for the given cluster. exFAT FAT
// entries are full 32-bit values (no reserved top bits as in FAT32).
func (exfat *EXFAT) fatEntry(cluster uint32) (uint32, error) {
	if cluster < 2 {
		return 0, fmt.Errorf("exFAT: invalid cluster number %d", cluster)
	}
	if cluster > exfat.clusterCount+1 {
		return 0, fmt.Errorf("exFAT: cluster %d out of range (cluster count %d)", cluster, exfat.clusterCount)
	}
	entryOffset := uint64(cluster) * 4
	fatSector := exfat.fatOffset + uint32(entryOffset/uint64(exfat.bytesPerSector))
	offInSector := entryOffset % uint64(exfat.bytesPerSector)

	data, err := exfat.readSectors(exfat.startLBA+uint64(fatSector), 1)
	if err != nil {
		return 0, fmt.Errorf("exFAT: failed to read FAT sector %d: %w", fatSector, err)
	}
	if offInSector+4 > uint64(len(data)) {
		return 0, fmt.Errorf("exFAT: FAT sector %d too short: got %d bytes", fatSector, len(data))
	}
	return binary.LittleEndian.Uint32(data[offInSector : offInSector+4]), nil
}

// clusterChain follows the exFAT FAT cluster chain starting at start, returning
// the ordered list of clusters. It stops at an end-of-chain marker and rejects
// bad clusters, free clusters, cycles, and over-long chains.
func (exfat *EXFAT) clusterChain(start uint32) ([]uint32, error) {
	if start < 2 {
		return nil, fmt.Errorf("exFAT: invalid start cluster %d", start)
	}
	chain := make([]uint32, 0, 8)
	visited := make(map[uint32]struct{})
	cluster := start
	for {
		if len(chain) >= maxClusterChain {
			return nil, fmt.Errorf("exFAT: cluster chain exceeds %d clusters", maxClusterChain)
		}
		if _, seen := visited[cluster]; seen {
			return nil, fmt.Errorf("exFAT: cycle detected in cluster chain at cluster %d", cluster)
		}
		visited[cluster] = struct{}{}
		chain = append(chain, cluster)

		next, err := exfat.fatEntry(cluster)
		if err != nil {
			return nil, fmt.Errorf("exFAT: FAT entry for cluster %d: %w", cluster, err)
		}
		switch {
		case next == exfatBadCluster:
			return nil, fmt.Errorf("exFAT: bad cluster marker at cluster %d", cluster)
		case next == 0:
			return nil, fmt.Errorf("exFAT: truncated cluster chain: cluster %d has no next/EOC entry", cluster)
		case next == exfatEOC:
			return chain, nil
		}
		cluster = next
	}
}

// readFileClusters reads the data clusters of a file, following the FAT chain
// and truncating the result to the file's logical size.
func (exfat *EXFAT) readFileClusters(start uint32, size uint64) ([]byte, error) {
	if size == 0 {
		return []byte{}, nil
	}
	if start < 2 {
		return nil, fmt.Errorf("exFAT: file has size %d but invalid start cluster %d", size, start)
	}
	chain, err := exfat.clusterChain(start)
	if err != nil {
		return nil, err
	}
	total := uint64(len(chain)) * exfat.clusterSize
	if total < size {
		return nil, fmt.Errorf("exFAT: file size %d exceeds %d bytes allocated by cluster chain", size, total)
	}

	out := make([]byte, 0, size)
	remaining := size
	for _, cl := range chain {
		if remaining == 0 {
			break
		}
		lba := exfat.clusterToLBA(cl)
		data, err := exfat.readSectors(lba, uint64(exfat.sectorsPerCluster))
		if err != nil {
			return nil, fmt.Errorf("exFAT: failed to read data cluster %d (LBA %d): %w", cl, lba, err)
		}
		if uint64(len(data)) < exfat.clusterSize {
			return nil, fmt.Errorf("exFAT: short read for data cluster %d: got %d bytes, want %d", cl, len(data), exfat.clusterSize)
		}
		take := exfat.clusterSize
		if take > remaining {
			take = remaining
		}
		out = append(out, data[:take]...)
		remaining -= take
	}
	return out, nil
}

// readDirCluster reads the first cluster of a directory at the given cluster.
func (exfat *EXFAT) readDirCluster(cluster uint32) ([]byte, error) {
	if cluster < 2 {
		return nil, fmt.Errorf("exFAT: invalid directory cluster %d", cluster)
	}
	lba := exfat.clusterToLBA(cluster)
	data, err := exfat.readSectors(lba, uint64(exfat.sectorsPerCluster))
	if err != nil {
		return nil, fmt.Errorf("exFAT: failed to read directory cluster %d (LBA %d): %w", cluster, lba, err)
	}
	if uint64(len(data)) < exfat.clusterSize {
		return nil, fmt.Errorf("exFAT: short read for directory cluster %d: got %d bytes, want %d", cluster, len(data), exfat.clusterSize)
	}
	return data[:exfat.clusterSize], nil
}

// readVolumeLabel reads the root directory's first cluster and extracts the
// 0x83 volume-label entry. Failures are ignored: GetVolumeLabel degrades to ""
// rather than erroring (the label is optional metadata).
func (exfat *EXFAT) readVolumeLabel() {
	if exfat.firstClusterOfRoot < 2 || exfat.readFunc == nil {
		return
	}
	buf, err := exfat.readDirCluster(exfat.firstClusterOfRoot)
	if err != nil {
		return
	}
	for i := 0; i+32 <= len(buf); i += 32 {
		e := buf[i : i+32]
		if e[0] == exfatEndOfDir || e[0] == 0x01 {
			return
		}
		if e[0] == exfatEntryVolume {
			exfat.volumeLabel = decodeVolumeLabel(e)
			return
		}
	}
}

// decodeVolumeLabel decodes the UTF-16LE label of a 0x83 volume-label entry.
func decodeVolumeLabel(e []byte) string {
	cnt := int(e[1])
	if cnt > exfatVolumeLabelMax {
		cnt = exfatVolumeLabelMax
	}
	var units []uint16
	for j := 0; j < cnt; j++ {
		off := 2 + j*2
		if off+2 > len(e) {
			break
		}
		u := binary.LittleEndian.Uint16(e[off : off+2])
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	return strings.TrimRight(string(utf16.Decode(units)), "\x00")
}

// readDirectory reads a directory via its FAT cluster chain and parses the
// entry sets into DirectoryEntry values. The cluster chain is walked to its
// end-of-chain marker (or a hard bound), then entries are parsed up to the first
// end-of-directory (0x00) marker.
func (exfat *EXFAT) readDirectory(cluster uint32) ([]filesystem.DirectoryEntry, error) {
	if cluster == 0 {
		// A genuine empty exFAT subdirectory stores FirstCluster = 0 in its 0xC0
		// stream. That is honest on-disk data: an empty directory. Return an
		// EMPTY non-nil listing, never (nil, nil), so callers can distinguish
		// "empty" from "failed" (解析红线).
		return []filesystem.DirectoryEntry{}, nil
	}
	if cluster < 2 {
		return nil, fmt.Errorf("exFAT: invalid directory cluster %d", cluster)
	}

	var buf []byte
	visited := make(map[uint32]struct{})
	current := cluster
	for {
		if len(visited) >= maxClusterChain {
			return nil, fmt.Errorf("exFAT: directory cluster chain exceeds %d clusters", maxClusterChain)
		}
		if _, seen := visited[current]; seen {
			return nil, fmt.Errorf("exFAT: cycle detected in directory cluster chain at cluster %d", current)
		}
		visited[current] = struct{}{}

		lba := exfat.clusterToLBA(current)
		chunk, err := exfat.readSectors(lba, uint64(exfat.sectorsPerCluster))
		if err != nil {
			return nil, fmt.Errorf("exFAT: failed to read directory cluster %d (LBA %d): %w", current, lba, err)
		}
		if uint64(len(chunk)) < exfat.clusterSize {
			return nil, fmt.Errorf("exFAT: short read for directory cluster %d: got %d bytes, want %d", current, len(chunk), exfat.clusterSize)
		}
		if uint64(len(buf))+exfat.clusterSize > maxDirBytes {
			return nil, fmt.Errorf("exFAT: directory at cluster %d exceeds %d bytes", cluster, maxDirBytes)
		}
		buf = append(buf, chunk...)

		next, err := exfat.fatEntry(current)
		if err != nil {
			return nil, fmt.Errorf("exFAT: FAT entry for directory cluster %d: %w", current, err)
		}
		switch {
		case next == exfatBadCluster:
			return nil, fmt.Errorf("exFAT: bad cluster marker in directory chain at cluster %d", current)
		case next == 0:
			return nil, fmt.Errorf("exFAT: truncated directory cluster chain at cluster %d", current)
		case next == exfatEOC:
			return exfat.parseDirectory(buf)
		}
		current = next
	}
}

// parseDirectory parses directory entry bytes, grouping entry sets (a 0x85 file
// directory entry plus its stream/name secondaries) into files. It stops at the
// first end-of-directory marker. Unknown or out-of-use entries are skipped; a
// truncated/invalid entry set is an explicit error (never a fabricated file).
func (exfat *EXFAT) parseDirectory(data []byte) ([]filesystem.DirectoryEntry, error) {
	// Non-nil empty slice so a genuinely empty on-disk directory is reported as
	// an empty listing, never a nil slice (解析红线).
	entries := make([]filesystem.DirectoryEntry, 0, 4)
	i := 0
	for i+32 <= len(data) {
		entry := data[i : i+32]
		typ := entry[0]

		if typ == exfatEndOfDir || typ == 0x01 {
			return entries, nil
		}
		if typ&0x80 == 0 {
			// Not in use (deleted, never used, reserved slot): skip.
			i += 32
			continue
		}

		switch typ {
		case exfatEntryVolume:
			if exfat.volumeLabel == "" {
				exfat.volumeLabel = decodeVolumeLabel(entry)
			}
			i += 32

		case exfatEntryBitmap, exfatEntryUpCase:
			// System entries; not user files.
			i += 32

		case exfatEntryFileDir:
			secCnt := int(entry[1])
			if secCnt == 0 {
				// A file directory entry claiming no secondaries is degenerate.
				i += 32
				continue
			}
			set, next, ok := exfat.collectSet(data, i, secCnt)
			if !ok {
				return nil, fmt.Errorf("exFAT: truncated entry set at offset %d (secondary count %d)", i, secCnt)
			}
			i = next
			de, err := exfat.assembleSet(set)
			if err != nil {
				return nil, err
			}
			if de != nil {
				entries = append(entries, *de)
			}

		default:
			// Unknown in-use entry type: skip rather than guess.
			i += 32
		}
	}
	return entries, nil
}

// collectSet gathers a file directory entry plus its SecondaryCount secondary
// entries from the directory buffer. ok is false when the set runs past the
// buffer, is interrupted by an end marker, or hits a non-in-use entry.
func (exfat *EXFAT) collectSet(data []byte, start int, secCnt int) (set [][]byte, next int, ok bool) {
	if secCnt < 1 || secCnt > 18 || start+32 > len(data) {
		return nil, 0, false
	}
	set = make([][]byte, 0, secCnt+1)
	set = append(set, data[start:start+32])
	next = start + 32
	for k := 0; k < secCnt; k++ {
		if next+32 > len(data) {
			return nil, 0, false
		}
		e := data[next : next+32]
		if e[0] == exfatEndOfDir || e[0] == 0x01 || e[0]&0x80 == 0 {
			return nil, 0, false
		}
		set = append(set, e)
		next += 32
	}
	return set, next, true
}

// assembleSet builds a DirectoryEntry from a file directory entry set. It reads
// the name from the 0xC1 file-name entries and the size/first-cluster from the
// 0xC0 stream extension. A set missing its stream or name is an explicit error.
func (exfat *EXFAT) assembleSet(set [][]byte) (*filesystem.DirectoryEntry, error) {
	primary := set[0]
	attrs := binary.LittleEndian.Uint16(primary[4:6])

	var (
		stream       []byte
		nameUnits    []uint16
		nameLen      int
		firstCluster uint32
		dataLength   uint64
	)

	for _, e := range set[1:] {
		switch e[0] {
		case exfatEntryStream:
			if stream != nil {
				return nil, fmt.Errorf("exFAT: multiple stream entries in one set")
			}
			stream = e
			nameLen = int(e[3])
			firstCluster = binary.LittleEndian.Uint32(e[20:24])
			dataLength = binary.LittleEndian.Uint64(e[24:32])
		case exfatEntryFileName:
			// File name UTF-16LE lives at bytes 2-31 (15 units per entry).
			for j := 0; j < 15; j++ {
				off := 2 + j*2
				if off+2 > len(e) {
					break
				}
				u := binary.LittleEndian.Uint16(e[off : off+2])
				if u == 0 {
					break
				}
				nameUnits = append(nameUnits, u)
			}
		default:
			return nil, fmt.Errorf("exFAT: unexpected secondary entry type 0x%02x in set", e[0])
		}
	}
	if stream == nil {
		return nil, fmt.Errorf("exFAT: file set missing stream extension")
	}
	if len(nameUnits) == 0 {
		return nil, fmt.Errorf("exFAT: file set has no name")
	}
	if nameLen > 0 && nameLen < len(nameUnits) {
		// The stream's NameLength is authoritative; trailing null padding may
		// have been collected.
		nameUnits = nameUnits[:nameLen]
	}
	if nameLen > 0 && nameLen > len(nameUnits) {
		// NameLength claims more UTF-16 units than the 0xC1 entries actually
		// carry: the entry set is truncated/malformed. Returning a silently
		// shortened name would fabricate a file name, so this is an explicit
		// error (解析红线).
		return nil, fmt.Errorf("exFAT: file name length %d exceeds the %d units carried by the name entries (truncated/malformed entry set)", nameLen, len(nameUnits))
	}
	name := strings.TrimRight(string(utf16.Decode(nameUnits)), "\x00")
	if name == "" {
		return nil, fmt.Errorf("exFAT: file set decoded to an empty name")
	}

	isDir := attrs&exfatAttrDir != 0
	return &filesystem.DirectoryEntry{
		Name:    name,
		Path:    "/" + name,
		Size:    dataLength,
		IsDir:   isDir,
		Cluster: firstCluster,
		ModTime: 0,
	}, nil
}

// ListDirectory lists files in the specified directory path. An empty or "/"
// path lists the root directory.
func (exfat *EXFAT) ListDirectory(path string) ([]filesystem.DirectoryEntry, error) {
	if exfat.readFunc == nil {
		return nil, fmt.Errorf("exFAT: handler has no reader")
	}
	if path == "" || path == "/" {
		return exfat.readDirectory(exfat.firstClusterOfRoot)
	}

	path = strings.TrimPrefix(path, "/")
	parts := strings.Split(path, "/")
	currentCluster := exfat.firstClusterOfRoot

	for _, part := range parts {
		if part == "" {
			continue
		}
		entries, err := exfat.readDirectory(currentCluster)
		if err != nil {
			return nil, fmt.Errorf("exFAT: failed to read directory: %w", err)
		}
		found := false
		for _, e := range entries {
			if e.IsDir && e.Name == part {
				currentCluster = e.Cluster
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("exFAT: directory not found: %s: %w", part, filesystem.ErrNotFound)
		}
	}
	return exfat.readDirectory(currentCluster)
}

// resolveEntry resolves a path to its directory entry by walking directories
// via their cluster chains.
func (exfat *EXFAT) resolveEntry(path string) (*filesystem.DirectoryEntry, error) {
	clean := strings.Trim(path, "/")
	if clean == "" {
		return nil, fmt.Errorf("exFAT: root path has no file entry")
	}
	var parts []string
	for _, p := range strings.Split(clean, "/") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("exFAT: invalid path %q", path)
	}

	currentCluster := exfat.firstClusterOfRoot
	for i, part := range parts {
		entries, err := exfat.readDirectory(currentCluster)
		if err != nil {
			return nil, fmt.Errorf("exFAT: failed to read directory while resolving %q: %w", part, err)
		}
		var match *filesystem.DirectoryEntry
		for j := range entries {
			if entries[j].Name == part {
				match = &entries[j]
				break
			}
		}
		if match == nil {
			return nil, fmt.Errorf("exFAT: path component not found: %q: %w", part, filesystem.ErrNotFound)
		}
		if i == len(parts)-1 {
			return match, nil
		}
		if !match.IsDir {
			return nil, fmt.Errorf("exFAT: path component %q is not a directory: %w", part, filesystem.ErrNotDirectory)
		}
		currentCluster = match.Cluster
	}
	return nil, fmt.Errorf("exFAT: unreachable path resolution for %q", path)
}

// GetFile reads a file's contents by following its FAT cluster chain.
func (exfat *EXFAT) GetFile(path string) ([]byte, error) {
	if exfat.readFunc == nil {
		return nil, fmt.Errorf("exFAT: handler has no reader")
	}
	entry, err := exfat.resolveEntry(path)
	if err != nil {
		return nil, err
	}
	if entry.IsDir {
		return nil, fmt.Errorf("exFAT: path is a directory: %s: %w", path, filesystem.ErrIsDirectory)
	}
	return exfat.readFileClusters(entry.Cluster, entry.Size)
}

// GetFileByPath gets file info by path.
func (exfat *EXFAT) GetFileByPath(path string) (*filesystem.FileInfo, error) {
	if exfat.readFunc == nil {
		return nil, fmt.Errorf("exFAT: handler has no reader")
	}
	entry, err := exfat.resolveEntry(path)
	if err != nil {
		return nil, err
	}

	mode := filesystem.FileMode(filesystem.ModeRegular)
	if entry.IsDir {
		mode = filesystem.ModeDir
	}
	return &filesystem.FileInfo{
		Name:    entry.Name,
		Path:    "/" + strings.Trim(path, "/"),
		Size:    entry.Size,
		Mode:    mode,
		IsDir:   entry.IsDir,
		ModTime: 0, // exFAT timestamps are not decoded; exposed as 0 here
	}, nil
}

// SearchFiles searches for files matching a predicate, recursing through
// directories. Depth and result count are bounded.
func (exfat *EXFAT) SearchFiles(rootPath string, predicate func(filesystem.FileInfo) bool) ([]filesystem.FileInfo, error) {
	if exfat.readFunc == nil {
		return nil, fmt.Errorf("exFAT: handler has no reader")
	}
	cleanRoot := strings.Trim(rootPath, "/")
	base := ""
	rootCluster := exfat.firstClusterOfRoot
	if cleanRoot != "" {
		root, err := exfat.resolveEntry(rootPath)
		if err != nil {
			return nil, err
		}
		if !root.IsDir {
			return nil, fmt.Errorf("exFAT: search root %q is not a directory", rootPath)
		}
		rootCluster = root.Cluster
		base = "/" + cleanRoot
	}

	results := make([]filesystem.FileInfo, 0)

	var walk func(cluster uint32, dirPath string, depth int) error
	walk = func(cluster uint32, dirPath string, depth int) error {
		if depth > maxSearchDepth {
			return nil
		}
		entries, err := exfat.readDirectory(cluster)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if len(results) >= maxSearchCount {
				return fmt.Errorf("exFAT: search exceeded %d results", maxSearchCount)
			}
			fi := filesystem.FileInfo{
				Name:  e.Name,
				Path:  dirPath + "/" + e.Name,
				Size:  e.Size,
				IsDir: e.IsDir,
			}
			if e.IsDir {
				fi.Mode = filesystem.ModeDir
			} else {
				fi.Mode = filesystem.ModeRegular
			}
			if predicate(fi) {
				results = append(results, fi)
			}
			if e.IsDir && depth < maxSearchDepth {
				if err := walk(e.Cluster, fi.Path, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}

	if err := walk(rootCluster, base, 0); err != nil {
		return nil, err
	}
	return results, nil
}

func init() {
	filesystem.RegisterFileSystem(filesystem.FS_EXFAT, func() filesystem.FileSystem { return &EXFAT{} })
	filesystem.RegisterHandler(filesystem.FS_EXFAT, func(r filesystem.Reader, startLBA, partitionSize uint64) (filesystem.FileSystem, error) {
		return NewEXFATHandler(r, startLBA)
	})
}
