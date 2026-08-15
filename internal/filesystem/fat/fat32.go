package fat

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/laenix/ewfgo/internal/filesystem"
)

// FAT filesystem constants
const (
	// fat32EOC is the minimum FAT32 end-of-chain marker value.
	fat32EOC = 0x0FFFFFF8
	// fat32BadCluster is the FAT32 bad-cluster marker.
	fat32BadCluster = 0x0FFFFFF7
	// fat16EOC is the minimum FAT16 end-of-chain marker value.
	fat16EOC = 0xFFF8
	// fat16BadCluster is the FAT16 bad-cluster marker.
	fat16BadCluster = 0xFFF7
	// fat12EOC is the minimum FAT12 end-of-chain marker value.
	fat12EOC = 0xFF8
	// fat12BadCluster is the FAT12 bad-cluster marker.
	fat12BadCluster = 0xFF7
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

// FAT32Handler handles FAT12, FAT16 and FAT32 filesystem operations. The
// handler detects the actual variant from the boot sector and serves each
// through the appropriate FAT layout (packed 12-bit, 16-bit, or 32-bit).
type FAT32Handler struct {
	reader   filesystem.Reader
	startLBA uint64
	bootData []byte

	// fatBits is the FAT width detected from the boot sector: 12, 16 or 32.
	fatBits uint8

	// Parsed boot sector values
	bytesPerSector    uint16
	sectorsPerCluster uint8
	reservedSectors   uint16
	numFATs           uint8
	sectorsPerFAT32   uint32
	rootCluster       uint32
	totalSectors32    uint32
	totalSectors16    uint16
	backupBootSector  uint16
	// FAT12/16 boot-sector fields (not meaningful for FAT32)
	rootEntryCount  uint16
	sectorsPerFAT16 uint16

	// Calculated values (absolute LBAs)
	fatStart      uint64
	dataAreaStart uint64
	// rootDirLBA is the fixed root-directory region for FAT12/16.
	rootDirLBA uint64
}

// NewFAT32Handler creates a new FAT32 handler
func NewFAT32Handler(reader filesystem.Reader, startLBA uint64, partitionSize uint64) (*FAT32Handler, error) {
	h := &FAT32Handler{
		reader:   reader,
		startLBA: startLBA,
	}

	// Read boot sector to get parameters
	if err := h.readBootSector(partitionSize); err != nil {
		return nil, err
	}

	// Calculate FAT locations
	h.fatStart, h.dataAreaStart, h.rootDirLBA = h.calculateFATLocation(partitionSize)

	return h, nil
}

// readBootSector reads and parses the FAT12/16/32 boot sector. A FAT32 volume
// carries "FAT32   " at 0x52; FAT12/16 carry "FAT16   "/"FAT12   " at 0x36 and
// have no fields at 0x24/0x2C (those are FAT32-only). The handler records
// h.fatBits so every later layout computation branches on the actual variant.
func (h *FAT32Handler) readBootSector(partitionSize uint64) error {
	// Read first few sectors to find valid FAT boot sector
	data, err := h.reader.ReadSectors(h.startLBA, 64)
	if err != nil {
		return fmt.Errorf("failed to read boot sector: %w", err)
	}

	for i := 0; i+512 <= len(data); i += 512 {
		chunk := data[i : i+512]
		if len(chunk) < 0x3E {
			continue
		}

		fsType := string(chunk[0x36:0x3E])
		isFAT32 := len(chunk) >= 0x5A && string(chunk[0x52:0x5A]) == "FAT32   "

		if isFAT32 {
			h.fatBits = 32
			h.bootData = make([]byte, 512)
			copy(h.bootData, chunk)

			// Parse boot sector fields
			h.bytesPerSector = uint16(chunk[0x0B]) | uint16(chunk[0x0C])<<8
			h.sectorsPerCluster = chunk[0x0D]
			h.reservedSectors = uint16(chunk[0x0E]) | uint16(chunk[0x0F])<<8
			h.numFATs = chunk[0x10]
			h.sectorsPerFAT32 = uint32(chunk[0x24]) | uint32(chunk[0x25])<<8 | uint32(chunk[0x26])<<16 | uint32(chunk[0x27])<<24
			h.rootCluster = uint32(chunk[0x2C]) | uint32(chunk[0x2D])<<8 | uint32(chunk[0x2E])<<16 | uint32(chunk[0x2F])<<24
			h.totalSectors32 = uint32(chunk[0x20]) | uint32(chunk[0x21])<<8 | uint32(chunk[0x22])<<16 | uint32(chunk[0x23])<<24
			h.backupBootSector = uint16(chunk[0x32]) | uint16(chunk[0x33])<<8
		} else if fsType == "FAT16   " {
			h.fatBits = 16
			h.bootData = make([]byte, 512)
			copy(h.bootData, chunk)

			// Parse FAT16 field offsets. The fixed root directory region and the
			// 16-bit FAT are described here; the 0x24/0x2C fields are FAT32-only
			// and deliberately not read.
			h.bytesPerSector = uint16(chunk[0x0B]) | uint16(chunk[0x0C])<<8
			h.sectorsPerCluster = chunk[0x0D]
			h.reservedSectors = uint16(chunk[0x0E]) | uint16(chunk[0x0F])<<8
			h.numFATs = chunk[0x10]
			h.rootEntryCount = uint16(chunk[0x11]) | uint16(chunk[0x12])<<8
			h.totalSectors16 = uint16(chunk[0x13]) | uint16(chunk[0x14])<<8
			h.sectorsPerFAT16 = uint16(chunk[0x16]) | uint16(chunk[0x17])<<8
			h.totalSectors32 = uint32(chunk[0x20]) | uint32(chunk[0x21])<<8 | uint32(chunk[0x22])<<16 | uint32(chunk[0x23])<<24
		} else if fsType == "FAT12   " {
			h.fatBits = 12
			h.bootData = make([]byte, 512)
			copy(h.bootData, chunk)

			// FAT12 shares the FAT16 field offsets (fixed root region, 16-bit
			// sectors-per-FAT); only the FAT entry encoding differs (packed 12-bit).
			h.bytesPerSector = uint16(chunk[0x0B]) | uint16(chunk[0x0C])<<8
			h.sectorsPerCluster = chunk[0x0D]
			h.reservedSectors = uint16(chunk[0x0E]) | uint16(chunk[0x0F])<<8
			h.numFATs = chunk[0x10]
			h.rootEntryCount = uint16(chunk[0x11]) | uint16(chunk[0x12])<<8
			h.totalSectors16 = uint16(chunk[0x13]) | uint16(chunk[0x14])<<8
			h.sectorsPerFAT16 = uint16(chunk[0x16]) | uint16(chunk[0x17])<<8
			h.totalSectors32 = uint32(chunk[0x20]) | uint32(chunk[0x21])<<8 | uint32(chunk[0x22])<<16 | uint32(chunk[0x23])<<24
		} else {
			continue
		}

		// Validate boot parameters defensively. A volume we cannot interpret
		// correctly must fail loudly rather than return garbage.
		bps := h.bytesPerSector
		if bps < 512 || bps&(bps-1) != 0 {
			return fmt.Errorf("invalid bytesPerSector %d", bps)
		}
		spc := h.sectorsPerCluster
		if spc == 0 || spc&(spc-1) != 0 || spc > 128 {
			return fmt.Errorf("invalid sectorsPerCluster %d", spc)
		}
		if h.numFATs == 0 {
			return fmt.Errorf("invalid number of FATs: 0")
		}
		if h.fatBits == 32 {
			if h.rootCluster < 2 {
				h.rootCluster = 2
			}
		} else {
			if h.sectorsPerFAT16 == 0 {
				return fmt.Errorf("invalid sectorsPerFAT16: 0")
			}
			if h.rootEntryCount == 0 {
				return fmt.Errorf("invalid rootEntryCount: 0")
			}
			// The root of a FAT12/16 volume is the fixed region, not a cluster.
			h.rootCluster = 0
		}

		return nil
	}

	return fmt.Errorf("FAT boot sector not found")
}

// calculateFATLocation calculates the FAT and data area locations.
//
// FAT32: the root directory is cluster 2 (the current FAT32 arithmetic).
// FAT12/16: the root directory is a FIXED region at
// `fatStart + numFATs*sectorsPerFAT16`, sized `ceil(rootEntryCount*32/bps)`;
// the data area starts after it. FAT12/16 never use the FAT32 rootCluster
// arithmetic.
func (h *FAT32Handler) calculateFATLocation(partitionSize uint64) (fatStart uint64, dataAreaStart uint64, rootDirLBA uint64) {
	reserved := uint64(h.reservedSectors)
	numFATs := uint64(h.numFATs)

	if h.fatBits == 12 || h.fatBits == 16 {
		spf := uint64(h.sectorsPerFAT16)
		rootEntryBytes := uint64(h.rootEntryCount) * 32
		rootDirSectors := (rootEntryBytes + uint64(h.bytesPerSector) - 1) / uint64(h.bytesPerSector)
		fatStart = h.startLBA + reserved
		rootDirLBA = fatStart + numFATs*spf
		dataAreaStart = rootDirLBA + rootDirSectors
		return
	}

	sectorsPerCluster := uint64(h.sectorsPerCluster)

	// Calculate sectors per FAT
	// Only use fallback calculation if sectorsPerFAT is clearly invalid (0 or very small)
	// A typical FAT32 sectorsPerFAT is at least a few hundred, so threshold of 100 is reasonable
	sectorsPerFAT := uint64(h.sectorsPerFAT32)
	if sectorsPerFAT == 0 || sectorsPerFAT < 100 {
		// Only use fallback for clearly invalid values
		if sectorsPerCluster == 0 {
			sectorsPerCluster = 1
		}
		clusters := partitionSize / sectorsPerCluster
		sectorsPerFAT = (clusters*4 + 511) / 512
		sectorsPerFAT += 100
		if sectorsPerFAT > 16000 {
			sectorsPerFAT = 16000
		}
	}

	fatStart = h.startLBA + reserved
	dataAreaStart = fatStart + (numFATs * sectorsPerFAT)

	// Root directory is at cluster 2
	rootCluster := uint64(h.rootCluster)
	if rootCluster < 2 {
		rootCluster = 2
	}
	rootDirLBA = dataAreaStart + ((rootCluster - 2) * sectorsPerCluster)

	return
}

// clusterToLBA converts a cluster number to absolute LBA
func (h *FAT32Handler) clusterToLBA(cluster uint32) uint64 {
	sectorsPerCluster := uint64(h.sectorsPerCluster)
	return h.dataAreaStart + (uint64(cluster)-2)*sectorsPerCluster
}

// effectiveSectorsPerFAT returns the sectors-per-FAT implied by the computed
// FAT/data-area layout. This uses the value actually applied by
// calculateFATLocation (including the fallback), not the raw boot-sector field.
func (h *FAT32Handler) effectiveSectorsPerFAT() (uint64, error) {
	if h.numFATs == 0 {
		return 0, fmt.Errorf("invalid number of FATs: 0")
	}
	if h.fatStart > h.dataAreaStart {
		return 0, fmt.Errorf("invalid FAT layout: dataAreaStart %d < fatStart %d", h.dataAreaStart, h.fatStart)
	}
	return (h.dataAreaStart - h.fatStart) / uint64(h.numFATs), nil
}

// fatClusterCount returns the number of cluster entries addressable by one FAT.
// The entry width is fatType-aware: 4 bytes (FAT32), 2 bytes (FAT16), or the
// packed 12-bit form (FAT12, 1.5 bytes per entry).
func (h *FAT32Handler) fatClusterCount() (uint64, error) {
	if h.bytesPerSector == 0 {
		return 0, fmt.Errorf("invalid bytesPerSector 0")
	}
	switch h.fatBits {
	case 12:
		return uint64(h.sectorsPerFAT16) * uint64(h.bytesPerSector) * 2 / 3, nil
	case 16:
		return uint64(h.sectorsPerFAT16) * uint64(h.bytesPerSector) / 2, nil
	default:
		spf, err := h.effectiveSectorsPerFAT()
		if err != nil {
			return 0, err
		}
		return spf * uint64(h.bytesPerSector) / 4, nil
	}
}

// isEOC reports whether a FAT entry value is an end-of-chain marker for this
// volume's FAT width.
func (h *FAT32Handler) isEOC(v uint32) bool {
	switch h.fatBits {
	case 12:
		return v >= fat12EOC
	case 16:
		return v >= fat16EOC
	default:
		return v >= fat32EOC
	}
}

// isBad reports whether a FAT entry value is the bad-cluster marker for this
// volume's FAT width.
func (h *FAT32Handler) isBad(v uint32) bool {
	switch h.fatBits {
	case 12:
		return v == fat12BadCluster
	case 16:
		return v == fat16BadCluster
	default:
		return v == fat32BadCluster
	}
}

// fatEntry returns the FAT entry for the given cluster. The encoding is
// fatType-aware: 32-bit masked to 28 bits (FAT32), 16-bit little-endian
// (FAT16), or the packed 12-bit form (FAT12, masked from a 16-bit window).
func (h *FAT32Handler) fatEntry(cluster uint32) (uint32, error) {
	if cluster < 2 {
		return 0, fmt.Errorf("invalid cluster number %d", cluster)
	}
	maxClusters, err := h.fatClusterCount()
	if err != nil {
		return 0, err
	}
	if uint64(cluster) >= maxClusters {
		return 0, fmt.Errorf("cluster %d out of FAT range (max valid cluster %d)", cluster, maxClusters-1)
	}

	var entryOffset uint64
	switch h.fatBits {
	case 12:
		entryOffset = (uint64(cluster) * 3) / 2
	case 16:
		entryOffset = uint64(cluster) * 2
	default:
		entryOffset = uint64(cluster) * 4
	}
	fatSectorIndex := entryOffset / uint64(h.bytesPerSector)
	sectorOffset := entryOffset % uint64(h.bytesPerSector)

	// A packed 12-bit entry may straddle a sector boundary; read two sectors so
	// the 16-bit window used to extract it is always available.
	sectors := uint64(1)
	if sectorOffset+2 > uint64(h.bytesPerSector) {
		sectors = 2
	}
	sector, err := h.reader.ReadSectors(h.fatStart+fatSectorIndex, sectors)
	if err != nil {
		return 0, fmt.Errorf("failed to read FAT sector %d: %w", fatSectorIndex, err)
	}
	if uint64(len(sector)) < sectorOffset+2 {
		return 0, fmt.Errorf("FAT sector %d too short: got %d bytes", fatSectorIndex, len(sector))
	}

	value := uint32(sector[sectorOffset]) |
		uint32(sector[sectorOffset+1])<<8

	switch h.fatBits {
	case 12:
		if cluster&1 == 0 {
			return value & 0x0FFF, nil
		}
		return (value >> 4) & 0x0FFF, nil
	case 16:
		return value, nil
	default:
		value |= uint32(sector[sectorOffset+2])<<16 |
			uint32(sector[sectorOffset+3])<<24
		// The top 4 bits of a FAT32 entry are reserved and must be masked off.
		return value & 0x0FFFFFFF, nil
	}
}

// clusterChain follows the FAT32 cluster chain starting at start, returning the
// ordered list of clusters. It stops at an end-of-chain marker and rejects bad
// clusters, free clusters, cycles, and over-long chains.
func (h *FAT32Handler) clusterChain(start uint32) ([]uint32, error) {
	if start < 2 {
		return nil, fmt.Errorf("invalid start cluster %d", start)
	}

	chain := make([]uint32, 0, 8)
	visited := make(map[uint32]struct{})
	cluster := start
	for {
		if len(chain) >= maxClusterChain {
			return nil, fmt.Errorf("cluster chain exceeds %d clusters", maxClusterChain)
		}
		if _, seen := visited[cluster]; seen {
			return nil, fmt.Errorf("cycle detected in cluster chain at cluster %d", cluster)
		}
		visited[cluster] = struct{}{}
		chain = append(chain, cluster)

		next, err := h.fatEntry(cluster)
		if err != nil {
			return nil, fmt.Errorf("FAT entry for cluster %d: %w", cluster, err)
		}
		switch {
		case h.isBad(next):
			return nil, fmt.Errorf("bad cluster marker at cluster %d", cluster)
		case next == 0:
			return nil, fmt.Errorf("truncated cluster chain: cluster %d has no next/EOC entry", cluster)
		case h.isEOC(next):
			return chain, nil
		}
		cluster = next
	}
}

// readFileClusters reads the data clusters of a file, following the FAT chain
// and truncating the result to the file's logical size.
func (h *FAT32Handler) readFileClusters(start uint32, size uint64) ([]byte, error) {
	if size == 0 {
		return []byte{}, nil
	}
	if start < 2 {
		return nil, fmt.Errorf("file has size %d but invalid start cluster %d", size, start)
	}

	chain, err := h.clusterChain(start)
	if err != nil {
		return nil, err
	}

	clusterSize := uint64(h.bytesPerSector) * uint64(h.sectorsPerCluster)
	total := uint64(len(chain)) * clusterSize
	if total < size {
		return nil, fmt.Errorf("file size %d exceeds %d bytes allocated by cluster chain", size, total)
	}

	out := make([]byte, 0, size)
	remaining := size
	for _, cl := range chain {
		if remaining == 0 {
			break
		}
		lba := h.clusterToLBA(cl)
		data, err := h.reader.ReadSectors(lba, uint64(h.sectorsPerCluster))
		if err != nil {
			return nil, fmt.Errorf("failed to read data cluster %d (LBA %d): %w", cl, lba, err)
		}
		if uint64(len(data)) < clusterSize {
			return nil, fmt.Errorf("short read for data cluster %d: got %d bytes, want %d", cl, len(data), clusterSize)
		}
		take := uint64(len(data))
		if take > remaining {
			take = remaining
		}
		out = append(out, data[:take]...)
		remaining -= take
	}
	return out, nil
}

// readRootDir reads the fixed root-directory region of a FAT12/16 volume
// (rootEntryCount x 32 bytes at h.rootDirLBA) and parses it. FAT12/16 root
// directories are a fixed region, not a cluster chain.
func (h *FAT32Handler) readRootDir() ([]filesystem.DirectoryEntry, error) {
	rootBytes := uint64(h.rootEntryCount) * 32
	rootSectors := (rootBytes + uint64(h.bytesPerSector) - 1) / uint64(h.bytesPerSector)
	data, err := h.reader.ReadSectors(h.rootDirLBA, rootSectors)
	if err != nil {
		return nil, fmt.Errorf("failed to read root directory (LBA %d): %w", h.rootDirLBA, err)
	}
	if uint64(len(data)) < rootBytes {
		return nil, fmt.Errorf("short read of root directory: got %d bytes, want %d", len(data), rootBytes)
	}
	if uint64(len(data)) > rootBytes {
		data = data[:rootBytes]
	}
	entries, _ := h.parseDirectory(data, "/")
	return entries, nil
}

// rootListing returns the entries of the root directory using whichever layout
// applies: the fixed region for FAT12/16, the cluster chain for FAT32. Root
// entries are returned with "/"-prefixed paths.
func (h *FAT32Handler) rootListing() ([]filesystem.DirectoryEntry, error) {
	if h.fatBits == 12 || h.fatBits == 16 {
		return h.readRootDir()
	}
	return h.readDirectory(h.rootCluster, "/")
}

// ListDirectory lists files in the specified directory path
// If path is empty or "/", lists root directory
func (h *FAT32Handler) ListDirectory(path string) ([]filesystem.DirectoryEntry, error) {
	// Parse path to find target directory
	if path == "" || path == "/" {
		// Root directory
		return h.rootListing()
	}

	// Remove leading slash
	path = strings.TrimPrefix(path, "/")

	// Find the directory by traversing path. The first level resolves in the
	// root (fixed region for FAT12/16); deeper levels use cluster chains. The
	// accumulated path is threaded into the final read so each returned entry
	// carries a real absolute path under its parent (not a root-relative one).
	parts := strings.Split(path, "/")
	entries, err := h.rootListing()
	if err != nil {
		return nil, fmt.Errorf("failed to read root directory: %w", err)
	}
	currentCluster := h.rootCluster
	currentPath := "/"

	for _, part := range parts {
		if part == "" {
			continue
		}

		// Find the subdirectory in the current level's entries
		found := false
		for _, e := range entries {
			if e.IsDir && e.Name == part {
				// Found - get cluster and continue
				currentCluster = e.Cluster
				found = true
				break
			}
		}

		if !found {
			return nil, fmt.Errorf("directory not found: %s: %w", part, filesystem.ErrNotFound)
		}

		currentPath = filesystem.JoinPath(currentPath, part)

		// Read the subdirectory (cluster chain)
		entries, err = h.readDirectory(currentCluster, currentPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read directory: %w", err)
		}
	}

	return entries, nil
}

// readDirectory reads directory entries from a given cluster, following the FAT
// chain for directories larger than one cluster. Parsing stops at an
// end-of-directory (0x00) marker or at the end of the cluster chain. parentPath
// is the directory's own path, used to build each entry's absolute Path.
func (h *FAT32Handler) readDirectory(cluster uint32, parentPath string) ([]filesystem.DirectoryEntry, error) {
	if cluster == 0 {
		// An empty directory on FAT32 has a first-cluster field of 0.
		return nil, nil
	}
	if cluster < 2 {
		return nil, fmt.Errorf("invalid directory cluster %d", cluster)
	}

	clusterSize := uint64(h.bytesPerSector) * uint64(h.sectorsPerCluster)
	var entries []filesystem.DirectoryEntry
	visited := make(map[uint32]struct{})
	totalBytes := uint64(0)

	current := cluster
	for {
		if len(visited) >= maxClusterChain {
			return nil, fmt.Errorf("directory cluster chain exceeds %d clusters", maxClusterChain)
		}
		if _, seen := visited[current]; seen {
			return nil, fmt.Errorf("cycle detected in directory cluster chain at cluster %d", current)
		}
		visited[current] = struct{}{}

		lba := h.clusterToLBA(current)
		chunk, err := h.reader.ReadSectors(lba, uint64(h.sectorsPerCluster))
		if err != nil {
			return nil, fmt.Errorf("failed to read directory cluster %d (LBA %d): %w", current, lba, err)
		}
		if uint64(len(chunk)) != clusterSize {
			return nil, fmt.Errorf("short read for directory cluster %d: got %d bytes, want %d", current, len(chunk), clusterSize)
		}
		totalBytes += clusterSize
		if totalBytes > maxDirBytes {
			return nil, fmt.Errorf("directory at cluster %d exceeds %d bytes", cluster, maxDirBytes)
		}

		parsed, ended := h.parseDirectory(chunk, parentPath)
		entries = append(entries, parsed...)
		if ended {
			return entries, nil
		}

		next, err := h.fatEntry(current)
		if err != nil {
			return nil, fmt.Errorf("FAT entry for directory cluster %d: %w", current, err)
		}
		switch {
		case h.isBad(next):
			return nil, fmt.Errorf("bad cluster marker in directory chain at cluster %d", current)
		case next == 0:
			return nil, fmt.Errorf("truncated directory cluster chain at cluster %d", current)
		case h.isEOC(next):
			return entries, nil
		}
		current = next
	}
}

// parseDirectory parses FAT32 directory entries from a block of directory data.
// The second return value reports whether an end-of-directory (0x00) marker was
// encountered, meaning no further clusters should be read. parentPath prefixes
// each entry's Path (see joinFATPath).
func (h *FAT32Handler) parseDirectory(data []byte, parentPath string) ([]filesystem.DirectoryEntry, bool) {
	var entries []filesystem.DirectoryEntry

	// Collect long-filename UTF-16 code units, one slice per LFN record in disk
	// order (highest ordinal first). A surrogate pair can straddle the boundary
	// between records, so the units are concatenated in name order and decoded
	// as one stream when the owning short entry is reached — never decoded
	// per-record (rune(uint16) would garble every supplementary-plane char).
	var longNameUnits [][]uint16
	var longNameSeq int

	for i := 0; i+32 <= len(data); i += 32 {
		entry := data[i : i+32]

		// Skip free/deleted entries
		if entry[0] == 0x00 {
			// End of directory
			return entries, true
		}
		if entry[0] == 0xE5 {
			// Deleted entry - reset long name buffer
			longNameUnits = nil
			longNameSeq = 0
			continue
		}

		// Check if this is a long filename entry (attribute = 0x0F)
		if entry[11] == 0x0F {
			// Get sequence number (bits 0-5)
			seq := int(entry[0] & 0x3F)
			if seq == 0 || seq > 20 {
				longNameUnits = nil
				longNameSeq = 0
				continue
			}

			// Check if this is a continuation of previous long name
			// Long names are stored in reverse order (last entry first)
			if seq != longNameSeq-1 && longNameSeq != 0 {
				// New long name, reset
				longNameUnits = nil
			}
			longNameSeq = seq

			// Extract UTF-16LE code units. Each entry holds up to 13 units:
			// bytes 1-10 (units 1-5), bytes 14-25 (units 6-11), bytes 28-31
			// (units 12-13). 0x0000 / 0xFFFF mark unused slots of a truncated
			// name and are dropped; a real filename never contains them.
			units := make([]uint16, 0, 13)
			for _, off := range []int{1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30} {
				if off+1 >= len(entry) {
					continue
				}
				u := uint16(entry[off]) | uint16(entry[off+1])<<8
				if u != 0x0000 && u != 0xFFFF {
					units = append(units, u)
				}
			}

			// Records are stored highest-ordinal first; prepend so the final
			// concatenation is in name order.
			longNameUnits = append([][]uint16{units}, longNameUnits...)

			continue
		}

		// This is a normal directory entry (short name)

		// Check if we have a long filename
		var filename string
		if len(longNameUnits) > 0 {
			var all []uint16
			for _, u := range longNameUnits {
				all = append(all, u...)
			}
			filename = strings.TrimRight(string(utf16.Decode(all)), "\x00")
		}

		// If no long filename, use short name
		if filename == "" {
			// Parse the short name field (8 bytes)
			name := make([]byte, 0)
			for j := 0; j < 8; j++ {
				if entry[j] != 0 && entry[j] != ' ' {
					name = append(name, entry[j])
				}
			}

			// Parse extension (3 bytes)
			ext := make([]byte, 0)
			for j := 8; j < 11; j++ {
				if entry[j] != 0 && entry[j] != ' ' {
					ext = append(ext, entry[j])
				}
			}

			// Check for UTF-16LE encoding (Chinese filenames)
			filename = string(name)
			if len(name) >= 4 {
				utf16Count := 0
				for j := 1; j < len(name); j += 2 {
					if name[j] == 0x00 {
						utf16Count++
					}
				}
				if utf16Count >= len(name)/2 {
					// Decode UTF-16LE as a unit stream (surrogate-pair safe).
					var chars []uint16
					for j := 0; j+1 < len(name); j += 2 {
						chars = append(chars, uint16(name[j])|uint16(name[j+1])<<8)
					}
					filename = string(utf16.Decode(chars))
				}
			}

			if len(ext) > 0 {
				filename += "." + string(ext)
			}
		}

		if len(filename) == 0 {
			longNameUnits = nil
			longNameSeq = 0
			continue
		}

		// Skip "." and "..": they are a directory's self/parent cluster
		// references, not real entries. Listing them lets a downstream walker
		// recurse into "." (or "..") and loop or fabricate nested paths.
		if filename == "." || filename == ".." {
			longNameUnits = nil
			longNameSeq = 0
			continue
		}

		// Skip volume labels
		if entry[11]&0x08 != 0 {
			longNameUnits = nil
			longNameSeq = 0
			continue
		}

		isDir := entry[11]&0x10 != 0

		// Get file size
		size := uint64(entry[28]) | uint64(entry[29])<<8 |
			uint64(entry[30])<<16 | uint64(entry[31])<<24

		// Get first cluster. FAT stores the low 16 bits at bytes 26-27 and the
		// high 16 bits at bytes 20-21; the high word must be shifted into bits
		// 16-31. Omitting those shifts corrupts every entry whose cluster is
		// >= 65536 (0x10000), silently producing another cluster's value.
		cluster := uint32(entry[26]) | uint32(entry[27])<<8 |
			uint32(entry[20])<<16 | uint32(entry[21])<<24

		// FAT timestamps from the packed DOS date/time fields: last write
		// (date 24-25, time 22-23), creation (date 16-17, time 14-15), last
		// access (date 18-19, no time-of-day — stored at midnight).
		modTime := fatDateTimeToUnix(binary.LittleEndian.Uint16(entry[24:26]), binary.LittleEndian.Uint16(entry[22:24]))
		accessTime := fatDateTimeToUnix(binary.LittleEndian.Uint16(entry[18:20]), 0)
		createTime := fatDateTimeToUnix(binary.LittleEndian.Uint16(entry[16:18]), binary.LittleEndian.Uint16(entry[14:16]))

		entries = append(entries, filesystem.DirectoryEntry{
			Name:       filename,
			Path:       filesystem.JoinPath(parentPath, filename),
			IsDir:      isDir,
			Size:       size,
			Cluster:    cluster,
			ModTime:    modTime,
			AccessTime: accessTime,
			CreateTime: createTime,
		})
		// A long filename belongs to exactly the short entry that follows its
		// LFN records. Not resetting here lets a stale name leak onto every
		// subsequent short entry that has no LFN of its own, misnaming real
		// files (e.g. "BOOT.STL" reported as the previous entry's "bg-BG").
		longNameUnits = nil
		longNameSeq = 0
	}

	return entries, false
}

// fatDateTimeToUnix converts a packed DOS date and time (the 16-bit date/time
// fields of a FAT directory entry) into Unix seconds. A zero date field, an
// out-of-range month/day/time, or a year before 1980 yields 0 (no timestamp)
// rather than a fabricated one.
func fatDateTimeToUnix(date, dosTime uint16) int64 {
	if date == 0 {
		return 0
	}
	year := int(date>>9) + 1980
	month := int((date >> 5) & 0x0F)
	day := int(date & 0x1F)
	hour := int(dosTime>>11) & 0x1F
	minute := int((dosTime >> 5) & 0x3F)
	second := int(dosTime&0x1F) * 2
	if month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59 {
		return 0
	}
	return time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC).Unix()
}

// resolveEntry resolves a path to its directory entry by walking directories
// via their cluster chains.
func (h *FAT32Handler) resolveEntry(path string) (*filesystem.DirectoryEntry, error) {
	clean := strings.Trim(path, "/")
	if clean == "" {
		return nil, fmt.Errorf("root path has no file entry")
	}

	var parts []string
	for _, p := range strings.Split(clean, "/") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("invalid path %q", path)
	}

	// The first path component resolves in the root: the fixed region for
	// FAT12/16, the root cluster chain for FAT32.
	entries, err := h.rootListing()
	if err != nil {
		return nil, fmt.Errorf("failed to read root directory while resolving %q: %w", parts[0], err)
	}
	currentCluster := h.rootCluster
	for i, part := range parts {
		var match *filesystem.DirectoryEntry
		for j := range entries {
			if entries[j].Name == part {
				match = &entries[j]
				break
			}
		}
		if match == nil {
			return nil, fmt.Errorf("path component not found: %q: %w", part, filesystem.ErrNotFound)
		}
		if i == len(parts)-1 {
			return match, nil
		}
		if !match.IsDir {
			return nil, fmt.Errorf("path component %q is not a directory: %w", part, filesystem.ErrNotDirectory)
		}
		currentCluster = match.Cluster
		entries, err = h.readDirectory(currentCluster, "")
		if err != nil {
			return nil, fmt.Errorf("failed to read directory while resolving %q: %w", part, err)
		}
	}
	return nil, fmt.Errorf("unreachable path resolution for %q", path)
}

// Type returns the actual detected filesystem type (FAT12/16/32).
func (h *FAT32Handler) Type() filesystem.FileSystemType {
	switch h.fatBits {
	case 12:
		return filesystem.FS_FAT12
	case 16:
		return filesystem.FS_FAT16
	default:
		return filesystem.FS_FAT32
	}
}

// Open initializes the filesystem (required by interface)
func (h *FAT32Handler) Open(sectorData []byte) error {
	return nil
}

// Close closes the filesystem handler
func (h *FAT32Handler) Close() error {
	return nil
}

// GetFile reads a file's contents by following its FAT32 cluster chain.
func (h *FAT32Handler) GetFile(path string) ([]byte, error) {
	entry, err := h.resolveEntry(path)
	if err != nil {
		return nil, err
	}
	if entry.IsDir {
		return nil, fmt.Errorf("path is a directory: %s: %w", path, filesystem.ErrIsDirectory)
	}
	return h.readFileClusters(entry.Cluster, entry.Size)
}

// GetFileByPath gets file info by path
func (h *FAT32Handler) GetFileByPath(path string) (*filesystem.FileInfo, error) {
	entry, err := h.resolveEntry(path)
	if err != nil {
		return nil, err
	}

	mode := filesystem.FileMode(filesystem.ModeRegular)
	if entry.IsDir {
		mode = filesystem.ModeDir
	}

	return &filesystem.FileInfo{
		Name:       entry.Name,
		Path:       "/" + strings.Trim(path, "/"),
		Size:       entry.Size,
		Mode:       mode,
		IsDir:      entry.IsDir,
		ModTime:    entry.ModTime,
		AccessTime: entry.AccessTime,
		CreateTime: entry.CreateTime,
	}, nil
}

// SearchFiles searches for files matching a predicate, recursing through
// directories. Depth and result count are bounded.
func (h *FAT32Handler) SearchFiles(rootPath string, predicate func(filesystem.FileInfo) bool) ([]filesystem.FileInfo, error) {
	cleanRoot := strings.Trim(rootPath, "/")
	base := ""
	rootCluster := h.rootCluster
	// isRoot is true only when the search root is the actual filesystem root.
	// FAT12/16 then read the fixed root region; a search rooted at a real
	// subdirectory walks that subdirectory's cluster chain (identical across all
	// three FAT types), never the fixed root region.
	atRoot := true
	if cleanRoot != "" {
		root, err := h.resolveEntry(rootPath)
		if err != nil {
			return nil, err
		}
		if !root.IsDir {
			return nil, fmt.Errorf("search root %q is not a directory", rootPath)
		}
		rootCluster = root.Cluster
		base = "/" + cleanRoot
		atRoot = false
	}

	results := make([]filesystem.FileInfo, 0)

	// isRoot marks the first level only when it is the filesystem root, so
	// FAT12/16 use the fixed root region exactly there.
	var walk func(cluster uint32, dirPath string, depth int, isRoot bool) error
	walk = func(cluster uint32, dirPath string, depth int, isRoot bool) error {
		if depth > maxSearchDepth {
			return nil
		}
		var entries []filesystem.DirectoryEntry
		var err error
		if isRoot && (h.fatBits == 12 || h.fatBits == 16) {
			entries, err = h.readRootDir()
		} else {
			entries, err = h.readDirectory(cluster, "")
		}
		if err != nil {
			return err
		}
		for _, e := range entries {
			if len(results) >= maxSearchCount {
				return fmt.Errorf("search exceeded %d results", maxSearchCount)
			}
			fi := filesystem.FileInfo{
				Name:       e.Name,
				Path:       dirPath + "/" + e.Name,
				Size:       e.Size,
				IsDir:      e.IsDir,
				ModTime:    e.ModTime,
				AccessTime: e.AccessTime,
				CreateTime: e.CreateTime,
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
				if err := walk(e.Cluster, fi.Path, depth+1, false); err != nil {
					return err
				}
			}
		}
		return nil
	}

	if err := walk(rootCluster, base, 0, atRoot); err != nil {
		return nil, err
	}
	return results, nil
}

// GetVolumeLabel returns the volume label (not implemented)
func (h *FAT32Handler) GetVolumeLabel() string {
	return ""
}
