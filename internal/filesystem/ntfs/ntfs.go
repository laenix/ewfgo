package ntfs

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/laenix/ewfgo/internal/filesystem"
)

// NTFS attribute type constants. Only the attributes this parser walks are
// defined; an $ATTRIBUTE_LIST (0x20) on a record whose data lives in external
// records is detected via attrAttributeList (see GetFile).
const (
	attrStandardInformation = 0x10
	attrAttributeList       = 0x20
	attrFileName            = 0x30
	attrVolumeName          = 0x60
	attrData                = 0x80
	attrEnd                 = 0xFFFFFFFF
)

// MFT record header flags.
const (
	mftRecordInUse = 0x0001
	mftRecordDir   = 0x0002
)

// ntfsRootRecord is the fixed MFT record number of the root directory (".").
const ntfsRootRecord = 5

// NTFS parsing safety bounds. Every bound is a guard against hostile/corrupt
// input: exceeding any of them produces an explicit error, never wrong data or
// a panic.
const (
	// ntfsDefaultRecordSize is the default MFT record size (1024 bytes), used
	// when the boot sector's ClustersPerMFTRecord field is zero. The real size
	// is derived at bootstrap and stored in NTFSHandler.recordSize.
	ntfsDefaultRecordSize = 1024
	// ntfsMaxClusterBytes bounds the total cluster span of a single data run
	// list (2^26 clusters * 4 KiB = 256 GiB worst case).
	ntfsMaxClusterBytes = 1 << 26
	// ntfsMaxMFTRecords bounds how many MFT records a walk will inspect.
	ntfsMaxMFTRecords = 1 << 24
	// ntfsMaxFileBytes bounds a single non-resident file read (4 GiB).
	ntfsMaxFileBytes = 1 << 32
	// ntfsMaxSearchCount bounds the number of results SearchFiles may return.
	ntfsMaxSearchCount = 100000
	// ntfsMaxPathDepth bounds parent-chain walking (cycle guard).
	ntfsMaxPathDepth = 64
)

// ntfsRun is a single NTFS data-run: a contiguous VCN -> LCN mapping.
type ntfsRun struct {
	vcnStart uint64 // starting VCN of this run
	lcnStart int64  // starting LCN; -1 marks a sparse run
	length   uint64 // number of clusters in the run
}

// ntfsAttr is a parsed MFT attribute header.
type ntfsAttr struct {
	typ         uint32
	offset      int
	length      int
	nonResident bool
	nameLen     int
	nameOffset  int
	// Resident value location (absolute offsets within the record).
	valueOffset int
	valueLen    uint32
	// Non-resident run data location (absolute offsets within the record).
	runDataOff int
	runDataEnd int
	realSize   uint64
}

// ntfsFileName is a parsed $FILE_NAME attribute value.
type ntfsFileName struct {
	parent   uint64
	name     string
	flags    uint32
	realSize uint64
}

// ntfsStandardInfo is a parsed $STANDARD_INFORMATION attribute value.
type ntfsStandardInfo struct {
	createTime int64
	modTime    int64
	accessTime int64
	flags      uint32
}

// ntfsIndexEntry aggregates the interesting fields of one in-use MFT record.
type ntfsIndexEntry struct {
	recNum   uint64
	isDir    bool
	names    []ntfsFileName
	si       *ntfsStandardInfo
	dataSize uint64
	hasData  bool
}

// NTFSHandler handles NTFS filesystem operations.
type NTFSHandler struct {
	reader   filesystem.Reader
	startLBA uint64

	bytesPerSector    uint16
	sectorsPerCluster uint8
	clusterSize       uint64
	mftLCN            int64
	recordSize        int

	mftRealSize uint64
	mftRuns     []ntfsRun
	recordCount uint64

	indexLoaded bool
	fileIndex   map[uint64]*ntfsIndexEntry
}

// NewNTFSHandler creates a new NTFS handler. reader is the absolute-LBA sector
// reader (see filesystem.Reader); startLBA is the partition's first sector.
func NewNTFSHandler(reader filesystem.Reader, startLBA uint64) (*NTFSHandler, error) {
	if reader == nil {
		return nil, fmt.Errorf("NTFS handler requires a reader")
	}
	h := &NTFSHandler{
		reader:   reader,
		startLBA: startLBA,
	}
	if err := h.readBootSector(); err != nil {
		return nil, err
	}
	if err := h.loadMFT(); err != nil {
		return nil, err
	}
	return h, nil
}

// readBootSector reads and validates the NTFS boot sector.
func (h *NTFSHandler) readBootSector() error {
	bootData, err := h.reader.ReadSectors(h.startLBA, 1)
	if err != nil {
		return fmt.Errorf("failed to read NTFS boot sector: %w", err)
	}
	if len(bootData) < 512 {
		return fmt.Errorf("short NTFS boot sector: got %d bytes", len(bootData))
	}
	if string(bootData[3:7]) != "NTFS" {
		return fmt.Errorf("not a valid NTFS filesystem")
	}

	bps := binary.LittleEndian.Uint16(bootData[0x0B:0x0D])
	if bps < 512 || bps&(bps-1) != 0 {
		return fmt.Errorf("invalid bytes per sector %d", bps)
	}
	spc := bootData[0x0D]
	if spc == 0 || spc&(spc-1) != 0 || spc > 128 {
		return fmt.Errorf("invalid sectors per cluster %d", spc)
	}
	h.bytesPerSector = bps
	h.sectorsPerCluster = spc
	h.clusterSize = uint64(bps) * uint64(spc)

	// MFT record size from the ClustersPerMFTRecord field (offset 0x40, signed
	// byte): positive -> that many clusters; negative -> 2^-n bytes (this is how
	// mkfs.ntfs encodes the default 1024-byte record, e.g. 0xF6=-10 -> 1024);
	// zero -> the 1024-byte default. The record size is the ground truth for
	// fixup granularity, so it must never depend on the logical sector size.
	recField := int8(bootData[0x40])
	switch {
	case recField == 0:
		h.recordSize = ntfsDefaultRecordSize
	case recField < 0:
		if -int(recField) > 16 {
			return fmt.Errorf("invalid MFT record size exponent %d", recField)
		}
		h.recordSize = 1 << uint(-int(recField))
	default:
		h.recordSize = int(recField) * int(h.clusterSize)
	}
	if h.recordSize < 512 || h.recordSize > 1<<20 || h.recordSize&(h.recordSize-1) != 0 {
		return fmt.Errorf("invalid MFT record size %d", h.recordSize)
	}

	// MFT LCN is a full 8-byte little-endian signed value at offset 0x30.
	mftLCN := int64(binary.LittleEndian.Uint64(bootData[0x30:0x38]))
	if mftLCN <= 0 {
		return fmt.Errorf("invalid MFT LCN %d", mftLCN)
	}
	h.mftLCN = mftLCN
	return nil
}

// loadMFT bootstraps the MFT: record 0 (the $MFT file's own record) is read
// from the boot-sector LCN, its $DATA run list is parsed, and the full MFT
// extent is derived from it.
func (h *NTFSHandler) loadMFT() error {
	if h.recordSize <= 0 {
		return fmt.Errorf("MFT record size %d not derived", h.recordSize)
	}
	// Read enough clusters starting at the boot-sector LCN to cover record 0.
	bootClusters := (uint64(h.recordSize) + h.clusterSize - 1) / h.clusterSize
	raw, err := h.readClustersAtLCN(h.mftLCN, bootClusters)
	if err != nil {
		return fmt.Errorf("failed to read MFT bootstrap: %w", err)
	}
	if uint64(len(raw)) < uint64(h.recordSize) {
		return fmt.Errorf("MFT bootstrap short read: got %d bytes, want %d", len(raw), h.recordSize)
	}
	rec0 := make([]byte, h.recordSize)
	copy(rec0, raw[:h.recordSize])
	if err := h.fixupRecord(rec0); err != nil {
		return fmt.Errorf("MFT record 0: %w", err)
	}

	attrs, err := h.parseAttrs(rec0)
	if err != nil {
		return fmt.Errorf("MFT record 0: %w", err)
	}
	var dataAttr *ntfsAttr
	for i := range attrs {
		if attrs[i].typ == attrData && attrs[i].nameLen == 0 && attrs[i].nonResident {
			dataAttr = &attrs[i]
			break
		}
	}
	if dataAttr == nil {
		return fmt.Errorf("$MFT has no non-resident $DATA attribute")
	}
	h.mftRuns, err = h.parseRuns(rec0[dataAttr.runDataOff:dataAttr.runDataEnd])
	if err != nil {
		return fmt.Errorf("$MFT data runs: %w", err)
	}
	h.mftRealSize = dataAttr.realSize
	if h.mftRealSize < uint64(h.recordSize) || h.mftRealSize%uint64(h.recordSize) != 0 {
		return fmt.Errorf("invalid $MFT size %d", h.mftRealSize)
	}
	h.recordCount = h.mftRealSize / uint64(h.recordSize)
	if h.recordCount > ntfsMaxMFTRecords {
		return fmt.Errorf("MFT record count %d exceeds limit %d", h.recordCount, ntfsMaxMFTRecords)
	}
	return nil
}

// fixupRecord applies the MFT record update-sequence (USA) fixup in place,
// restoring the original tail bytes of each 512-byte sector.
func (h *NTFSHandler) fixupRecord(rec []byte) error {
	if len(rec) < 0x2A {
		return fmt.Errorf("MFT record too short (%d bytes)", len(rec))
	}
	usaOff := int(binary.LittleEndian.Uint16(rec[0x04:0x06]))
	usaCount := int(rec[0x06])
	if usaOff == 0 || usaCount < 2 || usaOff+usaCount*2 > len(rec) {
		return fmt.Errorf("invalid fixup array (off %d count %d)", usaOff, usaCount)
	}
	seq := binary.LittleEndian.Uint16(rec[usaOff : usaOff+2])
	// NTFS applies the update-sequence array per 512-byte block of the MFT
	// record, regardless of the volume's logical sector size. The record itself
	// is the ground truth: usaCount-1 512-byte blocks fill it exactly.
	sectorSize := len(rec) / (usaCount - 1)
	if sectorSize == 0 || len(rec)%(usaCount-1) != 0 {
		return fmt.Errorf("invalid fixup geometry (rec %d bytes, usaCount %d)", len(rec), usaCount)
	}
	for i := 1; i < usaCount; i++ {
		off := i*sectorSize - 2
		if off < 0 || off+2 > len(rec) {
			return fmt.Errorf("fixup sector %d out of range", i)
		}
		if binary.LittleEndian.Uint16(rec[off:off+2]) != seq {
			return fmt.Errorf("fixup sequence mismatch at sector %d", i)
		}
		copy(rec[off:off+2], rec[usaOff+i*2:usaOff+i*2+2])
	}
	return nil
}

// parseAttrs walks the attribute list of an MFT record (fixup already applied)
// and returns the parsed attribute headers.
func (h *NTFSHandler) parseAttrs(rec []byte) ([]ntfsAttr, error) {
	if h.recordSize > 0 && len(rec) < h.recordSize {
		return nil, fmt.Errorf("MFT record too short (%d bytes)", len(rec))
	}
	if string(rec[0:4]) != "FILE" {
		return nil, fmt.Errorf("not an MFT record (signature %q)", string(rec[0:4]))
	}
	attrsOff := int(binary.LittleEndian.Uint16(rec[0x14:0x16]))
	if attrsOff < 0x18 || attrsOff >= len(rec)-8 {
		return nil, fmt.Errorf("invalid first attribute offset %d", attrsOff)
	}

	var attrs []ntfsAttr
	off := attrsOff
	for {
		if off+8 > len(rec) {
			return nil, fmt.Errorf("attribute header at %d overruns record", off)
		}
		typ := binary.LittleEndian.Uint32(rec[off : off+4])
		if typ == attrEnd {
			break
		}
		length := int(binary.LittleEndian.Uint32(rec[off+4 : off+8]))
		if length < 16 || off+length > len(rec) {
			return nil, fmt.Errorf("invalid attribute length %d at offset %d", length, off)
		}
		nonRes := rec[off+8] != 0
		nameLen := int(rec[off+9])
		nameOff := int(binary.LittleEndian.Uint16(rec[off+10 : off+12]))
		if nameLen > 0 && off+nameOff+nameLen*2 > len(rec) {
			return nil, fmt.Errorf("attribute name overruns record")
		}

		a := ntfsAttr{
			typ:         typ,
			offset:      off,
			length:      length,
			nonResident: nonRes,
			nameLen:     nameLen,
			nameOffset:  nameOff,
		}
		if !nonRes {
			if off+24 > len(rec) {
				return nil, fmt.Errorf("resident attribute header at %d overruns record", off)
			}
			valLen := binary.LittleEndian.Uint32(rec[off+16 : off+20])
			valOff := int(binary.LittleEndian.Uint16(rec[off+20 : off+22]))
			if valOff+int(valLen) > length {
				return nil, fmt.Errorf("resident value overruns attribute at %d", off)
			}
			a.valueOffset = off + valOff
			a.valueLen = valLen
		} else {
			if off+0x40 > len(rec) {
				return nil, fmt.Errorf("non-resident attribute header at %d overruns record", off)
			}
			runOff := int(binary.LittleEndian.Uint16(rec[off+0x20 : off+0x22]))
			if runOff < 0x40 || runOff > length {
				return nil, fmt.Errorf("invalid data run offset %d in attribute at %d", runOff, off)
			}
			a.runDataOff = off + runOff
			a.runDataEnd = off + length
			a.realSize = binary.LittleEndian.Uint64(rec[off+0x38 : off+0x40])
		}
		attrs = append(attrs, a)
		off += length
	}
	return attrs, nil
}

// parseFileName parses a resident $FILE_NAME attribute value.
func (h *NTFSHandler) parseFileName(rec []byte, a ntfsAttr) (*ntfsFileName, error) {
	val := rec[a.valueOffset : a.valueOffset+int(a.valueLen)]
	if len(val) < 0x42 {
		return nil, fmt.Errorf("$FILE_NAME value too short (%d bytes)", len(val))
	}
	nameLen := int(val[0x40])
	if 0x42+nameLen*2 > len(val) {
		return nil, fmt.Errorf("$FILE_NAME name overruns value")
	}
	units := make([]uint16, nameLen)
	for i := 0; i < nameLen; i++ {
		units[i] = binary.LittleEndian.Uint16(val[0x42+i*2 : 0x42+i*2+2])
	}
	return &ntfsFileName{
		parent:   binary.LittleEndian.Uint64(val[0:8]) & 0x0000FFFFFFFFFFFF,
		name:     string(utf16.Decode(units)),
		flags:    binary.LittleEndian.Uint32(val[0x38:0x3C]),
		realSize: binary.LittleEndian.Uint64(val[0x30:0x38]),
	}, nil
}

// parseStandardInfo parses a resident $STANDARD_INFORMATION attribute value.
func (h *NTFSHandler) parseStandardInfo(rec []byte, a ntfsAttr) *ntfsStandardInfo {
	val := rec[a.valueOffset : a.valueOffset+int(a.valueLen)]
	if len(val) < 0x24 {
		return nil
	}
	return &ntfsStandardInfo{
		createTime: int64(binary.LittleEndian.Uint64(val[0x00:0x08])),
		modTime:    int64(binary.LittleEndian.Uint64(val[0x08:0x10])),
		accessTime: int64(binary.LittleEndian.Uint64(val[0x18:0x20])),
		flags:      binary.LittleEndian.Uint32(val[0x20:0x24]),
	}
}

// filetimeToUnix converts a Windows FILETIME (100 ns ticks since 1601-01-01)
// to Unix seconds. Zero and negative values are left as 0.
func filetimeToUnix(ft int64) int64 {
	if ft <= 0 {
		return 0
	}
	return ft/10_000_000 - 11644473600
}

// parseRuns parses an NTFS data-run list (starting at runData). Returns the
// runs in VCN order with absolute LCNs and the VCN at which each run starts.
func (h *NTFSHandler) parseRuns(data []byte) ([]ntfsRun, error) {
	var runs []ntfsRun
	vcn := uint64(0)
	prevLCN := int64(0)
	off := 0
	for {
		if off >= len(data) {
			return nil, fmt.Errorf("data runs not terminated")
		}
		hdr := data[off]
		if hdr == 0 {
			break
		}
		lenBytes := int(hdr & 0x0F)
		offBytes := int(hdr >> 4)
		off++
		if lenBytes > 8 || offBytes > 8 {
			return nil, fmt.Errorf("data run header nibbles too large (len %d off %d)", lenBytes, offBytes)
		}
		if off+lenBytes+offBytes > len(data) {
			return nil, fmt.Errorf("data run truncated")
		}

		var length uint64
		for i := 0; i < lenBytes; i++ {
			length |= uint64(data[off+i]) << (8 * i)
		}
		var lcnDelta int64
		for i := 0; i < offBytes; i++ {
			lcnDelta |= int64(data[off+lenBytes+i]) << (8 * i)
		}
		if offBytes > 0 && lcnDelta&(1<<(8*offBytes-1)) != 0 {
			lcnDelta |= -1 << (8 * offBytes)
		}
		off += lenBytes + offBytes

		if length == 0 {
			return nil, fmt.Errorf("zero-length data run")
		}
		if vcn > ntfsMaxClusterBytes-length {
			return nil, fmt.Errorf("data runs exceed %d clusters", ntfsMaxClusterBytes)
		}

		var lcn int64
		if offBytes == 0 {
			lcn = -1 // sparse run
		} else {
			prevLCN += lcnDelta
			lcn = prevLCN
		}
		runs = append(runs, ntfsRun{vcnStart: vcn, lcnStart: lcn, length: length})
		vcn += length
	}
	if len(runs) == 0 {
		return nil, fmt.Errorf("empty data run list")
	}
	return runs, nil
}

// runForVCN returns the data run that maps vcn, and whether it exists.
func (h *NTFSHandler) runForVCN(vcn uint64) (ntfsRun, bool) {
	for _, r := range h.mftRuns {
		if vcn >= r.vcnStart && vcn < r.vcnStart+r.length {
			return r, true
		}
	}
	return ntfsRun{}, false
}

// readClustersAtLCN reads count clusters starting at absolute LCN lcn and
// returns their bytes. Every read is bounds-checked so a crafted image can
// never return silently truncated or wrong data.
func (h *NTFSHandler) readClustersAtLCN(lcn int64, count uint64) ([]byte, error) {
	if lcn < 0 {
		return nil, fmt.Errorf("negative LCN %d", lcn)
	}
	spc := uint64(h.sectorsPerCluster)
	if uint64(lcn) > (^uint64(0))/spc {
		return nil, fmt.Errorf("LCN %d overflows sector address", lcn)
	}
	relative := uint64(lcn) * spc
	if relative > (^uint64(0))-h.startLBA {
		return nil, fmt.Errorf("LCN %d overflows absolute LBA", lcn)
	}
	lba := h.startLBA + relative
	sectors := count * spc
	if sectors < count {
		return nil, fmt.Errorf("cluster span overflows sector count")
	}
	data, err := h.reader.ReadSectors(lba, sectors)
	if err != nil {
		return nil, fmt.Errorf("read %d clusters at LCN %d (LBA %d): %w", count, lcn, lba, err)
	}
	want := count * h.clusterSize
	if uint64(len(data)) < want {
		return nil, fmt.Errorf("short read at LCN %d: got %d bytes, want %d", lcn, len(data), want)
	}
	return data[:want], nil
}

// readMFTBytes reads byteLen bytes of the MFT file starting at byteStart,
// following the $MFT data runs.
func (h *NTFSHandler) readMFTBytes(byteStart, byteLen uint64) ([]byte, error) {
	startVCN := byteStart / h.clusterSize
	endVCN := (byteStart + byteLen - 1) / h.clusterSize
	var buf []byte
	for vcn := startVCN; vcn <= endVCN; {
		run, ok := h.runForVCN(vcn)
		if !ok {
			return nil, fmt.Errorf("MFT VCN %d not mapped", vcn)
		}
		avail := run.length - (vcn - run.vcnStart)
		take := avail
		if vcn+take > endVCN+1 {
			take = endVCN + 1 - vcn
		}
		if run.lcnStart >= 0 {
			cl, err := h.readClustersAtLCN(run.lcnStart+int64(vcn-run.vcnStart), take)
			if err != nil {
				return nil, err
			}
			buf = append(buf, cl...)
		} else {
			// Sparse MFT region: treat as zeros.
			buf = append(buf, make([]byte, take*h.clusterSize)...)
		}
		vcn += take
	}
	within := byteStart - startVCN*h.clusterSize
	if within+byteLen > uint64(len(buf)) {
		return nil, fmt.Errorf("MFT read short: want %d bytes at %d, got %d", byteLen, byteStart, len(buf))
	}
	out := make([]byte, byteLen)
	copy(out, buf[within:within+byteLen])
	return out, nil
}

// readRecord reads, fixup-repairs and returns the raw bytes of MFT record num.
func (h *NTFSHandler) readRecord(num uint64) ([]byte, error) {
	if num >= h.recordCount {
		return nil, fmt.Errorf("MFT record %d out of range (count %d)", num, h.recordCount)
	}
	raw, err := h.readMFTBytes(num*uint64(h.recordSize), uint64(h.recordSize))
	if err != nil {
		return nil, err
	}
	if err := h.fixupRecord(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// readNonResident reads the data of a non-resident $DATA attribute, following
// the run list and truncating to realSize. Cluster reads are capped and
// bounds-checked; a file whose runs cannot cover its declared size is an error.
func (h *NTFSHandler) readNonResident(runs []ntfsRun, realSize uint64) ([]byte, error) {
	if realSize == 0 {
		return []byte{}, nil
	}
	if realSize > ntfsMaxFileBytes {
		return nil, fmt.Errorf("file too large: %d bytes (limit %d)", realSize, ntfsMaxFileBytes)
	}
	var totalClusters uint64
	for _, r := range runs {
		if totalClusters > ntfsMaxClusterBytes-r.length {
			return nil, fmt.Errorf("file data runs exceed %d clusters", ntfsMaxClusterBytes)
		}
		totalClusters += r.length
	}
	if totalClusters*h.clusterSize < realSize {
		return nil, fmt.Errorf("file real size %d exceeds %d bytes allocated by data runs", realSize, totalClusters*h.clusterSize)
	}

	out := make([]byte, 0, 4096)
	for _, r := range runs {
		if uint64(len(out)) >= realSize {
			break
		}
		if r.lcnStart < 0 {
			// Sparse run: the logical bytes are all zero.
			zeros := r.length * h.clusterSize
			if zeros > realSize-uint64(len(out)) {
				zeros = realSize - uint64(len(out))
			}
			out = append(out, make([]byte, zeros)...)
			continue
		}
		for i := uint64(0); i < r.length && uint64(len(out)) < realSize; i++ {
			cl, err := h.readClustersAtLCN(r.lcnStart+int64(i), 1)
			if err != nil {
				return nil, err
			}
			take := uint64(len(cl))
			if take > realSize-uint64(len(out)) {
				take = realSize - uint64(len(out))
			}
			out = append(out, cl[:take]...)
		}
	}
	if uint64(len(out)) != realSize {
		return nil, fmt.Errorf("short read: got %d bytes, want %d", len(out), realSize)
	}
	return out, nil
}

// ensureIndex builds the in-memory index of in-use MFT records (names, parent
// pointers, timestamps, sizes). It is built lazily and cached.
func (h *NTFSHandler) ensureIndex() error {
	if h.indexLoaded {
		return nil
	}
	h.fileIndex = make(map[uint64]*ntfsIndexEntry)

	const chunk uint64 = 256 // records per bulk read
	for start := uint64(0); start < h.recordCount; start += chunk {
		count := chunk
		if start+count > h.recordCount {
			count = h.recordCount - start
		}
		raw, err := h.readMFTBytes(start*uint64(h.recordSize), count*uint64(h.recordSize))
		if err != nil {
			return fmt.Errorf("MFT read at record %d: %w", start, err)
		}
		for i := uint64(0); i < count; i++ {
			recNum := start + i
			rec := raw[i*uint64(h.recordSize) : (i+1)*uint64(h.recordSize)]
			if string(rec[0:4]) != "FILE" {
				continue
			}
			rc := make([]byte, h.recordSize)
			copy(rc, rec)
			if err := h.fixupRecord(rc); err != nil {
				continue
			}
			flags := binary.LittleEndian.Uint16(rc[0x16:0x18])
			if flags&mftRecordInUse == 0 {
				continue
			}
			attrs, err := h.parseAttrs(rc)
			if err != nil {
				continue
			}
			entry := &ntfsIndexEntry{recNum: recNum, isDir: flags&mftRecordDir != 0}
			for j := range attrs {
				a := &attrs[j]
				switch {
				case a.typ == attrFileName && a.nameLen == 0:
					if fn, err := h.parseFileName(rc, *a); err == nil {
						entry.names = append(entry.names, *fn)
					}
				case a.typ == attrStandardInformation && a.nameLen == 0 && entry.si == nil:
					entry.si = h.parseStandardInfo(rc, *a)
				case a.typ == attrData && a.nameLen == 0:
					entry.hasData = true
					if a.nonResident {
						entry.dataSize = a.realSize
					} else {
						entry.dataSize = uint64(a.valueLen)
					}
				}
			}
			if len(entry.names) > 0 {
				h.fileIndex[recNum] = entry
			}
		}
	}

	// The root directory (record 5) must be present and be a directory.
	if root, ok := h.fileIndex[ntfsRootRecord]; !ok || !root.isDir {
		return fmt.Errorf("NTFS root directory record %d not found", ntfsRootRecord)
	}
	h.indexLoaded = true
	return nil
}

// findChild returns the MFT record whose $FILE_NAME (parent, name) matches.
func (h *NTFSHandler) findChild(parent uint64, name string) (uint64, bool) {
	for rec, e := range h.fileIndex {
		for _, fn := range e.names {
			if fn.parent == parent && fn.name == name {
				return rec, true
			}
		}
	}
	return 0, false
}

// resolvePath resolves a filesystem path to an MFT record number by walking
// $FILE_NAME parent pointers (a full-MFT walk). The root path ("", "/")
// resolves to the root directory record.
func (h *NTFSHandler) resolvePath(path string) (uint64, error) {
	clean := strings.Trim(path, "/")
	if clean == "" {
		return ntfsRootRecord, nil
	}
	parts := strings.Split(clean, "/")
	current := uint64(ntfsRootRecord)
	for i, part := range parts {
		if part == "" {
			continue
		}
		next, ok := h.findChild(current, part)
		if !ok {
			return 0, fmt.Errorf("path component not found: %q: %w", part, filesystem.ErrNotFound)
		}
		if i < len(parts)-1 {
			if e, ok2 := h.fileIndex[next]; !ok2 || !e.isDir {
				return 0, fmt.Errorf("path component %q is not a directory: %w", part, filesystem.ErrNotDirectory)
			}
		}
		current = next
	}
	return current, nil
}

// relativePath computes the slash-joined path of record rec relative to the
// ancestor record, following $FILE_NAME parent pointers. It reports ok=false
// when rec is not a descendant of ancestor (or on a cycle).
func (h *NTFSHandler) relativePath(rec, ancestor uint64) (string, bool) {
	if rec == ancestor {
		return "", true
	}
	var parts []string
	cur := rec
	seen := make(map[uint64]bool)
	for depth := 0; depth < ntfsMaxPathDepth; depth++ {
		if seen[cur] {
			return "", false
		}
		seen[cur] = true
		entry, ok := h.fileIndex[cur]
		if !ok || len(entry.names) == 0 {
			return "", false
		}
		fn := entry.names[0]
		parts = append([]string{fn.name}, parts...)
		if fn.parent == ancestor {
			return strings.Join(parts, "/"), true
		}
		cur = fn.parent
	}
	return "", false
}

// fileInfoFromEntry builds a filesystem.FileInfo from an index entry.
func fileInfoFromEntry(entry *ntfsIndexEntry, path string) filesystem.FileInfo {
	fn := entry.names[0]
	mode := filesystem.ModeRegular
	if entry.isDir {
		mode = filesystem.ModeDir
	}
	var modT, accT, creT int64
	var flags uint32
	if entry.si != nil {
		modT = filetimeToUnix(entry.si.modTime)
		accT = filetimeToUnix(entry.si.accessTime)
		creT = filetimeToUnix(entry.si.createTime)
		flags = entry.si.flags
	} else {
		flags = fn.flags
	}
	size := entry.dataSize
	if !entry.hasData {
		size = fn.realSize
	}
	return filesystem.FileInfo{
		Name:       fn.name,
		Path:       path,
		Size:       size,
		Mode:       mode,
		IsDir:      entry.isDir,
		ModTime:    modT,
		AccessTime: accT,
		CreateTime: creT,
		IsHidden:   flags&0x02 != 0,
		IsSystem:   flags&0x04 != 0,
		IsReadOnly: flags&0x01 != 0,
	}
}

// Type returns the filesystem type.
func (h *NTFSHandler) Type() filesystem.FileSystemType {
	return filesystem.FS_NTFS
}

// Open initializes the filesystem from boot-sector data.
func (h *NTFSHandler) Open(sectorData []byte) error {
	if len(sectorData) >= 8 && string(sectorData[3:7]) == "NTFS" {
		return nil
	}
	return fmt.Errorf("not a valid NTFS boot sector")
}

// Close closes the filesystem handler.
func (h *NTFSHandler) Close() error {
	return nil
}

// ListDirectory lists the entries of the directory at path. The listing is
// reconstructed from the real $FILE_NAME attributes across the MFT (every
// in-use record whose parent pointer references the directory's MFT record).
func (h *NTFSHandler) ListDirectory(path string) ([]filesystem.DirectoryEntry, error) {
	if h.reader == nil {
		return nil, fmt.Errorf("NTFS handler has no reader")
	}
	if err := h.ensureIndex(); err != nil {
		return nil, err
	}
	dirRec, err := h.resolvePath(path)
	if err != nil {
		return nil, err
	}
	dirEntry, ok := h.fileIndex[dirRec]
	if !ok || !dirEntry.isDir {
		return nil, fmt.Errorf("path is not a directory: %s: %w", path, filesystem.ErrNotDirectory)
	}

	var out []filesystem.DirectoryEntry
	for rec, e := range h.fileIndex {
		if rec == dirRec {
			continue
		}
		for _, fn := range e.names {
			if fn.parent != dirRec {
				continue
			}
			modTime := int64(0)
			if e.si != nil {
				modTime = filetimeToUnix(e.si.modTime)
			}
			out = append(out, filesystem.DirectoryEntry{
				Name:    fn.name,
				Path:    filesystem.JoinPath(path, fn.name),
				Size:    e.dataSize,
				IsDir:   e.isDir,
				ModTime: modTime,
				Inode:   rec,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// GetFile reads a file's content by resolving its path and reading its unnamed
// $DATA attribute (resident inline, or non-resident via data runs).
func (h *NTFSHandler) GetFile(path string) ([]byte, error) {
	if h.reader == nil {
		return nil, fmt.Errorf("NTFS handler has no reader")
	}
	if err := h.ensureIndex(); err != nil {
		return nil, err
	}
	rec, err := h.resolvePath(path)
	if err != nil {
		return nil, err
	}
	entry := h.fileIndex[rec]
	if entry.isDir {
		return nil, fmt.Errorf("path is a directory: %s: %w", path, filesystem.ErrIsDirectory)
	}

	recBytes, err := h.readRecord(rec)
	if err != nil {
		return nil, err
	}
	attrs, err := h.parseAttrs(recBytes)
	if err != nil {
		return nil, err
	}
	var hasAttrList, hasUnnamedData bool
	for i := range attrs {
		a := &attrs[i]
		if a.typ == attrAttributeList {
			hasAttrList = true
		}
		if a.typ != attrData || a.nameLen != 0 {
			continue
		}
		hasUnnamedData = true
		if !a.nonResident {
			return recBytes[a.valueOffset : a.valueOffset+int(a.valueLen)], nil
		}
		runs, err := h.parseRuns(recBytes[a.runDataOff:a.runDataEnd])
		if err != nil {
			return nil, fmt.Errorf("data runs for %s: %w", path, err)
		}
		return h.readNonResident(runs, a.realSize)
	}
	// A record that carries an $ATTRIBUTE_LIST but no local unnamed $DATA holds
	// its data in external MFT records, which this parser does not follow.
	// Reporting an empty file here would be fabricated data.
	if hasAttrList && !hasUnnamedData {
		return nil, fmt.Errorf("attribute list not supported for %s: %w", path, filesystem.ErrUnsupported)
	}
	// No unnamed $DATA stream: the file is empty (non-nil, zero-length).
	return []byte{}, nil
}

// GetFileByPath returns metadata for the file at path.
func (h *NTFSHandler) GetFileByPath(path string) (*filesystem.FileInfo, error) {
	if h.reader == nil {
		return nil, fmt.Errorf("NTFS handler has no reader")
	}
	if err := h.ensureIndex(); err != nil {
		return nil, err
	}
	rec, err := h.resolvePath(path)
	if err != nil {
		return nil, err
	}
	entry, ok := h.fileIndex[rec]
	if !ok {
		return nil, fmt.Errorf("path not found: %s: %w", path, filesystem.ErrNotFound)
	}
	fi := fileInfoFromEntry(entry, "/"+strings.Trim(path, "/"))
	return &fi, nil
}

// SearchFiles walks the MFT and returns every record under rootPath whose
// filesystem.FileInfo satisfies predicate. Results are bounded by ntfsMaxSearchCount.
func (h *NTFSHandler) SearchFiles(rootPath string, predicate func(filesystem.FileInfo) bool) ([]filesystem.FileInfo, error) {
	if h.reader == nil {
		return nil, fmt.Errorf("NTFS handler has no reader")
	}
	if err := h.ensureIndex(); err != nil {
		return nil, err
	}
	rootRec, err := h.resolvePath(rootPath)
	if err != nil {
		return nil, err
	}
	rootEntry, ok := h.fileIndex[rootRec]
	if !ok || !rootEntry.isDir {
		return nil, fmt.Errorf("search root %q is not a directory", rootPath)
	}

	base := strings.Trim(rootPath, "/")
	basePrefix := ""
	if base != "" {
		basePrefix = "/" + base
	}
	results := make([]filesystem.FileInfo, 0)
	for rec := range h.fileIndex {
		if rec == rootRec {
			continue
		}
		rel, ok := h.relativePath(rec, rootRec)
		if !ok {
			continue
		}
		fi := fileInfoFromEntry(h.fileIndex[rec], filesystem.JoinPath(basePrefix, rel))
		if predicate(fi) {
			if len(results) >= ntfsMaxSearchCount {
				return nil, fmt.Errorf("search exceeded %d results", ntfsMaxSearchCount)
			}
			results = append(results, fi)
		}
	}
	return results, nil
}

// GetVolumeLabel returns the volume label from record 3's $VOLUME_NAME (0x60)
// attribute, or "" if absent.
func (h *NTFSHandler) GetVolumeLabel() string {
	if h.reader == nil {
		return ""
	}
	recBytes, err := h.readRecord(3)
	if err != nil {
		return ""
	}
	attrs, err := h.parseAttrs(recBytes)
	if err != nil {
		return ""
	}
	for i := range attrs {
		a := &attrs[i]
		if a.typ != attrVolumeName || a.nameLen != 0 || a.nonResident {
			continue
		}
		val := recBytes[a.valueOffset : a.valueOffset+int(a.valueLen)]
		var units []uint16
		for j := 0; j+1 < len(val); j += 2 {
			u := binary.LittleEndian.Uint16(val[j : j+2])
			if u == 0 {
				break
			}
			units = append(units, u)
		}
		return string(utf16.Decode(units))
	}
	return ""
}

func init() {
	// The registry factory has no reader; real use goes through
	// NewNTFSHandler. All data methods return explicit errors on a
	// reader-less handler (see the defabrication gate).
	filesystem.RegisterFileSystem(filesystem.FS_NTFS, func() filesystem.FileSystem { return &NTFSHandler{} })
	filesystem.RegisterHandler(filesystem.FS_NTFS, func(r filesystem.Reader, startLBA, partitionSize uint64) (filesystem.FileSystem, error) {
		return NewNTFSHandler(r, startLBA)
	})
}
