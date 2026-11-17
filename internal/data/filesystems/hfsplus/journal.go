package hfsplus

// The HFS+ journal: header, block lists, and transaction reporting.
//
// A journaled volume keeps metadata transactions in a circular buffer.  The
// volume header names a JournalInfoBlock, which gives the journal's byte offset
// and size; the journal begins with one sector of journal_header followed by
// transactions.  Each transaction is a sequence of block lists.  Every block
// info entry names a destination sector on the volume.
//
// This port reads the head and walks the transactions, reporting what a replay
// would write.  It does not build a replay overlay; that branch returns
// ErrUnsupported naming the feature rather than serving the on-disk bytes as
// if they were replayed.
//
// Layout and checksum (cksum = (cksum << 8) XOR (cksum + byte), then bitwise
// complement) follow Apple's hfs_journal.h and TN1150.

import (
	"github.com/laenix/ewfgo/internal/data/source"
)

const (
	// JournalMagic is the journal header's magic, "JNLx".
	JournalMagic uint32 = 0x4A4E_4C78
	// EndianMagic is the journal header's byte-order marker.
	EndianMagic uint32 = 0x1234_5678

	// JIInFS marks a journal that lives inside this volume.
	JIInFS uint32 = 0x0000_0001
	// JIOnOtherDevice marks a journal on another device.
	JIOnOtherDevice uint32 = 0x0000_0002
	// JINeedInit marks a journal that was never initialised.
	JINeedInit uint32 = 0x0000_0004

	// BLHdrCheckChecksums marks a block list whose block checksums are present.
	BLHdrCheckChecksums uint32 = 0x0000_0001
	// BLHdrFirstHeader marks the first block list of a transaction.
	BLHdrFirstHeader uint32 = 0x0000_0002

	blhdrChecksumSize = 32
	jhdrChecksumAt    = 36
	jhdrChecksumSize  = 44
	blhdrMin          = 32
	journalMin        = 1024
	maxJournalSector  = 4096
	maxTransactions   = 65_536

	// MaxScanBytes caps the journal bytes one walk reads.
	MaxScanBytes uint64 = 256 * 1024 * 1024
	// MaxReplayBytes caps the block data a replay view would hold.
	MaxReplayBytes uint64 = 256 * 1024 * 1024
)

// JournalInfoBlock is the structure the volume header points at.
type JournalInfoBlock struct {
	Flags  uint32
	Offset uint64
	Size   uint64
}

func parseJournalInfoBlock(bytes []byte) (JournalInfoBlock, error) {
	if len(bytes) < 52 {
		return JournalInfoBlock{}, invalidf("journal info block is %d bytes, too short for its flags, offset and size", len(bytes))
	}
	return JournalInfoBlock{Flags: be32(bytes, 0), Offset: be64(bytes, 36), Size: be64(bytes, 44)}, nil
}

// InFS reports whether the journal lives in this volume.
func (b JournalInfoBlock) InFS() bool { return b.Flags&JIInFS != 0 }

// OnOtherDevice reports whether the journal lives on another device.
func (b JournalInfoBlock) OnOtherDevice() bool { return b.Flags&JIOnOtherDevice != 0 }

// NeedsInit reports whether the journal has never been initialised.
func (b JournalInfoBlock) NeedsInit() bool { return b.Flags&JINeedInit != 0 }

// JournalHeader is the one-sector journal header.
type JournalHeader struct {
	Magic     uint32
	Endian    uint32
	Start     uint64
	End       uint64
	Size      uint64
	BlhdrSize uint32
	Checksum  uint32
	JhdrSize  uint32
}

func parseJournalHeader(bytes []byte) (JournalHeader, error) {
	if len(bytes) < jhdrChecksumSize {
		return JournalHeader{}, invalidf("journal header is %d bytes, expected at least %d", len(bytes), jhdrChecksumSize)
	}
	return JournalHeader{
		Magic:     be32(bytes, 0),
		Endian:    be32(bytes, 4),
		Start:     be64(bytes, 8),
		End:       be64(bytes, 16),
		Size:      be64(bytes, 24),
		BlhdrSize: be32(bytes, 32),
		Checksum:  be32(bytes, 36),
		JhdrSize:  be32(bytes, 40),
	}, nil
}

// IsEmpty reports whether the journal holds no transaction.
func (h JournalHeader) IsEmpty() bool { return h.Start == h.End }

// JournalHead is what reading a journal's head found.
type JournalHead struct {
	Info             JournalInfoBlock
	Header           JournalHeader
	JournalOffset    uint64
	HeaderChecksumOK bool
	NeedsInit        bool
}

// IsEmpty reports whether no transaction waits.
func (h JournalHead) IsEmpty() bool {
	return h.NeedsInit || !h.HeaderChecksumOK || h.Header.IsEmpty()
}

// JournalWrite is one journaled byte range a replay would apply.
type JournalWrite struct {
	Sector        uint64
	Data          []byte
	JournalOffset uint64
}

// Len returns the bytes this run copies.
func (w JournalWrite) Len() uint64 { return uint64(len(w.Data)) }

// Destination returns the byte offset on the volume this run overwrites.
func (w JournalWrite) Destination(sectorSize uint64) uint64 { return w.Sector * sectorSize }

// Transaction is one run of block lists and the writes it would apply.
type Transaction struct {
	StartsAt  uint64
	BytesUsed uint64
	Checksums bool
	Writes    []JournalWrite
}

// Bytes returns the bytes this transaction would copy.
func (t Transaction) Bytes() uint64 {
	var total uint64
	for _, write := range t.Writes {
		total += write.Len()
	}
	return total
}

// JournalStats reports what walking a journal found.
type JournalStats struct {
	Transactions     int
	BlockLists       int
	Writes           int
	Bytes            uint64
	Killed           int
	Malformed        int
	BlockChecksums   bool
	ChecksumMismatch bool
	Stopped          bool
	Limited          bool
}

// Journal is a parsed HFS+ journal.
type Journal struct {
	Head         JournalHead
	Transactions []Transaction
	Stats        JournalStats
}

// Pending reports whether a transaction waits to be replayed.
func (j *Journal) Pending() bool { return len(j.Transactions) > 0 }

// Replay builds the read-only view a replay would leave on disk.  This port
// does not implement the overlay: it refuses by name rather than presenting
// the un-replayed volume as if it were replayed.
func (j *Journal) Replay(volume *Volume, id source.ID) (source.ByteSource, error) {
	return nil, unsupportedf("journal replay overlay (destination source %d) is not ported", id)
}

// RecoveredName is a catalog name a replay would bring back.
type RecoveredName struct {
	Name        string
	Parent      uint32
	ID          *uint32
	Path        *string
	IsDirectory bool
}

// RecoveredNames is the result of comparing the current catalog with its
// replay.
type RecoveredNames struct {
	Names           []RecoveredName
	Records         int
	ReplayedRecords int
	Removed         int
	Truncated       bool
}

// RecoveredNames compares the current catalog with the journal's replay to
// report names a replay would restore.  This port does not implement that
// comparison; it refuses by name.
func (j *Journal) RecoveredNames(volume *Volume, id source.ID, limit int) (*RecoveredNames, error) {
	return nil, unsupportedf("journal recovered-name comparison (destination source %d) is not ported", id)
}

// Journal returns the volume's journal, head and transactions.
func (v *Volume) Journal() (*Journal, error) {
	head, err := readJournalHead(v)
	if err != nil {
		return nil, err
	}
	return walkJournal(v, head, MaxScanBytes)
}

// JournalHead reads only the info block and one header sector, or returns nil
// when the volume is not journaled.
func (v *Volume) JournalHead() (*JournalHead, error) {
	if !v.Journaled() {
		return nil, nil
	}
	head, err := readJournalHead(v)
	if err != nil {
		return nil, err
	}
	return &head, nil
}

func readJournalHead(v *Volume) (JournalHead, error) {
	header := v.header
	if header.JournalInfoBlock == 0 {
		return JournalHead{}, invalidf("the volume header names no journal info block")
	}
	blockSize := uint64(header.BlockSize)
	jibAt := uint64(header.JournalInfoBlock) * blockSize
	if jibAt/blockSize != uint64(header.JournalInfoBlock) {
		return JournalHead{}, invalidf("journal info block offset overflows")
	}
	jib, err := source.ReadVecAt(v.src, jibAt, 52)
	if err != nil {
		return JournalHead{}, err
	}
	info, err := parseJournalInfoBlock(jib)
	if err != nil {
		return JournalHead{}, err
	}
	if info.OnOtherDevice() {
		return JournalHead{}, unsupportedf("the journal lives on another device, which this reader cannot reach")
	}
	if !info.InFS() && !info.NeedsInit() {
		return JournalHead{}, unsupportedf("journal info flags 0x%08x do not place the journal in this volume", info.Flags)
	}
	if info.Offset%512 != 0 || info.Size%512 != 0 {
		return JournalHead{}, invalidf("journal offset %d and size %d are not sector multiples", info.Offset, info.Size)
	}
	if info.Size < journalMin {
		return JournalHead{}, invalidf("journal size %d is below the %d-byte minimum", info.Size, journalMin)
	}
	sourceLen := v.src.Len()
	if info.Offset > sourceLen || info.Size > sourceLen-info.Offset {
		return JournalHead{}, invalidf("journal [%d..%d) lies outside the %d-byte volume", info.Offset, info.Offset+info.Size, sourceLen)
	}
	sector, err := source.ReadVecAt(v.src, info.Offset, jhdrChecksumSize)
	if err != nil {
		return JournalHead{}, err
	}
	jhdr, err := parseJournalHeader(sector)
	if err != nil {
		return JournalHead{}, err
	}
	if jhdr.Magic != JournalMagic {
		return JournalHead{}, invalidf("journal header magic 0x%08x is not 0x%08x", jhdr.Magic, JournalMagic)
	}
	if jhdr.Endian != EndianMagic {
		return JournalHead{}, invalidf("journal header byte-order marker 0x%08x is not 0x%08x", jhdr.Endian, EndianMagic)
	}
	if jhdr.Size != info.Size {
		return JournalHead{}, invalidf("journal header size %d disagrees with the info block's %d", jhdr.Size, info.Size)
	}
	sectorSize := uint64(jhdr.JhdrSize)
	if sectorSize < 512 || sectorSize > maxJournalSector || sectorSize&(sectorSize-1) != 0 {
		return JournalHead{}, invalidf("journal sector size %d is not a power of two in 512..=%d", sectorSize, maxJournalSector)
	}
	if sectorSize > info.Size {
		return JournalHead{}, invalidf("journal sector size %d exceeds its %d bytes", sectorSize, info.Size)
	}
	blhdrSize := uint64(jhdr.BlhdrSize)
	if blhdrSize < blhdrMin || blhdrSize%sectorSize != 0 || blhdrSize > info.Size-sectorSize {
		return JournalHead{}, invalidf("block list header size %d is not a sector multiple in %d..=%d",
			blhdrSize, blhdrMin, info.Size-sectorSize)
	}
	full, err := source.ReadVecAt(v.src, info.Offset, sectorSize)
	if err != nil {
		return JournalHead{}, err
	}
	headerChecksumOK := verifyJournalChecksum(full[:jhdrChecksumSize], jhdrChecksumAt) == jhdr.Checksum
	return JournalHead{
		Info:             info,
		Header:           jhdr,
		JournalOffset:    info.Offset,
		HeaderChecksumOK: headerChecksumOK,
		NeedsInit:        info.NeedsInit(),
	}, nil
}

func walkJournal(v *Volume, head JournalHead, maxBytes uint64) (*Journal, error) {
	journal := &Journal{Head: head}
	if head.NeedsInit || !head.HeaderChecksumOK || head.Header.IsEmpty() {
		return journal, nil
	}
	src := v.src
	journalOffset := head.JournalOffset
	ringStart := uint64(head.Header.JhdrSize)
	journalSize := head.Header.Size
	sectorSize := ringStart
	blhdrSize := uint64(head.Header.BlhdrSize)
	sourceLen := src.Len()
	start, end := head.Header.Start, head.Header.End
	if start < ringStart || start >= journalSize || end < ringStart || end > journalSize {
		return nil, invalidf("journal start %d and end %d are outside [%d..%d]", start, end, ringStart, journalSize)
	}

	stats := JournalStats{}
	var transactions []Transaction
	cursor := start
	var scanned uint64
	for cursor != end {
		if len(transactions) >= maxTransactions {
			stats.Limited = true
			stats.Stopped = true
			break
		}
		if scanned >= maxBytes {
			stats.Limited = true
			stats.Stopped = true
			break
		}
		blhdr := make([]byte, int(blhdrSize))
		if err := readJournalRing(src, journalOffset, ringStart, journalSize, cursor, blhdr); err != nil {
			stats.Malformed++
			stats.Stopped = true
			break
		}
		scanned += blhdrSize
		maxBlocks := uint64(be16(blhdr, 0))
		numBlocks := uint64(be16(blhdr, 2))
		bytesUsed := uint64(be32(blhdr, 4))
		stored := be32(blhdr, 8)
		flags := be32(blhdr, 12)
		capacity := blhdrSize/16 - 1
		if numBlocks == 0 || numBlocks > capacity || maxBlocks > capacity || maxBlocks < numBlocks {
			stats.Malformed++
			stats.Stopped = true
			break
		}
		if verifyJournalChecksum(blhdr[:blhdrChecksumSize], 8) != stored {
			stats.ChecksumMismatch = true
			stats.Malformed++
			stats.Stopped = true
			break
		}
		if bytesUsed < blhdrSize || bytesUsed > journalSize {
			stats.Malformed++
			stats.Stopped = true
			break
		}
		checksums := flags&BLHdrCheckChecksums != 0
		writes := make([]JournalWrite, 0, numBlocks-1)
		consumed := blhdrSize
		dataAt := journalAdvance(cursor, blhdrSize, ringStart, journalSize)
		bad := false
		for index := uint64(1); index < numBlocks; index++ {
			at := int(16 + index*16)
			if at+16 > len(blhdr) {
				stats.Malformed++
				bad = true
				break
			}
			sector := be64(blhdr, at)
			size := uint64(be32(blhdr, at+8))
			blockChecksum := be32(blhdr, at+12)
			if size == 0 {
				continue
			}
			if size%sectorSize != 0 {
				stats.Malformed++
				bad = true
				break
			}
			if scanned+size > maxBytes {
				stats.Limited = true
				bad = true
				break
			}
			segments, err := readJournalRingSegments(src, journalOffset, ringStart, journalSize, dataAt, size)
			if err != nil {
				stats.Malformed++
				bad = true
				break
			}
			scanned += size
			data := make([]byte, 0, int(size))
			for _, segment := range segments {
				data = append(data, segment.data...)
			}
			if checksums && blockChecksum != 0 {
				stats.BlockChecksums = true
				if JournalChecksum(data) != blockChecksum {
					stats.ChecksumMismatch = true
					stats.Malformed++
					bad = true
					break
				}
			}
			if sector == ^uint64(0) {
				stats.Killed++
			} else {
				dest := sector * sectorSize
				if sector != 0 && dest/sectorSize != sector {
					stats.Malformed++
					bad = true
					break
				}
				if dest+size < dest || dest+size > sourceLen {
					stats.Malformed++
					bad = true
					break
				}
				var skip uint64
				for _, segment := range segments {
					writes = append(writes, JournalWrite{
						Sector:        sector + skip/sectorSize,
						Data:          segment.data,
						JournalOffset: segment.at,
					})
					skip += uint64(len(segment.data))
				}
				stats.Writes++
				stats.Bytes += size
			}
			consumed += size
			dataAt = journalAdvance(dataAt, size, ringStart, journalSize)
		}
		if bad {
			stats.Stopped = true
			break
		}
		if consumed > bytesUsed {
			stats.Malformed++
			stats.Stopped = true
			break
		}
		stats.BlockLists++
		transactions = append(transactions, Transaction{
			StartsAt:  cursor,
			BytesUsed: bytesUsed,
			Checksums: checksums,
			Writes:    writes,
		})
		stats.Transactions = len(transactions)
		next := journalAdvance(cursor, bytesUsed, ringStart, journalSize)
		if next == cursor {
			stats.Malformed++
			stats.Stopped = true
			break
		}
		cursor = next
	}
	if cursor != end && !stats.Stopped {
		stats.Stopped = true
	}
	journal.Transactions = transactions
	journal.Stats = stats
	return journal, nil
}

// JournalChecksum is Apple's journal checksum: shift/XOR fold, complemented.
func JournalChecksum(bytes []byte) uint32 {
	var sum uint32
	for _, b := range bytes {
		sum = (sum << 8) ^ (sum + uint32(b))
	}
	return ^sum
}

func verifyJournalChecksum(bytes []byte, fieldAt int) uint32 {
	copyBytes := append([]byte(nil), bytes...)
	for i := fieldAt; i < fieldAt+4 && i < len(copyBytes); i++ {
		copyBytes[i] = 0
	}
	return JournalChecksum(copyBytes)
}

func journalAdvance(offset, length, ringStart, journalSize uint64) uint64 {
	ring := journalSize - ringStart
	if ring == 0 {
		return ringStart
	}
	return ringStart + ((offset - ringStart + length) % ring)
}

func readJournalRing(src source.ByteSource, journalOffset, ringStart, journalSize, offset uint64, buf []byte) error {
	done := 0
	for done < len(buf) {
		if offset < ringStart || offset >= journalSize {
			return invalidf("journal offset %d is outside [%d..%d)", offset, ringStart, journalSize)
		}
		take := int(minU64(journalSize-offset, uint64(len(buf)-done)))
		if err := source.ReadExactAt(src, journalOffset+offset, buf[done:done+take]); err != nil {
			return err
		}
		done += take
		offset += uint64(take)
		if offset >= journalSize {
			offset = ringStart
		}
	}
	return nil
}

type journalSegment struct {
	at   uint64
	data []byte
}

func readJournalRingSegments(src source.ByteSource, journalOffset, ringStart, journalSize, offset, length uint64) ([]journalSegment, error) {
	var segments []journalSegment
	left := length
	for left > 0 {
		if offset < ringStart || offset >= journalSize {
			return nil, invalidf("journal offset %d is outside [%d..%d)", offset, ringStart, journalSize)
		}
		take := journalSize - offset
		if take > left {
			take = left
		}
		bytes, err := source.ReadVecAt(src, journalOffset+offset, take)
		if err != nil {
			return nil, err
		}
		segments = append(segments, journalSegment{at: journalOffset + offset, data: bytes})
		left -= take
		offset += take
		if offset >= journalSize {
			offset = ringStart
		}
	}
	return segments, nil
}
