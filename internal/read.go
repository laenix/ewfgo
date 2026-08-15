package internal

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/adler32"
	"io"
	"os"
	"runtime"
	"sync"
)

// 读取某位置的多少个字节
// ReadAt reads raw bytes from the logical EWF image (all segments concatenated
// in order) at the given offset. For actual sector data, use ReadSectorData
// instead. Reading past the end of the image returns the partial bytes that
// exist (never nil); nil is returned only for genuinely invalid reads. When a
// byte range crosses a segment boundary the head is taken from segment N and
// the tail from segment N+1, so chunk data that straddles two segment files is
// read contiguously before any decompression.
func (e *EWFImage) ReadAt(addr int64, length int64) []byte {
	if length < 0 {
		// Never panic on crafted input: make([]byte, negative) would panic, and
		// ParseHeader derives a negative length for any crafted section with
		// SectionSize < 76.
		return nil
	}
	if addr < 0 {
		return nil
	}
	if len(e.segments) == 0 {
		// Fallback: no open segment handles, open temporarily (segment 1 only)
		file, err := os.Open(e.filepath)
		if err != nil {
			return nil
		}
		defer file.Close()
		buffer := make([]byte, length)
		n, err := file.ReadAt(buffer, addr)
		if err != nil && err != io.EOF {
			return nil
		}
		return buffer[:n]
	}

	buffer := make([]byte, length)
	n := 0
	remaining := length
	cur := addr
	for remaining > 0 {
		seg := e.segmentAt(cur)
		if seg == nil {
			break // past the end of the logical image
		}
		local := cur - seg.start
		avail := seg.size - local
		if avail <= 0 {
			break
		}
		readLen := remaining
		if readLen > avail {
			readLen = avail
		}
		m, err := seg.file.ReadAt(buffer[n:n+int(readLen)], local)
		if err != nil && err != io.EOF {
			if n == 0 {
				return nil
			}
			break
		}
		n += m
		remaining -= int64(m)
		cur += int64(m)
		if int64(m) < readLen {
			break
		}
	}
	return buffer[:n]
}

// segmentAt returns the segment that contains the logical image offset addr,
// or nil if addr is past the end of the image.
func (e *EWFImage) segmentAt(addr int64) *SegmentFile {
	for _, seg := range e.segments {
		if addr >= seg.start && addr < seg.start+seg.size {
			return seg
		}
	}
	return nil
}

// segmentStart returns the logical offset at which segment idx begins.
func (e *EWFImage) segmentStart(idx int) (int64, bool) {
	if idx >= 0 && idx < len(e.segments) {
		return e.segments[idx].start, true
	}
	return 0, false
}

// totalSize returns the size of the logical image across all segments.
func (e *EWFImage) totalSize() int64 {
	if len(e.segments) == 0 {
		return 0
	}
	last := e.segments[len(e.segments)-1]
	return last.start + last.size
}

// ReadSectorAt reads one raw sector, delegating to the spec-compliant
// ReadSectorData path so layout (EnCase 1-7), base offsets, multi-section
// spanning, and zlib validation are all handled identically.
func (e *EWFImage) ReadSectorAt(sectorNum int) ([]byte, error) {
	return e.ReadSectorData(uint64(sectorNum), 1)
}

// ReadSectorData reads sector data from the compressed sectors sections.
// It uses the table mapping to resolve each chunk and handles decompression.
// On any resolution or decompression failure it returns an error — it never
// returns EWF container bytes as sector data.
func (e *EWFImage) ReadSectorData(startSector uint64, numSectors uint64) ([]byte, error) {
	if len(e.Sectors) == 0 {
		return nil, errors.New("no sectors data found")
	}

	sectorSize := uint64(512)
	chunkSectors := uint64(64)
	if len(e.DiskSMART) > 0 {
		if e.DiskSMART[0].SectorBytes > 0 {
			sectorSize = uint64(e.DiskSMART[0].SectorBytes)
		}
		if e.DiskSMART[0].ChunkSectors > 0 {
			chunkSectors = uint64(e.DiskSMART[0].ChunkSectors)
		}
	}
	// Guard against crafted DiskSMART geometry: a zero sector or chunk size would
	// divide-by-zero in rel/chunkSectors below, and an implausibly large chunk
	// would force a huge allocation (OOM) — never panic, always error.
	if sectorSize == 0 || chunkSectors == 0 {
		return nil, fmt.Errorf("invalid disk geometry: sectorSize=%d chunkSectors=%d", sectorSize, chunkSectors)
	}
	if chunkSectors > (64<<20)/sectorSize { // 64 MiB cap, overflow-safe
		return nil, fmt.Errorf("implausible chunk size: %d bytes", chunkSectors*sectorSize)
	}
	chunkBytes := int(chunkSectors * sectorSize)

	// Precompute each section's starting sector so reads can span sections.
	sectionOffsets := make([]uint64, len(e.Sectors))
	var totalSectors uint64
	for i := range e.Sectors {
		sectionOffsets[i] = totalSectors
		totalSectors += uint64(len(e.Sectors[i].TableEntry)) * chunkSectors
	}

	// The acquired media may not be chunk-aligned: the volume section records the
	// real sector count, and the final chunk then stores only the valid sectors
	// (e.g. a 500 GiB disk whose last chunk holds 33 of 64 sectors). totalSectors
	// is the chunk-coverage ceiling; mediaSectors is the authoritative media end.
	// A final partial chunk must be accepted at its stored length — not rejected
	// as "too short" — or whole-image reads (and hash verification) fail at the
	// last chunk.
	mediaSectors := totalSectors
	if len(e.DiskSMART) > 0 && e.DiskSMART[0].SectorsCount > 0 &&
		e.DiskSMART[0].SectorsCount < totalSectors {
		mediaSectors = e.DiskSMART[0].SectorsCount
	}

	// Reading starting at or past the media end must fail loudly — never wrap
	// into chunk 0 and return wrong data under a wrong LBA (red line).
	if startSector >= totalSectors {
		return nil, fmt.Errorf("start sector %d beyond media end %d", startSector, totalSectors)
	}

	// Guard the result allocation against a caller-controlled request size so a
	// huge numSectors cannot OOM. The cap is overflow-safe: sectorSize is known
	// nonzero here and the total stays under 1 GiB.
	if numSectors > (1<<30)/sectorSize { // 1 GiB cap on a single read request
		return nil, fmt.Errorf("read request too large: %d sectors", numSectors)
	}

	// Two passes. Pass 1 lays out the read: one job per covering chunk, each
	// recording where its span lands in the result. Pass 2 inflates the chunk
	// jobs — in parallel across a batch — and copies each span home. The result
	// is preallocated and zeroed, so the past-the-last-section region and a
	// short final chunk's tail are already zero without explicit fills.
	//
	// Decompression stays exact: every job goes through readChunkForSection,
	// which returns decompressed sector data or an explicit error — never EWF
	// container bytes. Only the scheduling differs from the sequential path.
	type chunkJob struct {
		si, ci   int   // section / chunk index
		dst      int   // byte offset into result
		srcFirst int   // byte offset into the decompressed chunk
		span     int   // bytes to copy (chunk tail beyond end is excluded)
		valid    int   // bytes the chunk must hold (final partial chunk < chunkBytes)
		sector   uint64
	}
	type chunkBatch []chunkJob

	var jobs chunkBatch
	si := 0   // current section index, advanced monotonically as cur grows
	cur := startSector
	end := startSector + numSectors
	for cur < end {
		// Advance to the section covering cur.
		for si < len(e.Sectors)-1 &&
			cur >= sectionOffsets[si]+uint64(len(e.Sectors[si].TableEntry))*chunkSectors {
			si++
		}

		sectionEnd := sectionOffsets[si] + uint64(len(e.Sectors[si].TableEntry))*chunkSectors

		// Past the last section's recorded chunks: legitimate sparse region or
		// media end. The preallocated result is zero there — never wrap and
		// never return container bytes.
		if cur >= sectionEnd {
			break
		}

		// Decompress the chunk covering cur exactly once and slice every
		// requested sector inside it from that single decompression. The old
		// per-sector loop re-read and re-inflated the same chunk per sector — a
		// chunkSectors-fold amplification (32 KiB chunk / 512-byte sector = 64x).
		rel := cur - sectionOffsets[si]
		chunkIndex := int(rel / chunkSectors)
		chunkStart := sectionOffsets[si] + uint64(chunkIndex)*chunkSectors
		chunkEnd := chunkStart + chunkSectors
		if chunkEnd > end {
			chunkEnd = end
		}
		// validBytes: the final partial chunk stores only its valid sectors
		// (mediaSectors - chunkStart); every other chunk stores the full size.
		validBytes := chunkBytes
		if chunkStart < mediaSectors && chunkStart+chunkSectors > mediaSectors {
			validBytes = int((mediaSectors - chunkStart) * sectorSize)
		}
		jobs = append(jobs, chunkJob{
			si:       si,
			ci:       chunkIndex,
			dst:      int((cur - startSector) * sectorSize),
			srcFirst: int((cur - chunkStart) * sectorSize),
			span:     int((chunkEnd - cur) * sectorSize),
			valid:    validBytes,
			sector:   cur,
		})
		cur = chunkEnd
	}

	result := make([]byte, numSectors*sectorSize)

	// parallelBatch caps how many decompressed chunks are held between
	// decompression and assembly, bounding peak memory to about 8 MiB plus the
	// result buffer regardless of the request size. Each batch is inflated by a
	// pool of workers and assembled in order, so the output is byte-identical to
	// the sequential path and the first failing chunk still aborts the read.
	const parallelBatch = 256
	for lo := 0; lo < len(jobs); lo += parallelBatch {
		hi := lo + parallelBatch
		if hi > len(jobs) {
			hi = len(jobs)
		}
		batch := jobs[lo:hi]

		data := make([][]byte, len(batch))
		errs := make([]error, len(batch))

		workers := runtime.GOMAXPROCS(0)
		if workers < 1 {
			workers = 1
		}
		if len(batch) >= workers*2 {
			// os.File.ReadAt is documented safe for concurrent use and every
			// job reads a distinct file offset, so workers can share the image.
			var wg sync.WaitGroup
			ch := make(chan int)
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := range ch {
						j := &batch[i]
						data[i], errs[i] = e.readChunkForSection(j.si, j.ci, chunkBytes, j.valid)
					}
				}()
			}
			for i := range batch {
				ch <- i
			}
			close(ch)
			wg.Wait()
		} else {
			// Small batch: sequential — goroutine setup would cost more than it saves.
			for i := range batch {
				j := &batch[i]
				data[i], errs[i] = e.readChunkForSection(j.si, j.ci, chunkBytes, j.valid)
			}
		}

		for i := range batch {
			j := &batch[i]
			if errs[i] != nil {
				return nil, fmt.Errorf("sector %d: %w", j.sector, errs[i])
			}
			// Copy the contiguous span in one memmove; a decompressed chunk
			// shorter than expected (only a partial final chunk) has its tail
			// left at zero in the preallocated result.
			avail := len(data[i]) - j.srcFirst
			if avail < 0 {
				avail = 0
			}
			if avail > j.span {
				avail = j.span
			}
			if avail > 0 {
				copy(result[j.dst:j.dst+avail], data[i][j.srcFirst:j.srcFirst+avail])
			}
		}
	}
	return result, nil
}

// readChunkForSection resolves and reads one chunk, validating its content.
// The chunk file offset comes from exactly one spec-defined formula — no
// candidate probing, no heuristic validity checks (approved design §1.2
// removed the old double-offset guessing). A chunk that fails to read or
// validate returns an explicit error.
// readChunkForSection resolves and reads one chunk, validating its content,
// with a decompressed-chunk cache in front of the raw read. The chunk data is
// immutable, so a cache hit returns the stored slice directly.
// expectedBytes is the length a chunk must decompress to: the full chunk size,
// except for the media's final partial chunk, which legitimately holds only its
// valid sectors (see ReadSectorData). The cached slice is the same regardless —
// the length check lives in readChunk, so the cache never varies by expectedBytes.
func (e *EWFImage) readChunkForSection(sectionIndex, chunkIndex, chunkBytes, expectedBytes int) ([]byte, error) {
	if e.chunkCache != nil {
		if d, ok := e.chunkCache.get(sectionIndex, chunkIndex); ok {
			return d, nil
		}
	}
	d, err := e.readChunkForSectionUncached(sectionIndex, chunkIndex, chunkBytes, expectedBytes)
	if err != nil {
		return nil, err
	}
	if e.chunkCache != nil {
		e.chunkCache.put(sectionIndex, chunkIndex, d)
	}
	return d, nil
}

func (e *EWFImage) readChunkForSectionUncached(sectionIndex, chunkIndex, chunkBytes, expectedBytes int) ([]byte, error) {
	sec := e.Sectors[sectionIndex]
	if chunkIndex < 0 || chunkIndex >= len(sec.TableEntry) {
		return nil, fmt.Errorf("chunk index %d out of range (section has %d entries)", chunkIndex, len(sec.TableEntry))
	}
	entry := sec.TableEntry[chunkIndex]
	isCompressed := entry&0x80000000 != 0
	rel := int64(entry & 0x7FFFFFFF)

	var chunkOffset int64
	if sec.BaseOffset != 0 {
		// EnCase 6-7: offset relative to the table base offset.
		chunkOffset = int64(sec.BaseOffset) + rel
	} else {
		// EnCase 1 / FTK / EnCase 2-5: offset relative to the file start.
		chunkOffset = rel
	}
	// Table entries and base offsets are relative to the segment file that holds
	// this table section; add the segment's cumulative offset to recover the
	// logical image offset used by ReadAt. For single-file images the segment
	// start is 0 and this is a no-op.
	if start, ok := e.segmentStart(sec.Segment); ok {
		chunkOffset += start
	}
	if chunkOffset < 0 {
		return nil, fmt.Errorf("chunk %d of section at 0x%x has invalid offset 0x%08x",
			chunkIndex, sec.Address, entry)
	}

	data, err := e.readChunk(chunkOffset, chunkBytes, isCompressed, expectedBytes)
	if err != nil {
		return nil, fmt.Errorf("chunk %d of section at 0x%x (entry=0x%08x): %w",
			chunkIndex, sec.Address, entry, err)
	}
	return data, nil
}

// readChunk reads and validates the chunk stored at off. Compressed chunks
// are inflated with the same code path that produced them: EWF compression
// method 1 is a zlib (RFC 1950) stream, and method 2 is a raw DEFLATE (RFC
// 1951) stream. A stream that fails both is an explicit error — the raw EWF
// container bytes are never returned as sector data. Method 3 (EWF-specific
// LZ) has no Go decompressor and is surfaced as an explicit unsupported error.
// expectedBytes is the length a chunk must decompress to: chunkBytes for a full
// chunk, or fewer for the media's final partial chunk (which stores only its
// valid sectors). A chunk that decompresses shorter than expectedBytes is a
// truncated/corrupt chunk and an explicit error — partial data is never served
// as sector data (red line).
func (e *EWFImage) readChunk(off int64, chunkBytes int, isCompressed bool, expectedBytes int) ([]byte, error) {
	if expectedBytes <= 0 || expectedBytes > chunkBytes {
		return nil, fmt.Errorf("chunk at offset 0x%x invalid expected length %d (chunk size %d)", off, expectedBytes, chunkBytes)
	}
	if isCompressed {
		data := e.ReadAt(off, int64(chunkBytes))
		if len(data) == 0 {
			return nil, fmt.Errorf("no data at offset 0x%x", off)
		}

		// Method 1: zlib (RFC 1950) stream — the common case for EnCase / FTK
		// images. A stream that passes the 2-byte header check but inflates
		// badly (corrupt body, short output) errors here directly; only a stream
		// that is NOT zlib at all (bad header) falls through to the raw-DEFLATE
		// method-2 attempt.
		zr, zerr := zlib.NewReader(bytes.NewReader(data))
		if zerr == nil {
			out, ierr := io.ReadAll(zr)
			zr.Close()
			if ierr != nil {
				return nil, fmt.Errorf("decompressing chunk at offset 0x%x: %w", off, ierr)
			}
			if len(out) < expectedBytes {
				return nil, fmt.Errorf("chunk at offset 0x%x decompressed to %d bytes, want at least %d",
					off, len(out), expectedBytes)
			}
			return out, nil
		}

		// Method 2: raw DEFLATE (RFC 1951) stream, no header. flate.NewReader
		// does not validate eagerly, so a corrupt stream only surfaces as an
		// error from io.ReadAll inside inflateChunk. Method 3 (EWF-specific LZ)
		// has no Go decompressor and is surfaced as an explicit unsupported
		// error — the raw container bytes are never returned as sector data.
		if out, derr := inflateChunk(data, expectedBytes, off, flateReader); derr == nil {
			return out, nil
		}
		return nil, fmt.Errorf("chunk at offset 0x%x is neither a zlib nor a raw DEFLATE stream (EWF method 3 LZ chunks are unsupported)", off)
	}

	// Uncompressed chunk: raw data followed by a 4-byte Adler-32 checksum.
	data := e.ReadAt(off, int64(expectedBytes)+chunkFooterLen)
	// Require the full data+footer before slicing — a truncated footer would
	// make data[expectedBytes:expectedBytes+4] panic (never panic on crafted
	// input).
	if int64(len(data)) < int64(expectedBytes)+chunkFooterLen {
		return nil, fmt.Errorf("chunk at offset 0x%x too short: %d bytes", off, len(data))
	}
	if adler32.Checksum(data[:expectedBytes]) != binary.LittleEndian.Uint32(data[expectedBytes:expectedBytes+4]) {
		return nil, fmt.Errorf("chunk at offset 0x%x fails Adler-32 checksum", off)
	}
	return data[:expectedBytes], nil
}

// inflateChunk inflates data with the given stream constructor and validates
// the decompressed length is at least expectedBytes. Any failure — bad stream
// header, corrupt data, or a short decompression — returns a non-nil error so
// callers never see a partial chunk as sector data.
func inflateChunk(data []byte, expectedBytes int, off int64, newReader func(io.Reader) (io.ReadCloser, error)) ([]byte, error) {
	r, err := newReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("decompressing chunk at offset 0x%x: %w", off, err)
	}
	if len(out) < expectedBytes {
		return nil, fmt.Errorf("chunk at offset 0x%x decompressed to %d bytes, want at least %d",
			off, len(out), expectedBytes)
	}
	return out, nil
}

// flateReader adapts flate.NewReader to the (io.Reader) (io.ReadCloser, error)
// shape used by inflateChunk. flate does not validate the stream eagerly, so a
// corrupt raw-DEFLATE chunk only surfaces as an error from io.ReadAll inside
// inflateChunk — both decompressors must fail before readChunk gives up.
func flateReader(r io.Reader) (io.ReadCloser, error) {
	return flate.NewReader(r), nil
}
