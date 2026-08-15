package internal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func (e *EWFImage) IsEWFFile() bool {
	file, err := os.Open(e.filepath)
	if err != nil {
		return false
	}

	header := make([]byte, 13)
	if _, err := file.Read(header); err != nil {
		return false
	}
	file.Close()
	return bytes.Equal(header[:8], EVFSignature[:])
}

func (e *EWFImage) Open(file string) (*EWFImage, error) {
	e.filepath = file
	// 打开文件并缓存句柄以提高性能
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	// 判断是否为EWF文件签名
	if !e.IsEWFFile() {
		f.Close()
		return nil, errors.New("not ewf file")
	}

	// Discover sibling segments <base>.E02, .E03, ... so a multi-segment image
	// reads as one logical disk. The primary file stays segment 1; with no
	// siblings the behavior is identical to the single-file case.
	segs, err := e.discoverSegments(file, f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to open segment files: %w", err)
	}
	var start int64
	for _, seg := range segs {
		seg.start = start
		start += seg.size
	}
	e.segments = segs
	e.filepath = segs[0].filepath
	e.chunkCache = newChunkCache(chunkCacheMaxBytes)
	return e, nil
}

// discoverSegments opens the sibling segment files for a multi-segment image.
// The primary file (already open as f) becomes segment 1; files named
// <stem>.E02, .E03, ... in the same directory (case-insensitive "E", or a bare
// two-digit number) are appended in ascending numeric order. Each sibling is
// validated as a real EWF segment: its 13-byte file header must carry the EVF
// signature and a segment number that continues the primary's sequence
// ascending with no gaps (E02 after E01, E03 after E02, ...). An unparseable
// or out-of-sequence sibling makes the whole open fail loudly — a garbage
// sibling must never be silently zero-filled. If discovery finds no siblings,
// exactly one segment — the primary — is returned and behavior is unchanged
// from the single-file case. On any error all sibling files opened so far are
// closed so a partially-successful open cannot leak file handles.
func (e *EWFImage) discoverSegments(path string, f *os.File) ([]*SegmentFile, error) {
	seg1 := &SegmentFile{filepath: path, file: f}
	if st, err := f.Stat(); err == nil {
		seg1.size = st.Size()
	}
	segs := []*SegmentFile{seg1}

	// Baseline segment number: read it from the primary file's 13-byte header so
	// a primary that is itself E02 (opened directly) validates siblings against
	// its own number. A primary with a valid signature and number 1 yields the
	// usual E01/E02/E03... sequence.
	prevNum := uint16(1)
	if n, ok := readSegmentNumber(f); ok {
		prevNum = n
	}

	dir := filepath.Dir(path)
	baseName := filepath.Base(path)
	stem := baseName
	if ext := filepath.Ext(baseName); ext != "" {
		stem = strings.TrimSuffix(baseName, ext)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		// Directory not listable — fall back to a single segment.
		return segs, nil
	}
	type sibling struct {
		num  int
		path string
	}
	var siblings []sibling
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if !strings.HasPrefix(name, stem+".") {
			continue
		}
		ext := strings.TrimPrefix(name, stem+".")
		num, ok := parseSegmentNumber(ext)
		if !ok || num <= 1 {
			continue
		}
		siblings = append(siblings, sibling{num: num, path: filepath.Join(dir, name)})
	}
	sort.Slice(siblings, func(i, j int) bool { return siblings[i].num < siblings[j].num })

	// closeSiblings closes every sibling opened so far (segments[1:]) and
	// drops them from the slice, so Open's error path only needs to close
	// segment 1's file (f). This prevents a handle leak when discovery opens
	// segments 2..k and then fails on segment k+1 (Windows file-lock issue).
	closeSiblings := func() {
		for _, s := range segs[1:] {
			if s.file != nil {
				s.file.Close()
				s.file = nil
			}
		}
		segs = segs[:1]
	}

	for _, s := range siblings {
		if filepath.Clean(s.path) == filepath.Clean(path) {
			continue
		}
		sf, err := e.openSegment(s.path)
		if err != nil {
			closeSiblings()
			return nil, err
		}
		num, ok := readSegmentNumber(sf.file)
		if !ok {
			sf.file.Close()
			closeSiblings()
			return nil, fmt.Errorf("segment file %s is not a valid EWF segment (missing EVF signature or truncated header)", s.path)
		}
		if num != prevNum+1 {
			sf.file.Close()
			closeSiblings()
			return nil, fmt.Errorf("segment file %s has segment number %d, expected %d after segment %d (gap or reordered segment sequence)", s.path, num, prevNum+1, prevNum)
		}
		if s.num != int(num) {
			sf.file.Close()
			closeSiblings()
			return nil, fmt.Errorf("segment file %s: header segment number %d does not match filename number %d", s.path, num, s.num)
		}
		prevNum = num
		segs = append(segs, sf)
	}
	return segs, nil
}

func (e *EWFImage) openSegment(path string) (*SegmentFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open segment file %s: %w", path, err)
	}
	sf := &SegmentFile{filepath: path, file: f}
	if st, err := f.Stat(); err == nil {
		sf.size = st.Size()
	} else {
		f.Close()
		return nil, fmt.Errorf("failed to stat segment file %s: %w", path, err)
	}
	return sf, nil
}

// readSegmentNumber reads the EWF segment number from a segment file's 13-byte
// header. It returns the number and ok=false if the header is unreadable or
// does not carry the EVF signature.
func readSegmentNumber(f *os.File) (uint16, bool) {
	header := make([]byte, EWFFileHeaderLength)
	n, err := f.ReadAt(header, 0)
	if err != nil || int64(n) < EWFFileHeaderLength {
		return 0, false
	}
	if !bytes.Equal(header[:8], EVFSignature[:]) {
		return 0, false
	}
	return binary.LittleEndian.Uint16(header[9:11]), true
}

// parseSegmentNumber parses a segment extension such as "E02", "e02" or "02"
// and returns the 1-based segment number. It returns ok=false for anything
// that does not match the two-digit numeric pattern.
func parseSegmentNumber(ext string) (int, bool) {
	s := ext
	if len(s) > 0 && (s[0] == 'e' || s[0] == 'E') {
		s = s[1:]
	}
	if len(s) != 2 || s[0] < '0' || s[0] > '9' || s[1] < '0' || s[1] > '9' {
		return 0, false
	}
	num := int(s[0]-'0')*10 + int(s[1]-'0')
	if num < 1 {
		return 0, false
	}
	return num, true
}

// Close closes all segment files of the image.
func (e *EWFImage) Close() error {
	var firstErr error
	for _, seg := range e.segments {
		if seg.file != nil {
			if err := seg.file.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
			seg.file = nil
		}
	}
	return firstErr
}

// Filepath returns the file path of the EWF image.
func (e *EWFImage) Filepath() string {
	return e.filepath
}
