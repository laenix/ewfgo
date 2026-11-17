package aff4

import (
	stdzip "archive/zip"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

// zipMember is one synthetic ZIP member.  Stored members are used for image
// payloads so the tests can reason about exact evidence offsets; descriptor
// members may be deflated.
type zipMember struct {
	name  string
	data  []byte
	store bool
}

func store(name string, data []byte) zipMember {
	return zipMember{name: name, data: data, store: true}
}

func deflateMember(name string, data []byte) zipMember {
	return zipMember{name: name, data: data}
}

// buildArchive writes a hermetic ZIP container with the standard library
// writer.  The AFF4 reader consumes it through the repo's independent ZIP
// reader, so the fixture shares no parsing code with the code under test.
func buildArchive(t *testing.T, members ...zipMember) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := stdzip.NewWriter(&buf)
	for _, member := range members {
		header := &stdzip.FileHeader{Name: member.name}
		if member.store {
			header.Method = stdzip.Store
		} else {
			header.Method = stdzip.Deflate
		}
		entry, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatalf("create %s: %v", member.name, err)
		}
		if _, err := entry.Write(member.data); err != nil {
			t.Fatalf("write %s: %v", member.name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}
	return buf.Bytes()
}

// indexBytes encodes 8-byte AFF4 index entries (little-endian bevy, offset).
func indexBytes(pairs ...[2]uint32) []byte {
	out := make([]byte, 0, 8*len(pairs))
	for _, pair := range pairs {
		var entry [8]byte
		binary.LittleEndian.PutUint32(entry[0:], pair[0])
		binary.LittleEndian.PutUint32(entry[4:], pair[1])
		out = append(out, entry[:]...)
	}
	return out
}

// mapBytes encodes 12-byte AFF4 map entries (offset u64, length u32).
func mapBytes(entries ...[2]uint64) []byte {
	out := make([]byte, 0, 12*len(entries))
	for _, entry := range entries {
		var raw [12]byte
		binary.LittleEndian.PutUint64(raw[0:], entry[0])
		binary.LittleEndian.PutUint32(raw[8:], uint32(entry[1]))
		out = append(out, raw[:]...)
	}
	return out
}

func zlibCompress(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zlib.NewWriter(&buf)
	if _, err := writer.Write(data); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

func openArchive(t *testing.T, data []byte, limits Limits) *Container {
	t.Helper()
	container, err := Open(source.NewMemorySource(1, data), limits)
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	return container
}

func openStream(t *testing.T, container *Container, uri string) *StreamSource {
	t.Helper()
	stream, err := container.OpenStream(uri)
	if err != nil {
		t.Fatalf("OpenStream(%q) error = %v", uri, err)
	}
	return stream
}

func readAll(t *testing.T, src source.ByteSource, offset, length uint64) []byte {
	t.Helper()
	buf := make([]byte, length)
	if _, err := src.ReadAt(offset, buf); err != nil {
		t.Fatalf("ReadAt(%d, %d) error = %v", offset, length, err)
	}
	return buf
}

// turtleHeader is the prefix block every fixture uses.
const turtleHeader = "@prefix aff4: <http://aff4.org/Schema#> .\n" +
	"@prefix hash: <http://aff4.org/Schema#> .\n"

// storedImageTurtle declares one uncompressed image stream.
func storedImageTurtle(uri string, size, chunkSize, chunksPerSegment uint64) string {
	return turtleHeader + "<" + uri + "> a aff4:Image ;\n" +
		"    aff4:category aff4:imageStream ;\n" +
		"    aff4:size " + u64String(size) + " ;\n" +
		"    aff4:chunkSize " + u64String(chunkSize) + " ;\n" +
		"    aff4:chunksPerSegment " + u64String(chunksPerSegment) + " ;\n" +
		"    aff4:compressionMethod aff4:stored .\n"
}

func u64String(value uint64) string {
	var buf [20]byte
	pos := len(buf)
	if value == 0 {
		return "0"
	}
	for value > 0 {
		pos--
		buf[pos] = byte('0' + value%10)
		value /= 10
	}
	return string(buf[pos:])
}
