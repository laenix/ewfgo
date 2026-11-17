package leveldb

import (
	"encoding/binary"
	"fmt"

	"github.com/laenix/ewfgo/internal/data/foundation"
)

// testKV is one block entry.
type testKV struct {
	key   []byte
	value []byte
}

// internalKey builds a user key followed by the little-endian sequence/type
// tag.
func internalKey(user string, sequence uint64, kind byte) []byte {
	out := []byte(user)
	tag := sequence<<8 | uint64(kind)
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], tag)
	return append(out, encoded[:]...)
}

// buildRawBlockShared builds a block with explicit shared-key lengths and
// restart entry indices.
func buildRawBlockShared(entries []testKV, shared []int, restarts []int) []byte {
	var out []byte
	offsets := make([]uint32, len(entries))
	for index, entry := range entries {
		offsets[index] = uint32(len(out))
		sharedLen := 0
		if index < len(shared) {
			sharedLen = shared[index]
		}
		if sharedLen > len(entry.key) {
			panic("fixture shares more key bytes than exist")
		}
		out = appendVarint(out, uint64(sharedLen))
		out = appendVarint(out, uint64(len(entry.key)-sharedLen))
		out = appendVarint(out, uint64(len(entry.value)))
		out = append(out, entry.key[sharedLen:]...)
		out = append(out, entry.value...)
	}
	var restartBytes []byte
	for _, index := range restarts {
		if index < 0 || index >= len(entries) {
			panic("fixture restart index out of range")
		}
		var encoded [4]byte
		binary.LittleEndian.PutUint32(encoded[:], offsets[index])
		restartBytes = append(restartBytes, encoded[:]...)
	}
	var count [4]byte
	binary.LittleEndian.PutUint32(count[:], uint32(len(restarts)))
	return append(append(out, restartBytes...), count[:]...)
}

// buildRawBlock builds an uncompressed block with no prefix sharing and one
// restart at entry zero.
func buildRawBlock(entries []testKV) []byte {
	restarts := []int(nil)
	if len(entries) > 0 {
		restarts = []int{0}
	}
	return buildRawBlockShared(entries, nil, restarts)
}

// snappyLiteral encodes raw bytes as a literal-only raw Snappy stream.
func snappyLiteral(raw []byte) []byte {
	out := appendVarint(nil, uint64(len(raw)))
	at := 0
	for at < len(raw) {
		chunk := len(raw) - at
		if chunk > 60 {
			chunk = 60
		}
		out = append(out, byte(chunk-1)<<2)
		out = append(out, raw[at:at+chunk]...)
		at += chunk
	}
	return out
}

// storedBlock appends a compression byte and the masked CRC-32C trailer.
func storedBlock(payload []byte, compression byte) []byte {
	stored := payload
	if compression == 1 {
		stored = snappyLiteral(payload)
	}
	crcInput := append(append([]byte(nil), stored...), compression)
	masked := maskCRC(foundation.CRC32C(crcInput))
	out := append([]byte(nil), stored...)
	out = append(out, compression)
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], masked)
	return append(out, encoded[:]...)
}

// tableFixture is a built table and the offsets of its data-block payloads.
type tableFixture struct {
	bytes        []byte
	dataOffsets  []int
	indexOffset  int
	metainOffset int
}

// buildTableFromStored assembles a table from already-stored data blocks.
func buildTableFromStored(blocks [][]byte) *tableFixture {
	fixture := &tableFixture{}
	var out []byte
	type handle struct{ offset, size int }
	handles := make([]handle, len(blocks))
	for index, block := range blocks {
		handles[index] = handle{offset: len(out), size: len(block) - BlockTrailerBytes}
		fixture.dataOffsets = append(fixture.dataOffsets, len(out))
		out = append(out, block...)
	}
	metaindex := storedBlock(buildRawBlock(nil), 0)
	fixture.metainOffset = len(out)
	metaHandle := handle{offset: len(out), size: len(metaindex) - BlockTrailerBytes}
	out = append(out, metaindex...)

	var indexEntries []testKV
	for number, handle := range handles {
		separator := []byte(fmt.Sprintf("sep%04d", number))
		value := appendVarint(nil, uint64(handle.offset))
		value = appendVarint(value, uint64(handle.size))
		indexEntries = append(indexEntries, testKV{key: separator, value: value})
	}
	index := storedBlock(buildRawBlock(indexEntries), 0)
	fixture.indexOffset = len(out)
	indexHandle := handle{offset: len(out), size: len(index) - BlockTrailerBytes}
	out = append(out, index...)

	var footer [LevelDBFooterBytes]byte
	var first []byte
	first = appendVarint(first, uint64(metaHandle.offset))
	first = appendVarint(first, uint64(metaHandle.size))
	copy(footer[:], first)
	var second []byte
	second = appendVarint(second, uint64(indexHandle.offset))
	second = appendVarint(second, uint64(indexHandle.size))
	copy(footer[len(first):], second)
	binary.LittleEndian.PutUint64(footer[LevelDBFooterBytes-8:], TableMagic)
	fixture.bytes = append(out, footer[:]...)
	return fixture
}

// tableBlockSpec is one data block for buildTable.
type tableBlockSpec struct {
	entries  []testKV
	compress bool
}

func buildTable(blocks []tableBlockSpec) *tableFixture {
	stored := make([][]byte, 0, len(blocks))
	for _, block := range blocks {
		compression := byte(0)
		if block.compress {
			compression = 1
		}
		stored = append(stored, storedBlock(buildRawBlock(block.entries), compression))
	}
	return buildTableFromStored(stored)
}

// logFragment builds one physical log record of the given type.
func logFragment(kind byte, payload []byte) []byte {
	crcInput := append([]byte{kind}, payload...)
	masked := maskCRC(foundation.CRC32C(crcInput))
	out := make([]byte, LogHeaderBytes+len(payload))
	binary.LittleEndian.PutUint32(out[0:4], masked)
	binary.LittleEndian.PutUint16(out[4:6], uint16(len(payload)))
	out[6] = kind
	copy(out[LogHeaderBytes:], payload)
	return out
}
