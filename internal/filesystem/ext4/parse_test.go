package ext4

import (
	"encoding/binary"
	"testing"
)

func TestExt4ParseDirectoryMalformedNameLen(t *testing.T) {
	h := &Ext4Handler{}
	data := make([]byte, 16)
	binary.LittleEndian.PutUint32(data[0:4], 2)
	binary.LittleEndian.PutUint16(data[4:6], 12)
	data[6] = 250
	data[7] = 2
	entries, err := h.parseDirectory(data, "")
	if err == nil {
		t.Fatalf("expected error for overrunning name_len, got %d entries: %+v", len(entries), entries)
	}
}

func TestExt4ParseDirectoryBadRecLen(t *testing.T) {
	h := &Ext4Handler{}
	data := make([]byte, 32)
	binary.LittleEndian.PutUint32(data[0:4], 2)
	binary.LittleEndian.PutUint16(data[4:6], 4)
	data[6] = 2
	data[7] = 2
	if _, err := h.parseDirectory(data, ""); err == nil {
		t.Fatal("expected error for rec_len < 8")
	}
}

func TestExt4ParseDirectoryNameExceedsRecLen(t *testing.T) {
	h := &Ext4Handler{}
	data := make([]byte, 64)
	binary.LittleEndian.PutUint32(data[0:4], 2)
	binary.LittleEndian.PutUint16(data[4:6], 12)
	data[6] = 20
	data[7] = 2
	if _, err := h.parseDirectory(data, ""); err == nil {
		t.Fatal("expected error for name_len exceeding rec_len")
	}
}

func TestExt4ParseDirectoryValid(t *testing.T) {
	h := &Ext4Handler{}
	data := make([]byte, 64)
	binary.LittleEndian.PutUint32(data[0:4], 2)
	binary.LittleEndian.PutUint16(data[4:6], 16)
	data[6] = 2
	data[7] = 2
	copy(data[8:10], "ab")
	entries, err := h.parseDirectory(data, "")
	if err != nil {
		t.Fatalf("parseDirectory(valid): %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "ab" || !entries[0].IsDir {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}

func TestExt4ParseDirectoryPathPrefix(t *testing.T) {
	h := &Ext4Handler{}
	data := make([]byte, 64)
	binary.LittleEndian.PutUint32(data[0:4], 2)
	binary.LittleEndian.PutUint16(data[4:6], 16)
	data[6] = 3
	data[7] = 2
	copy(data[8:11], "bin")
	entries, err := h.parseDirectory(data, "/")
	if err != nil {
		t.Fatalf("parseDirectory(root): %v", err)
	}
	if entries[0].Path != "/bin" {
		t.Fatalf("root entry Path = %q, want %q", entries[0].Path, "/bin")
	}
	entries, err = h.parseDirectory(data, "/bin")
	if err != nil {
		t.Fatalf("parseDirectory(/bin): %v", err)
	}
	if entries[0].Path != "/bin/bin" {
		t.Fatalf("subdir entry Path = %q, want %q", entries[0].Path, "/bin/bin")
	}
}
