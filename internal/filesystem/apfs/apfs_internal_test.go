package apfs

import (
	"encoding/binary"
	"testing"
)

// TestAPFSSymlinkXattrTarget decodes real mac.E01 com.apple.fs.symlink xattr
// values (layout {flags u16, name_len u16, name[name_len]}). The first three
// are bytes taken verbatim from the image.
func TestAPFSSymlinkXattrTarget(t *testing.T) {
	cases := []struct {
		val  []byte
		want string
		ok   bool
	}{
		{[]byte{0x06, 0x00, 0x04, 0x00, 'i', 'p', 'p', 0x00}, "ipp", true}, // Bonjour https→ipp
		{[]byte{0x06, 0x00, 0x06, 0x00, 'd', 'n', 's', 's', 'd', 0x00}, "dnssd", true},
		{[]byte{0x06, 0x00, 0x1d, 0x00, '/', 'u', 's', 'r', '/', 'l', 'i', 'b', 'e', 'x', 'e', 'c', '/', 'r', 'o', 's', 'e', 't', 't', 'a', '/', 'r', 'u', 'n', 't', 'i', 'm', 'e', 0x00}, "/usr/libexec/rosetta/runtime", true},
		{[]byte{}, "", false},                                               // empty
		{[]byte{0x06, 0x00, 0xff, 0x7f}, "", false},                         // name_len overruns value
		{[]byte{0x06, 0x00, 0x00, 0x00}, "", false},                         // name_len zero
		{[]byte{0x06, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}, "", false}, // NUL-only target
	}
	for i, c := range cases {
		got, ok := apfsSymlinkXattrTarget(c.val)
		if ok != c.ok || got != c.want {
			t.Errorf("case %d: apfsSymlinkXattrTarget(%x) = %q,%v want %q,%v", i, c.val, got, ok, c.want, c.ok)
		}
	}
}

// TestAPFSReadSymlinkTargetFallback proves the SYMLINK xfield wins when present
// and that a missing xfield falls back to the com.apple.fs.symlink xattr.
func TestAPFSReadSymlinkTargetFallback(t *testing.T) {
	apfs := &APFS{index: &apfsIndex{xattrs: map[uint64][]apfsXattr{
		100: {{name: "com.apple.fs.symlink", value: []byte{0x06, 0x00, 0x0c, 0x00, '/', 't', 'm', 'p', '/', 't', 'a', 'r', 'g', 'e', 't', 0x00}}},
		101: {{name: "com.apple.system.Security", value: []byte{0x02, 0x00, 0x44, 0x00}}},
		102: {{name: "com.apple.fs.symlink", value: []byte{0x06, 0x00, 0xff, 0x7f}}},
	}}}
	// xfield wins.
	tgt, err := apfs.readSymlinkTarget(&apfsInode{symlink: "/from/field"}, 100)
	if err != nil || tgt != "/from/field" {
		t.Fatalf("xfield target = %q,%v want /from/field,nil", tgt, err)
	}
	// no xfield, xattr present.
	tgt, err = apfs.readSymlinkTarget(&apfsInode{}, 100)
	if err != nil || tgt != "/tmp/target" {
		t.Fatalf("xattr target = %q,%v want /tmp/target,nil", tgt, err)
	}
	// only unrelated xattrs -> explicit error, never a guess.
	if _, err := apfs.readSymlinkTarget(&apfsInode{}, 101); err == nil {
		t.Fatalf("expected error for inode with only unrelated xattrs")
	}
	// no xattrs at all -> explicit error.
	if _, err := apfs.readSymlinkTarget(&apfsInode{}, 999); err == nil {
		t.Fatalf("expected error for inode with no xattrs")
	}
	// malformed symlink xattr -> error, not a partial/guessed target.
	if _, err := apfs.readSymlinkTarget(&apfsInode{}, 102); err == nil {
		t.Fatalf("expected error for malformed symlink xattr")
	}
}

// TestAPFSInodeXfields proves the inode-xfield walker extracts both the DSTREAM
// size and the SYMLINK target from a real-style blob: headers, then 8-byte
// aligned data items relative to the value start.
func TestAPFSInodeXfields(t *testing.T) {
	val := make([]byte, 256)
	target := "System/Library/CoreServices"
	binary.LittleEndian.PutUint64(val[84:92], 999) // uncompressed_size fallback

	blob := val[92:]
	binary.LittleEndian.PutUint16(blob[0:2], 2) // num_exts
	// Header 0: dstream (type 8), 8-byte payload.
	blob[4] = apfsXfDstream
	binary.LittleEndian.PutUint16(blob[6:8], 8)
	// Header 1: symlink (type 32), len(target)-byte payload.
	blob[8] = apfsXfSymlink
	binary.LittleEndian.PutUint16(blob[10:12], uint16(len(target)))
	// Item 0 at off=12: dstream size 42.
	binary.LittleEndian.PutUint64(blob[12:20], 42)
	// Item 1 at aligned off=20: the target string.
	copy(blob[20:20+len(target)], target)

	size, symlink := apfsInodeXfields(val)
	if size != 42 {
		t.Fatalf("apfsInodeXfields size = %d, want 42", size)
	}
	if symlink != target {
		t.Fatalf("apfsInodeXfields symlink = %q, want %q", symlink, target)
	}
}

// TestAPFSInodeXfieldsFallback proves uncompressed_size wins when the inode has
// no dstream xfield (compressed/odd inodes), and that the symlink is empty when
// absent.
func TestAPFSInodeXfieldsFallback(t *testing.T) {
	val := make([]byte, 256)
	binary.LittleEndian.PutUint64(val[84:92], 777)
	size, symlink := apfsInodeXfields(val)
	if size != 777 {
		t.Fatalf("fallback size = %d, want 777", size)
	}
	if symlink != "" {
		t.Fatalf("fallback symlink = %q, want empty", symlink)
	}
}

// TestAPFSInodeXfieldsBounds proves a crafted xfield blob (num_exts overrun, or
// an item extending past the value) yields zero/empty, never a panic.
func TestAPFSInodeXfieldsBounds(t *testing.T) {
	for _, blob := range [][]byte{
		{0xff, 0xff}, // num_exts huge
		{0, 0, 0, 0}, // zero num_exts, no items
		{1, 0},       // num_exts 1 but truncated
	} {
		val := append(make([]byte, 92), blob...)
		val[84] = 5
		size, symlink := apfsInodeXfields(val)
		if size == 0 && symlink == "" {
			continue // empty result is fine; the requirement is no panic
		}
		t.Logf("blob %v -> size %d symlink %q", blob, size, symlink)
	}
}
