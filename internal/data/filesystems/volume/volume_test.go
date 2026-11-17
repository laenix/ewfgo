package volume

import (
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
	"github.com/laenix/ewfgo/internal/filesystem"
)

func putLE16(b []byte, at int, v uint16) { b[at], b[at+1] = byte(v), byte(v>>8) }
func putLE32(b []byte, at int, v uint32) {
	b[at], b[at+1], b[at+2], b[at+3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}

func buildFAT32Image() []byte {
	const (
		bps       = 512
		reserved  = 4
		numFATs   = 2
		spf       = 200
		total     = 1024
		dataStart = reserved + numFATs*spf
	)
	img := make([]byte, total*bps)
	putLE16(img, 0x0B, bps)
	img[0x0D] = 1
	putLE16(img, 0x0E, reserved)
	img[0x10] = numFATs
	img[0x15] = 0xF8
	putLE16(img, 0x18, 0)
	putLE16(img, 0x1A, 0)
	putLE32(img, 0x20, total)
	putLE32(img, 0x24, spf)
	putLE32(img, 0x2C, 2)
	copy(img[0x52:0x5A], "FAT32   ")
	img[0x1FE], img[0x1FF] = 0x55, 0xAA

	fat := reserved * bps
	putLE32(img, fat+0, 0x0FFFFFF8)
	putLE32(img, fat+4, 0x0FFFFFFF)
	putLE32(img, fat+8, 0x0FFFFFFF)  // root directory
	putLE32(img, fat+12, 0x0FFFFFFF) // HELLO.TXT
	secondFAT := (reserved + spf) * bps
	copy(img[secondFAT:secondFAT+16], img[fat:fat+16])

	root := dataStart * bps
	copy(img[root:root+11], "HELLO   TXT")
	img[root+11] = 0x20
	putLE16(img, root+26, 3)
	putLE32(img, root+28, 5)

	copy(img[(dataStart+1)*bps:], "hello")
	return img
}

func TestOpenFAT32Volume(t *testing.T) {
	vol, err := Open(source.NewMemorySourceWithImage(1, 7, buildFAT32Image()), 512)
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	defer vol.Close()
	if vol.Type != filesystem.FS_FAT32 {
		t.Fatalf("Type = %v, want FAT32", vol.Type)
	}
	entries, err := vol.FS.ListDirectory("/")
	if err != nil {
		t.Fatalf("ListDirectory error = %v", err)
	}
	found := false
	for _, entry := range entries {
		if entry.Name == "HELLO.TXT" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ListDirectory did not return HELLO.TXT: %+v", entries)
	}
	data, err := vol.FS.GetFile("/HELLO.TXT")
	if err != nil {
		t.Fatalf("GetFile error = %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("GetFile = %q, want %q", data, "hello")
	}
}

func TestDetectVolumes(t *testing.T) {
	cases := []struct {
		name string
		head []byte
		want filesystem.FileSystemType
	}{
		{"ntfs", func() []byte { b := make([]byte, 512); copy(b[3:], "NTFS    "); return b }(), filesystem.FS_NTFS},
		{"exfat", func() []byte { b := make([]byte, 512); copy(b[3:], "EXFAT   "); return b }(), filesystem.FS_EXFAT},
		{"apfs", func() []byte { b := make([]byte, 512); copy(b[32:], "NXSB"); return b }(), filesystem.FS_APFS},
		{"xfs", func() []byte {
			b := make([]byte, 512)
			copy(b, "XFSB")
			putBE32 := func(at int, v uint32) {
				b[at], b[at+1], b[at+2], b[at+3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
			}
			putBE32(4, 4096)
			putBE32(32, 1)
			putBE32(36, 1024)
			return b
		}(), filesystem.FS_XFS},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Detect(source.NewMemorySource(1, tc.head))
			if err != nil {
				t.Fatalf("Detect error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("Detect = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOpenRejectsUnknownVolume(t *testing.T) {
	_, err := Open(source.NewMemorySource(1, make([]byte, 2048)), 512)
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Open error = %v, want ErrUnsupported", err)
	}
}

func TestOpenRejectsBadSectorSize(t *testing.T) {
	_, err := Open(source.NewMemorySource(1, make([]byte, 2048)), 500)
	if !errors.Is(err, source.ErrInvalidArgument) {
		t.Fatalf("Open error = %v, want ErrInvalidArgument", err)
	}
}
