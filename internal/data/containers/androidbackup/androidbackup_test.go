package androidbackup

import (
	stdtar "archive/tar"
	"bytes"
	"compress/zlib"
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/containers/archive"
	"github.com/laenix/ewfgo/internal/data/source"
)

func buildTar(t *testing.T, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := stdtar.NewWriter(&buf)
	header := &stdtar.Header{
		Name:     "apps/com.example/f/data.txt",
		Mode:     0o600,
		Size:     int64(len(content)),
		Typeflag: stdtar.TypeReg,
	}
	if err := writer.WriteHeader(header); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func buildBackup(t *testing.T, prefix string, compressed bool, tarBytes []byte) []byte {
	t.Helper()
	flag := "0"
	payload := tarBytes
	if compressed {
		flag = "1"
		var buf bytes.Buffer
		zw := zlib.NewWriter(&buf)
		if _, err := zw.Write(tarBytes); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		payload = buf.Bytes()
	}
	header := prefix + "ANDROID BACKUP\n5\n" + flag + "\nnone\n"
	return append([]byte(header), payload...)
}

func openBackup(t *testing.T, file []byte) *Backup {
	t.Helper()
	backup, err := Open(2, source.NewMemorySourceWithImage(1, 9, file), archive.DefaultLimits())
	if err != nil {
		t.Fatalf("Open error = %v", err)
	}
	return backup
}

func assertEntry(t *testing.T, backup *Backup, want string) {
	t.Helper()
	entries, err := backup.Entries()
	if err != nil {
		t.Fatalf("Entries error = %v", err)
	}
	found := false
	for _, entry := range entries {
		if entry.Path == "apps/com.example/f/data.txt" {
			found = true
		}
	}
	if !found {
		t.Fatalf("entry not listed: %+v", entries)
	}
	stream, err := backup.OpenEntry("apps/com.example/f/data.txt", 100)
	if err != nil {
		t.Fatalf("OpenEntry error = %v", err)
	}
	buf := make([]byte, stream.Len())
	if _, err := stream.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != want {
		t.Fatalf("entry = %q, want %q", buf, want)
	}
}

func TestAndroidBackupUncompressed(t *testing.T) {
	file := buildBackup(t, "", false, buildTar(t, []byte("hello backup")))
	backup := openBackup(t, file)
	if backup.Header.Compressed || backup.Header.Encryption != "none" {
		t.Fatalf("header = %+v", backup.Header)
	}
	assertEntry(t, backup, "hello backup")
}

func TestAndroidBackupCompressed(t *testing.T) {
	file := buildBackup(t, "", true, buildTar(t, []byte("compressed backup")))
	backup := openBackup(t, file)
	if !backup.Header.Compressed {
		t.Fatalf("header = %+v", backup.Header)
	}
	assertEntry(t, backup, "compressed backup")
}

func TestAndroidBackupMIUIPrefix(t *testing.T) {
	prefix := "MIUI BACKUP\n1\ncom.example\n0\n"
	file := buildBackup(t, prefix, false, buildTar(t, []byte("miui backup")))
	header, err := ParseHeader(source.NewMemorySource(1, file))
	if err != nil {
		t.Fatalf("ParseHeader error = %v", err)
	}
	if header.MIUI == nil || header.MIUI.Name != "com.example" || header.MIUI.Version != "1" {
		t.Fatalf("miui = %+v", header.MIUI)
	}
	assertEntry(t, openBackup(t, file), "miui backup")
}

func TestAndroidBackupEncryptedHeader(t *testing.T) {
	salt := bytes.Repeat([]byte{0x11}, 64)
	iv := bytes.Repeat([]byte{0x22}, 16)
	blob := bytes.Repeat([]byte{0x33}, 32)
	file := []byte("ANDROID BACKUP\n5\n0\nAES-256\n" +
		hexEncode(salt) + "\n" + hexEncode(salt) + "\n10000\n" +
		hexEncode(iv) + "\n" + hexEncode(blob) + "\n")
	header, err := ParseHeader(source.NewMemorySource(1, file))
	if err != nil {
		t.Fatalf("ParseHeader error = %v", err)
	}
	if !header.Encrypted() || header.EncryptionHeader.Rounds != 10000 ||
		len(header.EncryptionHeader.UserSalt) != 64 || len(header.EncryptionHeader.MasterKeyBlob) != 32 {
		t.Fatalf("encryption header = %+v", header.EncryptionHeader)
	}
	if _, err := Open(2, source.NewMemorySource(1, file), archive.DefaultLimits()); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Open(encrypted) error = %v, want ErrUnsupported", err)
	}
}

func TestAndroidBackupRefusals(t *testing.T) {
	version6 := []byte("ANDROID BACKUP\n6\n0\nnone\n")
	if _, err := ParseHeader(source.NewMemorySource(1, version6)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("ParseHeader(version 6) error = %v", err)
	}
	badFlag := []byte("ANDROID BACKUP\n5\n2\nnone\n")
	if _, err := ParseHeader(source.NewMemorySource(1, badFlag)); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("ParseHeader(flag 2) error = %v", err)
	}
	badMagic := []byte("NOT A BACKUP\n")
	if _, err := ParseHeader(source.NewMemorySource(1, badMagic)); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("ParseHeader(bad magic) error = %v", err)
	}
}

func hexEncode(data []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(data)*2)
	for i, b := range data {
		out[i*2] = digits[b>>4]
		out[i*2+1] = digits[b&0xF]
	}
	return string(out)
}
