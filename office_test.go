package forensic_test

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	forensic "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/data/source"
)

func ownerFileFixture() []byte {
	data := make([]byte, 0xa2)
	data[0] = 11
	copy(data[1:], "Alice UTF16")
	name := utf16.Encode([]rune("Alice UTF16"))
	binary.LittleEndian.PutUint16(data[0x36:], uint16(len(name)))
	for i, unit := range name {
		binary.LittleEndian.PutUint16(data[0x38+i*2:], unit)
	}
	return data
}

func TestOpenOfficeOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "~$report.docx")
	if err := os.WriteFile(path, ownerFileFixture(), 0o600); err != nil {
		t.Fatal(err)
	}
	owner, err := forensic.OpenOfficeOwner(context.Background(), path, forensic.Options{})
	if err != nil {
		t.Fatalf("OpenOfficeOwner: %v", err)
	}
	defer owner.Close()
	name, ok := owner.Owner()
	if !ok || name != "Alice UTF16" {
		t.Fatalf("Owner = %q, %v", name, ok)
	}
	if owner.Layout() == "" {
		t.Fatal("Layout is empty")
	}
	if !owner.SlotsAgree() {
		t.Fatalf("slots disagree for %q", name)
	}
	if !forensic.IsOwnerFileName("~$report.docx") || forensic.IsOwnerFileName("report.docx") {
		t.Fatal("owner-file name detection is wrong")
	}

	fromSource, err := forensic.OpenOfficeOwnerSource(context.Background(), source.NewMemorySource(1, ownerFileFixture()), forensic.Options{})
	if err != nil {
		t.Fatalf("OpenOfficeOwnerSource: %v", err)
	}
	if got, ok := fromSource.Owner(); !ok || got != "Alice UTF16" {
		t.Fatalf("source owner = %q, %v", got, ok)
	}
}
