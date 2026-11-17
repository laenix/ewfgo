package forensic_test

import (
	"context"
	"encoding/binary"
	"testing"

	forensic "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/data/source"
)

func bmpFixture() []byte {
	const size = 58
	data := make([]byte, size)
	data[0], data[1] = 'B', 'M'
	binary.LittleEndian.PutUint32(data[2:], size)
	binary.LittleEndian.PutUint32(data[10:], 54)
	dib := data[14:]
	binary.LittleEndian.PutUint32(dib[0:], 40)
	binary.LittleEndian.PutUint32(dib[4:], 1)  // width
	binary.LittleEndian.PutUint32(dib[8:], 1)  // height
	binary.LittleEndian.PutUint16(dib[12:], 1) // planes
	binary.LittleEndian.PutUint16(dib[14:], 24)
	binary.LittleEndian.PutUint32(dib[16:], 0) // BI_RGB
	binary.LittleEndian.PutUint32(dib[20:], 4) // pixel bytes
	return data
}

func TestCarveFindsBMP(t *testing.T) {
	payload := append([]byte("prefix---"), bmpFixture()...)
	payload = append(payload, []byte("---suffix")...)
	img, err := forensic.OpenSource(context.Background(), source.NewMemorySource(1, payload), forensic.Options{})
	if err != nil {
		t.Fatal(err)
	}
	report, err := img.Carve(context.Background(), 0, uint64(len(payload)), forensic.DefaultCarveOptions())
	if err != nil {
		t.Fatalf("Carve: %v", err)
	}
	if len(report.Objects) != 1 {
		t.Fatalf("objects = %+v", report.Objects)
	}
	object := report.Objects[0]
	if object.Offset != 9 || object.Len != 58 || !object.Terminated {
		t.Fatalf("object = %+v", object)
	}
	if object.Format.ID() != "bmp" {
		t.Fatalf("format = %s", object.Format.ID())
	}
	if len(report.TopLevel()) != 1 {
		t.Fatalf("top-level = %d", len(report.TopLevel()))
	}
}

func TestCarveEmptyRange(t *testing.T) {
	img, err := forensic.OpenSource(context.Background(), source.NewMemorySource(1, make([]byte, 1024)), forensic.Options{})
	if err != nil {
		t.Fatal(err)
	}
	report, err := img.Carve(context.Background(), 0, 1024, forensic.DefaultCarveOptions())
	if err != nil || len(report.Objects) != 0 {
		t.Fatalf("Carve = %+v, %v", report, err)
	}
}
