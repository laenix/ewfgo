package zfs

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

// labelVectorB64 is the gzip-compressed, base64-encoded vdev_phys buffer of
// label 1 (absolute label offset 256 KiB) from the Rust reference fixture
// corpus' zfs-basic.img. The vector is embedded so this test never reads the
// Rust tree at run time.
//
// It is a reference-derived vector for the label checksum: the stored digest
// is SHA-256 over the whole 112 KiB with the checksum field replaced by the
// *vdev_phys* absolute offset, 256 KiB + 16 KiB = 278528, stored as four
// byte-swapped 64-bit words. Sealing with the label's own start offset (256
// KiB) does not match.
const labelVectorB64 = "H4sIAAAAAAAC/+3QT0sVURQA8NFe+R65SHLlSqIgCBEU2qi7ti1cRDtlaEbfoL0Z3kwvfat0JRR+Bl23kj5EraOVn8Jd0B9o9F1kNIKIlr8fnLmXuefee86NogtjdcyGaPXil2k9dsL/VhX3turxYYhOkefb65uvsmS0t32eN/No+elaXuzV8/shJgZpv8zy3mXOKP3uQeOuG9XO5rX1qD527Msoos4gSQfrVT9Nw+ZG3pWaq93iSs39PK8a6+Oh2OY9UXN/aOdPvdyKy262Uf12xmQj52ZcZsM0upbz5uL7I0T7RTfbTvrp+aNMh5y/6ifJyq1/7Wfq3uKTZxuvDxq1toq46jbOb8/X7zxfJvF/7BkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC5NDSdPhqd3xs9+vr89t/z12+FC/unByuN3H49XF5c+73z4PnP09vn+UfELArJEpgDAAQA="

func labelVector(t *testing.T) []byte {
	t.Helper()
	compressed, err := base64.StdEncoding.DecodeString(labelVectorB64)
	if err != nil {
		t.Fatalf("decode label vector: %v", err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("open label vector: %v", err)
	}
	defer reader.Close()
	var phys bytes.Buffer
	if _, err := phys.ReadFrom(reader); err != nil {
		t.Fatalf("read label vector: %v", err)
	}
	if phys.Len() != LabelPhysSize {
		t.Fatalf("label vector is %d bytes, want %d", phys.Len(), LabelPhysSize)
	}
	return phys.Bytes()
}

// A label is sealed over its vdev_phys absolute offset, not the offset of the
// 256 KiB label slot. The fixture corpus caught a reader that used the slot
// offset and refused every label of a valid pool.
func TestLabelVectorSealsTheVdevPhysOffset(t *testing.T) {
	phys := labelVector(t)
	eck := LabelPhysSize - LabelECKSize
	if got := leUint64(phys[eck : eck+8]); got != ZECMagic {
		t.Fatalf("embedded checksum magic = 0x%016x", got)
	}

	verified, err := verifyLabel(phys, LabelSize+LabelPhysOffset)
	if err != nil {
		t.Fatalf("verifyLabel at vdev_phys offset: %v", err)
	}
	if verified != "sha256" {
		t.Fatalf("label verified by %q, want sha256", verified)
	}

	// The regression: the label slot's start is not the verifier.
	if _, err := verifyLabel(phys, LabelSize); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("verifyLabel at label slot offset = %v, want ErrCorrupt", err)
	}

	// Verification still rejects a damaged body or a damaged digest.
	damaged := append([]byte(nil), phys...)
	damaged[0] ^= 0xff
	if _, err := verifyLabel(damaged, LabelSize+LabelPhysOffset); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("damaged body = %v, want ErrCorrupt", err)
	}
	damaged = append([]byte(nil), phys...)
	damaged[eck+8] ^= 0xff
	if _, err := verifyLabel(damaged, LabelSize+LabelPhysOffset); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("damaged digest = %v, want ErrCorrupt", err)
	}
}

// The same reference label placed in an image, at the label offset it was
// sealed for, is found and reported; damaging its digest leaves no label.
func TestReadLabelsAcceptsReferenceVector(t *testing.T) {
	vector := labelVector(t)
	data := make([]byte, 4*LabelSize)
	copy(data[LabelSize+LabelPhysOffset:], vector)

	labels, problems, err := readLabels(source.NewMemorySource(1, data))
	if err != nil {
		t.Fatalf("readLabels: %v (problems %v)", err, problems)
	}
	if len(labels) != 1 {
		t.Fatalf("readLabels found %d labels, want 1 (problems %v)", len(labels), problems)
	}
	label := labels[0]
	if label.Index != 1 || label.Offset != LabelSize {
		t.Fatalf("label at index %d offset %d, want index 1 offset %d", label.Index, label.Offset, LabelSize)
	}
	if label.Verified != "sha256" {
		t.Fatalf("label verified by %q, want sha256", label.Verified)
	}
	if label.Pool.Name != "tank" {
		t.Fatalf("pool name = %q, want tank", label.Pool.Name)
	}

	// A genuinely corrupt label is still rejected: with the only valid label
	// damaged there is no readable label at all.
	data[LabelSize+LabelPhysOffset+LabelPhysSize-LabelECKSize+8] ^= 0xff
	if _, _, err := readLabels(source.NewMemorySource(1, data)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("readLabels on a corrupt vector = %v, want ErrCorrupt", err)
	}
}
