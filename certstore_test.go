package forensic_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	forensic "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/data/containers/certstore"
	"github.com/laenix/ewfgo/internal/data/source"
)

func certificateStoreFixture() ([]byte, []byte) {
	der := []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02}
	record := func(recordType, version uint32, payload []byte) []byte {
		out := make([]byte, 12)
		binary.LittleEndian.PutUint32(out[0:], recordType)
		binary.LittleEndian.PutUint32(out[4:], version)
		binary.LittleEndian.PutUint32(out[8:], uint32(len(payload)))
		return append(out, payload...)
	}
	data := []byte{0, 0, 0, 0, 'C', 'E', 'R', 'T'}
	data = append(data, record(certstore.TypeCertificate, 1, der)...)
	data = append(data, record(0, 0, nil)...)
	return data, der
}

func TestOpenCertificateStoreSource(t *testing.T) {
	data, der := certificateStoreFixture()
	store, err := forensic.OpenCertificateStoreSource(context.Background(), source.NewMemorySource(1, data), forensic.Options{})
	if err != nil {
		t.Fatalf("OpenCertificateStoreSource: %v", err)
	}
	blob, err := store.OpenCertificate(context.Background(), 0)
	if err != nil {
		t.Fatalf("OpenCertificate: %v", err)
	}
	buf := make([]byte, len(der))
	if _, err := blob.ReadAt(0, buf); err != nil || !bytes.Equal(buf, der) {
		t.Fatalf("blob = % x, %v", buf, err)
	}
}

func TestOpenCertificateStore(t *testing.T) {
	data, der := certificateStoreFixture()
	path := filepath.Join(t.TempDir(), "store.sst")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := forensic.OpenCertificateStore(context.Background(), path, forensic.Options{})
	if err != nil {
		t.Fatalf("OpenCertificateStore: %v", err)
	}
	defer store.Close()

	info := store.Info()
	if info.Certificates != 1 || info.Records != 1 || !info.Terminated {
		t.Fatalf("info = %+v", info)
	}
	certs, err := store.Certificates(context.Background())
	if err != nil || len(certs) != 1 || certs[0].Len != uint64(len(der)) || certs[0].SHA256 == "" {
		t.Fatalf("certificates = %+v, %v", certs, err)
	}
	blob, err := store.OpenCertificate(context.Background(), 0)
	if err != nil {
		t.Fatalf("OpenCertificate: %v", err)
	}
	buf := make([]byte, len(der))
	if _, err := blob.ReadAt(0, buf); err != nil || !bytes.Equal(buf, der) {
		t.Fatalf("blob = % x, %v", buf, err)
	}
}
