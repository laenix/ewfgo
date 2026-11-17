package foundation

import "testing"

func TestCRC32KnownVectors(t *testing.T) {
	if got := CRC32(nil); got != 0 {
		t.Fatalf("CRC32(empty) = %#x, want 0", got)
	}
	if got := CRC32([]byte("123456789")); got != 0xCBF43926 {
		t.Fatalf("CRC32(123456789) = %#x, want 0xCBF43926", got)
	}
	if got := CRC32Seeded(0, nil); got != 0 {
		t.Fatalf("CRC32Seeded(0, empty) = %#x", got)
	}
	if got := CRC32Seeded(0xFFFFFFFF, []byte("123456789")) ^ 0xFFFFFFFF; got != 0xCBF43926 {
		t.Fatalf("seeded CRC32 does not match the plain form: %#x", got)
	}
}

func TestCRC32CKnownVectors(t *testing.T) {
	if got := CRC32C(nil); got != 0 {
		t.Fatalf("CRC32C(empty) = %#x, want 0", got)
	}
	if got := CRC32C([]byte("123456789")); got != 0xE3069283 {
		t.Fatalf("CRC32C(123456789) = %#x, want 0xE3069283", got)
	}
	if got := CRC32CSeeded(0xFFFFFFFF, []byte("123456789")); got != 0x1CF96D7C {
		t.Fatalf("CRC32CSeeded(0xFFFFFFFF, 123456789) = %#x, want 0x1CF96D7C", got)
	}
	if got := CRC32CSeeded(0, nil); got != 0 {
		t.Fatalf("CRC32CSeeded(0, empty) = %#x", got)
	}
}
