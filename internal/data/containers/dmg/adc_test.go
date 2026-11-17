package dmg

import (
	"bytes"
	"testing"
)

func TestADCLiterals(t *testing.T) {
	data := bytes.Repeat([]byte("adc literal data "), 40)
	decoded, err := adcDecompress(adcLiteral(data), len(data))
	if err != nil {
		t.Fatalf("adcDecompress error = %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Fatal("ADC literals differ")
	}
	if empty, err := adcDecompress(nil, 0); err != nil || len(empty) != 0 {
		t.Fatalf("empty = %v, %v", empty, err)
	}
}

func TestADCMatch(t *testing.T) {
	// "abc" literal, then a six-byte match three bytes back.
	encoded := []byte{2, 'a', 'b', 'c', 0x83, 0x00, 0x02}
	decoded, err := adcDecompress(encoded, 9)
	if err != nil {
		t.Fatalf("adcDecompress error = %v", err)
	}
	if string(decoded) != "abcabcabc" {
		t.Fatalf("decoded = %q", decoded)
	}

	// An overlapping run repeats one byte.
	encoded = []byte{0, 'a', 0x85, 0x00, 0x00}
	decoded, err = adcDecompress(encoded, 9)
	if err != nil {
		t.Fatalf("overlap error = %v", err)
	}
	if string(decoded) != "aaaaaaaaa" {
		t.Fatalf("overlap = %q", decoded)
	}
}

func TestADCErrors(t *testing.T) {
	cases := []struct {
		name  string
		bytes []byte
		limit int
	}{
		{"literal-past-input", []byte{5, 'a', 'b'}, 10},
		{"missing-distance", []byte{0x80}, 10},
		{"forward-distance", []byte{0x80, 0x00, 0x04}, 10},
		{"literal-limit", []byte{4, 'a', 'b', 'c', 'd', 'e'}, 3},
		{"match-limit", []byte{0, 'a', 0x83, 0x00, 0x00}, 4},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := adcDecompress(test.bytes, test.limit); err == nil {
				t.Fatal("decode succeeded, want an error")
			}
		})
	}
}
