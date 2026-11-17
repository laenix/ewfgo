package ntfs

import "testing"

func TestParseRunsForms(t *testing.T) {
	h := &NTFSHandler{}
	cases := []struct {
		name string
		data []byte
		want []ntfsRun
	}{
		{"terminated", []byte{0x11, 0x01, 0x02, 0x00}, []ntfsRun{{vcnStart: 0, lcnStart: 2, length: 1}}},
		{"unterminated at attribute end", []byte{0x11, 0x01, 0x02}, []ntfsRun{{vcnStart: 0, lcnStart: 2, length: 1}}},
		{"sparse offset zero bytes", []byte{0x01, 0x05, 0x00}, []ntfsRun{{vcnStart: 0, lcnStart: -1, length: 5}}},
		{"lcn zero is sparse and keeps previous", []byte{0x11, 0x01, 0x00, 0x11, 0x02, 0x05, 0x00}, []ntfsRun{
			{vcnStart: 0, lcnStart: -1, length: 1},
			{vcnStart: 1, lcnStart: 5, length: 2},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := h.parseRuns(tc.data)
			if err != nil {
				t.Fatalf("parseRuns: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("runs = %+v, want %+v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("run %d = %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestParseRunsRefusals(t *testing.T) {
	h := &NTFSHandler{}
	for _, data := range [][]byte{
		{0x11, 0x01},          // ends inside the run
		{0x10, 0x00},          // zero length-field width
		{0x11, 0x00, 0x00},    // zero-cluster run
		{0x11, 0x01, 0xFF, 0}, // LCN delta lands below zero
		{0x99, 0, 0, 0, 0, 0}, // field widths too large
	} {
		if _, err := h.parseRuns(data); err == nil {
			t.Fatalf("parseRuns(%x) accepted a malformed runlist", data)
		}
	}
}
