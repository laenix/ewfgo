package componentstore

import "testing"

func TestIdentify(t *testing.T) {
	for signature, want := range map[string]Kind{
		"DCN": KindDCN, "DCM": KindDCM, "DCS": KindDCS,
		"DCD": KindDCD, "DCH": KindDCH, "DCX": KindDCX,
	} {
		head := append([]byte(signature), 1, 'r', 'e', 's', 't')
		got, ok := Identify(head)
		if !ok || got != want {
			t.Fatalf("Identify(%q) = %v, %v; want %v", signature, got, ok, want)
		}
	}
	if _, ok := Identify([]byte("DCS\x02rest")); ok {
		t.Fatal("Identify claimed a version 2 payload")
	}
	if _, ok := Identify([]byte("PReg\x01")); ok {
		t.Fatal("Identify claimed a non-component payload")
	}
	if _, ok := Identify([]byte("DCS")); ok {
		t.Fatal("Identify claimed a short head")
	}
}

func TestLabels(t *testing.T) {
	if KindDCS.Packing() != "packed LZMS" || KindDCS.Signature() != "DCS" {
		t.Fatalf("DCS labels = %q, %q", KindDCS.Packing(), KindDCS.Signature())
	}
	if !KindDCD.NeedsSource() || !KindDCM.NeedsSource() || KindDCS.NeedsSource() {
		t.Fatal("NeedsSource classification is wrong")
	}
}
