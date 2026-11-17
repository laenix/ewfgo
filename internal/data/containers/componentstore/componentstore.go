// Package componentstore identifies Windows component-store packed payloads
// (`DC*` version 1). It decodes none of the coders; the marker is recognized
// so a name-routed parser does not mistake a packed stand-in for the file its
// name promises.
package componentstore

// Kind is a component-store packing method.
type Kind uint8

const (
	// KindDCN is packed IPD PA30.
	KindDCN Kind = iota
	// KindDCM is packed IPD PA30 with a source manifest.
	KindDCM
	// KindDCS is packed LZMS.
	KindDCS
	// KindDCD is an IPD PA30 delta.
	KindDCD
	// KindDCH is not packed; header only.
	KindDCH
	// KindDCX is an unknown packing (Windows 10+).
	KindDCX
)

// Signature returns the three-letter signature.
func (k Kind) Signature() string {
	switch k {
	case KindDCN:
		return "DCN"
	case KindDCM:
		return "DCM"
	case KindDCS:
		return "DCS"
	case KindDCD:
		return "DCD"
	case KindDCH:
		return "DCH"
	default:
		return "DCX"
	}
}

// Packing returns the packing description.
func (k Kind) Packing() string {
	switch k {
	case KindDCN:
		return "packed IPD PA30"
	case KindDCM:
		return "packed IPD PA30 with a source manifest"
	case KindDCS:
		return "packed LZMS"
	case KindDCD:
		return "IPD PA30 delta"
	case KindDCH:
		return "not packed; header only"
	default:
		return "unknown packing"
	}
}

// NeedsSource reports whether the payload is a difference that needs a source.
func (k Kind) NeedsSource() bool { return k == KindDCD || k == KindDCM }

// Identify recognizes a version-1 component-store payload from its first bytes.
func Identify(head []byte) (Kind, bool) {
	if len(head) < 4 || head[3] != 1 {
		return 0, false
	}
	switch string(head[0:3]) {
	case "DCN":
		return KindDCN, true
	case "DCM":
		return KindDCM, true
	case "DCS":
		return KindDCS, true
	case "DCD":
		return KindDCD, true
	case "DCH":
		return KindDCH, true
	case "DCX":
		return KindDCX, true
	default:
		return 0, false
	}
}
