package source

import (
	"errors"
	"reflect"
	"testing"
)

func TestSourceGraphAddNodeValidatesSource(t *testing.T) {
	g := NewSourceGraph()
	src := NewMemorySourceWithImage(1, 7, make([]byte, 4))

	if err := g.AddNode(NewSourceNode(2, SourceImage, 4, nil, ""), src); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("AddNode(source id mismatch) error = %v, want ErrInvalidNode", err)
	}
	if err := g.AddNode(NewSourceNode(1, SourceImage, 5, nil, ""), src); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("AddNode(source length mismatch) error = %v, want ErrInvalidNode", err)
	}
	if err := g.AddNode(NewSourceNode(1, SourceImage, 4, nil, ""), src); err != nil {
		t.Fatalf("AddNode(valid) error = %v", err)
	}
	if err := g.AddNode(NewSourceNode(1, SourceImage, 4, nil, ""), nil); !errors.Is(err, ErrDuplicateSource) {
		t.Fatalf("AddNode(duplicate) error = %v, want ErrDuplicateSource", err)
	}
}

func TestSourceGraphValidateRejectsMissingParent(t *testing.T) {
	g := NewSourceGraph()
	node := NewSourceNode(1, SourcePartition, 10, []ParentRef{{Parent: 99, OffsetInParent: 0, Len: 10}}, "")
	if err := g.AddNode(node, nil); err != nil {
		t.Fatal(err)
	}
	if err := g.Validate(); !errors.Is(err, ErrMissingParent) {
		t.Fatalf("Validate error = %v, want ErrMissingParent", err)
	}
}

func TestSourceGraphValidateRejectsParentOutOfBounds(t *testing.T) {
	g := NewSourceGraph()
	if err := g.AddNode(NewSourceNode(1, SourceImage, 10, nil, ""), nil); err != nil {
		t.Fatal(err)
	}
	child := NewSourceNode(2, SourcePartition, 4, []ParentRef{{Parent: 1, OffsetInParent: 8, Len: 4}}, "")
	if err := g.AddNode(child, nil); err != nil {
		t.Fatal(err)
	}
	if err := g.Validate(); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("Validate error = %v, want ErrInvalidNode", err)
	}
}

func TestSourceGraphValidateRejectsCycle(t *testing.T) {
	g := NewSourceGraph()
	a := NewSourceNode(1, SourcePartition, 4, []ParentRef{{Parent: 2, OffsetInParent: 0, Len: 4}}, "")
	b := NewSourceNode(2, SourceVolume, 4, []ParentRef{{Parent: 1, OffsetInParent: 0, Len: 4}}, "")
	if err := g.AddNode(a, nil); err != nil {
		t.Fatal(err)
	}
	if err := g.AddNode(b, nil); err != nil {
		t.Fatal(err)
	}
	if err := g.Validate(); !errors.Is(err, ErrSourceCycle) {
		t.Fatalf("Validate error = %v, want ErrSourceCycle", err)
	}
}

func TestSourceGraphRoots(t *testing.T) {
	g := NewSourceGraph()
	_ = g.AddNode(NewSourceNode(3, SourceImage, 10, nil, ""), nil)
	_ = g.AddNode(NewSourceNode(1, SourceImage, 10, nil, ""), nil)
	_ = g.AddNode(NewSourceNode(2, SourcePartition, 4, []ParentRef{{Parent: 1, OffsetInParent: 0, Len: 4}}, ""), nil)

	got := g.Roots()
	want := []ID{1, 3}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Roots() = %v, want %v", got, want)
	}
}

func TestSourceGraphMapToImage(t *testing.T) {
	g := NewSourceGraph()
	src := NewMemorySourceWithImage(1, 7, []byte("0123456789"))
	if err := g.AddNode(NewSourceNode(1, SourceImage, 10, nil, ""), src); err != nil {
		t.Fatal(err)
	}

	got, err := g.MapToImage(1, 3, 4)
	if err != nil {
		t.Fatalf("MapToImage error = %v", err)
	}
	want := []ImageRange{{ImageID: 7, ImageOffset: 3, Len: 4, Kind: RangeData}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MapToImage = %+v, want %+v", got, want)
	}

	if _, err := g.MapToImage(99, 0, 1); !errors.Is(err, ErrMissingSource) {
		t.Fatalf("MapToImage(missing) error = %v, want ErrMissingSource", err)
	}
}
