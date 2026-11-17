package vmdkdisk

import (
	"bytes"
	"errors"
	"testing"

	"github.com/laenix/ewfgo/internal/data/source"
)

func putLE32(b []byte, at int, v uint32) {
	b[at], b[at+1], b[at+2], b[at+3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}

func putLE64(b []byte, at int, v uint64) {
	for i := 0; i < 8; i++ {
		b[at+i] = byte(v >> (8 * i))
	}
}

func buildSparseFile(fill byte) []byte {
	file := make([]byte, 6*512)
	copy(file[:4], "KDMV")
	putLE32(file, 4, 1)
	putLE64(file, 12, 1) // one sector capacity
	putLE64(file, 20, 1) // one sector grain
	putLE32(file, 44, 1) // one grain per table
	putLE64(file, 56, 2) // grain directory at sector 2
	putLE32(file, 2*512, 3)
	putLE32(file, 3*512, 4)
	for i := 0; i < 512; i++ {
		file[4*512+i] = fill
	}
	return file
}

func TestParseDescriptor(t *testing.T) {
	text := "\xEF\xBB\xBF" + DescriptorSignature + "\r\n" +
		"version=1\r\n" +
		"CID=1a2b3c4d\r\n" +
		"parentCID=ffffffff\r\n" +
		"createType=\"twoGbMaxExtentSparse\"\r\n" +
		"# Extent description\r\n" +
		"RW 4192256 SPARSE \"win10-s001.vmdk\"\r\n" +
		"RDONLY 8 FLAT \"flat.bin\" 2\r\n" +
		"RW 4 ZERO\r\n" +
		"ddb.adapterType = \"lsilogic\"\r\n"

	descriptor, err := ParseDescriptor([]byte(text))
	if err != nil {
		t.Fatalf("ParseDescriptor error = %v", err)
	}
	if descriptor.Version != 1 || descriptor.CID != "1a2b3c4d" ||
		descriptor.ParentCID != "ffffffff" || descriptor.CreateType != "twoGbMaxExtentSparse" {
		t.Fatalf("descriptor = %+v", descriptor)
	}
	if len(descriptor.Extents) != 3 {
		t.Fatalf("extents = %d", len(descriptor.Extents))
	}
	if e := descriptor.Extents[0]; e.Access != AccessReadWrite || e.Kind != KindSparse ||
		e.File != "win10-s001.vmdk" || e.Sectors != 4192256 {
		t.Fatalf("extent 0 = %+v", e)
	}
	if e := descriptor.Extents[1]; e.Access != AccessReadOnly || e.Kind != KindFlat ||
		e.File != "flat.bin" || e.Offset != 2 {
		t.Fatalf("extent 1 = %+v", e)
	}
	if e := descriptor.Extents[2]; e.Kind != KindZero || e.HasFile {
		t.Fatalf("extent 2 = %+v", e)
	}
	if len(descriptor.Options) != 1 || descriptor.Options[0].Key != "ddb.adapterType" {
		t.Fatalf("options = %+v", descriptor.Options)
	}
	if descriptor.DeclaresParent() {
		t.Fatal("DeclaresParent = true for ffffffff")
	}
}

func TestDescriptorSignatureAndSafety(t *testing.T) {
	if !MatchesDescriptor([]byte(DescriptorSignature + "\nversion=1\n")) {
		t.Fatal("MatchesDescriptor = false")
	}
	if _, err := ParseDescriptor([]byte(DescriptorSignature + "\nversion=1\nRW 1 FLAT \"../evil.bin\"\n")); !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("ParseDescriptor(path traversal) error = %v, want ErrCorrupt", err)
	}
	if _, err := ParseDescriptor([]byte(DescriptorSignature + "\nversion=1\nRW 1 VMFS \"x\"\n")); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("ParseDescriptor(VMFS) error = %v, want ErrUnsupported", err)
	}
}

func TestAssembleFlatAndZero(t *testing.T) {
	descriptor, err := ParseDescriptor([]byte(DescriptorSignature + "\nversion=1\nCID=1\nparentCID=ffffffff\n" +
		"RW 2 FLAT \"flat.bin\" 1\nRW 1 ZERO\n"))
	if err != nil {
		t.Fatal(err)
	}
	flat := make([]byte, 4*512)
	for i := range flat {
		flat[i] = 'X'
	}
	for i := 512; i < 3*512; i++ {
		flat[i] = 'F'
	}
	disk, err := Assemble(100, descriptor, func(name string) (source.ByteSource, error) {
		if name != "flat.bin" {
			t.Fatalf("unexpected extent %q", name)
		}
		return source.NewMemorySourceWithImage(1, 7, flat), nil
	})
	if err != nil {
		t.Fatalf("Assemble error = %v", err)
	}
	if disk.Len() != 3*512 {
		t.Fatalf("Len = %d", disk.Len())
	}
	buf := make([]byte, 3*512)
	if _, err := disk.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:2*512], bytes.Repeat([]byte{'F'}, 2*512)) {
		t.Fatal("flat extent bytes did not read back")
	}
	if !bytes.Equal(buf[2*512:], make([]byte, 512)) {
		t.Fatal("ZERO extent is not zero")
	}

	extents, err := disk.Extents(0, disk.Len())
	if err != nil {
		t.Fatal(err)
	}
	if len(extents) != 2 || extents[0].Kind != source.RangeData ||
		extents[0].ParentOffset != 512 || extents[0].Len != 2*512 {
		t.Fatalf("extents = %+v", extents)
	}
	if extents[1].Kind != source.RangeZero {
		t.Fatalf("zero extent = %+v", extents[1])
	}
}

func TestAssembleSparseExtent(t *testing.T) {
	descriptor, err := ParseDescriptor([]byte(DescriptorSignature + "\nversion=1\nCID=1\nparentCID=ffffffff\n" +
		"RW 1 SPARSE \"s1.vmdk\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	disk, err := Assemble(100, descriptor, func(name string) (source.ByteSource, error) {
		return source.NewMemorySourceWithImage(1, 7, buildSparseFile('S')), nil
	})
	if err != nil {
		t.Fatalf("Assemble error = %v", err)
	}
	buf := make([]byte, 512)
	if _, err := disk.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, bytes.Repeat([]byte{'S'}, 512)) {
		t.Fatal("sparse extent did not read back")
	}
}

func TestAssembleRejectsSparseSizeMismatch(t *testing.T) {
	descriptor, err := ParseDescriptor([]byte(DescriptorSignature + "\nversion=1\nCID=1\nparentCID=ffffffff\n" +
		"RW 2 SPARSE \"s1.vmdk\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Assemble(100, descriptor, func(name string) (source.ByteSource, error) {
		return source.NewMemorySource(1, buildSparseFile('S')), nil
	})
	if !errors.Is(err, source.ErrCorrupt) {
		t.Fatalf("Assemble error = %v, want ErrCorrupt", err)
	}
}

func TestAssembleRejectsMissingExtent(t *testing.T) {
	descriptor, err := ParseDescriptor([]byte(DescriptorSignature + "\nversion=1\nCID=1\nparentCID=ffffffff\n" +
		"RW 1 FLAT \"missing.bin\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Assemble(100, descriptor, func(name string) (source.ByteSource, error) {
		return nil, errors.New("not found")
	})
	if err == nil {
		t.Fatal("Assemble accepted a missing extent")
	}
}

func buildSparseUnallocated() []byte {
	file := make([]byte, 4*512)
	copy(file[:4], "KDMV")
	putLE32(file, 4, 1)
	putLE64(file, 12, 1)
	putLE64(file, 20, 1)
	putLE32(file, 44, 1)
	putLE64(file, 56, 2)
	putLE32(file, 2*512, 3)
	// Grain table entry stays zero: the grain was never written.
	return file
}

func TestAssembleSplitDifferencingReadsParent(t *testing.T) {
	parentDescriptor, err := ParseDescriptor([]byte(DescriptorSignature + "\nversion=1\nCID=deadbeef\nparentCID=ffffffff\n" +
		"RW 1 FLAT \"parent-flat.bin\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	parent, err := Assemble(100, parentDescriptor, func(name string) (source.ByteSource, error) {
		return source.NewMemorySourceWithImage(1, 9, bytes.Repeat([]byte{'P'}, 512)), nil
	})
	if err != nil {
		t.Fatalf("parent Assemble error = %v", err)
	}

	childDescriptor, err := ParseDescriptor([]byte(DescriptorSignature + "\nversion=1\nCID=cafebabe\nparentCID=deadbeef\n" +
		"parentFileNameHint=\"parent.vmdk\"\nRW 1 SPARSE \"child-s001.vmdk\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	child, err := AssembleWithParent(200, childDescriptor, func(name string) (source.ByteSource, error) {
		return source.NewMemorySource(3, buildSparseUnallocated()), nil
	}, parent)
	if err != nil {
		t.Fatalf("AssembleWithParent error = %v", err)
	}
	buf := make([]byte, 512)
	if _, err := child.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, bytes.Repeat([]byte{'P'}, 512)) {
		t.Fatal("unallocated child grain did not come from the parent")
	}

	// The same child with an allocated grain reads its own data.
	childData, err := AssembleWithParent(200, childDescriptor, func(name string) (source.ByteSource, error) {
		return source.NewMemorySource(3, buildSparseFile('C')), nil
	}, parent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := childData.ReadAt(0, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, bytes.Repeat([]byte{'C'}, 512)) {
		t.Fatal("allocated child grain did not read back")
	}
}

func TestAssembleSplitDifferencingRejectsWrongParent(t *testing.T) {
	parentDescriptor, err := ParseDescriptor([]byte(DescriptorSignature + "\nversion=1\nCID=11111111\nparentCID=ffffffff\n" +
		"RW 1 FLAT \"parent-flat.bin\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	parent, err := Assemble(100, parentDescriptor, func(name string) (source.ByteSource, error) {
		return source.NewMemorySource(1, make([]byte, 512)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	childDescriptor, err := ParseDescriptor([]byte(DescriptorSignature + "\nversion=1\nCID=cafebabe\nparentCID=deadbeef\n" +
		"RW 1 ZERO\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AssembleWithParent(200, childDescriptor, func(name string) (source.ByteSource, error) {
		return nil, errors.New("not called")
	}, parent); !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("AssembleWithParent error = %v, want ErrUnsupported", err)
	}
}

func TestAssembleRejectsDifferencing(t *testing.T) {
	descriptor, err := ParseDescriptor([]byte(DescriptorSignature + "\nversion=1\nCID=1\nparentCID=2\n" +
		"RW 1 ZERO\n"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Assemble(100, descriptor, func(name string) (source.ByteSource, error) {
		return nil, errors.New("not called")
	})
	if !errors.Is(err, source.ErrUnsupported) {
		t.Fatalf("Assemble error = %v, want ErrUnsupported", err)
	}
}
