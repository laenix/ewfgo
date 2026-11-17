package forensic_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	forensic "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/internal/data/source"
	"github.com/laenix/ewfgo/internal/ewffixture"
)

func tarFixture(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := tar.NewWriter(&buf)
	for name, data := range files {
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func nestedZipFixture(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for name, data := range files {
		entry, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func dumpNested(node *forensic.NestedNode, indent string) string {
	if node == nil {
		return indent + "<nil>\n"
	}
	out := indent + node.Kind + " " + node.Path + " err=" + node.Err + " detail=" + node.Detail + "\n"
	for _, child := range node.Children {
		out += dumpNested(child, indent+"  ")
	}
	return out
}

func findNested(node *forensic.NestedNode, kind string, pathSuffix string) *forensic.NestedNode {
	if node == nil {
		return nil
	}
	if node.Kind == kind && strings.HasSuffix(node.Path, pathSuffix) {
		return node
	}
	for _, child := range node.Children {
		if found := findNested(child, kind, pathSuffix); found != nil {
			return found
		}
	}
	return nil
}

// TestNestedZipE01TarMemoryDocument builds the full nesting chain asked for:
// ZIP -> E01 -> (partition) TAR -> memory dump and OOXML document.
func TestNestedZipE01TarMemoryDocument(t *testing.T) {
	memory := limeFixture()
	document := docxFixture(t)
	tarBytes := tarFixture(t, map[string][]byte{
		"mem.lime": memory,
		"doc.docx": document,
	})
	disk := ewffixture.WrapMBRDisk(tarBytes, 0x0C, 2048)
	e01 := ewffixture.WrapDisk(disk, ewffixture.Options{})
	outer := nestedZipFixture(t, map[string][]byte{
		"disk.E01":  e01,
		"notes.txt": []byte("outer archive entry"),
	})

	path := filepath.Join(t.TempDir(), "outer.zip")
	if err := os.WriteFile(path, outer, 0o600); err != nil {
		t.Fatal(err)
	}
	tree, err := forensic.OpenNested(context.Background(), path, forensic.DefaultNestedOptions())
	if err != nil {
		t.Fatalf("OpenNested: %v", err)
	}
	defer tree.Close()
	if tree.Truncated {
		t.Fatalf("tree truncated unexpectedly (nodes=%d)", tree.Nodes)
	}

	archiveNode := findNested(tree.Root, "zip", "outer.zip")
	if archiveNode == nil {
		t.Fatalf("ZIP node missing: %+v", tree.Root)
	}
	e01Node := findNested(tree.Root, "E01", "disk.E01")
	if e01Node == nil {
		t.Fatalf("E01 node missing: %+v", tree.Root)
	}
	if e01Node.Source == nil || e01Node.Size != uint64(len(disk)) {
		t.Fatalf("E01 node = size %d source %v", e01Node.Size, e01Node.Source)
	}
	partitionNode := findNested(tree.Root, "partition", "partition-0")
	if partitionNode == nil {
		t.Fatalf("partition node missing:\n%s", dumpNested(tree.Root, ""))
	}
	tarNode := findNested(tree.Root, "tar", "partition-0/content")
	if tarNode == nil {
		t.Fatalf("TAR node missing: %+v", tree.Root)
	}
	memoryNode := findNested(tree.Root, "memory dump", "mem.lime")
	if memoryNode == nil {
		t.Fatalf("memory node missing: %+v", tree.Root)
	}
	if !strings.Contains(memoryNode.Detail, "LiME") {
		t.Fatalf("memory detail = %q", memoryNode.Detail)
	}
	documentNode := findNested(tree.Root, "OOXML", "doc.docx")
	if documentNode == nil {
		t.Fatalf("document node missing: %+v", tree.Root)
	}
	if !strings.Contains(documentNode.Detail, "word processing") {
		t.Fatalf("document detail = %q", documentNode.Detail)
	}
	if tree.Nodes < 6 {
		t.Fatalf("tree has only %d nodes: %+v", tree.Nodes, tree.Root)
	}
}

func TestNestedWalksFilesystem(t *testing.T) {
	path := filepath.Join("testdata", "e01", "fat16-encase6-zlib.E01")
	tree, err := forensic.OpenNested(context.Background(), path, forensic.DefaultNestedOptions())
	if err != nil {
		t.Fatalf("OpenNested: %v", err)
	}
	defer tree.Close()

	fsNode := findNested(tree.Root, "FAT16", "")
	if fsNode == nil {
		t.Fatalf("filesystem node missing:\n%s", dumpNested(tree.Root, ""))
	}
	fileNode := findNested(tree.Root, "file", "FIXTURE.TXT")
	if fileNode == nil {
		t.Fatalf("file node missing:\n%s", dumpNested(tree.Root, ""))
	}
	if fileNode.Source == nil || fileNode.Size != 8 {
		t.Fatalf("file node = %+v", fileNode)
	}
}

func TestOpenNestedSource(t *testing.T) {
	data := nestedZipFixture(t, map[string][]byte{"note.txt": []byte("source entry")})
	tree, err := forensic.OpenNestedSource(context.Background(), source.NewMemorySource(1, data), forensic.DefaultNestedOptions())
	if err != nil {
		t.Fatalf("OpenNestedSource: %v", err)
	}
	defer tree.Close()
	if tree.Root == nil || tree.Root.Kind != "zip" {
		t.Fatalf("root = %+v", tree.Root)
	}
	if findNested(tree.Root, "file", "note.txt") == nil {
		t.Fatalf("entry missing:\n%s", dumpNested(tree.Root, ""))
	}
}

func TestNestedRespectsDepthAndNodeLimits(t *testing.T) {
	outer := nestedZipFixture(t, map[string][]byte{
		"inner.zip": nestedZipFixture(t, map[string][]byte{
			"leaf.txt": []byte("leaf"),
		}),
	})
	path := filepath.Join(t.TempDir(), "outer.zip")
	if err := os.WriteFile(path, outer, 0o600); err != nil {
		t.Fatal(err)
	}
	options := forensic.DefaultNestedOptions()
	options.MaxDepth = 1
	tree, err := forensic.OpenNested(context.Background(), path, options)
	if err != nil {
		t.Fatalf("OpenNested: %v", err)
	}
	defer tree.Close()
	if !tree.Truncated {
		t.Fatalf("depth limit did not report truncation: %+v", tree.Root)
	}

	options = forensic.DefaultNestedOptions()
	options.MaxNodes = 2
	tree2, err := forensic.OpenNested(context.Background(), path, options)
	if err != nil {
		t.Fatalf("OpenNested: %v", err)
	}
	defer tree2.Close()
	if tree2.Nodes > 2 || !tree2.Truncated {
		t.Fatalf("node limit = nodes %d truncated %v", tree2.Nodes, tree2.Truncated)
	}
}
