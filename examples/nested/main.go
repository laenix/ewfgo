// Command nested recursively inspects an evidence file: containers inside
// containers, partitions, filesystems, archives and files. For example a ZIP
// containing an E01 whose filesystem contains a TAR, whose entries include a
// memory dump and an OOXML document.
//
// Usage:
//
//	go run ./examples/nested -image outer.zip
//	go run ./examples/nested -image outer.zip -depth 6 -nodes 5000
//	go run ./examples/nested -image outer.zip -files=false
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	forensic "github.com/laenix/ewfgo"
)

func main() {
	imagePath := flag.String("image", "", "evidence file (image, archive, document, memory dump, ...)")
	depth := flag.Int("depth", 12, "maximum nesting depth")
	nodes := flag.Int("nodes", 20000, "maximum tree nodes")
	files := flag.Bool("files", true, "inspect files inside filesystems and archives")
	flag.Parse()
	if *imagePath == "" {
		fmt.Fprintln(os.Stderr, "usage: nested -image <path> [-depth N] [-nodes N] [-files=false]")
		os.Exit(2)
	}
	if err := run(*imagePath, *depth, *nodes, *files); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(imagePath string, depth, nodes int, files bool) error {
	options := forensic.DefaultNestedOptions()
	options.MaxDepth = depth
	options.MaxNodes = nodes
	options.InspectFiles = files

	ctx := context.Background()
	tree, err := forensic.OpenNested(ctx, imagePath, options)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", imagePath, err)
	}
	defer tree.Close()

	fmt.Printf("root      : %s\n", imagePath)
	fmt.Printf("kind      : %s\n", tree.Root.Kind)
	fmt.Printf("detail    : %s\n", tree.Root.Detail)
	fmt.Printf("nodes     : %d (truncated=%v)\n\n", tree.Nodes, tree.Truncated)
	printNode(tree.Root, 0)
	return nil
}

func printNode(node *forensic.NestedNode, level int) {
	if node == nil {
		return
	}
	indent := ""
	for i := 0; i < level; i++ {
		indent += "  "
	}
	line := fmt.Sprintf("%s%s [%s]", indent, node.Name, node.Kind)
	if node.Size > 0 {
		line += fmt.Sprintf(" %d bytes", node.Size)
	}
	if node.Detail != "" {
		line += " - " + node.Detail
	}
	if node.Err != "" {
		line += " ERROR: " + node.Err
	}
	fmt.Println(line)
	for _, child := range node.Children {
		printNode(child, level+1)
	}
}
