package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"path"
	"strings"

	forensic "github.com/laenix/ewfgo"
)

// version is stamped at release-build time via -ldflags "-X main.version=<tag>";
// it defaults to "dev" for local builds.
var version = "dev"

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "-version" || os.Args[1] == "--version") {
		fmt.Printf("ewftool %s\n", version)
		return
	}

	if len(os.Args) < 2 {
		fmt.Println("Usage: ewftool <image> [command] [args]")
		fmt.Println("")
		fmt.Println("Commands:")
		fmt.Println("  info     Show image/partition info (default)")
		fmt.Println("  parts    List partitions")
		fmt.Println("  fs       Show detected filesystem per partition")
		fmt.Println("  vols     Assemble and list mdraid/LVM volumes")
		fmt.Println("  enc      Show encryption metadata per partition")
		fmt.Println("  nested   Recursively inspect nested containers")
		fmt.Println("  ls       List directory: ls [partition#] [path]")
		fmt.Println("")
		fmt.Println("Examples:")
		fmt.Println("  ewftool image.E01 info")
		fmt.Println("  ewftool image.E01 parts")
		fmt.Println("  ewftool image.E01 ls 0 /")
		fmt.Println("  ewftool image.E01 vols")
		fmt.Println("  ewftool image.E01 enc")
		fmt.Println("  ewftool image.E01 nested")
		os.Exit(1)
	}

	imagePath := os.Args[1]
	command := "info"
	if len(os.Args) >= 3 {
		command = os.Args[2]
	}

	ctx := context.Background()
	if command == "nested" {
		showNested(ctx, imagePath)
		return
	}
	img, err := forensic.Open(ctx, imagePath, forensic.Options{})
	if err != nil {
		log.Fatal(err)
	}
	defer img.Close()

	parts, err := img.Partitions(ctx)
	if err != nil {
		log.Fatal(err)
	}

	switch command {
	case "info":
		printImageInfo(img, parts)
	case "parts":
		showPartitions(img, parts)
	case "fs":
		showFilesystems(img, parts)
	case "vols":
		showVolumes(ctx, img)
	case "enc":
		showEncryption(ctx, parts)
	case "nested":
		showNested(ctx, imagePath)
	case "ls":
		index, dir := 0, "/"
		if len(os.Args) >= 4 {
			fmt.Sscanf(os.Args[3], "%d", &index)
		}
		if len(os.Args) >= 5 {
			dir = os.Args[4]
		}
		listDirectory(ctx, img, parts, index, dir)
	default:
		fmt.Println("Unknown command:", command)
		fmt.Println("Available: info, parts, fs, vols, enc, nested, ls")
		os.Exit(1)
	}
}

func printImageInfo(img *forensic.Image, parts []*forensic.Partition) {
	info := img.Info()
	fmt.Println("╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║                     EWF Image Info                        ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════╣")

	caseNum := info.CaseNumber
	if caseNum == "" {
		caseNum = "(none)"
	}
	fmt.Printf("║ Case:         %-42s ║\n", caseNum)

	evidenceNum := info.EvidenceNumber
	if evidenceNum == "" {
		evidenceNum = "(none)"
	}
	fmt.Printf("║ Evidence:     %-42s ║\n", evidenceNum)

	if info.Examiner != "" {
		fmt.Printf("║ Examiner:     %-42s ║\n", info.Examiner)
	}

	fmt.Println("╠═══════════════════════════════════════════════════════════╣")
	fmt.Printf("║ Total Size:   %-42s ║\n", formatBytes(img.Size()))
	fmt.Printf("║ Sector Size:  %-42d bytes║\n", img.SectorSize())
	fmt.Printf("║ Total Sectors: %-41d ║\n", img.Size()/uint64(img.SectorSize()))

	if len(parts) > 0 {
		fmt.Println("╠═══════════════════════════════════════════════════════════╣")
		fmt.Printf("║ Partitions:   %-42s ║\n", fmt.Sprintf("%d found", len(parts)))
		for _, p := range parts {
			fmt.Printf("║   %d: %-10s | %-10s | %10s           ║\n",
				p.Index(), p.TypeName(), p.Format(), formatBytes(p.Length()))
		}
	}

	fmt.Println("╚═══════════════════════════════════════════════════════════╝")
}

func showPartitions(img *forensic.Image, parts []*forensic.Partition) {
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                   Partition Table                       ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║ Total Size:  %-45s ║\n", formatBytes(img.Size()))
	fmt.Printf("║ Block Size: %-45d ║\n", img.SectorSize())
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	if len(parts) == 0 {
		fmt.Println("║ No partitions found                                       ║")
	} else {
		for _, p := range parts {
			fmt.Printf("║ %2d  %-12s %-12s %10s @ %d  ║\n",
				p.Index(), p.TypeName(), p.Format(), formatBytes(p.Length()), p.Offset())
		}
	}
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
}

func showFilesystems(img *forensic.Image, parts []*forensic.Partition) {
	fmt.Println("╔═══════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║              Filesystem Detection                      ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════════════╣")
	if len(parts) == 0 {
		fmt.Println("║ No partitions found                                                   ║")
	} else {
		for _, p := range parts {
			enc := ""
			if p.Encrypted() {
				enc = " (encrypted)"
			}
			fmt.Printf("║   Part %d: %-8s | %-8s%s | %10s           ║\n",
				p.Index(), p.TypeName(), p.Format(), enc, formatBytes(p.Length()))
		}
	}
	fmt.Println("╠═══════════════════════════════════════════════════════════════════════╣")

	if sig, ok := mbrSignature(img); ok {
		fmt.Printf("║ Disk Signature: 0x%X                                     ║\n", sig.disk)
		fmt.Printf("║ Boot Signature: 0x%X                                       ║\n", sig.boot)
	}
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
}

type mbrSignatures struct {
	disk uint32
	boot uint16
}

func mbrSignature(img *forensic.Image) (mbrSignatures, bool) {
	if img.Size() < 512 {
		return mbrSignatures{}, false
	}
	sector := make([]byte, 512)
	if _, err := img.Source().ReadAt(0, sector); err != nil {
		return mbrSignatures{}, false
	}
	if sector[510] != 0x55 || sector[511] != 0xAA {
		return mbrSignatures{}, false
	}
	return mbrSignatures{
		disk: binary.LittleEndian.Uint32(sector[440:444]),
		boot: binary.LittleEndian.Uint16(sector[510:512]),
	}, true
}

func showVolumes(ctx context.Context, img *forensic.Image) {
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                 Assembled Volumes                       ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	volumes, err := img.Volumes(ctx)
	if err != nil {
		printBoxError(err)
		return
	}
	if len(volumes) == 0 {
		fmt.Println("║ No mdraid arrays or LVM logical volumes found            ║")
	} else {
		for _, v := range volumes {
			status := "readable"
			if !v.Readable() {
				status = "INCOMPLETE"
			}
			fmt.Println(fmt.Sprintf("║ %-24s %-16s %-10s %s ║", v.Name(), v.Kind(), v.Format(), status))
			if !v.Readable() {
				fmt.Println(fmt.Sprintf("║   problem: %-48s ║", truncate(v.Problem(), 48)))
			}
		}
	}
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
}

func showEncryption(ctx context.Context, parts []*forensic.Partition) {
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                 Encryption Metadata                     ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	found := false
	for _, p := range parts {
		info, err := p.Encryption(ctx)
		if err != nil {
			fmt.Println(fmt.Sprintf("║ part %d: %-48s ║", p.Index(), truncate(err.Error(), 48)))
			continue
		}
		if info == nil {
			continue
		}
		found = true
		fmt.Println(fmt.Sprintf("║ part %d: %s (%s), metadata-only                 ║", p.Index(), info.Format, info.Method))
		if info.UUID != "" {
			fmt.Println(fmt.Sprintf("║   UUID: %-50s ║", truncate(info.UUID, 50)))
		}
		if info.Format == "BitLocker" {
			fmt.Println(fmt.Sprintf("║   protectors=%d recovery-password=%v              ║", info.Protectors, info.HasRecoveryPassword))
		} else if info.KeySlots > 0 || info.ActiveKeySlots > 0 {
			fmt.Println(fmt.Sprintf("║   keyslots=%d active=%d                          ║", info.KeySlots, info.ActiveKeySlots))
		}
	}
	if !found {
		fmt.Println("║ No recognised encryption headers                         ║")
	}
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
}

func showNested(ctx context.Context, imagePath string) {
	tree, err := forensic.OpenNested(ctx, imagePath, forensic.DefaultNestedOptions())
	if err != nil {
		fmt.Println("nested:", err)
		return
	}
	defer tree.Close()
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              Nested Evidence Tree                       ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║ nodes: %-5d truncated: %-5v                              ║\n", tree.Nodes, tree.Truncated)
	printNested(tree.Root, 0)
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
}

func printNested(node *forensic.NestedNode, level int) {
	if node == nil {
		return
	}
	indent := strings.Repeat("  ", level)
	line := fmt.Sprintf("%s%s [%s]", indent, node.Name, node.Kind)
	if node.Detail != "" {
		line += " - " + node.Detail
	}
	if node.Err != "" {
		line += " ERROR: " + node.Err
	}
	fmt.Println(line)
	for _, child := range node.Children {
		printNested(child, level+1)
	}
}

func truncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit]
}

func listDirectory(ctx context.Context, img *forensic.Image, parts []*forensic.Partition, index int, dir string) {
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║              Root Directory Listing                   ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")

	if len(parts) == 0 {
		fmt.Println("║ No partitions found                                         ║")
		fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
		return
	}
	if index < 0 || index >= len(parts) {
		fmt.Printf("║ Invalid partition index %d (max %d)                          ║\n", index, len(parts)-1)
		fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
		return
	}
	p := parts[index]
	fmt.Printf("║ Partition %d: %s at byte %-12d             ║\n", p.Index(), p.Format(), p.Offset())
	if dir != "" {
		fmt.Printf("║ Directory: %-45s ║\n", dir)
	}

	fsys, err := p.OpenFilesystem(ctx)
	if err != nil {
		printBoxError(err)
		return
	}
	defer fsys.Close()

	if dir == "" {
		dir = "/"
	}
	entries, err := fsys.ListDir(ctx, dir)
	if err != nil {
		printBoxError(err)
		return
	}
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║ Found %d entries:                                         ║\n", len(entries))
	for i, e := range entries {
		if i >= 20 {
			break
		}
		marker := "[FILE]"
		if e.IsDir {
			marker = "[DIR ]"
		}
		name := path.Base(e.Path)
		if len(name) > 30 {
			name = name[:30]
		}
		fmt.Printf("║   %s %-30s %10d bytes          ║\n", marker, name, e.Size)
	}
	if len(entries) > 20 {
		fmt.Printf("║   ... and %d more                                        ║\n", len(entries)-20)
	}
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
}

func printBoxError(err error) {
	text := err.Error()
	if len(text) > 58 {
		text = text[:58]
	}
	fmt.Printf("║ Error: %-54s ║\n", text)
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
}

func formatBytes(bytes uint64) string {
	if bytes >= 1024*1024*1024*1024 {
		return fmt.Sprintf("%.2f TB", float64(bytes)/1024/1024/1024/1024)
	}
	if bytes >= 1024*1024*1024 {
		return fmt.Sprintf("%.2f GB", float64(bytes)/1024/1024/1024)
	}
	if bytes >= 1024*1024 {
		return fmt.Sprintf("%.2f MB", float64(bytes)/1024/1024)
	}
	return fmt.Sprintf("%d bytes", bytes)
}
