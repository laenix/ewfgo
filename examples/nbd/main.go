// Command nbd exports an E01 (whole disk or one partition) as a read-only NBD
// block device and prints attach/mount commands for the current export.
//
//	go run ./examples/nbd -image evidence.E01
//	go run ./examples/nbd -image evidence.E01 -partition 2 -export part2
//
// The server is a thin wrapper over github.com/laenix/ewfgo/nbd. See
// docs/nbd-mount.md for Linux mount steps and platform notes.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path"
	"path/filepath"

	forensic "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/nbd"
)

func main() {
	image := flag.String("image", "", "EWF/E01 image path")
	partition := flag.Int("partition", 0, "1-based partition to export, 0 = whole disk")
	addr := flag.String("addr", "127.0.0.1:10809", "NBD listen address")
	export := flag.String("export", "", "NBD export name (default: image basename)")
	flag.Parse()

	if *image == "" {
		fmt.Fprintln(os.Stderr, "usage: nbd -image <evidence.E01> [-partition N] [-addr host:port] [-export name]")
		os.Exit(2)
	}
	if err := run(*image, *partition, *addr, *export); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(imagePath string, partition int, addr, export string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	img, err := forensic.Open(ctx, imagePath, forensic.Options{})
	if err != nil {
		return fmt.Errorf("open %s: %w", imagePath, err)
	}
	defer img.Close()

	name := export
	if name == "" {
		name = filepath.Base(imagePath)
	}

	var (
		exp         nbd.Exporter
		label       string
		mountDev    string
		description string
	)
	if partition > 0 {
		parts, err := img.Partitions(ctx)
		if err != nil {
			return fmt.Errorf("list partitions: %w", err)
		}
		if partition > len(parts) {
			return fmt.Errorf("partition %d does not exist (image has %d)", partition, len(parts))
		}
		src := parts[partition-1].Source()
		exp = nbd.NewExporter(src)
		label = fmt.Sprintf("partition %d (%s, %s)", partition, parts[partition-1].TypeName(), parts[partition-1].Format())
		mountDev = path.Join("/dev", "nbd0")
		description = "raw volume"
	} else {
		exp = nbd.NewExporter(img.Source())
		label = "whole disk"
		mountDev = path.Join("/dev", "nbd0p1")
		description = "disk with a partition table"
	}

	listener, err := nbd.Listen(addr, exp, name)
	if err != nil {
		return err
	}
	defer listener.Close()

	fmt.Printf("serving  %s: %s, %d bytes\n", label, description, exp.Size())
	fmt.Printf("export   %q on %s (read-only)\n", name, listener.Addr())
	nbdAddr := addr
	if host, port, err := net.SplitHostPort(addr); err == nil {
		nbdAddr = host + " " + port
	}
	fmt.Println()
	fmt.Println("Linux mount:")
	fmt.Printf("  sudo modprobe nbd max_part=16\n")
	fmt.Printf("  sudo nbd-client -N %s %s /dev/nbd0\n", name, nbdAddr)
	if partition == 0 {
		fmt.Printf("  lsblk /dev/nbd0          # pick the partition, usually /dev/nbd0p1\n")
	}
	fmt.Printf("  sudo mount -o ro %s /mnt/evidence\n", mountDev)
	fmt.Printf("  ... use /mnt/evidence ...\n")
	fmt.Printf("  sudo umount /mnt/evidence && sudo nbd-client -d /dev/nbd0\n")
	fmt.Println()
	fmt.Println("Verify without mounting (QEMU, any OS):")
	fmt.Printf("  qemu-img info \"nbd://%s/%s\"\n", addr, name)
	fmt.Println()
	fmt.Println("Press Ctrl-C to stop the export.")

	serveErr := make(chan error, 1)
	go func() { serveErr <- listener.Serve() }()

	select {
	case err := <-serveErr:
		if err != nil {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	case <-ctx.Done():
		_ = listener.Close()
		<-serveErr
		return nil
	}
}
