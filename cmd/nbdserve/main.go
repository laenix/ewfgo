// Command nbdserve exposes an EWF image as a read-only Network Block Device
// over TCP (NBD newstyle protocol), so an external forensic tool can attach the
// image as a block device. It is pure Go and cross-platform (Windows, Linux,
// macOS): no CGO, no external processes, and no syscall-specific signal code —
// shutdown uses os/signal.NotifyContext, which works on every platform.
//
// Usage: nbdserve [flags] <image.E01>
//
//	-addr      listen address (default 127.0.0.1:10809, the IANA NBD port)
//	-export    NBD export name (default: the image filename)
//	-partition 1-based partition number to export, 0 = the whole image (default 0)
//	-unix      instead of TCP, bind a Unix domain socket at this path (the
//	           socket file is removed on exit); mutually exclusive with -addr
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"

	forensic "github.com/laenix/ewfgo"
	"github.com/laenix/ewfgo/nbd"
)

// version is stamped at release-build time via -ldflags "-X main.version=<tag>";
// it defaults to "dev" for local builds.
var version = "dev"

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	addr := flag.String("addr", "127.0.0.1:10809", "listen address (default 127.0.0.1:10809, the IANA NBD port)")
	unixPath := flag.String("unix", "", "bind a Unix domain socket at this path instead of TCP")
	export := flag.String("export", "", "NBD export name (default: the image filename)")
	partition := flag.Int("partition", 0, "1-based partition number to export, 0 = the whole image")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("nbdserve %s\n", version)
		return nil
	}

	args := flag.Args()
	if len(args) != 1 {
		flag.Usage()
		return fmt.Errorf("nbdserve: expected exactly one E01 image argument")
	}
	imagePath := args[0]

	ctx := context.Background()
	img, err := forensic.Open(ctx, imagePath, forensic.Options{})
	if err != nil {
		return fmt.Errorf("open %s: %w", imagePath, err)
	}
	defer img.Close()

	name := *export
	if name == "" {
		name = filepath.Base(imagePath)
	}

	var exp nbd.Exporter
	if *partition > 0 {
		parts, err := img.Partitions(ctx)
		if err != nil {
			return fmt.Errorf("list partitions: %w", err)
		}
		if *partition > len(parts) {
			return fmt.Errorf("partition %d does not exist (image has %d)", *partition, len(parts))
		}
		exp = nbd.NewExporter(parts[*partition-1].Source())
	} else {
		exp = nbd.NewExporter(img.Source())
	}
	size := exp.Size()

	var l *nbd.Listener
	if *unixPath != "" {
		l, err = nbd.ListenUnix(*unixPath, exp, name)
	} else {
		l, err = nbd.Listen(*addr, exp, name)
	}
	if err != nil {
		return err
	}

	// os/signal + signal.NotifyContext is Windows-safe; no syscall constants
	// are used, so SIGTERM is not explicitly caught (on Unix a SIGTERM still
	// terminates the process).
	runCtx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	fmt.Printf("serving %s (%d bytes) on %s\n", imagePath, size, l.Addr())

	serveErr := make(chan error, 1)
	go func() { serveErr <- l.Serve() }()

	select {
	case err := <-serveErr:
		if err != nil {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	case <-runCtx.Done():
		// SIGINT: stop accepting and exit 0.
		_ = l.Close()
		<-serveErr
		return nil
	}
}
