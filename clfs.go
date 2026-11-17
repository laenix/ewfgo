package forensic

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/laenix/ewfgo/internal/data/containers/clfs"
	"github.com/laenix/ewfgo/internal/data/source"
)

// CLFS is an opened Windows Common Log File System file: a base log (`.blf`)
// or a container (`*.regtrans-ms`). This reader exposes metadata only; log
// record payloads are not reconstructed.
type CLFS struct {
	path      string
	container *clfs.Container
	close     io.Closer
}

// CLFSInfo summarizes a CLFS file.
type CLFSInfo struct {
	Kind       string
	BaseLog    bool
	Container  bool
	LogID      string
	DumpCount  uint64
	SectorSize uint32
	Clients    int
	Containers int
	FileLen    uint64
	Warnings   []string
}

// OpenCLFS opens a CLFS base log or container file.
func OpenCLFS(ctx context.Context, imagePath string, opts Options) (*CLFS, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	raw, err := source.OpenRawFileWithSectorSize(imagePath, 1, 1, opts.sectorSize(nil, 512))
	if err != nil {
		return nil, fmt.Errorf("open CLFS %s: %w", imagePath, err)
	}
	container, err := OpenCLFSSource(ctx, raw, opts)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("parse CLFS %s: %w", imagePath, err)
	}
	container.path = imagePath
	container.close = raw
	return container, nil
}

// OpenCLFSSource opens a CLFS file over an existing byte source. The source is
// not closed by CLFS.Close.
func OpenCLFSSource(ctx context.Context, src ByteSource, opts Options) (*CLFS, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, fmt.Errorf("%w: nil CLFS source", ErrInvalidArgument)
	}
	container, err := clfs.Open(src)
	if err != nil {
		return nil, err
	}
	return &CLFS{container: container}, nil
}

// Path returns the CLFS file path.
func (c *CLFS) Path() string { return c.path }

// Info returns the parsed metadata summary.
func (c *CLFS) Info() CLFSInfo {
	info := CLFSInfo{Kind: c.container.Kind().Label(), FileLen: c.container.Source().Len()}
	if base := c.container.BaseLog(); base != nil {
		info.BaseLog = true
		record := base.BaseRecord()
		info.LogID = hex.EncodeToString(record.LogID[:])
		info.DumpCount = record.DumpCount
		info.SectorSize = record.SectorSize
		stats := base.Stats()
		info.Clients = stats.Clients
		info.Containers = stats.Containers
		info.Warnings = append([]string(nil), stats.Warnings...)
	}
	if header := c.container.Header(); header != nil {
		info.Container = true
		info.Warnings = append(info.Warnings, header.Warnings...)
	}
	return info
}

// ClientNames returns the registry/client names the base log names.
func (c *CLFS) ClientNames(ctx context.Context) ([]string, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	base := c.container.BaseLog()
	if base == nil {
		return nil, fmt.Errorf("%w: %s is a container, not a base log", ErrInvalidArgument, c.path)
	}
	var names []string
	for _, client := range base.Clients() {
		if name, ok := client.Name(); ok {
			names = append(names, name)
		}
	}
	return names, nil
}

// ContainerNames returns the container paths the base log records.
func (c *CLFS) ContainerNames(ctx context.Context) ([]string, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	base := c.container.BaseLog()
	if base == nil {
		return nil, fmt.Errorf("%w: %s is a container, not a base log", ErrInvalidArgument, c.path)
	}
	var names []string
	for _, container := range base.Containers() {
		if name, ok := container.Name(); ok {
			names = append(names, name)
		}
	}
	return names, nil
}

// OpenStream reports that CLFS log record payload reconstruction is not
// implemented; the reader is metadata-only.
func (c *CLFS) OpenStream(ctx context.Context, name string) (ByteSource, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	_, err := c.container.OpenStream(name)
	return nil, fmt.Errorf("CLFS stream %q: %w", name, err)
}

// OpenRecord refuses log-record payload reconstruction by LSN.
func (c *CLFS) OpenRecord(ctx context.Context, lsn uint64) (ByteSource, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	_, err := c.container.OpenRecord(lsn)
	return nil, fmt.Errorf("CLFS record at LSN %#x: %w", lsn, err)
}

// Close releases the file handle.
func (c *CLFS) Close() error {
	if c.close == nil {
		return nil
	}
	err := c.close.Close()
	c.close = nil
	return err
}
