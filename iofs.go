package forensic

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"math"
	"path"
	"strings"
	"time"
)

// AsFS adapts an opened filesystem to io/fs. The adapter is read-only and uses
// ctx for every operation, so a cancelled context stops directory listings and
// file opens. Names follow io/fs conventions: "." is the root and names are
// slash-separated with no leading slash.
func AsFS(ctx context.Context, fsys FileSystem) fs.FS {
	return &fsAdapter{ctx: ctx, fsys: fsys}
}

type fsAdapter struct {
	ctx  context.Context
	fsys FileSystem
}

var (
	_ fs.FS         = (*fsAdapter)(nil)
	_ fs.ReadDirFS  = (*fsAdapter)(nil)
	_ fs.StatFS     = (*fsAdapter)(nil)
	_ fs.ReadFileFS = (*fsAdapter)(nil)
)

func (a *fsAdapter) toForensic(name string) (string, error) {
	if name == "" {
		return "", errors.New("forensic: empty fs path")
	}
	trimmed := strings.TrimLeft(name, "/")
	if !fs.ValidPath(trimmed) {
		return "", fs.ErrInvalid
	}
	return path.Clean("/" + trimmed), nil
}

// Open implements fs.FS.
func (a *fsAdapter) Open(name string) (fs.File, error) {
	p, err := a.toForensic(name)
	if err != nil {
		return nil, err
	}
	if entry, statErr := a.Stat(name); statErr == nil && entry.IsDir() {
		return &dirFile{adapter: a, name: name, info: entry}, nil
	}
	file, err := a.fsys.Open(a.ctx, p)
	if err != nil {
		return nil, err
	}
	return file, nil
}

// dirFile presents a directory through fs.File. io/fs consumers that call
// Open on a directory can Stat it and, through ReadDir, list its children.
type dirFile struct {
	adapter *fsAdapter
	name    string
	info    fs.FileInfo
}

func (d *dirFile) Stat() (fs.FileInfo, error) { return d.info, nil }
func (d *dirFile) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.name, Err: errors.New("is a directory")}
}
func (d *dirFile) Close() error { return nil }
func (d *dirFile) ReadDir(n int) ([]fs.DirEntry, error) {
	entries, err := d.adapter.ReadDir(d.name)
	if err != nil {
		return nil, err
	}
	if n <= 0 || n >= len(entries) {
		return entries, nil
	}
	return entries[:n], nil
}

// ReadDir implements fs.ReadDirFS.
func (a *fsAdapter) ReadDir(name string) ([]fs.DirEntry, error) {
	p, err := a.toForensic(name)
	if err != nil {
		return nil, err
	}
	entries, err := a.fsys.ListDir(a.ctx, p)
	if err != nil {
		return nil, err
	}
	out := make([]fs.DirEntry, 0, len(entries))
	for i := range entries {
		out = append(out, dirEntry{entry: entries[i]})
	}
	return out, nil
}

// Stat implements fs.StatFS.
func (a *fsAdapter) Stat(name string) (fs.FileInfo, error) {
	p, err := a.toForensic(name)
	if err != nil {
		return nil, err
	}
	if p == "/" {
		return entryInfo{entry: Entry{Name: ".", Path: "/", IsDir: true}}, nil
	}
	entry, err := a.fsys.Stat(a.ctx, p)
	if err != nil {
		return nil, err
	}
	return entryInfo{entry: *entry}, nil
}

// ReadFile implements fs.ReadFileFS.
func (a *fsAdapter) ReadFile(name string) ([]byte, error) {
	file, err := a.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}

type dirEntry struct {
	entry Entry
}

func (d dirEntry) Name() string { return d.entry.Name }
func (d dirEntry) IsDir() bool  { return d.entry.IsDir }
func (d dirEntry) Type() fs.FileMode {
	if d.entry.IsDir {
		return fs.ModeDir
	}
	if d.entry.IsSymlink {
		return fs.ModeSymlink
	}
	return 0
}
func (d dirEntry) Info() (fs.FileInfo, error) { return entryInfo{entry: d.entry}, nil }

type entryInfo struct {
	entry Entry
}

func (i entryInfo) Name() string {
	if i.entry.Name != "" {
		return i.entry.Name
	}
	return path.Base(i.entry.Path)
}

func (i entryInfo) Size() int64 {
	if i.entry.Size > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(i.entry.Size)
}

func (i entryInfo) Mode() fs.FileMode {
	mode := fs.FileMode(i.entry.Mode & 0o777)
	if i.entry.IsDir {
		mode |= fs.ModeDir | 0o555
	} else {
		mode |= 0o444
	}
	if i.entry.IsSymlink {
		mode |= fs.ModeSymlink
	}
	return mode
}

func (i entryInfo) ModTime() time.Time { return i.entry.Modified }
func (i entryInfo) IsDir() bool        { return i.entry.IsDir }
func (i entryInfo) Sys() any           { return i.entry }

// Stat implements fs.File for File handles, using the entry captured when the
// file was opened.
func (f *File) Stat() (fs.FileInfo, error) {
	return entryInfo{entry: f.entry}, nil
}

var (
	_ fs.ReadDirFile = (*dirFile)(nil)
	_ fs.File        = (*File)(nil)
	_ fs.FileInfo    = entryInfo{}
	_ fs.DirEntry    = dirEntry{}
)
