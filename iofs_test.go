package forensic_test

import (
	"context"
	"io/fs"
	"testing"

	forensic "github.com/laenix/ewfgo"
)

func TestAsFSWalksFilesystem(t *testing.T) {
	ctx := context.Background()
	img, err := forensic.Open(ctx, fixture(t, "fat16-encase6-zlib.E01"), forensic.Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer img.Close()
	parts, err := img.Partitions(ctx)
	if err != nil || len(parts) == 0 {
		t.Fatalf("Partitions: %v (%d)", err, len(parts))
	}
	fsys, err := parts[0].OpenFilesystem(ctx)
	if err != nil {
		t.Fatalf("OpenFilesystem: %v", err)
	}
	defer fsys.Close()

	vfs := forensic.AsFS(ctx, fsys)
	root, err := vfs.Open(".")
	if err != nil {
		t.Fatalf("Open(.): %v", err)
	}
	rootInfo, err := root.Stat()
	if err != nil || !rootInfo.IsDir() {
		t.Fatalf("root Stat = %+v, %v", rootInfo, err)
	}
	dir, ok := root.(fs.ReadDirFile)
	if !ok {
		t.Fatal("root file does not implement fs.ReadDirFile")
	}
	children, err := dir.ReadDir(-1)
	root.Close()
	if err != nil || len(children) == 0 {
		t.Fatalf("root ReadDir = %d, %v", len(children), err)
	}

	data, err := fs.ReadFile(vfs, "FIXTURE.TXT")
	if err != nil {
		t.Fatalf("fs.ReadFile: %v", err)
	}
	if string(data) != "fixture\n" {
		t.Fatalf("content = %q", data)
	}

	info, err := fs.Stat(vfs, "FIXTURE.TXT")
	if err != nil {
		t.Fatalf("fs.Stat: %v", err)
	}
	if info.Name() != "FIXTURE.TXT" || info.Size() != 8 || info.IsDir() {
		t.Fatalf("info = %s %d %v", info.Name(), info.Size(), info.IsDir())
	}

	var visited []string
	err = fs.WalkDir(vfs, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		visited = append(visited, name)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
	found := false
	for _, name := range visited {
		if name == "FIXTURE.TXT" {
			found = true
		}
	}
	if !found {
		t.Fatalf("WalkDir did not visit FIXTURE.TXT: %v", visited)
	}

	if _, err := vfs.Open("../escape"); err == nil {
		t.Fatal("fs adapter accepted a parent traversal")
	}
}
