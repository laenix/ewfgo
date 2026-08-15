package main

// exec-based CLI tests: TestMain builds the real ewftool binary once with
// `go build` into a temp dir, then each test runs that binary as a subprocess
// against the committed E01 fixtures in ../testdata/e01. This is the
// release-facing smoke test: it exercises the actual CLI (os.Args handling,
// exit codes, stdout formatting), not an in-process reimplementation.
//
// os/exec is used only in this _test.go file, which scripts/check-hermetic.sh
// excludes from its platform-dependency audit.

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var ewftoolBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ewftool-test")
	if err != nil {
		panic(err)
	}
	name := "ewftool"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	ewftoolBin = filepath.Join(dir, name)

	cmd := exec.Command("go", "build", "-o", ewftoolBin, ".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.RemoveAll(dir)
		panic("go build failed: " + err.Error())
	}

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type toolResult struct {
	stdout, stderr string
	exitCode       int
}

// runTool runs the built ewftool binary with args and captures its output.
func runTool(t *testing.T, args ...string) toolResult {
	t.Helper()
	var out, errBuf strings.Builder
	cmd := exec.Command(ewftoolBin, args...)
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err := cmd.Run()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("failed to run ewftool %v: %v", args, err)
		}
		code = ee.ExitCode()
	}
	return toolResult{stdout: out.String(), stderr: errBuf.String(), exitCode: code}
}

// fixturePath resolves a committed E01 fixture relative to the cmd/ test dir.
func fixturePath(name string) string {
	return filepath.Join("..", "testdata", "e01", name)
}

func TestEWFToolInfo(t *testing.T) {
	res := runTool(t, fixturePath("fat16-encase6-zlib.E01"), "info")
	if res.exitCode != 0 {
		t.Fatalf("info: exit %d, want 0\nstdout:\n%s\nstderr:\n%s", res.exitCode, res.stdout, res.stderr)
	}
	for _, want := range []string{
		"EWF Image Info",
		"Total Sectors:",
		"Partitions:",
		"1 found",
		"FAT16",
	} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("info: stdout missing %q\nstdout:\n%s", want, res.stdout)
		}
	}
}

func TestEWFToolFs(t *testing.T) {
	res := runTool(t, fixturePath("fat16-encase6-zlib.E01"), "fs")
	if res.exitCode != 0 {
		t.Fatalf("fs: exit %d, want 0\nstdout:\n%s\nstderr:\n%s", res.exitCode, res.stdout, res.stderr)
	}
	for _, want := range []string{
		"Filesystem Detection",
		"FAT16",
		"Disk Signature: 0x",
		"Boot Signature: 0xAA55",
	} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("fs: stdout missing %q\nstdout:\n%s", want, res.stdout)
		}
	}
}

func TestEWFToolLs(t *testing.T) {
	res := runTool(t, fixturePath("fat16-encase6-zlib.E01"), "ls")
	if res.exitCode != 0 {
		t.Fatalf("ls: exit %d, want 0\nstdout:\n%s\nstderr:\n%s", res.exitCode, res.stdout, res.stderr)
	}
	// The injected file FIXTURE.TXT ("fixture\n") must appear in the listing.
	if !strings.Contains(res.stdout, "FIXTURE.TXT") {
		t.Errorf("ls: stdout missing injected file FIXTURE.TXT\nstdout:\n%s", res.stdout)
	}
}

func TestEWFToolNoArgs(t *testing.T) {
	res := runTool(t)
	if res.exitCode != 1 {
		t.Fatalf("no args: exit %d, want 1", res.exitCode)
	}
	if !strings.Contains(res.stdout, "Usage: ewftool") {
		t.Errorf("no args: stdout missing usage\nstdout:\n%s", res.stdout)
	}
}

func TestEWFToolMissingImage(t *testing.T) {
	res := runTool(t, fixturePath("nonexistent.E01"), "info")
	if res.exitCode != 1 {
		t.Fatalf("missing image: exit %d, want 1", res.exitCode)
	}
	if strings.TrimSpace(res.stderr) == "" {
		t.Errorf("missing image: stderr empty, want an error message")
	}
}

func TestEWFToolUnknownCommand(t *testing.T) {
	res := runTool(t, fixturePath("fat16-encase6-zlib.E01"), "bogus")
	if res.exitCode != 1 {
		t.Fatalf("unknown command: exit %d, want 1\nstdout:\n%s", res.exitCode, res.stdout)
	}
	if !strings.Contains(res.stdout, "Unknown command:") {
		t.Errorf("unknown command: stdout missing error\nstdout:\n%s", res.stdout)
	}
}

func TestEWFToolVersion(t *testing.T) {
	res := runTool(t, "-version")
	if res.exitCode != 0 {
		t.Fatalf("-version: exit %d, want 0\nstdout:\n%s\nstderr:\n%s", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.HasPrefix(res.stdout, "ewftool ") {
		t.Errorf("-version: stdout does not start with %q\nstdout:\n%s", "ewftool ", res.stdout)
	}
	// Local builds print "dev"; release builds stamp the tag via ldflags.
	if !strings.Contains(res.stdout, "dev") {
		t.Errorf("-version: stdout missing version\nstdout:\n%s", res.stdout)
	}
}
