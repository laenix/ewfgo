#!/usr/bin/env bash
# Cross-platform build matrix gate for ewfgo.
#
# Run under WSL (or any Linux) with Go ≥1.24 installed.
#
# Proves the 7 toolchain-feasible (GOOS x GOARCH) pairs compile clean with
# CGO_ENABLED=0, produces the command binaries for each pair, and finishes with
# a native build + vet + test gate.
#
# Go rejects windows/riscv64 and darwin/riscv64 (`go tool dist list` omits
# them; RISC-V is linux-only), so the matrix is exactly the 7 pairs below:
# x86/amd64 and arm/arm64 on Windows/Linux/macOS, plus riscv64 on Linux.
set -euo pipefail

# Each entry is "GOOS GOARCH".
MATRIX=(
    "windows amd64"
    "windows arm64"
    "linux amd64"
    "linux arm64"
    "linux riscv64"
    "darwin amd64"
    "darwin arm64"
)

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v go >/dev/null 2>&1; then
    echo "error: 'go' not found on PATH (run under WSL or any Linux with Go >= 1.24)" >&2
    exit 1
fi

BUILDDIR="$(mktemp -d)"
trap 'rm -rf "$BUILDDIR"' EXIT

FAILED=""
for pair in "${MATRIX[@]}"; do
    read -r os arch <<<"$pair"
    bindir="$BUILDDIR/$os-$arch"
    errlog="$BUILDDIR/$os-$arch.err"

    echo "== GOOS=$os GOARCH=$arch =="

    # Build every package (libraries + examples) for the target.
    if ! CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build ./... 2>"$errlog"; then
        echo "  [FAIL] go build ./... failed" >&2
        cat "$errlog" >&2
        FAILED="$FAILED $os/$arch"
        continue
    fi

    # Build the command binaries for the target so real executables exist.
    mkdir -p "$bindir"
    if ! CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -o "$bindir" ./cmd/... 2>>"$errlog"; then
        echo "  [FAIL] go build -o $bindir ./cmd/... failed" >&2
        cat "$errlog" >&2
        FAILED="$FAILED $os/$arch"
        continue
    fi

    # vet: best-effort for cross targets. Recent Go vets stdlib-only code under
    # a foreign GOOS/GOARCH, but if a specific pair fails for vet only it is
    # recorded without blocking the build gate.
    if CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go vet ./... 2>"$BUILDDIR/$os-$arch.vet"; then
        echo "  vet ok"
    else
        echo "  [WARN] go vet failed for $os/$arch (recorded; not blocking the build gate):" >&2
        cat "$BUILDDIR/$os-$arch.vet" >&2
    fi

    echo "  ✓ $os/$arch"
done

echo
echo "=== Produced binaries ==="
find "$BUILDDIR" -maxdepth 2 -type f ! -name '*.err' ! -name '*.vet' | sort | while read -r b; do
    echo "  $(basename "$(dirname "$b")")/$(basename "$b")"
done

if [ -n "$FAILED" ]; then
    echo "BUILD MATRIX FAILED for:$FAILED" >&2
    exit 1
fi

echo
echo "=== Native local gate (host GOOS=$(go env GOOS) GOARCH=$(go env GOARCH)) ==="
go build ./...
go vet ./...
go test ./...
echo "✓ native build + vet + test green"
