#!/usr/bin/env bash
# One-time dev tool: generate testdata/e01/*.E01 (7 FS x 5 container variants)
# from real filesystem images with known injected files.
# Run under WSL (Ubuntu). Requires mkfs.fat, mkfs.exfat, mkfs.ext4, mkfs.xfs,
# mkfs.btrfs, mkfs.ntfs, mtools (mcopy), debugfs and ntfscp. No root needed.
#
# testdata/fs/ (raw images) is git-ignored; only the E01s and the injected.txt
# marker (repo-root testdata/) are committed.
set -euo pipefail
# Non-login shells (wsl -e bash script.sh) may miss /snap/bin where the
# snap-installed Go lives; surface it so `go run`/`go build` work regardless.
if ! command -v go >/dev/null 2>&1; then
    for g in /snap/bin /usr/local/go/bin /usr/lib/go/bin; do
        if [ -x "$g/go" ]; then
            export PATH="$g:$PATH"
            break
        fi
    done
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FSDIR="$ROOT/testdata/fs"
E01DIR="$ROOT/testdata/e01"
MARKER="$ROOT/testdata/injected.txt"
mkdir -p "$FSDIR" "$E01DIR"
rm -f "$E01DIR"/*.E01
echo "fixture" > /tmp/fixture.txt

# has_fixture returns 0 if the image bytes contain the injected file name/content
# (lowercase "fixture"); volume labels are uppercase FIXTURE so they don't match.
has_fixture() {
    grep -a -m1 -q "fixture" "$1"
}

# INJECTED accumulates the <base> names whose raw image actually holds a real
# injected fixture file; it is persisted to $MARKER so tests only assert
# injection-backed reads where the fixture truly has them.
INJECTED=""

# FAT32 (32 MiB) + injected file via mtools
truncate -s 32M "$FSDIR/fat32.img"
mkfs.fat -F 32 -n FIXTURE "$FSDIR/fat32.img" >/dev/null
mcopy -i "$FSDIR/fat32.img" /tmp/fixture.txt ::FIXTURE.TXT
if has_fixture "$FSDIR/fat32.img"; then INJECTED="$INJECTED fat32"; fi

# FAT16 (16 MiB) + injected file
truncate -s 16M "$FSDIR/fat16.img"
mkfs.fat -F 16 -n FIXTURE16 "$FSDIR/fat16.img" >/dev/null
mcopy -i "$FSDIR/fat16.img" /tmp/fixture.txt ::FIXTURE.TXT
if has_fixture "$FSDIR/fat16.img"; then INJECTED="$INJECTED fat16"; fi

# exFAT (32 MiB) + injected file via the dedicated cmd/exfat-inject tool. mtools
# (4.0.43) CANNOT write exFAT — mcopy fails "init :: non DOS media" — so the file
# entry set, FAT cluster chain and allocation bitmap are patched in-place by the
# dev-time tool instead. Best-effort: record exfat only if the injection landed.
truncate -s 32M "$FSDIR/exfat.img"
mkfs.exfat -n FIXTURE "$FSDIR/exfat.img" >/dev/null
if command -v go >/dev/null 2>&1; then
    (cd "$ROOT" && go run ./cmd/exfat-inject "$FSDIR/exfat.img")
else
    # Windows-side fallback: WSL runs Windows exes, but translate the Linux
    # path to a Windows path first so the exe can open it.
    echo "WARN: no Go in WSL; building Windows exfat-inject.exe" >&2
    (cd "$ROOT" && GOOS=windows GOARCH=amd64 go build -o /tmp/exfat-inject.exe ./cmd/exfat-inject)
    /tmp/exfat-inject.exe "$(wslpath -w "$FSDIR/exfat.img")"
fi
if has_fixture "$FSDIR/exfat.img"; then INJECTED="$INJECTED exfat"; fi

# ext4 (64 MiB) + injected file via debugfs (no mount/root needed)
truncate -s 64M "$FSDIR/ext4.img"
mkfs.ext4 -F -L FIXTURE "$FSDIR/ext4.img" >/dev/null 2>&1
debugfs -w -R "write /tmp/fixture.txt /fixture.txt" "$FSDIR/ext4.img" >/dev/null 2>&1
if has_fixture "$FSDIR/ext4.img"; then INJECTED="$INJECTED ext4"; fi

# XFS (512 MiB, empty; no mount-free injection tool). The XFS task asserts a
# REAL (non-fabricated) root listing, not a known injected file.
truncate -s 512M "$FSDIR/xfs.img"
mkfs.xfs -f -L FIXTURE "$FSDIR/xfs.img" >/dev/null 2>&1

# Btrfs (256 MiB) + injected files populated at mkfs time via --rootdir staging
# dir (NOT process substitution — verified to land fixture.txt in the root).
# The 64 KiB disk.bin exceeds the inline extent limit, so mkfs.btrfs writes it
# as a genuine on-disk extent (EXTENT_DATA type 1) — the parser's disk-extent
# read path (bytenr -> chunk map -> sectors) is exercised against real data.
# Content is deterministic: bytes(range(256)) repeated 256 times (= 65536 bytes).
truncate -s 256M "$FSDIR/btrfs.img"
rm -rf /tmp/btrfs_root
mkdir -p /tmp/btrfs_root
cp /tmp/fixture.txt /tmp/btrfs_root/fixture.txt
python3 -c "import sys; sys.stdout.buffer.write(bytes(range(256))*256)" > /tmp/btrfs_root/disk.bin
mkfs.btrfs -f -L FIXTURE --rootdir /tmp/btrfs_root "$FSDIR/btrfs.img" >/dev/null 2>&1
if has_fixture "$FSDIR/btrfs.img"; then INJECTED="$INJECTED btrfs"; fi

# NTFS (64 MiB) + injected file via ntfscp (mount-free). Prefer ntfscp; try to
# install ntfs-3g (best-effort) if it is missing.
truncate -s 64M "$FSDIR/ntfs.img"
mkfs.ntfs -F -L FIXTURE "$FSDIR/ntfs.img" >/dev/null 2>&1
if ! command -v ntfscp >/dev/null 2>&1; then
    echo "WARN: ntfscp missing; trying apt-get install ntfs-3g (best-effort)" >&2
    apt-get install -y ntfs-3g >/dev/null 2>&1 || true
fi
if command -v ntfscp >/dev/null 2>&1; then
    ntfscp -f "$FSDIR/ntfs.img" /tmp/fixture.txt /fixture.txt
    if has_fixture "$FSDIR/ntfs.img"; then INJECTED="$INJECTED ntfs"; fi
else
    echo "WARN: ntfscp unavailable; NTFS image has no injected file" >&2
fi

# Persist which filesystems have a real injected fixture.txt.
: > "$MARKER"
for f in $INJECTED; do
    printf '%s\n' "$f"
done >> "$MARKER"
echo "injected.txt: $(cat "$MARKER" | tr '\n' ' ')"

# Wrap everything into the 5-variant E01 cross-product.
if command -v go >/dev/null 2>&1; then
    (cd "$ROOT" && go run ./cmd/ewffixture gen-matrix "$FSDIR" "$E01DIR")
else
    # Windows-side fallback: WSL runs Windows exes, but translate the Linux
    # paths to Windows paths first so the exe can open them.
    echo "WARN: no Go in WSL; building Windows ewffixture.exe" >&2
    (cd "$ROOT" && GOOS=windows GOARCH=amd64 go build -o /tmp/ewffixture.exe ./cmd/ewffixture)
    /tmp/ewffixture.exe gen-matrix "$(wslpath -w "$FSDIR")" "$(wslpath -w "$E01DIR")"
fi
