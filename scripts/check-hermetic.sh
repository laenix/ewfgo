#!/usr/bin/env bash
# Hermeticity / platform-independence audit for ewfgo.
#
# Run under WSL, Git Bash, macOS or any bash with Go installed. Scans every
# non-test *.go source for accidental platform dependence (CGO, os/exec,
# syscall, unsafe, absolute path literals, endianness misuse, Windows path
# separators / drive letters) and exits nonzero when a hit is not whitelisted.
#
# This is a lint, not a rewrite: a hit that is legitimately cross-platform is
# justified in the task report and whitelisted below with a "# allowed:"
# comment so the audit stays green.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Every *.go except _test.go (test scaffolding may legitimately shell out) and
# hidden/scratch directories that are not part of the module. The while-loop
# (not mapfile) keeps the script compatible with macOS bash 3.2.
FILES=()
while IFS= read -r f; do
    FILES+=("$f")
done < <(find . -type f -name '*.go' \
    ! -name '*_test.go' \
    ! -path './.git/*' \
    ! -path './.fixture-test/*' \
    ! -path './.superpowers/*' \
    ! -path './.codegraph/*')
if [ "${#FILES[@]}" -eq 0 ]; then
    echo "error: no Go files scanned" >&2
    exit 1
fi

FAIL=0

# scan prints every file:line hit of $2 (an ERE pattern) in the scanned files
# after applying the $3 exclusion ERE, then fails unless $1 is a whitelisted
# pattern. The "$4" label prefixes the summary line.
scan() {
    local label="$1" pattern="$2" exclude="${3:-}"
    local hits
    if [ -n "$exclude" ]; then
        hits=$(grep -nE "$pattern" "${FILES[@]}" | grep -vE "$exclude" || true)
    else
        hits=$(grep -nE "$pattern" "${FILES[@]}" || true)
    fi
    if [ -n "$hits" ]; then
        echo "[$label]"
        echo "$hits"
        echo
        FAIL=1
    fi
}

echo "Auditing ${#FILES[@]} non-test Go files for platform dependence..."
echo

# 1. cgo / C interop. The bare word "cgo" also appears in justified comments
#    ("no CGO", "CGO_ENABLED=0"), so only actual interop constructs fail.
scan "cgo-import-C" 'import "C"' ''
scan "cgo-include" '^[[:space:]]*(//|#)[[:space:]]*#include' ''
scan "cgo-pragma" '//[[:space:]]*#cgo' ''
# review note only (never fails): the word "cgo" in comments must be benign.
note_cgo=$(grep -nE '[cC][gG][oO]' "${FILES[@]}" || true)
if [ -n "$note_cgo" ]; then
    echo "[note] 'cgo' appears (justified comments only, see report):"
    echo "$note_cgo"
    echo
fi

# 2. Runtime external processes.
scan "os-exec" '"os/exec"'

# 3. syscall package / constants in library code. cmd/ is allowed os/signal
#    (preferred over syscall for signals) but any syscall use is still flagged.
scan "syscall" '("syscall"|syscall\.)'

# 4. unsafe.
scan "unsafe" '("unsafe"|unsafe\.Pointer)'

# 5. Absolute path literals (quoted): a forensic library must never embed host
#    OS paths; on-disk fixture paths in tests use filepath.Join and are excluded
#    here (tests are scanned out). "/tmp/..." etc. in a Go string literal is a
#    real red flag.
scan "abs-path" '"/tmp/|"/var/|"/dev/|"/usr/|"/etc/|"/home/|"/opt/'

# 6. binary. endianness: every use must name an explicit endianness. Only the
#    two explicit endianness selectors are whitelisted; anything else (notably
#    binary.NativeEndian, which is platform-dependent) is flagged.
binary_misuse=$(grep -n 'binary\.' "${FILES[@]}" | grep -vE '\.(LittleEndian|BigEndian)' || true)
if [ -n "$binary_misuse" ]; then
    echo "[binary-endianness]"
    echo "$binary_misuse"
    echo
    FAIL=1
fi

# 7. Windows drive-letter path literals (e.g. C:\...) in source. The escaped
#    form is letter-colon-TWO backslashes (one literal backslash in a Go
#    string); "%d:\n" style format escapes have only one backslash and are not
#    flagged.
#    allowed: none today; a legit drive-letter constant would be justified here.
scan "drive-letter" '[A-Za-z]:[\\][\\]' ''

# 8. Escaped backslashes (two consecutive literal backslashes in source) mark a
#    Windows path or a hand-rolled separator. The single legit use is the
#    normalizeInternalPath helper in filesystem.go, which translates '\' to '/'
#    by design (that is the whole point of the helper); it is whitelisted by
#    file and printed as a note.
bs_hits=$(grep -nE '[\\][\\]' "${FILES[@]}" || true)
if [ -n "$bs_hits" ]; then
    bs_unallowed=$(printf '%s\n' "$bs_hits" | grep -vE '^\./filesystem\.go:' || true)
    if [ -n "$bs_unallowed" ]; then
        echo "[escaped-backslash]"
        echo "$bs_unallowed"
        echo
        FAIL=1
    fi
    bs_allowed=$(printf '%s\n' "$bs_hits" | grep -E '^\./filesystem\.go:' || true)
    if [ -n "$bs_allowed" ]; then
        echo "[note] escaped backslashes (whitelisted: normalizeInternalPath in filesystem.go):"
        echo "$bs_allowed"
        echo
    fi
fi

# 9. Internal-path splitting: filesystem handlers split caller paths on a
#    literal "/". This is the documented internal convention (E01 contents are
#    OS-neutral, '/' -separated names); the public ewf layer normalizes '\' ->
#    '/' before delegating (filesystem.go normalizeInternalPath). Every hit is a
#    POSIX-internal path and is whitelisted/justified, not a bug.
#    allowed: filesystem handlers' internal path split.
split_all=$(grep -nE 'strings\.Split\([^)]*"/"' "${FILES[@]}" || true)
if [ -n "$split_all" ]; then
    split_review=$(printf '%s\n' "$split_all" | grep -E '^\./internal/filesystem/' || true)
    split_other=$(printf '%s\n' "$split_all" | grep -vE '^\./internal/filesystem/' || true)
    if [ -n "$split_other" ]; then
        echo "[strings-split-slash]"
        echo "$split_other"
        echo
        FAIL=1
    fi
    if [ -n "$split_review" ]; then
        echo "[note] strings.Split(p, \"/\") in filesystem handlers (POSIX-internal names; whitelisted):"
        echo "$split_review"
        echo
    fi
fi

if [ "$FAIL" -eq 0 ]; then
    echo "✓ hermetic: no unwhitelisted platform-dependence patterns"
    exit 0
fi
echo "HERMETIC AUDIT FAILED: unwhitelisted platform-dependence pattern(s) above" >&2
exit 1
