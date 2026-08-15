package filesystem

import "strings"

// JoinPath joins a directory path and an entry name, keeping the "/" prefix
// convention used across all handlers. It is the single shared path joiner;
// the per-filesystem helpers (joinFATPath, joinExt4Path, joinXfsPath, pathJoin)
// it replaces were all equivalent to this, and the btrfs form was already a
// safe superset — it also collapses a trailing slash on dir, so a caller that
// passes "/bin/" yields "/bin/name" rather than "/bin//name".
func JoinPath(dir, name string) string {
	if dir == "" || dir == "/" {
		return "/" + name
	}
	return strings.TrimRight(dir, "/") + "/" + name
}
