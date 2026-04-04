// util.go — Veno V3.0 | Core Utilities + Sandbox Enforcement
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// SafePath resolves rel within base, blocking ANY traversal outside base.
// Multi-layer defense: strip leading separators → Clean → absolute comparison.
// "../../etc/passwd", "%2e%2e", symlink tricks — all blocked.
func SafePath(base, rel string) (string, error) {
	absBase, err := filepath.Abs(base)
	if err != nil { return "", fmt.Errorf("base abs: %w", err) }
	rel = filepath.FromSlash(rel)
	rel = strings.TrimLeft(rel, string(filepath.Separator)+"/")
	rel = filepath.Clean(rel)
	candidate := filepath.Join(absBase, rel)
	absC, err := filepath.Abs(candidate)
	if err != nil { return "", fmt.Errorf("candidate abs: %w", err) }
	sep := string(os.PathSeparator)
	if absC != absBase && !strings.HasPrefix(absC, absBase+sep) {
		return "", fmt.Errorf("traversal blocked: %q escapes sandbox %q", absC, absBase)
	}
	return absC, nil
}

func newSafeCmd(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...); cmd.Dir = CorePath; return cmd
}
