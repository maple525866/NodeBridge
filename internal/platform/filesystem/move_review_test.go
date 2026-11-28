package filesystem

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"nodebridge/internal/config"
)

func TestDirectoryMoveChecksMappedDestinationChildren(t *testing.T) {
	root := t.TempDir()
	mgr, err := NewManager([]config.WorkspaceConfig{{
		ID: "demo", Root: root, DenyGlobs: []string{"release/settings.txt"},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "draft"), 0o755); err != nil {
		t.Fatal(err)
	}
	oldFile := filepath.Join(root, "draft", "settings.txt")
	if err := os.WriteFile(oldFile, []byte("settings"), 0o600); err != nil {
		t.Fatal(err)
	}
	req := MoveRequest{WorkspaceID: "demo", SourcePath: "draft", DestinationPath: "release"}
	if _, err := mgr.PreviewMove(req); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("preview should reject the protected destination child: %v", err)
	}
	if _, err := mgr.Move(req); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("move should reject the protected destination child: %v", err)
	}
	if data, err := os.ReadFile(oldFile); err != nil || string(data) != "settings" {
		t.Fatalf("source changed: %q, %v", data, err)
	}
	if _, err := os.Lstat(filepath.Join(root, "release")); !os.IsNotExist(err) {
		t.Fatalf("unexpected destination: %v", err)
	}
}

func TestCrossVolumeMovePreservesEntries(t *testing.T) {
	mgr, root := setupTestFS(t)
	mgr.SetAllowAllDirs(true)

	dir := "/dev/shm"
	if runtime.GOOS == "windows" {
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		if strings.EqualFold(filepath.VolumeName(cwd), filepath.VolumeName(root)) {
			t.Skip("workspace and temporary directory use the same volume")
		}
		dir = cwd
	}
	target, err := os.MkdirTemp(dir, ".nodebridge-cross-volume-test-*")
	if err != nil {
		t.Skipf("second writable filesystem unavailable: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(target); err != nil {
			t.Error(err)
		}
	})
	probe := filepath.Join(root, "probe")
	if err := os.WriteFile(probe, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(probe, filepath.Join(target, "probe")); err == nil {
		t.Skip("test directories use the same filesystem")
	}
	t.Logf("cross-volume source %s, destination %s", root, target)

	src := filepath.Join(root, "source.txt")
	dst := filepath.Join(target, "target.txt")
	if err := os.WriteFile(src, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("destination"), 0o600); err != nil {
		t.Fatal(err)
	}
	checkFailure := func(sourcePath, destinationPath string, overwrite bool) {
		t.Helper()
		_, err := mgr.Move(MoveRequest{WorkspaceID: "demo", SourcePath: sourcePath, DestinationPath: destinationPath, Overwrite: overwrite})
		if err == nil || !strings.Contains(err.Error(), "同一文件系统") {
			t.Fatalf("expected cross-volume refusal, got %v", err)
		}
	}
	checkFailure(src, dst, true)
	for p, want := range map[string]string{src: "source", dst: "destination"} {
		if data, err := os.ReadFile(p); err != nil || string(data) != want {
			t.Fatalf("unexpected contents at %q: %q, %v", p, data, err)
		}
	}
	srcTree := filepath.Join(root, "tree")
	if err := os.Mkdir(srcTree, 0o755); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(srcTree, "child.txt")
	if err := os.WriteFile(child, []byte("child"), 0o600); err != nil {
		t.Fatal(err)
	}
	dstTree := filepath.Join(target, "tree")
	checkFailure(srcTree, dstTree, false)
	if data, err := os.ReadFile(child); err != nil || string(data) != "child" {
		t.Fatalf("source tree changed: %q, %v", data, err)
	}
	if _, err := os.Lstat(dstTree); !os.IsNotExist(err) {
		t.Fatalf("unexpected destination tree: %v", err)
	}
}
