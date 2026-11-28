package filesystem

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSearchSelectionAndRedactedContext(t *testing.T) {
	mgr, root := setupTestFS(t)
	write := func(name, body string) {
		t.Helper()
		name = filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(".gitignore", "pkg/generated/\n*.ignored.txt\n")
	write("pkg/generated/file.txt", "find me")
	write("pkg/a.ignored.txt", "find me")
	write("pkg/.ci/source.txt", "-----BEGIN PRIVATE KEY-----\nfixture line 1\nfixture line 2\nfind me\nfixture line 4\n-----END PRIVATE KEY-----\nlast line\n")
	for _, forceGo := range []bool{true, false} {
		t.Run(fmt.Sprint("forceGo=", forceGo), func(t *testing.T) {
			if _, err := exec.LookPath("rg"); !forceGo && err != nil {
				t.Skip("ripgrep unavailable")
			}
			opts := SearchOptions{WorkspaceID: "demo", Path: "pkg", Glob: "*.txt", Query: "find me", ContextLines: 1, ForceGoEngine: forceGo, MaxResults: 1}
			result, err := mgr.SearchWithOptions(opts)
			if err != nil || len(result.Matches) != 1 || result.Truncated {
				t.Fatalf("expected one visible match, got %+v, %v", result, err)
			}
			if !forceGo && result.Engine != "ripgrep" {
				t.Fatal("ripgrep was available but not used")
			}
			hit := result.Matches[0]
			if hit.Path != "pkg/.ci/source.txt" || hit.LineNumber != 4 || len(hit.ContextBefore) != 1 || len(hit.ContextAfter) != 1 ||
				strings.Contains(fmt.Sprint(hit), "fixture") || strings.Contains(hit.Line, opts.Query) {
				t.Fatalf("context did not redact the complete block: %+v", hit)
			}
			respect := false
			opts.RespectGitignore = &respect
			result, err = mgr.SearchWithOptions(opts)
			if err != nil || len(result.Matches) != 1 || !result.Truncated {
				t.Fatalf("expected another eligible hit with .gitignore disabled: %+v, %v", result, err)
			}
			opts.Path, opts.Query, opts.ContextLines = "pkg/.ci/source.txt", "last line", 0
			result, err = mgr.SearchWithOptions(opts)
			if err != nil || len(result.Matches) != 1 || result.Matches[0].LineNumber != 7 || result.Matches[0].Line != "last line" {
				t.Fatalf("expected content after the block at its original line: %+v, %v", result, err)
			}
		})
	}
	for _, query := range []struct {
		path  string
		count int
	}{{"pkg", 1}, {"pkg/generated", 0}} {
		found, err := mgr.Glob(GlobOptions{WorkspaceID: "demo", Path: query.path, Pattern: "*.txt"})
		if err != nil || len(found.Entries) != query.count {
			t.Fatalf("glob %s should inherit root ignores: %+v, %v", query.path, found, err)
		}
	}
}

func TestGitignoreContentsCanBeReincluded(t *testing.T) {
	mgr, root := setupTestFS(t)
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("sub/**\n!sub/keep.go\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "keep.go"), []byte("package demo"), 0o644); err != nil {
		t.Fatal(err)
	}
	results, err := mgr.Glob(GlobOptions{WorkspaceID: "demo", Path: "sub", Pattern: "*"})
	if err != nil || len(results.Entries) != 1 || results.Entries[0].Path != "sub/keep.go" {
		t.Fatalf("gitignore negation should keep the selected child: %+v, %v", results, err)
	}
}
