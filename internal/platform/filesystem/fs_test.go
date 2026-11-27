package filesystem

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nodebridge/internal/config"
)

func setupTestFS(t *testing.T) (*Manager, string) {
	t.Helper()
	wsDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(wsDir, "hello.go"), []byte("package main\n\nfunc main() {\n\tprintln(\"hi\")\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wsDir, ".env"), []byte("API_KEY=super_secret_123\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(wsDir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wsDir, "sub", "id_rsa"), []byte("PRIVATE KEY"), 0o644); err != nil {
		t.Fatal(err)
	}

	mgr, err := NewManager([]config.WorkspaceConfig{
		{ID: "demo", Root: wsDir, ReadOnly: false},
	}, nil)
	if err != nil {
		t.Fatalf("NewManager 失败: %v", err)
	}
	return mgr, wsDir
}

func TestSecurityPathBlocking(t *testing.T) {
	mgr, _ := setupTestFS(t)

	cases := []struct {
		name string
		path string
	}{
		{"父目录穿越", "../outside.txt"},
		{"深层穿越", "sub/../../outside.txt"},
		{"UNC网络路径", `\\evil-server\share\file.txt`},
		{"双斜杠UNC", `//evil-server/share/file.txt`},
		{"Windows设备路径", `\\.\PhysicalDrive0`},
		{"ADS数据流", `hello.go:hidden_stream`},
		{"Windows保留名", `sub/NUL.txt`},
		{"敏感文件.env", `.env`},
		{"敏感私钥id_rsa", `sub/id_rsa`},
		{"NUL字节注入", "hello.go\x00.txt"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mgr.Resolve("demo", tc.path, false)
			if !errors.Is(err, ErrAccessDenied) {
				t.Fatalf("期望 %q 被 ErrAccessDenied 拦截，实际 err=%v", tc.path, err)
			}
		})
	}
}

func TestReadPatchOptimisticLockAndCreate(t *testing.T) {
	mgr, _ := setupTestFS(t)

	// 1. 读取并获取 sha256
	readRes, err := mgr.Read("demo", "hello.go", 1, 10)
	if err != nil {
		t.Fatalf("Read 失败: %v", err)
	}
	if readRes.SHA256 == "" || !strings.Contains(readRes.Content, `println("hi")`) {
		t.Fatalf("Read 结果异常: %+v", readRes)
	}

	// 2. 携带错误 sha256 必须触发乐观锁冲突
	_, err = mgr.ApplyPatch(PatchRequest{
		WorkspaceID:    "demo",
		Path:           "hello.go",
		ExpectedSHA256: "0000000000000000000000000000000000000000000000000000000000000000",
		Edits:          []PatchEdit{{OldText: `"hi"`, NewText: `"hello"`}},
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("期望乐观锁触发 ErrConflict，实际 err=%v", err)
	}

	// 3. 携带正确 sha256 成功补丁并返回 Unified Diff
	patchRes, err := mgr.ApplyPatch(PatchRequest{
		WorkspaceID:    "demo",
		Path:           "hello.go",
		ExpectedSHA256: readRes.SHA256,
		Edits:          []PatchEdit{{OldText: `println("hi")`, NewText: `println("hello world")`}},
	})
	if err != nil {
		t.Fatalf("ApplyPatch 失败: %v", err)
	}
	if patchRes.NewSHA256 == readRes.SHA256 || !strings.Contains(patchRes.UnifiedDiff, `+	println("hello world")`) {
		t.Fatalf("PatchResult 异常: %+v", patchRes)
	}

	// 4. 支持新建文件
	createRes, err := mgr.ApplyPatch(PatchRequest{
		WorkspaceID:     "demo",
		Path:            "sub/new_file.txt",
		CreateIfMissing: true,
		Edits:           []PatchEdit{{OldText: "", NewText: "created line 1\n"}},
	})
	if err != nil {
		t.Fatalf("新建文件失败: %v", err)
	}
	if !createRes.Created {
		t.Fatalf("期望 Created=true")
	}

	// 5. 列表与搜索均不能泄露 .env 内容
	listRes, err := mgr.List("demo", ".", 3, 100)
	if err != nil {
		t.Fatalf("List 失败: %v", err)
	}
	for _, e := range listRes.Entries {
		if strings.Contains(e.Path, ".env") || strings.Contains(e.Path, "id_rsa") {
			t.Fatalf("List 泄露了敏感文件: %s", e.Path)
		}
	}
	searchRes, err := mgr.Search("demo", "super_secret_123", false, "", 50)
	if err != nil {
		t.Fatalf("Search 失败: %v", err)
	}
	if len(searchRes.Matches) != 0 {
		t.Fatalf("Search 泄露了 .env 敏感内容: %+v", searchRes.Matches)
	}
}
