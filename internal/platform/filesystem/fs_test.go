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

func TestAllowAllDirsAndFullPermissionsModes(t *testing.T) {
	mgr, _ := setupTestFS(t)

	// 在工作区之外创建另一个独立目录（包含普通文件与敏感 .ssh 私钥目录）
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "note.txt")
	outsideEnv := filepath.Join(outsideDir, ".env")
	outsideSSHDir := filepath.Join(outsideDir, ".ssh")
	outsideSSHKey := filepath.Join(outsideSSHDir, "id_ed25519")
	outsidePPK := filepath.Join(outsideDir, "server.ppk")
	if err := os.WriteFile(outsideFile, []byte("hello outside world\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outsideEnv, []byte("OUTSIDE_SECRET=abc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outsideSSHDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outsideSSHKey, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nSECRET\n-----END OPENSSH PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outsidePPK, []byte("PuTTY-User-Key-File-2: ssh-rsa\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// 1. 默认模式下严格拒绝工作区外绝对路径
	if _, err := mgr.Read("demo", outsideFile, 1, 10); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("默认模式应拒绝访问工作区外文件，实际 err=%v", err)
	}

	// 2. 开启「默认全部目录」后，可读取、列出、搜索、修改任意普通目录（支持留空 workspace_id 或直接传目录）
	mgr.SetAllowAllDirs(true)

	listRes, err := mgr.List("", outsideDir, 2, 50)
	if err != nil {
		t.Fatalf("全部目录模式下 List 工作区外目录失败: %v", err)
	}
	foundNote := false
	for _, e := range listRes.Entries {
		if strings.HasSuffix(e.Path, "note.txt") {
			foundNote = true
		}
		if strings.Contains(e.Path, ".ssh") || strings.HasSuffix(e.Path, ".env") || strings.HasSuffix(e.Path, ".ppk") {
			t.Fatalf("列表不应暴露敏感目录或私钥文件: %s", e.Path)
		}
	}
	if !foundNote {
		t.Fatalf("全部目录模式下未列出工作区外文件 note.txt: %+v", listRes.Entries)
	}

	readRes, err := mgr.Read("", outsideFile, 1, 10)
	if err != nil || !strings.Contains(readRes.Content, "hello outside world") {
		t.Fatalf("全部目录模式下读取工作区外文件失败: err=%v res=%+v", err, readRes)
	}

	searchRes, err := mgr.SearchInPath(outsideDir, "", "outside world", false, "", 20)
	if err != nil || len(searchRes.Matches) != 1 {
		t.Fatalf("全部目录模式下 SearchInPath 失败: err=%v res=%+v", err, searchRes)
	}

	patchRes, err := mgr.ApplyPatch(PatchRequest{
		WorkspaceID:    "",
		Path:           outsideFile,
		ExpectedSHA256: readRes.SHA256,
		Edits:          []PatchEdit{{OldText: "outside world", NewText: "any dir"}},
	})
	if err != nil || !strings.Contains(patchRes.UnifiedDiff, "+hello any dir") {
		t.Fatalf("全部目录模式下修改工作区外文件失败: err=%v res=%+v", err, patchRes)
	}

	// 3. 即使同时开启「全部权限」与「默认全部目录」，SSH 密钥目录、私钥与 .env 也永远禁止 CRUD 和查看目录
	mgr.SetFullPermissions(true)

	// 直接查看 .ssh 目录本身（无论是通过 path 还是直接作为 workspace_id）都必须被拒绝
	if _, err := mgr.List("", outsideSSHDir, 2, 50); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("期望禁止列出 .ssh 目录，实际 err=%v", err)
	}
	if _, err := mgr.List(outsideSSHDir, "", 2, 50); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("期望禁止将 .ssh 作为 workspace_id 列出，实际 err=%v", err)
	}
	if _, err := mgr.Read("", outsideSSHKey, 1, 10); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("期望禁止读取 SSH 私钥，实际 err=%v", err)
	}
	if _, err := mgr.ApplyPatch(PatchRequest{
		WorkspaceID:     "",
		Path:            filepath.Join(outsideSSHDir, "authorized_keys"),
		CreateIfMissing: true,
		Edits:           []PatchEdit{{OldText: "", NewText: "ssh-rsa HACKED\n"}},
	}); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("期望禁止写入 .ssh/authorized_keys，实际 err=%v", err)
	}
	if _, err := mgr.Read("", outsidePPK, 1, 10); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("期望禁止读取 .ppk 私钥，实际 err=%v", err)
	}
	if _, err := mgr.Read("", outsideEnv, 1, 10); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("期望禁止读取 .env 敏感文件，实际 err=%v", err)
	}
	// 搜索父目录绝不能搜出 .ssh 私钥内容
	secretSearch, err := mgr.SearchInPath("", outsideDir, "OPENSSH PRIVATE KEY", false, "", 20)
	if err != nil {
		t.Fatalf("搜索普通父目录失败: %v", err)
	}
	if len(secretSearch.Matches) != 0 {
		t.Fatalf("搜索绝不能命中 .ssh 目录内私钥内容: %+v", secretSearch.Matches)
	}

	// 4. 关闭「默认全部目录」后，立刻恢复边界隔离
	mgr.SetAllowAllDirs(false)
	if _, err := mgr.Read("demo", outsideFile, 1, 10); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("关闭全部目录模式后应恢复拦截工作区外文件，实际 err=%v", err)
	}
}
