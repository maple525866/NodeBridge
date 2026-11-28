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

func TestWriteBoundsBothVersions(t *testing.T) {
	m, dir := setupTestFS(t)
	dst := filepath.Join(dir, "existing.txt")
	req := WriteRequest{WorkspaceID: "demo", Path: "existing.txt", Content: "short", Overwrite: true}
	if err := os.WriteFile(dst, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(dst, defaultReadMaxBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := m.PreviewWrite(req); err == nil {
		t.Fatal("oversize existing file was accepted")
	}
	if err := os.WriteFile(dst, []byte("old\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	req.Content = strings.Repeat("\n", defaultReadMaxBytes/2+1)
	if _, err := m.WriteFile(req); err == nil {
		t.Fatal("oversize CRLF conversion was accepted")
	}
}

func TestWriteRejectsNULAfterTextHeader(t *testing.T) {
	m, root := setupTestFS(t)
	binary := strings.Repeat("a", 8192) + "\x00"
	req := WriteRequest{WorkspaceID: "demo", Path: "sample.dat", Content: binary, Overwrite: true}
	if _, err := m.WriteFile(req); err == nil {
		t.Fatal("created a file containing NUL")
	}
	if err := os.WriteFile(filepath.Join(root, req.Path), []byte(binary), 0o600); err != nil {
		t.Fatal(err)
	}
	req.Content = "replacement"
	if _, err := m.WriteFile(req); err == nil {
		t.Fatal("overwrote a file containing NUL")
	}
}

func TestMutationRequiresApprovedPaths(t *testing.T) {
	m, root := setupTestFS(t)
	approved := filepath.Join(root, "previous")
	if _, err := m.WriteFile(WriteRequest{WorkspaceID: "demo", Path: "new.go", ApprovedPath: approved}); !errors.Is(err, ErrConflict) {
		t.Fatalf("write expected path conflict, got %v", err)
	}
	if _, err := m.Delete(DeleteRequest{WorkspaceID: "demo", Path: "hello.go", ApprovedPath: approved}); !errors.Is(err, ErrConflict) {
		t.Fatalf("delete expected path conflict, got %v", err)
	}
	for _, req := range []MoveRequest{
		{WorkspaceID: "demo", SourcePath: "hello.go", DestinationPath: "new.go", ApprovedSource: approved},
		{WorkspaceID: "demo", SourcePath: "hello.go", DestinationPath: "new.go", ApprovedDestination: approved},
	} {
		if _, err := m.Move(req); !errors.Is(err, ErrConflict) {
			t.Fatalf("move expected path conflict, got %v", err)
		}
	}
}

func TestMoveFailurePreservesDestination(t *testing.T) {
	m, dir := setupTestFS(t)
	if err := os.Mkdir(filepath.Join(dir, "source"), 0o755); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "keep.txt")
	if err := os.WriteFile(dst, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Move(MoveRequest{WorkspaceID: "demo", SourcePath: "source", DestinationPath: "keep.txt", Overwrite: true}); err == nil {
		t.Fatal("replaced regular file with a directory")
	}
	if got, err := os.ReadFile(dst); err != nil || string(got) != "keep" {
		t.Fatalf("destination changed after failed move: %q, %v", got, err)
	}
}

func TestMoveDeleteProtectNestedWorkspaceRoots(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "projects", "nested")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager([]config.WorkspaceConfig{{ID: "outer", Root: root}, {ID: "inner", Root: nested}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"projects/nested", "projects"} {
		if _, err := m.PreviewDelete(DeleteRequest{WorkspaceID: "outer", Path: path, Recursive: true}); !errors.Is(err, ErrAccessDenied) {
			t.Fatalf("delete %s: %v", path, err)
		}
		if _, err := m.PreviewMove(MoveRequest{WorkspaceID: "outer", SourcePath: path, DestinationPath: "new"}); !errors.Is(err, ErrAccessDenied) {
			t.Fatalf("move %s: %v", path, err)
		}
	}
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
		{"Windows尾随点号绕过", `nodebridge.yaml.`},
		{"Windows尾随空格绕过", `server.key `},
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

func TestSymlinkCannotBypassSecretGuardInListAndSearch(t *testing.T) {
	mgr, wsDir := setupTestFS(t)
	outsideDir := t.TempDir()
	outsideSSH := filepath.Join(outsideDir, ".ssh")
	if err := os.MkdirAll(outsideSSH, 0o700); err != nil {
		t.Fatal(err)
	}
	outsideKey := filepath.Join(outsideSSH, "id_rsa")
	if err := os.WriteFile(outsideKey, []byte("OUTSIDE_SSH_PRIVATE_KEY_DATA\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	linkInside := filepath.Join(wsDir, "innocent_env.txt")
	if err := os.Symlink(filepath.Join(wsDir, ".env"), linkInside); err != nil {
		t.Skipf("当前环境无创建符号链接权限，跳过符号链接绕过测试: %v", err)
	}
	linkOutside := filepath.Join(wsDir, "innocent_key.txt")
	if err := os.Symlink(outsideKey, linkOutside); err != nil {
		t.Skipf("当前环境无创建外部符号链接权限，跳过: %v", err)
	}

	// 默认模式与双开模式下，List 和 Search 均不得泄露指向 .env 或外部 .ssh/id_rsa 的符号链接内容
	for _, enableAll := range []bool{false, true} {
		mgr.SetAllowAllDirs(enableAll)
		mgr.SetFullPermissions(enableAll)

		listRes, err := mgr.List("demo", ".", 3, 100)
		if err != nil {
			t.Fatalf("List 失败 (all=%v): %v", enableAll, err)
		}
		for _, e := range listRes.Entries {
			if strings.Contains(e.Path, "innocent_env.txt") || strings.Contains(e.Path, "innocent_key.txt") {
				t.Fatalf("List 不应暴露指向敏感文件的符号链接 (all=%v): %s", enableAll, e.Path)
			}
		}

		s1, err := mgr.Search("demo", "super_secret_123", false, "", 50)
		if err != nil || len(s1.Matches) != 0 {
			t.Fatalf("Search 不得通过同工作区符号链接泄露 .env (all=%v): err=%v matches=%+v", enableAll, err, s1)
		}
		s2, err := mgr.Search("demo", "OUTSIDE_SSH_PRIVATE_KEY_DATA", false, "", 50)
		if err != nil || len(s2.Matches) != 0 {
			t.Fatalf("Search 不得通过跨目录符号链接泄露 SSH 私钥 (all=%v): err=%v matches=%+v", enableAll, err, s2)
		}
	}
}

func TestWriteMoveAndDeleteWithSecurityAndRiskFlags(t *testing.T) {
	mgr, wsDir := setupTestFS(t)

	// 1. workspace.write：新建、overwrite=false 拒绝、乐观锁、覆写保留 CRLF、禁止二进制与敏感路径
	w1, err := mgr.WriteFile(WriteRequest{
		WorkspaceID: "demo",
		Path:        "notes/app.txt",
		Content:     "line1\r\nline2\r\n",
		Overwrite:   true,
	})
	if err != nil || !w1.Created || w1.NewSHA256 == "" {
		t.Fatalf("新建文件失败: err=%v res=%+v", err, w1)
	}
	if _, err := mgr.WriteFile(WriteRequest{
		WorkspaceID: "demo",
		Path:        "notes/app.txt",
		Content:     "conflict",
		Overwrite:   false,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("overwrite=false 时覆盖已有文件应返回 ErrConflict，实际: %v", err)
	}
	if _, err := mgr.WriteFile(WriteRequest{
		WorkspaceID:    "demo",
		Path:           "notes/app.txt",
		Content:        "bad lock",
		ExpectedSHA256: "0000000000000000000000000000000000000000000000000000000000000000",
		Overwrite:      true,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("错误 expected_sha256 应触发 ErrConflict，实际: %v", err)
	}
	w2, err := mgr.WriteFile(WriteRequest{
		WorkspaceID:    "demo",
		Path:           "notes/app.txt",
		Content:        "line1\nline2_new\n",
		ExpectedSHA256: w1.NewSHA256,
		Overwrite:      true,
	})
	if err != nil || w2.Created || !strings.Contains(w2.UnifiedDiff, "+line2_new") {
		t.Fatalf("覆写文件失败: err=%v res=%+v", err, w2)
	}
	rawWritten, _ := os.ReadFile(filepath.Join(wsDir, "notes", "app.txt"))
	if !strings.Contains(string(rawWritten), "\r\n") {
		t.Fatalf("覆写已有 CRLF 文件应保留 CRLF 行尾，实际: %q", string(rawWritten))
	}
	if _, err := mgr.WriteFile(WriteRequest{
		WorkspaceID: "demo",
		Path:        "bin.dat",
		Content:     "abc\x00def",
		Overwrite:   true,
	}); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("workspace.write 应拒绝含 NUL 字节的二进制内容，实际: %v", err)
	}
	if _, err := mgr.WriteFile(WriteRequest{
		WorkspaceID: "demo",
		Path:        ".env",
		Content:     "HACK=1",
		Overwrite:   true,
	}); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("workspace.write 应拒绝写入 .env，实际: %v", err)
	}

	// 2. workspace.move：重命名文件、目标冲突保护、overwrite、防移入自身子目录与敏感目录拦截
	mvRes, err := mgr.Move(MoveRequest{
		WorkspaceID:     "demo",
		SourcePath:      "notes/app.txt",
		DestinationPath: "notes/renamed.txt",
	})
	if err != nil || mvRes.DestinationPath != "notes/renamed.txt" {
		t.Fatalf("移动文件失败: err=%v res=%+v", err, mvRes)
	}
	if _, err := mgr.Move(MoveRequest{
		WorkspaceID:     "demo",
		SourcePath:      "notes/renamed.txt",
		DestinationPath: "hello.go",
		Overwrite:       false,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("目标已存在且 overwrite=false 应返回 ErrConflict，实际: %v", err)
	}
	if _, err := mgr.Move(MoveRequest{
		WorkspaceID:     "demo",
		SourcePath:      "notes",
		DestinationPath: "notes/inside",
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("禁止将目录移动到自身子目录，实际: %v", err)
	}
	if _, err := mgr.Move(MoveRequest{
		WorkspaceID:     "demo",
		SourcePath:      "sub", // 内含 id_rsa 敏感文件
		DestinationPath: "sub_moved",
	}); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("禁止移动包含敏感私钥文件的目录，实际: %v", err)
	}

	// 3. workspace.delete：单文件 L1、非空目录未开 recursive 拒绝、开启 recursive 标记 L2、敏感目录拦截、符号链接不跟随删除目标
	pvFile, err := mgr.PreviewDelete(DeleteRequest{WorkspaceID: "demo", Path: "notes/renamed.txt"})
	if err != nil || pvFile.RecursiveNonEmpty || pvFile.IsDir {
		t.Fatalf("单文件删除预检异常: err=%v pv=%+v", err, pvFile)
	}
	if _, err := mgr.Delete(DeleteRequest{WorkspaceID: "demo", Path: "notes/renamed.txt"}); err != nil {
		t.Fatalf("删除单文件失败: %v", err)
	}
	// 空目录可直接删且不触发递归 L2
	pvEmptyDir, err := mgr.PreviewDelete(DeleteRequest{WorkspaceID: "demo", Path: "notes"})
	if err != nil || !pvEmptyDir.IsDir || pvEmptyDir.RecursiveNonEmpty {
		t.Fatalf("空目录删除预检异常: err=%v pv=%+v", err, pvEmptyDir)
	}
	if _, err := mgr.Delete(DeleteRequest{WorkspaceID: "demo", Path: "notes"}); err != nil {
		t.Fatalf("删除空目录失败: %v", err)
	}

	// 非空目录测试
	if err := os.MkdirAll(filepath.Join(wsDir, "tmp_dir", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wsDir, "tmp_dir", "nested", "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.PreviewDelete(DeleteRequest{WorkspaceID: "demo", Path: "tmp_dir", Recursive: false}); !errors.Is(err, ErrConflict) {
		t.Fatalf("非空目录未传 recursive=true 应返回 ErrConflict，实际: %v", err)
	}
	pvRec, err := mgr.PreviewDelete(DeleteRequest{WorkspaceID: "demo", Path: "tmp_dir", Recursive: true})
	if err != nil || !pvRec.RecursiveNonEmpty {
		t.Fatalf("非空目录 recursive=true 应标记 RecursiveNonEmpty=true: err=%v pv=%+v", err, pvRec)
	}
	if _, err := mgr.Delete(DeleteRequest{WorkspaceID: "demo", Path: "tmp_dir", Recursive: true}); err != nil {
		t.Fatalf("递归删除非空目录失败: %v", err)
	}
	if _, err := mgr.Delete(DeleteRequest{WorkspaceID: "demo", Path: "sub", Recursive: true}); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("禁止递归删除包含敏感私钥的目录 sub，实际: %v", err)
	}
	if _, err := mgr.Delete(DeleteRequest{WorkspaceID: "demo", Path: ".", Recursive: true}); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("禁止删除工作区根目录，实际: %v", err)
	}
}

func TestGlobAndEnhancedSearchDualEngine(t *testing.T) {
	mgr, wsDir := setupTestFS(t)

	// 构造 .gitignore、构建产物目录 dist/、多文件代码结构
	if err := os.WriteFile(filepath.Join(wsDir, ".gitignore"), []byte("ignored.log\nignored_dir/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wsDir, "ignored.log"), []byte("AuthToken should be ignored\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(wsDir, "ignored_dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wsDir, "ignored_dir", "hidden.go"), []byte("package x\n// AuthToken\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(wsDir, "dist"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wsDir, "dist", "bundle.js"), []byte("const AuthToken = 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(wsDir, "pkg", "auth"), 0o755); err != nil {
		t.Fatal(err)
	}
	authContent := "package auth\n\n// before line\nfunc VerifyAuthToken() bool {\n\treturn true\n}\n"
	if err := os.WriteFile(filepath.Join(wsDir, "pkg", "auth", "verify_auth.go"), []byte(authContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. workspace.glob 测试（.gitignore 生效 + 裸文件名模式 + 跳过 dist 与敏感文件）
	g1, err := mgr.Glob(GlobOptions{WorkspaceID: "demo", Pattern: "**/*.go"})
	if err != nil {
		t.Fatalf("Glob 失败: %v", err)
	}
	foundVerify := false
	for _, e := range g1.Entries {
		if e.Path == "pkg/auth/verify_auth.go" {
			foundVerify = true
		}
		if strings.Contains(e.Path, "ignored_dir") || strings.Contains(e.Path, "id_rsa") {
			t.Fatalf("Glob 不应返回被 .gitignore 忽略或敏感文件: %s", e.Path)
		}
	}
	if !foundVerify {
		t.Fatalf("Glob 未找到 pkg/auth/verify_auth.go: %+v", g1.Entries)
	}

	g2, err := mgr.Glob(GlobOptions{WorkspaceID: "demo", Pattern: "*auth*"})
	if err != nil || len(g2.Entries) != 1 || g2.Entries[0].Path != "pkg/auth/verify_auth.go" {
		t.Fatalf("裸文件名模式 *auth* 匹配异常: err=%v res=%+v", err, g2)
	}

	falseVal := false
	g3, err := mgr.Glob(GlobOptions{WorkspaceID: "demo", Pattern: "*.log", RespectGitignore: &falseVal})
	if err != nil || len(g3.Entries) != 1 || g3.Entries[0].Path != "ignored.log" {
		t.Fatalf("respect_gitignore=false 时应找到 ignored.log: err=%v res=%+v", err, g3)
	}

	// 2. 双引擎搜索一致性测试（默认优先 rg + 强制纯 Go 引擎）
	for _, forceGo := range []bool{false, true} {
		res, err := mgr.SearchWithOptions(SearchOptions{
			WorkspaceID:   "demo",
			Query:         "verifyauthtoken",
			IgnoreCase:    true,
			ContextLines:  1,
			ForceGoEngine: forceGo,
		})
		if err != nil {
			t.Fatalf("SearchWithOptions(forceGo=%v) 失败: %v", forceGo, err)
		}
		if len(res.Matches) != 1 {
			t.Fatalf("期望命中 1 条 (forceGo=%v, engine=%s)，实际: %+v", forceGo, res.Engine, res.Matches)
		}
		m := res.Matches[0]
		if m.Path != "pkg/auth/verify_auth.go" || m.LineNumber != 4 {
			t.Fatalf("命中位置异常 (forceGo=%v): %+v", forceGo, m)
		}
		if len(m.ContextBefore) != 1 || !strings.Contains(m.ContextBefore[0], "before line") {
			t.Fatalf("前上下文异常 (forceGo=%v): %+v", forceGo, m.ContextBefore)
		}
		if len(m.ContextAfter) != 1 || !strings.Contains(m.ContextAfter[0], "return true") {
			t.Fatalf("后上下文异常 (forceGo=%v): %+v", forceGo, m.ContextAfter)
		}

		// 验证 .env 绝不被任何搜索引擎泄露
		secRes, err := mgr.SearchWithOptions(SearchOptions{
			WorkspaceID:      "demo",
			Query:            "super_secret_123",
			RespectGitignore: &falseVal,
			ForceGoEngine:    forceGo,
		})
		if err != nil || len(secRes.Matches) != 0 {
			t.Fatalf("搜索绝不能泄露 .env (forceGo=%v, engine=%s): err=%v res=%+v", forceGo, secRes.Engine, err, secRes)
		}
	}
}
