package git

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"nodebridge/internal/config"
	"nodebridge/internal/platform/filesystem"
)

func TestGitAdapterStatusDiffAndApplyPatchSecurity(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("系统未安装 git，跳过测试")
	}

	repoDir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repoDir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v 失败: %v\n%s", args, err, string(out))
		}
	}

	run("init")
	run("config", "user.email", "test@nodebridge.local")
	run("config", "user.name", "NodeBridge Test")
	if err := os.WriteFile(filepath.Join(repoDir, "app.txt"), []byte("line1\nline2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "app.txt")
	run("commit", "-m", "initial")

	fsMgr, err := filesystem.NewManager([]config.WorkspaceConfig{
		{ID: "repo", Root: repoDir},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewAdapter(fsMgr)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	st, err := adapter.Status(ctx, "repo")
	if err != nil || !st.Clean {
		t.Fatalf("期望干净工作区，实际 st=%+v err=%v", st, err)
	}

	// 1. 合法补丁成功应用
	goodPatch := `diff --git a/app.txt b/app.txt
--- a/app.txt
+++ b/app.txt
@@ -1,2 +1,2 @@
 line1
-line2
+line2_updated
`
	res, err := adapter.ApplyPatch(ctx, "repo", goodPatch)
	if err != nil {
		t.Fatalf("合法补丁应用失败: %v", err)
	}
	if len(res.AffectedFiles) != 1 || res.AffectedFiles[0] != "app.txt" {
		t.Fatalf("受影响文件列表异常: %+v", res.AffectedFiles)
	}

	diffRes, err := adapter.Diff(ctx, "repo", false, []string{"app.txt"}, 0)
	if err != nil || !strings.Contains(diffRes.Diff, "+line2_updated") {
		t.Fatalf("Diff 结果异常: %+v err=%v", diffRes, err)
	}

	// 2. 尝试通过补丁越权修改 .env 或 ../outside.txt 必须被拦截
	evilPatch := `diff --git a/.env b/.env
--- /dev/null
+++ b/.env
@@ -0,0 +1 @@
+HACKED=1
`
	_, err = adapter.ApplyPatch(ctx, "repo", evilPatch)
	if !errors.Is(err, filesystem.ErrAccessDenied) {
		t.Fatalf("期望修改 .env 的补丁被 ErrAccessDenied 拦截，实际 err=%v", err)
	}

	escapePatch := `diff --git a/../escape.txt b/../escape.txt
--- /dev/null
+++ b/../escape.txt
@@ -0,0 +1 @@
+ESCAPE
`
	_, err = adapter.ApplyPatch(ctx, "repo", escapePatch)
	if !errors.Is(err, filesystem.ErrAccessDenied) {
		t.Fatalf("期望路径穿越补丁被 ErrAccessDenied 拦截，实际 err=%v", err)
	}

	// 3. 拦截 C-style 引号转义路径补丁（防止绕过敏感路径匹配）
	quotedEscapePatch := "diff --git \"a/server.\\160em\" \"b/server.\\160em\"\n" +
		"new file mode 100644\n" +
		"--- /dev/null\n" +
		"+++ \"b/server.\\160em\"\n" +
		"@@ -0,0 +1 @@\n" +
		"+FAKE\n"
	_, err = adapter.ApplyPatch(ctx, "repo", quotedEscapePatch)
	if !errors.Is(err, filesystem.ErrAccessDenied) {
		t.Fatalf("期望 C-style 转义路径补丁被 ErrAccessDenied 拦截，实际 err=%v", err)
	}

	// 4. 拦截创建符号链接（new file mode 120000）补丁
	symlinkPatch := `diff --git a/innocent_link b/innocent_link
new file mode 120000
--- /dev/null
+++ b/innocent_link
@@ -0,0 +1 @@
+.env
`
	_, err = adapter.ApplyPatch(ctx, "repo", symlinkPatch)
	if !errors.Is(err, filesystem.ErrAccessDenied) {
		t.Fatalf("期望符号链接补丁 (mode 120000) 被 ErrAccessDenied 拦截，实际 err=%v", err)
	}
}

func TestGitDiffRangeLogAndShow(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("系统未安装 git，跳过测试")
	}

	repoDir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repoDir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v 失败: %v\n%s", args, err, string(out))
		}
	}

	run("init")
	run("config", "user.email", "test@nodebridge.local")
	run("config", "user.name", "NodeBridge Test")
	if err := os.WriteFile(filepath.Join(repoDir, "main.go"), []byte("package main\nfunc v() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "main.go")
	run("commit", "-m", "commit 1: init")

	if err := os.WriteFile(filepath.Join(repoDir, "main.go"), []byte("package main\nfunc v() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 即使仓库历史中意外提交了 .env，git.show 与 git.diff 也必须自动排除它
	if err := os.WriteFile(filepath.Join(repoDir, ".env"), []byte("DB_PASS=super_secret_env\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "-f", "main.go", ".env")
	run("commit", "-m", "commit 2: bump v to 2")

	fsMgr, err := filesystem.NewManager([]config.WorkspaceConfig{{ID: "repo", Root: repoDir}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewAdapter(fsMgr)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// 1. DiffRangeAt 对比 HEAD~1..HEAD
	diffRes, err := adapter.DiffRangeAt(ctx, "repo", "", false, "HEAD~1", "HEAD", nil, 0)
	if err != nil {
		t.Fatalf("DiffRangeAt 失败: %v", err)
	}
	if !strings.Contains(diffRes.Diff, "+func v() int { return 2 }") {
		t.Fatalf("DiffRangeAt 未包含预期差异: %s", diffRes.Diff)
	}
	if strings.Contains(diffRes.Diff, "super_secret_env") {
		t.Fatalf("DiffRangeAt 泄露了 .env 内容: %s", diffRes.Diff)
	}

	// 2. LogAt 查询提交历史
	logRes, err := adapter.LogAt(ctx, "repo", "", "", "", 10)
	if err != nil || len(logRes.Commits) != 2 {
		t.Fatalf("LogAt 结果异常: err=%v res=%+v", err, logRes)
	}
	if logRes.Commits[0].Subject != "commit 2: bump v to 2" || logRes.Commits[1].Subject != "commit 1: init" {
		t.Fatalf("LogAt 提交顺序异常: %+v", logRes.Commits)
	}

	// 3. ShowAt 查看详情与差异（排除 .env）
	showRes, err := adapter.ShowAt(ctx, "repo", "", "HEAD", false, 0)
	if err != nil {
		t.Fatalf("ShowAt 失败: %v", err)
	}
	if showRes.Subject != "commit 2: bump v to 2" || !strings.Contains(showRes.Diff, "+func v() int { return 2 }") {
		t.Fatalf("ShowAt 内容异常: %+v", showRes)
	}
	if strings.Contains(showRes.Diff, "super_secret_env") {
		t.Fatalf("ShowAt 泄露了 .env 敏感内容: %s", showRes.Diff)
	}

	// 4. 拦截非法 '-' 开头 ref 注入
	if _, err := adapter.DiffRangeAt(ctx, "repo", "", false, "--output=/tmp/pwn", "", nil, 0); err == nil {
		t.Fatalf("应拦截以 '-' 开头的非法 base 参数")
	}
	if _, err := adapter.LogAt(ctx, "repo", "", "--all", "", 10); err == nil {
		t.Fatalf("应拦截以 '-' 开头的非法 ref 参数")
	}
	if _, err := adapter.ShowAt(ctx, "repo", "", "--pretty=raw", false, 0); err == nil {
		t.Fatalf("应拦截以 '-' 开头的非法 ref 参数")
	}
}
