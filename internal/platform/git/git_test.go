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
}
