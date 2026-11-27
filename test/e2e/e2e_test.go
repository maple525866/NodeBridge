package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"nodebridge/internal/admin"
	"nodebridge/internal/config"
	"nodebridge/internal/core/approval"
	"nodebridge/internal/core/audit"
	"nodebridge/internal/core/policy"
	"nodebridge/internal/core/session"
	"nodebridge/internal/core/store"
	"nodebridge/internal/core/task"
	"nodebridge/internal/mcpserver"
	"nodebridge/internal/mcpserver/tools"
	"nodebridge/internal/platform/capability"
	"nodebridge/internal/platform/filesystem"
	"nodebridge/internal/platform/git"
	"nodebridge/internal/transport/relay"
)

type authTransport struct {
	base  http.RoundTripper
	token string
}

func (a *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	if a.token != "" {
		clone.Header.Set("Authorization", "Bearer "+a.token)
	}
	return a.base.RoundTrip(clone)
}

func TestStageOneEndToEndMCPWorkflow(t *testing.T) {
	// 准备一个带 Git 仓库与单元测试的临时项目工作区
	wsDir := t.TempDir()
	dataDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(wsDir, "go.mod"), []byte("module demo\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wsDir, "calc.go"), []byte("package demo\n\nfunc Add(a, b int) int {\n\treturn a - b // intentional bug\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wsDir, "calc_test.go"), []byte("package demo\n\nimport \"testing\"\n\nfunc TestAdd(t *testing.T) {\n\tif Add(2, 3) != 5 {\n\t\tt.Fatalf(\"want 5, got %d\", Add(2, 3))\n\t}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wsDir, ".env"), []byte("SECRET_TOKEN=must_not_leak_999\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := exec.LookPath("git"); err == nil {
		runGit := func(args ...string) {
			cmd := exec.Command("git", args...)
			cmd.Dir = wsDir
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("git %v 失败: %v\n%s", args, err, string(out))
			}
		}
		runGit("init")
		runGit("config", "user.email", "e2e@nodebridge.local")
		runGit("config", "user.name", "E2E")
		runGit("add", "go.mod", "calc.go", "calc_test.go")
		runGit("commit", "-m", "init demo")
	}

	cfg, err := config.DefaultConfig(wsDir)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Storage.DataDir = dataDir

	taskStore, err := store.NewJSONFileTaskStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	auditLog, err := audit.NewLogger(dataDir, 10, 5)
	if err != nil {
		t.Fatal(err)
	}
	fsMgr, err := filesystem.NewManager(cfg.Workspaces, cfg.Security.GlobalDenyGlobs)
	if err != nil {
		t.Fatal(err)
	}
	gitAdapter, _ := git.NewAdapter(fsMgr)
	taskMgr, err := task.NewManager(taskStore, task.Options{
		MaxConcurrent:  2,
		DefaultTimeout: 30 * time.Second,
		MaxTimeout:     60 * time.Second,
		MaxOutputBytes: 256 * 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	policyEng := policy.NewEngine(cfg.Security)
	broker := approval.NewBroker(0, 60, taskMgr.CancelAll)

	mcpSrv := mcpserver.NewMCPServer("0.1.0-e2e", tools.Deps{
		FS:     fsMgr,
		Git:    gitAdapter,
		Tasks:  taskMgr,
		Policy: policyEng,
		Broker: broker,
		Audit:  auditLog,
	})
	mcpHandler := mcpserver.NewHTTPHandler(mcpSrv, mcpserver.GatewayConfig{
		AuthProvider:   session.NewBearerTokenAuthProvider(cfg.Server.MCPToken),
		AllowedOrigins: cfg.Server.AllowedOrigins,
	})
	adminSrv := admin.NewServer(
		cfg.Server.AdminToken,
		"127.0.0.1:0",
		broker,
		taskMgr,
		auditLog,
		fsMgr,
		capability.Detect(),
		relay.DisabledConnector{},
	)

	mcpTS := httptest.NewServer(mcpHandler)
	defer mcpTS.Close()
	adminTS := httptest.NewServer(adminSrv.Handler())
	defer adminTS.Close()

	// --- 验收 1：HTTP 鉴权与 Origin 防护 ---
	respNoAuth, err := http.Post(mcpTS.URL+"/mcp", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	respNoAuth.Body.Close()
	if respNoAuth.StatusCode != http.StatusUnauthorized {
		t.Fatalf("未携带 Token 期望 HTTP 401，实际 %d", respNoAuth.StatusCode)
	}

	reqBadOrigin, _ := http.NewRequest(http.MethodPost, mcpTS.URL+"/mcp", strings.NewReader(`{}`))
	reqBadOrigin.Header.Set("Origin", "https://evil.example")
	reqBadOrigin.Header.Set("Authorization", "Bearer "+cfg.Server.MCPToken)
	respBadOrigin, err := http.DefaultClient.Do(reqBadOrigin)
	if err != nil {
		t.Fatal(err)
	}
	respBadOrigin.Body.Close()
	if respBadOrigin.StatusCode != http.StatusForbidden {
		t.Fatalf("非法 Origin 期望 HTTP 403，实际 %d", respBadOrigin.StatusCode)
	}

	// 建立官方 MCP Streamable HTTP 客户端连接
	ctx := context.Background()
	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "e2e-client", Version: "1.0.0"}, nil)
	cs, err := mcpClient.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: mcpTS.URL + "/mcp",
		HTTPClient: &http.Client{
			Transport: &authTransport{
				base:  http.DefaultTransport,
				token: cfg.Server.MCPToken,
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("连接 MCP Server 失败: %v", err)
	}
	defer cs.Close()

	// 验证全部 11 个工具（10 个 P0 工具 + 阶段二 approval.status）均已暴露
	listToolsRes, err := cs.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools 失败: %v", err)
	}
	if len(listToolsRes.Tools) != 11 {
		t.Fatalf("期望暴露 11 个 MCP 工具，实际 %d", len(listToolsRes.Tools))
	}

	// 辅助函数：调用本地管理 API
	adminCall := func(method, path string, body any) []byte {
		t.Helper()
		var r io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			r = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, adminTS.URL+path, r)
		req.Header.Set("Authorization", "Bearer "+cfg.Server.AdminToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Admin API %s %s 失败: %v", method, path, err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 400 {
			t.Fatalf("Admin API %s %s 返回 HTTP %d: %s", method, path, resp.StatusCode, string(out))
		}
		return out
	}

	waitPendingID := func() approval.Request {
		t.Helper()
		for i := 0; i < 80; i++ {
			raw := adminCall(http.MethodGet, "/api/state", nil)
			var st struct {
				Pending []approval.Request `json:"pending"`
			}
			_ = json.Unmarshal(raw, &st)
			if len(st.Pending) > 0 {
				return st.Pending[0]
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatalf("等待待审批单出现超时")
		return approval.Request{}
	}

	// --- 验收 2：只读工具（list / read / search / git.status） ---
	readRes, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "workspace.read",
		Arguments: map[string]any{
			"workspace_id": "default",
			"path":         "calc.go",
		},
	})
	if err != nil || readRes.IsError {
		t.Fatalf("workspace.read 失败: err=%v res=%+v", err, readRes)
	}
	var readOut filesystem.ReadResult
	decodeToolJSON(t, readRes, &readOut)
	if readOut.SHA256 == "" || !strings.Contains(readOut.Content, "a - b") {
		t.Fatalf("workspace.read 返回异常: %+v", readOut)
	}

	// --- 验收 3：敏感文件与越权路径必须返回 MCP 工具级错误 ---
	for _, badPath := range []string{".env", "../outside.txt", "calc.go:ads"} {
		badRes, err := cs.CallTool(ctx, &mcp.CallToolParams{
			Name: "workspace.read",
			Arguments: map[string]any{
				"workspace_id": "default",
				"path":         badPath,
			},
		})
		if err != nil {
			t.Fatalf("协议级错误不应出现: %v", err)
		}
		if !badRes.IsError {
			t.Fatalf("期望非法路径 %q 返回 IsError=true，但居然成功了", badPath)
		}
	}

	// --- 验收 4：workspace.patch 触发审批（先拒绝，再批准，再验证乐观锁） ---
	// 4a. 拒绝流程
	rejectDone := make(chan *mcp.CallToolResult, 1)
	go func() {
		r, _ := cs.CallTool(ctx, &mcp.CallToolParams{
			Name: "workspace.patch",
			Arguments: map[string]any{
				"workspace_id":    "default",
				"path":            "calc.go",
				"expected_sha256": readOut.SHA256,
				"edits": []map[string]any{
					{"old_text": "return a - b // intentional bug", "new_text": "return a + b"},
				},
			},
		})
		rejectDone <- r
	}()
	apr1 := waitPendingID()
	if !strings.Contains(apr1.DiffPreview, "+	return a + b") {
		t.Fatalf("审批预览缺少 Unified Diff: %q", apr1.DiffPreview)
	}
	adminCall(http.MethodPost, "/api/approvals/"+apr1.ID+"/reject", map[string]any{"note": "先演示拒绝"})
	rejRes := <-rejectDone
	if rejRes == nil || !rejRes.IsError {
		t.Fatalf("期望拒绝后返回 IsError=true")
	}

	// 4b. 批准流程
	approveDone := make(chan *mcp.CallToolResult, 1)
	go func() {
		r, _ := cs.CallTool(ctx, &mcp.CallToolParams{
			Name: "workspace.patch",
			Arguments: map[string]any{
				"workspace_id":    "default",
				"path":            "calc.go",
				"expected_sha256": readOut.SHA256,
				"edits": []map[string]any{
					{"old_text": "return a - b // intentional bug", "new_text": "return a + b"},
				},
			},
		})
		approveDone <- r
	}()
	apr2 := waitPendingID()
	adminCall(http.MethodPost, "/api/approvals/"+apr2.ID+"/approve", map[string]any{"grant_minutes": 0})
	okPatchRes := <-approveDone
	if okPatchRes == nil || okPatchRes.IsError {
		t.Fatalf("批准后补丁失败: %+v", okPatchRes)
	}

	// 4c. 过期 sha256 必须被乐观锁拦截（且不会触发人工审批）
	conflictRes, _ := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "workspace.patch",
		Arguments: map[string]any{
			"workspace_id":    "default",
			"path":            "calc.go",
			"expected_sha256": readOut.SHA256,
			"edits": []map[string]any{
				{"old_text": "return a + b", "new_text": "return a * b"},
			},
		},
	})
	if conflictRes == nil || !conflictRes.IsError {
		t.Fatalf("期望过期 expected_sha256 被拦截")
	}

	// --- 验收 5：git.diff 验证变更可见 ---
	if gitAdapter != nil {
		diffRes, err := cs.CallTool(ctx, &mcp.CallToolParams{
			Name:      "git.diff",
			Arguments: map[string]any{"workspace_id": "default"},
		})
		if err != nil || diffRes.IsError {
			t.Fatalf("git.diff 失败: err=%v res=%+v", err, diffRes)
		}
		var diffOut git.DiffResult
		decodeToolJSON(t, diffRes, &diffOut)
		if !strings.Contains(diffOut.Diff, "+	return a + b") {
			t.Fatalf("git.diff 未反映修改: %s", diffOut.Diff)
		}
	}

	// --- 验收 6：高危命令拦截 + 批准运行 go test + 一键急停终止长任务 ---
	denyCmdRes, _ := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "terminal.start",
		Arguments: map[string]any{
			"workspace_id": "default",
			"executable":   "sudo",
			"args":         []string{"rm", "-rf", "/"},
		},
	})
	if denyCmdRes == nil || !denyCmdRes.IsError {
		t.Fatalf("期望 L3 硬拒绝命令 sudo 被拦截")
	}

	// 运行修复后的 `go test ./...`
	testStartDone := make(chan *mcp.CallToolResult, 1)
	go func() {
		r, _ := cs.CallTool(ctx, &mcp.CallToolParams{
			Name: "terminal.start",
			Arguments: map[string]any{
				"workspace_id": "default",
				"executable":   "go",
				"args":         []string{"test", "./..."},
			},
		})
		testStartDone <- r
	}()
	apr3 := waitPendingID()
	adminCall(http.MethodPost, "/api/approvals/"+apr3.ID+"/approve", map[string]any{"grant_minutes": 0})
	startRes := <-testStartDone
	if startRes == nil || startRes.IsError {
		t.Fatalf("terminal.start go test 失败: %+v", startRes)
	}
	var startOut tools.TerminalStartOutput
	decodeToolJSON(t, startRes, &startOut)

	var pollOut task.PollResult
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		pr, err := cs.CallTool(ctx, &mcp.CallToolParams{
			Name:      "terminal.poll",
			Arguments: map[string]any{"task_id": startOut.TaskID},
		})
		if err != nil || pr.IsError {
			t.Fatalf("terminal.poll 失败: err=%v res=%+v", err, pr)
		}
		decodeToolJSON(t, pr, &pollOut)
		if pollOut.Status.IsTerminal() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if pollOut.Status != task.StatusSucceeded || !strings.Contains(pollOut.StdoutChunk, "ok") {
		t.Fatalf("期望 go test 成功通过，实际 pollOut=%+v", pollOut)
	}

	// 启动长任务并触发一键急停
	sleepCmd := "sleep 30"
	if runtime.GOOS == "windows" {
		sleepCmd = "Start-Sleep -Seconds 30"
	}
	sleepStartDone := make(chan *mcp.CallToolResult, 1)
	go func() {
		r, _ := cs.CallTool(ctx, &mcp.CallToolParams{
			Name: "terminal.start",
			Arguments: map[string]any{
				"workspace_id": "default",
				"executable":   sleepCmd,
				"use_shell":    true,
			},
		})
		sleepStartDone <- r
	}()
	apr4 := waitPendingID()
	adminCall(http.MethodPost, "/api/approvals/"+apr4.ID+"/approve", map[string]any{"grant_minutes": 0})
	sleepStartRes := <-sleepStartDone
	var sleepOut tools.TerminalStartOutput
	decodeToolJSON(t, sleepStartRes, &sleepOut)
	time.Sleep(250 * time.Millisecond)

	// 触发一键急停
	adminCall(http.MethodPost, "/api/kill-switch/kill-all", map[string]any{"reason": "e2e 急停验收"})

	var killedPoll task.PollResult
	for i := 0; i < 60; i++ {
		pr, _ := cs.CallTool(ctx, &mcp.CallToolParams{
			Name:      "terminal.poll",
			Arguments: map[string]any{"task_id": sleepOut.TaskID},
		})
		decodeToolJSON(t, pr, &killedPoll)
		if killedPoll.Status.IsTerminal() {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if killedPoll.Status != task.StatusCancelled {
		t.Fatalf("期望一键急停终止任务为 CANCELLED，实际 %s", killedPoll.Status)
	}

	// --- 验收 7：检查审计日志已落盘 ---
	auditRaw, err := os.ReadFile(auditLog.FilePath())
	if err != nil || len(auditRaw) == 0 {
		t.Fatalf("审计日志未正确落盘: err=%v", err)
	}
	if strings.Contains(string(auditRaw), "must_not_leak_999") {
		t.Fatalf("审计日志泄露了 .env 敏感内容")
	}
}

func decodeToolJSON(t *testing.T, res *mcp.CallToolResult, target any) {
	t.Helper()
	if res == nil || len(res.Content) == 0 {
		t.Fatalf("工具返回内容为空")
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("期望 TextContent，实际 %T", res.Content[0])
	}
	if err := json.Unmarshal([]byte(tc.Text), target); err != nil {
		t.Fatalf("反序列化工具 JSON 输出失败: %v\nraw=%s", err, tc.Text)
	}
}

func TestSecurityModeFullPermissionsAndAllDirsE2E(t *testing.T) {
	wsDir := t.TempDir()
	outsideDir := t.TempDir()
	dataDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(wsDir, "inside.txt"), []byte("inside\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outsideFile := filepath.Join(outsideDir, "outside.txt")
	if err := os.WriteFile(outsideFile, []byte("outside-initial\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outsideSSHDir := filepath.Join(outsideDir, ".ssh")
	if err := os.MkdirAll(outsideSSHDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outsideSSHKey := filepath.Join(outsideSSHDir, "id_rsa")
	if err := os.WriteFile(outsideSSHKey, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nTOP_SECRET_SSH_KEY_MATERIAL\n-----END OPENSSH PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.DefaultConfig(wsDir)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Storage.DataDir = dataDir

	taskStore, _ := store.NewJSONFileTaskStore(dataDir)
	auditLog, _ := audit.NewLogger(dataDir, 10, 5)
	fsMgr, err := filesystem.NewManager(cfg.Workspaces, cfg.Security.GlobalDenyGlobs)
	if err != nil {
		t.Fatal(err)
	}
	gitAdapter, _ := git.NewAdapter(fsMgr)
	taskMgr, _ := task.NewManager(taskStore, task.Options{
		MaxConcurrent:  2,
		DefaultTimeout: 20 * time.Second,
		MaxTimeout:     30 * time.Second,
		MaxOutputBytes: 128 * 1024,
	})
	policyEng := policy.NewEngine(cfg.Security)
	broker := approval.NewBroker(0, 60, taskMgr.CancelAll)

	mcpSrv := mcpserver.NewMCPServer("0.2.0-e2e", tools.Deps{
		FS:     fsMgr,
		Git:    gitAdapter,
		Tasks:  taskMgr,
		Policy: policyEng,
		Broker: broker,
		Audit:  auditLog,
	})
	mcpHandler := mcpserver.NewHTTPHandler(mcpSrv, mcpserver.GatewayConfig{
		AuthProvider:   session.NewBearerTokenAuthProvider(cfg.Server.MCPToken),
		AllowedOrigins: cfg.Server.AllowedOrigins,
	})
	adminSrv := admin.NewServer(
		cfg.Server.AdminToken,
		"127.0.0.1:0",
		broker,
		taskMgr,
		auditLog,
		fsMgr,
		capability.Detect(),
		relay.DisabledConnector{},
	)
	adminSrv.AttachSecurityControl(policyEng, dataDir, store.SecurityMode{})

	mcpTS := httptest.NewServer(mcpHandler)
	defer mcpTS.Close()
	adminTS := httptest.NewServer(adminSrv.Handler())
	defer adminTS.Close()

	adminCall := func(method, path string, body any) []byte {
		t.Helper()
		var r io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			r = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, adminTS.URL+path, r)
		req.Header.Set("Authorization", "Bearer "+cfg.Server.AdminToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Admin API %s %s 失败: %v", method, path, err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 400 {
			t.Fatalf("Admin API %s %s 返回 HTTP %d: %s", method, path, resp.StatusCode, string(out))
		}
		return out
	}

	ctx := context.Background()
	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "e2e-mode-client", Version: "1.0.0"}, nil)
	cs, err := mcpClient.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: mcpTS.URL + "/mcp",
		HTTPClient: &http.Client{
			Transport: &authTransport{base: http.DefaultTransport, token: cfg.Server.MCPToken},
		},
	}, nil)
	if err != nil {
		t.Fatalf("连接 MCP 失败: %v", err)
	}
	defer cs.Close()

	// 1. 默认关闭时，无法读取工作区外文件
	deniedRes, _ := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "workspace.read",
		Arguments: map[string]any{"workspace_id": "default", "path": outsideFile},
	})
	if deniedRes == nil || !deniedRes.IsError {
		t.Fatalf("默认未勾选全部目录时应拒绝访问工作区外文件")
	}

	// 2. 通过管理后台 API 勾选「全部权限」与「默认全部目录」
	adminCall(http.MethodPost, "/api/security/mode", map[string]any{
		"full_permissions": true,
		"allow_all_dirs":   true,
	})

	// 校验持久化文件与 /api/state 返回一致
	loadedMode, err := store.LoadSecurityMode(dataDir, false, false)
	if err != nil || !loadedMode.FullPermissions || !loadedMode.AllowAllDirs {
		t.Fatalf("期望安全模式已持久化为双开，实际: err=%v mode=%+v", err, loadedMode)
	}

	// 3. 免审批读取并直接修改工作区外文件
	readRes, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "workspace.read",
		Arguments: map[string]any{"workspace_id": "", "path": outsideFile},
	})
	if err != nil || readRes.IsError {
		t.Fatalf("全部目录模式下读取工作区外文件失败: err=%v res=%+v", err, readRes)
	}
	var readOut filesystem.ReadResult
	decodeToolJSON(t, readRes, &readOut)

	patchRes, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "workspace.patch",
		Arguments: map[string]any{
			"workspace_id":    "",
			"path":            outsideFile,
			"expected_sha256": readOut.SHA256,
			"edits":           []map[string]any{{"old_text": "outside-initial", "new_text": "outside-patched-no-approval"}},
		},
	})
	if err != nil || patchRes.IsError {
		t.Fatalf("全权限+全目录模式下应无需审批直接修改工作区外文件: err=%v res=%+v", err, patchRes)
	}
	if len(broker.Pending()) != 0 {
		t.Fatalf("全权限模式下不应产生待审批单")
	}

	// 4. 在工作区外目录直接免审批执行显式 Shell 命令
	echoCmd := "echo full-perm-ok"
	startRes, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "terminal.start",
		Arguments: map[string]any{
			"workspace_id": "",
			"cwd":          outsideDir,
			"executable":   echoCmd,
			"use_shell":    true,
		},
	})
	if err != nil || startRes.IsError {
		t.Fatalf("全权限+全目录模式下执行显式 Shell 命令失败: err=%v res=%+v", err, startRes)
	}
	var startOut tools.TerminalStartOutput
	decodeToolJSON(t, startRes, &startOut)

	var pollOut task.PollResult
	for i := 0; i < 60; i++ {
		pr, _ := cs.CallTool(ctx, &mcp.CallToolParams{
			Name:      "terminal.poll",
			Arguments: map[string]any{"task_id": startOut.TaskID},
		})
		decodeToolJSON(t, pr, &pollOut)
		if pollOut.Status.IsTerminal() {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if pollOut.Status != task.StatusSucceeded || !strings.Contains(pollOut.StdoutChunk, "full-perm-ok") {
		t.Fatalf("期望显式 Shell 命令免审批执行成功，实际: %+v", pollOut)
	}

	// 4.5 验证 SSH 密钥目录硬保护与终端输出私钥脱敏（即使双开全部权限 + 全部目录也不可绕过）
	listOutsideRes, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "workspace.list",
		Arguments: map[string]any{"workspace_id": "", "path": outsideDir},
	})
	if err != nil || listOutsideRes.IsError {
		t.Fatalf("列出外部普通目录失败: err=%v res=%+v", err, listOutsideRes)
	}
	var listOutside filesystem.ListResult
	decodeToolJSON(t, listOutsideRes, &listOutside)
	for _, e := range listOutside.Entries {
		if strings.Contains(e.Path, ".ssh") || strings.Contains(e.Path, "id_rsa") {
			t.Fatalf("列出目录时绝不能暴露 .ssh 目录或私钥文件: %+v", e)
		}
	}

	sshListDenied, _ := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "workspace.list",
		Arguments: map[string]any{"workspace_id": "", "path": outsideSSHDir},
	})
	if sshListDenied == nil || !sshListDenied.IsError {
		t.Fatalf("即使双开全权限与全目录，也必须禁止查看 .ssh 目录")
	}
	sshReadDenied, _ := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "workspace.read",
		Arguments: map[string]any{"workspace_id": "", "path": outsideSSHKey},
	})
	if sshReadDenied == nil || !sshReadDenied.IsError {
		t.Fatalf("即使双开全权限与全目录，也必须禁止读取 SSH 私钥文件")
	}
	sshCmdDenied, _ := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "terminal.start",
		Arguments: map[string]any{
			"workspace_id": "",
			"cwd":          outsideDir,
			"executable":   "cat " + outsideSSHKey,
			"use_shell":    true,
		},
	})
	if sshCmdDenied == nil || !sshCmdDenied.IsError {
		t.Fatalf("即使双开全权限与全目录，也必须禁止通过终端命令读取 .ssh/id_rsa")
	}

	// 即使间接命令往 stdout 打印私钥块，返回给模型时也必须被实时脱敏
	leakCmd := `printf 'prefix\n-----BEGIN OPENSSH PRIVATE KEY-----\nSUPER_SECRET_KEY_BODY\n-----END OPENSSH PRIVATE KEY-----\nsuffix\n'`
	if runtime.GOOS == "windows" {
		leakCmd = `Write-Output "prefix"; Write-Output "-----BEGIN OPENSSH PRIVATE KEY-----"; Write-Output "SUPER_SECRET_KEY_BODY"; Write-Output "-----END OPENSSH PRIVATE KEY-----"; Write-Output "suffix"`
	}
	leakStartRes, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "terminal.start",
		Arguments: map[string]any{
			"workspace_id": "",
			"cwd":          outsideDir,
			"executable":   leakCmd,
			"use_shell":    true,
		},
	})
	if err != nil || leakStartRes.IsError {
		t.Fatalf("启动脱敏测试命令失败: err=%v res=%+v", err, leakStartRes)
	}
	var leakStartOut tools.TerminalStartOutput
	decodeToolJSON(t, leakStartRes, &leakStartOut)
	var leakPoll task.PollResult
	for i := 0; i < 60; i++ {
		pr, _ := cs.CallTool(ctx, &mcp.CallToolParams{
			Name:      "terminal.poll",
			Arguments: map[string]any{"task_id": leakStartOut.TaskID},
		})
		decodeToolJSON(t, pr, &leakPoll)
		if leakPoll.Status.IsTerminal() {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if strings.Contains(leakPoll.StdoutChunk, "SUPER_SECRET_KEY_BODY") {
		t.Fatalf("终端输出泄露了私钥明文: %q", leakPoll.StdoutChunk)
	}
	if !strings.Contains(leakPoll.StdoutChunk, "[REDACTED_PRIVATE_KEY]") || !strings.Contains(leakPoll.StdoutChunk, "suffix") {
		t.Fatalf("终端输出未正确脱敏并保留非敏感正文: %q", leakPoll.StdoutChunk)
	}

	// 5. 取消勾选两个按钮后，立即恢复目录限制
	adminCall(http.MethodPost, "/api/security/mode", map[string]any{
		"full_permissions": false,
		"allow_all_dirs":   false,
	})
	deniedAgain, _ := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "workspace.read",
		Arguments: map[string]any{"workspace_id": "default", "path": outsideFile},
	})
	if deniedAgain == nil || !deniedAgain.IsError {
		t.Fatalf("取消勾选全部目录后应重新拦截工作区外文件")
	}
}
