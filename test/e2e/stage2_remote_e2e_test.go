package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"nodebridge/internal/admin"
	"nodebridge/internal/config"
	"nodebridge/internal/core/approval"
	"nodebridge/internal/core/audit"
	"nodebridge/internal/core/oauth"
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

// remoteTunnelTransport 模拟经由 Cloudflare Tunnel / HTTPS 反代进入本地 127.0.0.1 的远程流量。
type remoteTunnelTransport struct {
	base       http.RoundTripper
	publicHost string
	token      string
}

func (rt *remoteTunnelTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	if rt.publicHost != "" {
		clone.Host = rt.publicHost
		clone.Header.Set("X-Forwarded-Proto", "https")
	}
	if rt.token != "" {
		clone.Header.Set("Authorization", "Bearer "+rt.token)
	}
	return rt.base.RoundTrip(clone)
}

func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestStageTwoRemoteOAuthAndHybridApprovalE2E(t *testing.T) {
	wsAlpha := t.TempDir()
	wsBeta := t.TempDir()
	dataDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(wsAlpha, "main.go"), []byte("package alpha\n\nfunc Value() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wsBeta, "secret_project.txt"), []byte("beta workspace content\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.DefaultConfig(wsAlpha)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Storage.DataDir = dataDir
	cfg.Workspaces = []config.WorkspaceConfig{
		{ID: "ws_alpha", Root: wsAlpha, ReadOnly: false},
		{ID: "ws_beta", Root: wsBeta, ReadOnly: false},
	}
	cfg.Relay.Mode = config.RelayModeExternal
	cfg.Relay.PublicURL = "https://mcp.e2e.example"
	cfg.OAuth.Enabled = true
	cfg.OAuth.RateLimitPerMinute = 200
	cfg.ApplyDefaults(dataDir)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("配置校验失败: %v", err)
	}

	devIdent, err := store.LoadOrCreateDeviceIdentity(dataDir, "")
	if err != nil {
		t.Fatal(err)
	}
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
	// 配置 1 秒短窗口以便快速验收异步续接与幂等去重
	broker.ConfigureRemote(1, 300, 300)

	relayConn, err := relay.NewConnector(cfg.Relay, "127.0.0.1:0", devIdent.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	_ = relayConn.Start(context.Background(), nil)

	oauthSrv, err := oauth.NewServer(oauth.Options{
		Config:            cfg.OAuth,
		DataDir:           dataDir,
		DeviceID:          devIdent.DeviceID,
		PublicURLProvider: relayConn.PublicURL,
	})
	if err != nil {
		t.Fatal(err)
	}

	mcpSrv := mcpserver.NewMCPServer("0.2.0-e2e", tools.Deps{
		FS:     fsMgr,
		Git:    gitAdapter,
		Tasks:  taskMgr,
		Policy: policyEng,
		Broker: broker,
		Audit:  auditLog,
	})
	authProvider := session.NewCompositeAuthProvider(
		oauthSrv,
		session.NewBearerTokenAuthProvider(cfg.Server.MCPToken),
	)
	mcpHandler := mcpserver.NewHTTPHandler(mcpSrv, mcpserver.GatewayConfig{
		AuthProvider:   authProvider,
		OAuthServer:    oauthSrv,
		RelayConnector: relayConn,
		AllowedOrigins: cfg.Server.AllowedOrigins,
		Version:        "0.2.0-e2e",
	})

	adminSrv := admin.NewServer(
		cfg.Server.AdminToken,
		"127.0.0.1:0",
		broker,
		taskMgr,
		auditLog,
		fsMgr,
		capability.Detect(),
		relayConn,
	)
	adminSrv.AttachRemoteGovernance(devIdent.DeviceID, oauthSrv, false)

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

	// --- 验收 1：Host 白名单防护、CORS 预检与 RFC 9728 401 引导头 ---
	evilReq, _ := http.NewRequest(http.MethodPost, mcpTS.URL+"/mcp", strings.NewReader(`{}`))
	evilReq.Host = "evil-rebind.attacker.example"
	evilResp, err := http.DefaultClient.Do(evilReq)
	if err != nil {
		t.Fatal(err)
	}
	evilResp.Body.Close()
	if evilResp.StatusCode != http.StatusForbidden {
		t.Fatalf("非法 Host 应返回 403，实际 %d", evilResp.StatusCode)
	}

	unauthReq, _ := http.NewRequest(http.MethodPost, mcpTS.URL+"/mcp", strings.NewReader(`{}`))
	unauthReq.Host = "mcp.e2e.example"
	unauthResp, err := http.DefaultClient.Do(unauthReq)
	if err != nil {
		t.Fatal(err)
	}
	unauthResp.Body.Close()
	wwwAuth := unauthResp.Header.Get("WWW-Authenticate")
	if unauthResp.StatusCode != http.StatusUnauthorized || !strings.Contains(wwwAuth, `resource_metadata="https://mcp.e2e.example/.well-known/oauth-protected-resource"`) {
		t.Fatalf("未鉴权应返回 401 + RFC 9728 引导头，实际 status=%d header=%q", unauthResp.StatusCode, wwwAuth)
	}

	optReq, _ := http.NewRequest(http.MethodOptions, mcpTS.URL+"/mcp", nil)
	optReq.Host = "mcp.e2e.example"
	optReq.Header.Set("Origin", "https://gemini.google.com")
	optResp, err := http.DefaultClient.Do(optReq)
	if err != nil {
		t.Fatal(err)
	}
	optResp.Body.Close()
	if optResp.StatusCode != http.StatusNoContent || optResp.Header.Get("Access-Control-Allow-Origin") != "https://gemini.google.com" {
		t.Fatalf("CORS 预检异常: status=%d allow-origin=%q", optResp.StatusCode, optResp.Header.Get("Access-Control-Allow-Origin"))
	}

	// 辅助函数：通过完整 DCR + PKCE S256 绑定一个远程客户端
	bindClient := func(name, redirectURI string, usePairingCode, readOnly bool, workspaces []string) (clientID, accessToken string) {
		t.Helper()
		regPayload, _ := json.Marshal(map[string]any{
			"client_name":                name,
			"redirect_uris":              []string{redirectURI},
			"token_endpoint_auth_method": "none",
		})
		regReq, _ := http.NewRequest(http.MethodPost, mcpTS.URL+"/oauth/register", bytes.NewReader(regPayload))
		regReq.Host = "mcp.e2e.example"
		regReq.Header.Set("Content-Type", "application/json")
		regResp, err := http.DefaultClient.Do(regReq)
		if err != nil || regResp.StatusCode != http.StatusCreated {
			t.Fatalf("DCR 失败: err=%v resp=%+v", err, regResp)
		}
		var regOut struct {
			ClientID string `json:"client_id"`
		}
		_ = json.NewDecoder(regResp.Body).Decode(&regOut)
		regResp.Body.Close()

		verifier := "e2e_pkce_verifier_0123456789_abcdefghijklmnopqrstuvwxyz"
		authURL := mcpTS.URL + "/oauth/authorize?response_type=code&client_id=" + regOut.ClientID +
			"&redirect_uri=" + url.QueryEscape(redirectURI) +
			"&code_challenge=" + pkceS256(verifier) +
			"&code_challenge_method=S256&state=e2e_state&scope=mcp:tools"
		authReq, _ := http.NewRequest(http.MethodGet, authURL, nil)
		authReq.Host = "mcp.e2e.example"
		authResp, err := http.DefaultClient.Do(authReq)
		if err != nil || authResp.StatusCode != http.StatusOK {
			t.Fatalf("打开公网授权页失败: err=%v status=%d", err, authResp.StatusCode)
		}
		authResp.Body.Close()

		stateRaw := adminCall(http.MethodGet, "/api/state", nil)
		var st struct {
			OAuthPending []oauth.PendingAuthRequest `json:"oauth_pending"`
		}
		_ = json.Unmarshal(stateRaw, &st)
		if len(st.OAuthPending) == 0 {
			t.Fatalf("本地控制台未收到待确认 OAuth 绑定请求")
		}
		reqID := st.OAuthPending[0].ID

		var code string
		if usePairingCode {
			// 路径二：本地生成 5 分钟一次性配对码 -> 公网确认页表单提交
			pcRaw := adminCall(http.MethodPost, "/api/oauth/pairing-codes", map[string]any{
				"read_only":          readOnly,
				"allowed_workspaces": workspaces,
				"note":               "e2e",
			})
			var pc oauth.PairingCode
			_ = json.Unmarshal(pcRaw, &pc)

			form := url.Values{"request_id": {reqID}, "action": {"approve"}, "pairing_code": {pc.Code}}
			confirmReq, _ := http.NewRequest(http.MethodPost, mcpTS.URL+"/oauth/authorize/confirm", strings.NewReader(form.Encode()))
			confirmReq.Host = "mcp.e2e.example"
			confirmReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			noRedir := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			confirmResp, err := noRedir.Do(confirmReq)
			if err != nil || confirmResp.StatusCode != http.StatusFound {
				t.Fatalf("配对码确认失败: err=%v status=%d", err, confirmResp.StatusCode)
			}
			loc, _ := url.Parse(confirmResp.Header.Get("Location"))
			confirmResp.Body.Close()
			code = loc.Query().Get("code")
		} else {
			// 路径一：本地控制台一键批准 -> 公网页 poll 获取回调 URL
			adminCall(http.MethodPost, "/api/oauth/requests/"+reqID+"/approve", map[string]any{
				"read_only":          readOnly,
				"allowed_workspaces": workspaces,
				"note":               "本地控制台批准",
			})
			pollReq, _ := http.NewRequest(http.MethodGet, mcpTS.URL+"/oauth/authorize/poll?req="+reqID, nil)
			pollReq.Host = "mcp.e2e.example"
			pollResp, err := http.DefaultClient.Do(pollReq)
			if err != nil || pollResp.StatusCode != http.StatusOK {
				t.Fatalf("poll 授权状态失败: err=%v", err)
			}
			var pollOut struct {
				Status      string `json:"status"`
				RedirectURL string `json:"redirect_url"`
			}
			_ = json.NewDecoder(pollResp.Body).Decode(&pollOut)
			pollResp.Body.Close()
			loc, _ := url.Parse(pollOut.RedirectURL)
			code = loc.Query().Get("code")
		}

		tokForm := url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {regOut.ClientID},
			"code":          {code},
			"redirect_uri":  {redirectURI},
			"code_verifier": {verifier},
		}
		tokReq, _ := http.NewRequest(http.MethodPost, mcpTS.URL+"/oauth/token", strings.NewReader(tokForm.Encode()))
		tokReq.Host = "mcp.e2e.example"
		tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		tokResp, err := http.DefaultClient.Do(tokReq)
		if err != nil || tokResp.StatusCode != http.StatusOK {
			t.Fatalf("换取 Token 失败: err=%v status=%d", err, tokResp.StatusCode)
		}
		var tokOut struct {
			AccessToken string `json:"access_token"`
		}
		_ = json.NewDecoder(tokResp.Body).Decode(&tokOut)
		tokResp.Body.Close()
		return regOut.ClientID, tokOut.AccessToken
	}

	connectRemoteMCP := func(token string) *mcp.ClientSession {
		t.Helper()
		cli := mcp.NewClient(&mcp.Implementation{Name: "cloud-web-sim", Version: "1.0.0"}, nil)
		cs, err := cli.Connect(context.Background(), &mcp.StreamableClientTransport{
			Endpoint: mcpTS.URL + "/mcp",
			HTTPClient: &http.Client{
				Transport: &remoteTunnelTransport{
					base:       http.DefaultTransport,
					publicHost: "mcp.e2e.example",
					token:      token,
				},
			},
		}, nil)
		if err != nil {
			t.Fatalf("连接远程 MCP 失败: %v", err)
		}
		return cs
	}

	// --- 验收 2：客户端 A（只读 + 仅限 ws_alpha）工作区与写权限隔离 ---
	_, tokenA := bindClient("Claude Web (RO)", "https://claude.ai/api/mcp/auth_callback", false, true, []string{"ws_alpha"})
	csA := connectRemoteMCP(tokenA)
	defer csA.Close()

	// 可读 ws_alpha
	readOK, err := csA.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "workspace.read",
		Arguments: map[string]any{"workspace_id": "ws_alpha", "path": "main.go"},
	})
	if err != nil || readOK.IsError {
		t.Fatalf("只读客户端读取授权工作区应成功: err=%v res=%+v", err, readOK)
	}
	var readAlpha filesystem.ReadResult
	decodeToolJSON(t, readOK, &readAlpha)

	// 不可读未授权工作区 ws_beta
	readBetaDenied, _ := csA.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "workspace.read",
		Arguments: map[string]any{"workspace_id": "ws_beta", "path": "secret_project.txt"},
	})
	if readBetaDenied == nil || !readBetaDenied.IsError {
		t.Fatalf("期望拦截跨工作区越权读取 ws_beta")
	}

	// 不可写入 ws_alpha（只读限制）
	writeDenied, _ := csA.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "workspace.patch",
		Arguments: map[string]any{
			"workspace_id":    "ws_alpha",
			"path":            "main.go",
			"expected_sha256": readAlpha.SHA256,
			"edits":           []map[string]any{{"old_text": "return 1", "new_text": "return 2"}},
		},
	})
	if writeDenied == nil || !writeDenied.IsError {
		t.Fatalf("期望拦截只读客户端写入操作")
	}

	// --- 验收 3：客户端 B（一次性配对码绑定，可读写 ws_alpha）混合短等待超时 -> 异步续接 -> 幂等防重 ---
	clientBID, tokenB := bindClient("Gemini Web (RW)", "https://gemini.google.com/mcp/oauth/callback", true, false, []string{"ws_alpha"})
	csB := connectRemoteMCP(tokenB)
	defer csB.Close()

	patchArgs := map[string]any{
		"workspace_id":    "ws_alpha",
		"path":            "main.go",
		"expected_sha256": readAlpha.SHA256,
		"edits":           []map[string]any{{"old_text": "return 1", "new_text": "return 42"}},
	}

	// 3a. 无人审批 -> 1s 短窗口超时，返回 Pending=true + ApprovalID（不销毁审批单）
	patchRes1, err := csB.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "workspace.patch",
		Arguments: patchArgs,
	})
	if err != nil || patchRes1.IsError {
		t.Fatalf("远程短窗口超时应返回结构化 Pending 而非错误: err=%v res=%+v", err, patchRes1)
	}
	var patchOut1 filesystem.PatchResult
	decodeToolJSON(t, patchRes1, &patchOut1)
	if !patchOut1.Pending || patchOut1.ApprovalID == "" {
		t.Fatalf("期望 Pending=true 且返回 ApprovalID，实际: %+v", patchOut1)
	}

	// 3b. 客户端 A 越权查询客户端 B 的审批单必须被拒绝
	crossStatus, _ := csA.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "approval.status",
		Arguments: map[string]any{"approval_id": patchOut1.ApprovalID},
	})
	if crossStatus == nil || !crossStatus.IsError {
		t.Fatalf("期望拒绝跨客户端查询其他客户端审批单")
	}

	// 3c. 设备主人事后在本地控制台批准 -> 后台自动执行补丁
	adminCall(http.MethodPost, "/api/approvals/"+patchOut1.ApprovalID+"/approve", map[string]any{"grant_minutes": 0})

	// 3d. 客户端 B 调用 approval.status 拿到最终执行结果
	var statusOut tools.ApprovalStatusOutput
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		sr, err := csB.CallTool(context.Background(), &mcp.CallToolParams{
			Name:      "approval.status",
			Arguments: map[string]any{"approval_id": patchOut1.ApprovalID},
		})
		if err != nil || sr.IsError {
			t.Fatalf("approval.status 调用失败: err=%v res=%+v", err, sr)
		}
		decodeToolJSON(t, sr, &statusOut)
		if statusOut.ExecStatus == "SUCCEEDED" {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if statusOut.Status != string(approval.StatusApproved) || statusOut.ExecStatus != "SUCCEEDED" {
		t.Fatalf("期望后台续接执行成功: %+v", statusOut)
	}

	// 验证磁盘文件确实已更新为 return 42
	updatedContent, _ := os.ReadFile(filepath.Join(wsAlpha, "main.go"))
	if !strings.Contains(string(updatedContent), "return 42") {
		t.Fatalf("后台续接执行未写入文件，内容: %s", string(updatedContent))
	}

	// 3e. 模拟云端模型重发同一个 workspace.patch（带旧 sha256） -> 命中幂等缓存直接返回成功且不报错
	replayRes, err := csB.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "workspace.patch",
		Arguments: patchArgs,
	})
	if err != nil || replayRes.IsError {
		t.Fatalf("同指纹重试应命中幂等缓存直接成功: err=%v res=%+v", err, replayRes)
	}

	// --- 验收 4：一键断开隧道瞬间阻断远程请求 + 单点吊销客户端令牌 ---
	adminCall(http.MethodPost, "/api/relay/disconnect", map[string]any{"reason": "e2e 断开验收"})
	disReq, _ := http.NewRequest(http.MethodPost, mcpTS.URL+"/mcp", strings.NewReader(`{}`))
	disReq.Host = "mcp.e2e.example"
	disReq.Header.Set("Authorization", "Bearer "+tokenB)
	disResp, err := http.DefaultClient.Do(disReq)
	if err != nil {
		t.Fatal(err)
	}
	disResp.Body.Close()
	if disResp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("断开隧道后远程请求应立即返回 503，实际 %d", disResp.StatusCode)
	}

	// 恢复隧道并吊销客户端 B
	adminCall(http.MethodPost, "/api/relay/connect", nil)
	adminCall(http.MethodPost, "/api/oauth/clients/"+clientBID+"/revoke", nil)

	revokedReq, _ := http.NewRequest(http.MethodPost, mcpTS.URL+"/mcp", strings.NewReader(`{}`))
	revokedReq.Host = "mcp.e2e.example"
	revokedReq.Header.Set("Authorization", "Bearer "+tokenB)
	revokedResp, err := http.DefaultClient.Do(revokedReq)
	if err != nil {
		t.Fatal(err)
	}
	revokedResp.Body.Close()
	if revokedResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("吊销客户端后访问应返回 401，实际 %d", revokedResp.StatusCode)
	}
}
