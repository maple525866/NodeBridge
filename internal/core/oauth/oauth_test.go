package oauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"nodebridge/internal/config"
)

func makePKCE(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestOAuth21FullLifecycleAndReplayProtection(t *testing.T) {
	dataDir := t.TempDir()
	pubURL := "https://mcp.unit-test.example"

	srv, err := NewServer(Options{
		Config: config.OAuthConfig{
			Enabled:                true,
			AccessTokenTTLSeconds:  3600,
			RefreshTokenTTLSeconds: 86400,
			PairingCodeTTLSeconds:  300,
			RateLimitPerMinute:     100,
		},
		DataDir:           dataDir,
		DeviceID:          "dev_test_01",
		PublicURLProvider: func() string { return pubURL },
	})
	if err != nil {
		t.Fatalf("NewServer 失败: %v", err)
	}

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// 1. 验证 RFC 9728 & RFC 8414 发现元数据
	resp, err := http.Get(ts.URL + "/.well-known/oauth-protected-resource")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("RFC 9728 发现失败: err=%v status=%v", err, resp)
	}
	var prm map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&prm)
	resp.Body.Close()
	if prm["resource"] != pubURL+"/mcp" {
		t.Fatalf("resource 不匹配: %+v", prm)
	}

	respAS, err := http.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil || respAS.StatusCode != http.StatusOK {
		t.Fatalf("RFC 8414 发现失败: %v", err)
	}
	var asm map[string]any
	_ = json.NewDecoder(respAS.Body).Decode(&asm)
	respAS.Body.Close()
	if asm["issuer"] != pubURL || asm["registration_endpoint"] != pubURL+"/oauth/register" {
		t.Fatalf("AS 元数据异常: %+v", asm)
	}

	// 2. DCR 拒绝不安全的明文公网 redirect_uri
	badRegBody := `{"client_name":"Evil","redirect_uris":["http://evil.example/cb"]}`
	badRegResp, _ := http.Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(badRegBody))
	if badRegResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("应当拒绝非 HTTPS 公网 redirect_uri，实际 %d", badRegResp.StatusCode)
	}
	badRegResp.Body.Close()

	// 3. 合法 DCR 动态注册
	regBody := `{"client_name":"ChatGPT Web","redirect_uris":["https://chatgpt.com/connector/oauth/callback"],"token_endpoint_auth_method":"none"}`
	regResp, err := http.Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(regBody))
	if err != nil || regResp.StatusCode != http.StatusCreated {
		t.Fatalf("DCR 注册失败: err=%v status=%d", err, regResp.StatusCode)
	}
	var regOut struct {
		ClientID string `json:"client_id"`
	}
	_ = json.NewDecoder(regResp.Body).Decode(&regOut)
	regResp.Body.Close()
	if regOut.ClientID == "" {
		t.Fatalf("未返回 client_id")
	}

	// 4. 发起授权请求（PKCE S256），并使用“本地控制台批准”路径限定只读与工作区
	verifier := "abcdefghijklmnopqrstuvwxyz0123456789_ABCDEFGHIJKLMN"
	challenge := makePKCE(verifier)

	noRedirectClient := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 验证降级 plain 被拒
	plainURL := ts.URL + "/oauth/authorize?response_type=code&client_id=" + regOut.ClientID +
		"&redirect_uri=" + url.QueryEscape("https://chatgpt.com/connector/oauth/callback") +
		"&code_challenge=abc&code_challenge_method=plain&state=s0"
	plainResp, _ := noRedirectClient.Get(plainURL)
	if plainResp.StatusCode != http.StatusFound || !strings.Contains(plainResp.Header.Get("Location"), "error=invalid_request") {
		t.Fatalf("期望拒绝 PKCE plain，实际 status=%d loc=%s", plainResp.StatusCode, plainResp.Header.Get("Location"))
	}
	plainResp.Body.Close()

	// 发起合法 S256 授权页请求
	authURL := ts.URL + "/oauth/authorize?response_type=code&client_id=" + regOut.ClientID +
		"&redirect_uri=" + url.QueryEscape("https://chatgpt.com/connector/oauth/callback") +
		"&code_challenge=" + challenge + "&code_challenge_method=S256&state=st_123&scope=mcp:tools"
	authPageResp, err := noRedirectClient.Get(authURL)
	if err != nil || authPageResp.StatusCode != http.StatusOK {
		t.Fatalf("授权页加载失败: err=%v status=%d", err, authPageResp.StatusCode)
	}
	authPageResp.Body.Close()

	pending := srv.PendingAuthRequests()
	if len(pending) != 1 {
		t.Fatalf("期望 1 条待确认 OAuth 请求，实际 %d", len(pending))
	}

	// 模拟本地控制台批准，并限定 ReadOnly=true + 仅允许 ws_alpha
	resolved, err := srv.ResolveAuthRequest(pending[0].ID, true, true, []string{"ws_alpha"}, "控制台批准")
	if err != nil || resolved.Status != "approved" {
		t.Fatalf("ResolveAuthRequest 失败: err=%v req=%+v", err, resolved)
	}

	// 公网页轮询获取 302 回调 URL 与一次性授权码
	pollResp, _ := http.Get(ts.URL + "/oauth/authorize/poll?req=" + pending[0].ID)
	var pollOut struct {
		Status      string `json:"status"`
		RedirectURL string `json:"redirect_url"`
	}
	_ = json.NewDecoder(pollResp.Body).Decode(&pollOut)
	pollResp.Body.Close()
	if pollOut.Status != "approved" || pollOut.RedirectURL == "" {
		t.Fatalf("poll 结果异常: %+v", pollOut)
	}
	// 验证 poll 一次性消费 redirect_url，第二次轮询不应再次返回含 code 的回调地址
	pollResp2, _ := http.Get(ts.URL + "/oauth/authorize/poll?req=" + pending[0].ID)
	var pollOut2 struct {
		Status      string `json:"status"`
		RedirectURL string `json:"redirect_url"`
	}
	_ = json.NewDecoder(pollResp2.Body).Decode(&pollOut2)
	pollResp2.Body.Close()
	if pollOut2.RedirectURL != "" {
		t.Fatalf("poll 应一次性消费 redirect_url，第二次仍返回了: %s", pollOut2.RedirectURL)
	}
	parsedCB, _ := url.Parse(pollOut.RedirectURL)
	code := parsedCB.Query().Get("code")
	if code == "" || parsedCB.Query().Get("state") != "st_123" {
		t.Fatalf("回调参数异常: %s", pollOut.RedirectURL)
	}

	// 5. OAuth 2.1 客户端凭 PKCE 换码，无需再次发送 redirect_uri。
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", regOut.ClientID)
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	tokResp, err := http.PostForm(ts.URL+"/oauth/token", form)
	if err != nil || tokResp.StatusCode != http.StatusOK {
		t.Fatalf("换取 Token 失败: err=%v status=%d", err, tokResp.StatusCode)
	}
	var tokOut struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
	}
	_ = json.NewDecoder(tokResp.Body).Decode(&tokOut)
	tokResp.Body.Close()
	if tokOut.AccessToken == "" || tokOut.RefreshToken == "" {
		t.Fatalf("令牌响应缺失: %+v", tokOut)
	}

	// 6. 验证 Authenticate 返回正确的客户端级权限边界（只读 + ws_alpha）
	reqCheck, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp", nil)
	reqCheck.Header.Set("Authorization", "Bearer "+tokOut.AccessToken)
	principal, err := srv.Authenticate(reqCheck)
	if err != nil {
		t.Fatalf("Authenticate 失败: %v", err)
	}
	if !principal.IsRemote || !principal.ReadOnly || principal.HasWritePermission() {
		t.Fatalf("权限边界未生效: %+v", principal)
	}
	if !principal.CanAccessWorkspace("ws_alpha") || principal.CanAccessWorkspace("ws_beta") {
		t.Fatalf("工作区子集隔离异常: %+v", principal)
	}

	// 7. 验证持久化恢复（模拟 Daemon 重启）
	reloaded, err := NewServer(Options{
		Config:            srv.cfg,
		DataDir:           dataDir,
		DeviceID:          "dev_test_01",
		PublicURLProvider: func() string { return pubURL },
	})
	if err != nil {
		t.Fatalf("重启加载 OAuth 状态失败: %v", err)
	}
	if _, err := reloaded.Authenticate(reqCheck); err != nil {
		t.Fatalf("重启后既有 Access Token 应继续有效: %v", err)
	}

	// 8. Refresh Token 轮换 + 重放旧 Refresh Token 自动吊销整个客户端
	refForm := url.Values{}
	refForm.Set("grant_type", "refresh_token")
	refForm.Set("client_id", regOut.ClientID)
	refForm.Set("refresh_token", tokOut.RefreshToken)
	refResp, _ := http.PostForm(ts.URL+"/oauth/token", refForm)
	if refResp.StatusCode != http.StatusOK {
		t.Fatalf("Refresh Token 轮换失败: status=%d", refResp.StatusCode)
	}
	var refOut struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.NewDecoder(refResp.Body).Decode(&refOut)
	refResp.Body.Close()
	if refOut.RefreshToken == "" || refOut.RefreshToken == tokOut.RefreshToken {
		t.Fatalf("Refresh Token 未轮换")
	}

	// 恶意重放旧 Refresh Token
	replayResp, _ := http.PostForm(ts.URL+"/oauth/token", refForm)
	if replayResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("重放旧 Refresh Token 应当返回 400，实际 %d", replayResp.StatusCode)
	}
	replayResp.Body.Close()

	// 验证新签发的 Access Token 也已被连带自动吊销
	reqNew, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp", nil)
	reqNew.Header.Set("Authorization", "Bearer "+refOut.AccessToken)
	if _, err := srv.Authenticate(reqNew); err == nil {
		t.Fatalf("触发重放保护后，该客户端新旧令牌必须全部失效")
	}
}

func TestPairingCodeOneTimeUseAndRateLimit(t *testing.T) {
	srv, err := NewServer(Options{
		Config: config.OAuthConfig{
			Enabled:               true,
			PairingCodeTTLSeconds: 300,
			RateLimitPerMinute:    50,
		},
		DataDir:  t.TempDir(),
		DeviceID: "dev_pair",
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// 注册客户端
	regResp, _ := http.Post(ts.URL+"/oauth/register", "application/json", bytes.NewBufferString(`{"client_name":"Gemini Web","redirect_uris":["https://gemini.google.com/mcp/cb"]}`))
	var regOut struct {
		ClientID string `json:"client_id"`
	}
	_ = json.NewDecoder(regResp.Body).Decode(&regOut)
	regResp.Body.Close()

	// 生成一次性配对码
	pc, err := srv.CreatePairingCode(false, []string{"default"}, "测试配对")
	if err != nil || !strings.HasPrefix(pc.Code, "nb_pair_") {
		t.Fatalf("生成配对码失败: err=%v pc=%+v", err, pc)
	}

	// 发起两个授权请求
	makeReq := func() string {
		u := ts.URL + "/oauth/authorize?response_type=code&client_id=" + regOut.ClientID +
			"&redirect_uri=" + url.QueryEscape("https://gemini.google.com/mcp/cb") +
			"&code_challenge=" + makePKCE("123456789012345678901234567890123456789012345") +
			"&code_challenge_method=S256"
		r, _ := http.Get(u)
		r.Body.Close()
		all := srv.PendingAuthRequests()
		return all[0].ID
	}

	req1 := makeReq()
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// 第一次提交配对码成功并 302 跳转
	f1 := url.Values{"request_id": {req1}, "action": {"approve"}, "pairing_code": {pc.Code}}
	r1, err := noRedirect.PostForm(ts.URL+"/oauth/authorize/confirm", f1)
	if err != nil || r1.StatusCode != http.StatusFound || !strings.Contains(r1.Header.Get("Location"), "code=nb_code_") {
		t.Fatalf("首次使用配对码应成功跳转，实际 err=%v status=%d loc=%s", err, r1.StatusCode, r1.Header.Get("Location"))
	}
	r1.Body.Close()

	// 第二次复用同一配对码必须被拒绝（403）
	req2 := makeReq()
	f2 := url.Values{"request_id": {req2}, "action": {"approve"}, "pairing_code": {pc.Code}}
	r2, err := noRedirect.PostForm(ts.URL+"/oauth/authorize/confirm", f2)
	if err != nil || r2.StatusCode != http.StatusForbidden {
		t.Fatalf("复用已消费配对码应返回 403，实际 err=%v status=%d", err, r2.StatusCode)
	}
	r2.Body.Close()
}

func TestOAuthSecurityHardening(t *testing.T) {
	srv, err := NewServer(Options{
		Config: config.OAuthConfig{
			Enabled:            true,
			RateLimitPerMinute: 100,
		},
		DataDir:  t.TempDir(),
		DeviceID: "dev_sec",
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// 1. BaseURL 绝不信任伪造的 X-Forwarded-Host
	reqMeta, _ := http.NewRequest(http.MethodGet, ts.URL+"/.well-known/oauth-authorization-server", nil)
	reqMeta.Header.Set("X-Forwarded-Host", "evil.attacker.example")
	respMeta, err := http.DefaultClient.Do(reqMeta)
	if err != nil {
		t.Fatal(err)
	}
	var asm map[string]any
	_ = json.NewDecoder(respMeta.Body).Decode(&asm)
	respMeta.Body.Close()
	if strings.Contains(asm["issuer"].(string), "evil.attacker.example") {
		t.Fatalf("BaseURL 不应信任伪造的 X-Forwarded-Host: %+v", asm)
	}

	// 2. 拒绝反射 Origin: null
	reqNull, _ := http.NewRequest(http.MethodGet, ts.URL+"/.well-known/oauth-protected-resource", nil)
	reqNull.Header.Set("Origin", "null")
	respNull, err := http.DefaultClient.Do(reqNull)
	if err != nil {
		t.Fatal(err)
	}
	respNull.Body.Close()
	if respNull.StatusCode != http.StatusForbidden {
		t.Fatalf("Origin: null 应返回 403，实际 %d", respNull.StatusCode)
	}

	// 3. 每次授权码兑换独立校验客户端身份与传入的回调地址。
	regResp, _ := http.Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(`{"client_name":"StrictClient","redirect_uris":["https://app.example/cb"]}`))
	var regOut struct {
		ClientID string `json:"client_id"`
	}
	_ = json.NewDecoder(regResp.Body).Decode(&regOut)
	regResp.Body.Close()

	verifier := "strict_client_verifier_0123456789_abcdefghijklmnop"
	const callback = "https://app.example/cb"
	for _, tc := range []struct {
		name, clientID, redirectURI, wantError string
	}{
		{"missing client ID", "", callback, "invalid_request"},
		{"matching redirect URI", regOut.ClientID, callback, ""},
		{"different redirect URI", regOut.ClientID, callback + "/other", "invalid_grant"},
		{"padded redirect URI", regOut.ClientID, callback + " ", "invalid_grant"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authResp, err := http.Get(ts.URL + "/oauth/authorize?response_type=code&client_id=" + regOut.ClientID +
				"&redirect_uri=" + url.QueryEscape(callback) +
				"&code_challenge=" + makePKCE(verifier) + "&code_challenge_method=S256")
			if err != nil {
				t.Fatal(err)
			}
			authResp.Body.Close()
			pending := srv.PendingAuthRequests()
			if len(pending) != 1 {
				t.Fatalf("期望一条待确认授权，实际 %d", len(pending))
			}
			resolved, err := srv.ResolveAuthRequest(pending[0].ID, true, false, nil, "ok")
			if err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(resolved.RedirectResult)
			if err != nil {
				t.Fatal(err)
			}
			form := url.Values{
				"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")},
				"redirect_uri": {tc.redirectURI}, "code_verifier": {verifier},
			}
			if tc.clientID != "" {
				form.Set("client_id", tc.clientID)
			}
			resp, err := http.PostForm(ts.URL+"/oauth/token", form)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			var result struct {
				Error       string `json:"error"`
				AccessToken string `json:"access_token"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				t.Fatal(err)
			}
			if tc.wantError == "" {
				if resp.StatusCode != http.StatusOK || result.AccessToken == "" {
					t.Fatalf("期望成功换码，实际 %d %s", resp.StatusCode, result.Error)
				}
			} else if resp.StatusCode != http.StatusBadRequest || result.Error != tc.wantError {
				t.Fatalf("期望 400 %s，实际 %d %s", tc.wantError, resp.StatusCode, result.Error)
			}
		})
	}
}
