package oauth

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// RegisterRoutes 将标准 OAuth 2.1 与 MCP 发现端点挂载到 HTTP Mux。
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/oauth-protected-resource", s.withCORS(s.handleProtectedResourceMetadata))
	mux.HandleFunc("/.well-known/oauth-protected-resource/", s.withCORS(s.handleProtectedResourceMetadata))
	mux.HandleFunc("/.well-known/oauth-authorization-server", s.withCORS(s.handleAuthServerMetadata))
	mux.HandleFunc("/.well-known/openid-configuration", s.withCORS(s.handleAuthServerMetadata))
	mux.HandleFunc("/oauth/register", s.withCORS(s.handleRegister))
	mux.HandleFunc("/oauth/authorize", s.handleAuthorize)
	mux.HandleFunc("/oauth/authorize/poll", s.handleAuthorizePoll)
	mux.HandleFunc("/oauth/authorize/confirm", s.handleAuthorizeConfirm)
	mux.HandleFunc("/oauth/token", s.withCORS(s.handleToken))
	mux.HandleFunc("/oauth/revoke", s.withCORS(s.handleRevoke))
}

// BaseURL 推导当前对外公告的 Issuer / 公网基地址（优先采用隧道公网 HTTPS URL）。
func (s *Server) BaseURL(r *http.Request) string {
	if s.publicURLProvider != nil {
		if pub := strings.TrimRight(strings.TrimSpace(s.publicURLProvider()), "/"); pub != "" {
			return pub
		}
	}
	if r == nil {
		return ""
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
		scheme = "https"
	}
	// 仅信任已经过外层网关 Host 白名单检验的 r.Host，不信任可能被客户端伪造的 X-Forwarded-Host
	host := strings.TrimSpace(r.Host)
	if host == "" {
		return ""
	}
	return scheme + "://" + host
}

// ResourceMetadataURL 返回 RFC 9728 Protected Resource Metadata 地址，用于 401 WWW-Authenticate 头。
func (s *Server) ResourceMetadataURL(r *http.Request) string {
	base := s.BaseURL(r)
	if base == "" {
		return "/.well-known/oauth-protected-resource"
	}
	return base + "/.well-known/oauth-protected-resource"
}

func (s *Server) withCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
			if !isValidCORSOrigin(origin) {
				http.Error(w, `{"error":"forbidden origin"}`, http.StatusForbidden)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, Mcp-Session-Id, MCP-Protocol-Version")
		w.Header().Set("Access-Control-Max-Age", "600")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func isValidCORSOrigin(origin string) bool {
	if strings.EqualFold(origin, "null") {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	return (scheme == "https" || scheme == "http") && u.Hostname() != ""
}

func (s *Server) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	base := s.BaseURL(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 base + "/mcp",
		"authorization_servers":    []string{base},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{"mcp:tools", "mcp:read", "mcp:write"},
		"resource_name":            "NodeBridge Personal Computer Agent Gateway",
	})
}

func (s *Server) handleAuthServerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	base := s.BaseURL(r)
	meta := map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/oauth/authorize",
		"token_endpoint":                        base + "/oauth/token",
		"revocation_endpoint":                   base + "/oauth/revoke",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post", "client_secret_basic"},
		"scopes_supported":                      []string{"mcp:tools", "mcp:read", "mcp:write"},
	}
	if s.cfg.DynamicRegistrationEnabled() {
		meta["registration_endpoint"] = base + "/oauth/register"
	}
	writeJSON(w, http.StatusOK, meta)
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.cfg.DynamicRegistrationEnabled() {
		writeOAuthError(w, http.StatusForbidden, "registration_not_supported", "服务端已禁用动态客户端注册")
		return
	}
	if !s.limiter.allow(clientIP(r)) {
		writeOAuthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "请求过于频繁，请稍后重试")
		return
	}

	var req struct {
		ClientName              string   `json:"client_name"`
		RedirectURIs            []string `json:"redirect_uris"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		Scope                   string   `json:"scope"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32*1024)).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "注册请求 JSON 格式无效")
		return
	}
	if len(req.RedirectURIs) == 0 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris 不能为空")
		return
	}
	for _, uri := range req.RedirectURIs {
		if err := s.ValidateRedirectURI(uri); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
			return
		}
	}

	authMethod := strings.TrimSpace(req.TokenEndpointAuthMethod)
	if authMethod == "" {
		authMethod = "none"
	}
	if authMethod != "none" && authMethod != "client_secret_post" && authMethod != "client_secret_basic" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "不支持的 token_endpoint_auth_method")
		return
	}

	clientID, err := randomHexToken("nb_cli_", 12)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "生成客户端 ID 失败")
		return
	}
	clientName := strings.TrimSpace(req.ClientName)
	if clientName == "" {
		clientName = "Remote MCP Client"
	}

	var plainSecret string
	var secretHash string
	if authMethod != "none" {
		plainSecret, err = randomHexToken("nb_sec_", 20)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "生成客户端密钥失败")
			return
		}
		secretHash = sha256Hex(plainSecret)
	}

	now := time.Now().UTC()
	cli := &Client{
		ClientID:          clientID,
		ClientName:        clientName,
		ClientSecretHash:  secretHash,
		RedirectURIs:      cleanStringSlice(req.RedirectURIs),
		TokenEndpointAuth: authMethod,
		Scopes:            strings.Fields(req.Scope),
		CreatedAt:         now,
	}

	s.mu.Lock()
	if err := s.pruneUnboundClientsLocked(now); err != nil {
		s.mu.Unlock()
		writeOAuthError(w, http.StatusTooManyRequests, "temporarily_unavailable", err.Error())
		return
	}
	s.clients[clientID] = cli
	_ = s.saveStateLocked()
	s.broadcastLocked(Event{Type: "oauth_clients_updated", Payload: s.listClientsLocked(now)})
	s.mu.Unlock()

	resp := map[string]any{
		"client_id":                  cli.ClientID,
		"client_name":                cli.ClientName,
		"redirect_uris":              cli.RedirectURIs,
		"token_endpoint_auth_method": cli.TokenEndpointAuth,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"client_id_issued_at":        now.Unix(),
	}
	if plainSecret != "" {
		resp["client_secret"] = plainSecret
		resp["client_secret_expires_at"] = 0
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.limiter.allow(clientIP(r)) {
		http.Error(w, "请求过于频繁，请稍后再试", http.StatusTooManyRequests)
		return
	}

	q := r.URL.Query()
	responseType := strings.TrimSpace(q.Get("response_type"))
	clientID := strings.TrimSpace(q.Get("client_id"))
	redirectURI := strings.TrimSpace(q.Get("redirect_uri"))
	state := strings.TrimSpace(q.Get("state"))
	scopeStr := strings.TrimSpace(q.Get("scope"))
	resource := strings.TrimSpace(q.Get("resource"))
	codeChallenge := strings.TrimSpace(q.Get("code_challenge"))
	codeChallengeMethod := strings.TrimSpace(q.Get("code_challenge_method"))

	s.mu.Lock()
	cli, ok := s.clients[clientID]
	s.mu.Unlock()
	if !ok {
		http.Error(w, "未知的 client_id，请先完成客户端注册", http.StatusBadRequest)
		return
	}
	if !containsExact(cli.RedirectURIs, redirectURI) {
		http.Error(w, "redirect_uri 与客户端注册信息不匹配", http.StatusBadRequest)
		return
	}
	if responseType != "code" {
		http.Redirect(w, r, buildErrorRedirect(redirectURI, state, "unsupported_response_type", "仅支持 response_type=code"), http.StatusFound)
		return
	}
	if codeChallenge == "" || !strings.EqualFold(codeChallengeMethod, "S256") {
		http.Redirect(w, r, buildErrorRedirect(redirectURI, state, "invalid_request", "OAuth 2.1 强制要求 PKCE S256（code_challenge_method=S256）"), http.StatusFound)
		return
	}

	reqID, err := randomHexToken("oar_", 10)
	if err != nil {
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	pending := &PendingAuthRequest{
		ID:                  reqID,
		ClientID:            cli.ClientID,
		ClientName:          cli.ClientName,
		RedirectURI:         redirectURI,
		State:               state,
		Scopes:              strings.Fields(scopeStr),
		Resource:            resource,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
		Status:              "pending",
		CreatedAt:           now,
		ExpiresAt:           now.Add(5 * time.Minute),
	}

	s.mu.Lock()
	s.cleanupEphemeralLocked(now)
	s.pendingAuths[reqID] = pending
	s.broadcastLocked(Event{Type: "oauth_auth_requested", Payload: *pending})
	s.mu.Unlock()

	s.renderAuthorizePage(w, *pending, "")
}

func (s *Server) handleAuthorizePoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.pollLimiter.allow(clientIP(r)) {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"status": "rate_limited"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	reqID := strings.TrimSpace(r.URL.Query().Get("req"))
	now := time.Now().UTC()

	s.mu.Lock()
	s.cleanupEphemeralLocked(now)
	req, ok := s.pendingAuths[reqID]
	if !ok {
		s.mu.Unlock()
		writeJSON(w, http.StatusNotFound, map[string]any{"status": "expired"})
		return
	}
	resp := map[string]any{
		"status": req.Status,
	}
	if (req.Status == "approved" || req.Status == "denied") && !req.PollConsumed && req.RedirectResult != "" {
		resp["redirect_url"] = req.RedirectResult
		// 一次性消费含授权码的回调地址，防止重复轮询泄露 code
		req.PollConsumed = true
		req.RedirectResult = ""
	}
	if req.ErrorMessage != "" {
		resp["error_message"] = req.ErrorMessage
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAuthorizeConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.limiter.allow(clientIP(r)) {
		http.Error(w, "尝试过于频繁，已触发防爆破限流，请 1 分钟后再试", http.StatusTooManyRequests)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "表单格式无效", http.StatusBadRequest)
		return
	}
	reqID := strings.TrimSpace(r.FormValue("request_id"))
	action := strings.TrimSpace(r.FormValue("action"))
	pairingCode := strings.TrimSpace(r.FormValue("pairing_code"))

	if action == "deny" {
		redirectURL, err := s.DenyAuthRequestFromPublic(reqID)
		if err != nil || redirectURL == "" {
			http.Error(w, "授权请求已失效", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	redirectURL, err := s.ConfirmAuthWithPairingCode(reqID, pairingCode)
	if err != nil {
		s.mu.Lock()
		req, ok := s.pendingAuths[reqID]
		var reqCopy PendingAuthRequest
		if ok {
			reqCopy = *req
		}
		s.mu.Unlock()
		if !ok {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		s.renderAuthorizePage(w, reqCopy, err.Error())
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.limiter.allow(clientIP(r)) {
		writeOAuthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "令牌接口速率超限")
		return
	}

	params := parseTokenParams(r)
	grantType := strings.TrimSpace(params["grant_type"])
	clientID := strings.TrimSpace(params["client_id"])
	clientSecret := strings.TrimSpace(params["client_secret"])
	if basicID, basicSecret, ok := r.BasicAuth(); ok {
		if clientID == "" {
			clientID = basicID
		}
		if clientSecret == "" {
			clientSecret = basicSecret
		}
	}

	switch grantType {
	case "authorization_code":
		s.handleAuthCodeGrant(w, clientID, clientSecret, params)
	case "refresh_token":
		s.handleRefreshTokenGrant(w, clientID, clientSecret, params)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "仅支持 authorization_code 与 refresh_token")
	}
}

func (s *Server) handleAuthCodeGrant(w http.ResponseWriter, clientID, clientSecret string, params map[string]string) {
	code := strings.TrimSpace(params["code"])
	redirectURI := params["redirect_uri"]
	verifier := strings.TrimSpace(params["code_verifier"])
	if code == "" || verifier == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "缺少 code 或 code_verifier")
		return
	}

	now := time.Now().UTC()
	codeHash := sha256Hex(code)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupEphemeralLocked(now)

	rec, ok := s.authCodes[codeHash]
	if !ok || rec.Used || now.After(rec.ExpiresAt) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "授权码无效、已使用或已过期")
		return
	}
	// 单次消费：无论后续校验是否成功，立刻作废该授权码防重放
	rec.Used = true
	delete(s.authCodes, codeHash)

	// OAuth 2.1 要求必须显式提供 client_id（表单/JSON 或 HTTP Basic Auth）
	if clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "缺少必需参数 client_id")
		return
	}
	if rec.ClientID != clientID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "client_id 与授权码不匹配")
		return
	}
	cli, ok := s.clients[clientID]
	if !ok || cli.Revoked {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "客户端不存在或已撤销")
		return
	}
	if err := verifyClientSecret(cli, clientSecret); err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	// OAuth 2.1 §10.2 允许换码时省略回调地址；兼容客户端传入的非空值必须完全匹配。
	if redirectURI != "" && redirectURI != rec.RedirectURI {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri 不匹配")
		return
	}
	if !verifyPKCES256(verifier, rec.CodeChallenge) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE S256 校验失败")
		return
	}

	familyID, err := randomHexToken("fam_", 8)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "生成令牌族失败")
		return
	}
	s.issueTokenPairLocked(w, cli, familyID, rec.Resource, rec.Scopes, rec.ReadOnly, rec.AllowedWorkspaces, now)
}

func (s *Server) handleRefreshTokenGrant(w http.ResponseWriter, clientID, clientSecret string, params map[string]string) {
	rawRT := strings.TrimSpace(params["refresh_token"])
	if rawRT == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "缺少 refresh_token")
		return
	}

	now := time.Now().UTC()
	rtHash := sha256Hex(rawRT)

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.refreshTokens[rtHash]
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh_token 无效或已吊销")
		return
	}

	// 重放检测：如果该 Refresh Token 已经轮换过却再次被提交，说明可能被窃取，立刻吊销该客户端全部令牌！
	if rec.Rotated || rec.Revoked {
		s.revokeClientTokensLocked(rec.ClientID, now)
		if cli, exists := s.clients[rec.ClientID]; exists {
			cli.Revoked = true
			cli.RevokedAt = now
		}
		_ = s.saveStateLocked()
		s.broadcastLocked(Event{Type: "oauth_clients_updated", Payload: s.listClientsLocked(now)})
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "检测到已轮换 Refresh Token 重放，已自动吊销该客户端全部令牌")
		return
	}

	if now.After(rec.ExpiresAt) {
		delete(s.refreshTokens, rtHash)
		_ = s.saveStateLocked()
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh_token 已过期，请重新授权")
		return
	}

	if clientID != "" && clientID != rec.ClientID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "client_id 与 refresh_token 不匹配")
		return
	}
	cli, ok := s.clients[rec.ClientID]
	if !ok || cli.Revoked {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "客户端授权已撤销")
		return
	}
	if err := verifyClientSecret(cli, clientSecret); err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}

	// 标记旧 Refresh Token 为已轮换（保留记录以便后续检测重放攻击）
	rec.Rotated = true
	s.issueTokenPairLocked(w, cli, rec.FamilyID, rec.Resource, rec.Scopes, rec.ReadOnly, rec.AllowedWorkspaces, now)
}

func (s *Server) issueTokenPairLocked(
	w http.ResponseWriter,
	cli *Client,
	familyID, resource string,
	scopes []string,
	readOnly bool,
	allowedWorkspaces []string,
	now time.Time,
) {
	rawAT, err := randomHexToken("nb_at_", 24)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "签发 Access Token 失败")
		return
	}
	rawRT, err := randomHexToken("nb_rt_", 24)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "签发 Refresh Token 失败")
		return
	}

	atTTL := time.Duration(s.cfg.AccessTokenTTLSeconds) * time.Second
	rtTTL := time.Duration(s.cfg.RefreshTokenTTLSeconds) * time.Second

	atHash := sha256Hex(rawAT)
	rtHash := sha256Hex(rawRT)

	s.accessTokens[atHash] = &AccessTokenRecord{
		TokenHash:         atHash,
		ClientID:          cli.ClientID,
		Resource:          resource,
		Scopes:            append([]string(nil), scopes...),
		ReadOnly:          readOnly,
		AllowedWorkspaces: append([]string(nil), allowedWorkspaces...),
		CreatedAt:         now,
		ExpiresAt:         now.Add(atTTL),
	}
	s.refreshTokens[rtHash] = &RefreshTokenRecord{
		TokenHash:         rtHash,
		FamilyID:          familyID,
		ClientID:          cli.ClientID,
		Resource:          resource,
		Scopes:            append([]string(nil), scopes...),
		ReadOnly:          readOnly,
		AllowedWorkspaces: append([]string(nil), allowedWorkspaces...),
		CreatedAt:         now,
		ExpiresAt:         now.Add(rtTTL),
	}
	cli.LastUsedAt = now
	_ = s.saveStateLocked()
	s.broadcastLocked(Event{Type: "oauth_clients_updated", Payload: s.listClientsLocked(now)})

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  rawAT,
		"token_type":    "Bearer",
		"expires_in":    s.cfg.AccessTokenTTLSeconds,
		"refresh_token": rawRT,
		"scope":         strings.Join(scopes, " "),
	})
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.limiter.allow(clientIP(r)) {
		writeOAuthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "吊销接口速率超限")
		return
	}
	params := parseTokenParams(r)
	rawToken := strings.TrimSpace(params["token"])
	if rawToken != "" {
		hash := sha256Hex(rawToken)
		now := time.Now().UTC()
		s.mu.Lock()
		delete(s.accessTokens, hash)
		if rt, ok := s.refreshTokens[hash]; ok {
			rt.Revoked = true
			// RFC 7009：撤销 Refresh Token 时联动撤销该客户端的活跃 Access Token
			for atHash, at := range s.accessTokens {
				if at.ClientID == rt.ClientID {
					delete(s.accessTokens, atHash)
				}
			}
		}
		_ = s.saveStateLocked()
		s.broadcastLocked(Event{Type: "oauth_clients_updated", Payload: s.listClientsLocked(now)})
		s.mu.Unlock()
	}
	// RFC 7009：即使 token 不存在也返回 200
	w.WriteHeader(http.StatusOK)
}

var authorizePageTmpl = template.Must(template.New("authorize").Parse(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NodeBridge OAuth 2.1 客户端绑定确认</title>
<style>
  body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Microsoft YaHei",sans-serif; background:#0f172a; color:#e2e8f0; display:flex; align-items:center; justify-content:center; min-height:100vh; padding:20px; }
  .card { max-width:520px; width:100%; background:#1e293b; border:1px solid #334155; border-radius:12px; padding:24px; box-shadow:0 20px 50px rgba(0,0,0,.35); }
  h1 { margin:0 0 8px; font-size:19px; }
  p { margin:0 0 14px; color:#94a3b8; font-size:13.5px; line-height:1.55; }
  .box { background:#0b1220; border:1px solid #334155; border-radius:8px; padding:12px 14px; margin:14px 0; font-size:13px; }
  .row { display:flex; justify-content:space-between; gap:10px; padding:4px 0; border-bottom:1px solid rgba(51,65,85,.5); }
  .row:last-child { border-bottom:none; }
  .k { color:#94a3b8; flex-shrink:0; }
  .v { font-family:ui-monospace,Consolas,monospace; word-break:break-all; text-align:right; color:#e2e8f0; }
  .status { background:rgba(59,130,246,.16); border:1px solid rgba(59,130,246,.45); color:#bfdbfe; padding:10px 12px; border-radius:8px; font-size:13px; margin:14px 0; }
  .err { background:rgba(239,68,68,.18); border:1px solid rgba(239,68,68,.5); color:#fecaca; padding:10px 12px; border-radius:8px; font-size:13px; margin:12px 0; }
  input[type="text"] { width:100%; box-sizing:border-box; padding:10px 12px; border-radius:8px; border:1px solid #475569; background:#0b1220; color:#f8fafc; font-family:ui-monospace,Consolas,monospace; font-size:14px; margin:8px 0 12px; }
  .actions { display:flex; gap:10px; }
  button { flex:1; padding:10px 14px; border-radius:8px; border:1px solid transparent; font-size:14px; font-weight:600; cursor:pointer; }
  .btn-ok { background:#16a34a; color:#fff; }
  .btn-no { background:#334155; color:#e2e8f0; border-color:#475569; }
  .hint { font-size:12px; color:#94a3b8; margin-top:14px; }
</style>
</head>
<body>
<div class="card">
  <h1>NodeBridge 远程客户端授权确认</h1>
  <p>以下云端 AI 客户端正在申请绑定您的本地 NodeBridge 安全网关。为保护设备安全，此公网页面<strong>不会</strong>询问您的本地管理令牌（admin_token）。</p>

  <div class="box">
    <div class="row"><span class="k">客户端名称</span><span class="v">{{.Req.ClientName}}</span></div>
    <div class="row"><span class="k">客户端 ID</span><span class="v">{{.Req.ClientID}}</span></div>
    <div class="row"><span class="k">回调地址</span><span class="v">{{.Req.RedirectURI}}</span></div>
    <div class="row"><span class="k">申请范围</span><span class="v">{{.ScopeText}}</span></div>
    <div class="row"><span class="k">请求编号</span><span class="v">{{.Req.ID}}</span></div>
  </div>

  <div id="pollStatus" class="status">
    <strong>方式一（推荐）：</strong>请直接打开您本机的 NodeBridge Web 控制台（127.0.0.1），点击批准此次绑定请求。批准后本页面将自动跳转完成绑定。
  </div>

  {{if .ErrMsg}}<div class="err">{{.ErrMsg}}</div>{{end}}

  <form method="POST" action="/oauth/authorize/confirm">
    <input type="hidden" name="request_id" value="{{.Req.ID}}">
    <label for="pairing_code" style="font-size:13px;font-weight:600;">方式二：输入本地生成的一次性配对码（5 分钟单次有效）</label>
    <input id="pairing_code" name="pairing_code" type="text" placeholder="例如 nb_pair_xxxxxxxxxxxx" autocomplete="off">
    <div class="actions">
      <button type="submit" name="action" value="approve" class="btn-ok">使用配对码批准绑定</button>
      <button type="submit" name="action" value="deny" class="btn-no">拒绝授权</button>
    </div>
  </form>

  <div class="hint">提示：您可在本地终端运行 <code>nodebridge pair</code> 或在本地控制台一键生成一次性配对码。</div>
</div>
<script>
(function() {
  const reqId = {{.Req.ID}};
  async function poll() {
    try {
      const res = await fetch('/oauth/authorize/poll?req=' + encodeURIComponent(reqId), { cache: 'no-store' });
      const data = await res.json();
      if ((data.status === 'approved' || data.status === 'denied') && data.redirect_url) {
        document.getElementById('pollStatus').textContent = data.status === 'approved' ? '已获本机控制台批准，正在安全跳转...' : '已拒绝，正在返回...';
        window.location.href = data.redirect_url;
        return;
      }
      if (data.status === 'expired') {
        document.getElementById('pollStatus').textContent = '本次授权请求已过期，请在云端客户端重新发起。';
        return;
      }
    } catch (_) {}
    setTimeout(poll, 1500);
  }
  setTimeout(poll, 1500);
})();
</script>
</body>
</html>`))

func (s *Server) renderAuthorizePage(w http.ResponseWriter, req PendingAuthRequest, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'")
	scopeText := strings.Join(req.Scopes, " ")
	if scopeText == "" {
		scopeText = "mcp:tools"
	}
	_ = authorizePageTmpl.Execute(w, map[string]any{
		"Req":       req,
		"ScopeText": scopeText,
		"ErrMsg":    errMsg,
	})
}

func verifyClientSecret(cli *Client, provided string) error {
	if cli.TokenEndpointAuth == "" || cli.TokenEndpointAuth == "none" {
		return nil
	}
	if provided == "" {
		return fmt.Errorf("客户端 %s 需要提供 client_secret", cli.ClientID)
	}
	hash := sha256Hex(provided)
	if subtle.ConstantTimeCompare([]byte(hash), []byte(cli.ClientSecretHash)) != 1 {
		return errors.New("client_secret 校验失败")
	}
	return nil
}

func parseTokenParams(r *http.Request) map[string]string {
	out := make(map[string]string)
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(ct, "application/json") {
		var body map[string]any
		if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 32*1024)).Decode(&body); err == nil {
			for k, v := range body {
				if s, ok := v.(string); ok {
					out[k] = s
				}
			}
		}
		return out
	}
	_ = r.ParseForm()
	for k, vals := range r.Form {
		if len(vals) > 0 {
			out[k] = vals[0]
		}
	}
	return out
}

func containsExact(list []string, target string) bool {
	for _, s := range list {
		if s == target {
			return true
		}
	}
	return false
}

func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]any{
		"error":             code,
		"error_description": desc,
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func clientIP(r *http.Request) string {
	remoteHost, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		remoteHost = strings.TrimSpace(r.RemoteAddr)
	}
	// 仅当直连来源为本地回环（本机 cloudflared 或本地反代）时才读取转发 IP 头，防止客户端直接伪造头绕过限流
	if ip := net.ParseIP(strings.Trim(remoteHost, "[]")); ip != nil && ip.IsLoopback() {
		for _, h := range []string{"CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP"} {
			if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
				if idx := strings.Index(v, ","); idx >= 0 {
					v = strings.TrimSpace(v[:idx])
				}
				if v != "" {
					return v
				}
			}
		}
	}
	if remoteHost != "" {
		return remoteHost
	}
	return strings.TrimSpace(r.RemoteAddr)
}

// ipRateLimiter 实现简单的按 IP 滑动窗口速率限制器，防公网 OAuth 接口爆破并定期清理过期桶防内存泄漏。
type ipRateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	entries map[string][]time.Time
}

func newIPRateLimiter(limit int, window time.Duration) *ipRateLimiter {
	return &ipRateLimiter{
		limit:   limit,
		window:  window,
		entries: make(map[string][]time.Time),
	}
}

func (l *ipRateLimiter) allow(ip string) bool {
	if l == nil || l.limit <= 0 {
		return true
	}
	if ip == "" {
		ip = "unknown"
	}
	now := time.Now()
	cutoff := now.Add(-l.window)

	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.entries) > 256 {
		for k, times := range l.entries {
			alive := times[:0]
			for _, ts := range times {
				if ts.After(cutoff) {
					alive = append(alive, ts)
				}
			}
			if len(alive) == 0 {
				delete(l.entries, k)
			} else {
				l.entries[k] = alive
			}
		}
	}

	hits := l.entries[ip]
	kept := hits[:0]
	for _, ts := range hits {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	if len(kept) >= l.limit {
		l.entries[ip] = kept
		return false
	}
	l.entries[ip] = append(kept, now)
	return true
}
