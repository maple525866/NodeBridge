// Package oauth 实现零外部依赖的内置单用户 OAuth 2.1 授权服务器，遵循 MCP 远程鉴权规范
// （RFC 9728 Protected Resource Metadata、RFC 8414 AS Metadata、RFC 7591 DCR、PKCE S256、
// Refresh Token 轮换与重放吊销、零长期凭据公网授权确认）。
package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"nodebridge/internal/config"
	"nodebridge/internal/core/session"
)

// Client 描述通过 DCR 或预配置注册的 OAuth 2.1 客户端及其权限边界。
type Client struct {
	ClientID          string    `json:"client_id"`
	ClientName        string    `json:"client_name"`
	ClientSecretHash  string    `json:"client_secret_hash,omitempty"`
	RedirectURIs      []string  `json:"redirect_uris"`
	TokenEndpointAuth string    `json:"token_endpoint_auth_method"`
	ReadOnly          bool      `json:"read_only"`
	AllowedWorkspaces []string  `json:"allowed_workspaces,omitempty"`
	Scopes            []string  `json:"scopes,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	AuthorizedAt      time.Time `json:"authorized_at,omitempty"`
	LastUsedAt        time.Time `json:"last_used_at,omitempty"`
	Revoked           bool      `json:"revoked"`
	RevokedAt         time.Time `json:"revoked_at,omitempty"`
}

// ClientSummary 是暴露给本地控制台与 CLI 的脱敏客户端摘要视图。
type ClientSummary struct {
	ClientID          string    `json:"client_id"`
	ClientName        string    `json:"client_name"`
	RedirectURIs      []string  `json:"redirect_uris"`
	ReadOnly          bool      `json:"read_only"`
	AllowedWorkspaces []string  `json:"allowed_workspaces,omitempty"`
	Scopes            []string  `json:"scopes,omitempty"`
	ActiveTokens      int       `json:"active_tokens"`
	Authorized        bool      `json:"authorized"`
	Revoked           bool      `json:"revoked"`
	CreatedAt         time.Time `json:"created_at"`
	LastUsedAt        time.Time `json:"last_used_at,omitempty"`
}

// AccessTokenRecord 持久化保存已签发的短期 Access Token 元数据（仅存哈希，不存明文）。
type AccessTokenRecord struct {
	TokenHash         string    `json:"token_hash"`
	ClientID          string    `json:"client_id"`
	Resource          string    `json:"resource,omitempty"`
	Scopes            []string  `json:"scopes"`
	ReadOnly          bool      `json:"read_only"`
	AllowedWorkspaces []string  `json:"allowed_workspaces,omitempty"`
	ExpiresAt         time.Time `json:"expires_at"`
	CreatedAt         time.Time `json:"created_at"`
	Revoked           bool      `json:"revoked,omitempty"`
}

// RefreshTokenRecord 持久化保存可轮换 Refresh Token 元数据（仅存哈希，支持重放检测）。
type RefreshTokenRecord struct {
	TokenHash         string    `json:"token_hash"`
	FamilyID          string    `json:"family_id"`
	ClientID          string    `json:"client_id"`
	Resource          string    `json:"resource,omitempty"`
	Scopes            []string  `json:"scopes"`
	ReadOnly          bool      `json:"read_only"`
	AllowedWorkspaces []string  `json:"allowed_workspaces,omitempty"`
	ExpiresAt         time.Time `json:"expires_at"`
	CreatedAt         time.Time `json:"created_at"`
	Rotated           bool      `json:"rotated,omitempty"`
	Revoked           bool      `json:"revoked,omitempty"`
}

// PairingCode 描述由设备主人在本地生成的一次性短期配对码。
type PairingCode struct {
	Code              string    `json:"code"`
	ReadOnly          bool      `json:"read_only"`
	AllowedWorkspaces []string  `json:"allowed_workspaces,omitempty"`
	Note              string    `json:"note,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	Used              bool      `json:"used,omitempty"`
}

// PendingAuthRequest 描述正在等待用户在本地控制台批准或输入配对码的 OAuth 授权请求。
type PendingAuthRequest struct {
	ID                  string    `json:"id"`
	ClientID            string    `json:"client_id"`
	ClientName          string    `json:"client_name"`
	RedirectURI         string    `json:"redirect_uri"`
	State               string    `json:"state,omitempty"`
	Scopes              []string  `json:"scopes"`
	Resource            string    `json:"resource,omitempty"`
	CodeChallenge       string    `json:"-"`
	CodeChallengeMethod string    `json:"-"`
	Status              string    `json:"status"` // pending | approved | denied | expired
	RedirectResult      string    `json:"-"`
	PollConsumed        bool      `json:"-"`
	ErrorMessage        string    `json:"error_message,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	ExpiresAt           time.Time `json:"expires_at"`
}

type authCodeRecord struct {
	CodeHash            string
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	Resource            string
	Scopes              []string
	ReadOnly            bool
	AllowedWorkspaces   []string
	ExpiresAt           time.Time
	Used                bool
}

// Event 用于向本地 Web 控制台通过 SSE 推送 OAuth 客户端绑定与吊销状态变化。
type Event struct {
	Type    string `json:"type"` // oauth_auth_requested | oauth_auth_resolved | oauth_clients_updated | oauth_pairing_created
	Payload any    `json:"payload"`
}

type persistedState struct {
	Clients       map[string]*Client             `json:"clients"`
	AccessTokens  map[string]*AccessTokenRecord  `json:"access_tokens"`
	RefreshTokens map[string]*RefreshTokenRecord `json:"refresh_tokens"`
}

// Options 配置 OAuth 2.1 授权服务器运行参数。
type Options struct {
	Config            config.OAuthConfig
	DataDir           string
	DeviceID          string
	PublicURLProvider func() string
}

// Server 管理内置单用户 OAuth 2.1 授权流、令牌生命周期与客户端级权限边界。
type Server struct {
	cfg               config.OAuthConfig
	statePath         string
	deviceID          string
	publicURLProvider func() string

	mu            sync.Mutex
	clients       map[string]*Client
	accessTokens  map[string]*AccessTokenRecord
	refreshTokens map[string]*RefreshTokenRecord
	pendingAuths  map[string]*PendingAuthRequest
	authCodes     map[string]*authCodeRecord
	pairingCodes  map[string]*PairingCode
	listeners     map[chan Event]struct{}
	limiter       *ipRateLimiter
	pollLimiter   *ipRateLimiter
}

// NewServer 创建并从磁盘加载 OAuth 2.1 授权服务器状态。
func NewServer(opts Options) (*Server, error) {
	if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建 OAuth 数据目录失败: %w", err)
	}
	if opts.Config.AccessTokenTTLSeconds <= 0 {
		opts.Config.AccessTokenTTLSeconds = 3600
	}
	if opts.Config.RefreshTokenTTLSeconds <= 0 {
		opts.Config.RefreshTokenTTLSeconds = 604800
	}
	if opts.Config.PairingCodeTTLSeconds <= 0 {
		opts.Config.PairingCodeTTLSeconds = 300
	}
	if opts.Config.RateLimitPerMinute <= 0 {
		opts.Config.RateLimitPerMinute = 20
	}

	s := &Server{
		cfg:               opts.Config,
		statePath:         filepath.Join(opts.DataDir, "oauth_state.json"),
		deviceID:          opts.DeviceID,
		publicURLProvider: opts.PublicURLProvider,
		clients:           make(map[string]*Client),
		accessTokens:      make(map[string]*AccessTokenRecord),
		refreshTokens:     make(map[string]*RefreshTokenRecord),
		pendingAuths:      make(map[string]*PendingAuthRequest),
		authCodes:         make(map[string]*authCodeRecord),
		pairingCodes:      make(map[string]*PairingCode),
		listeners:         make(map[chan Event]struct{}),
		limiter:           newIPRateLimiter(opts.Config.RateLimitPerMinute, time.Minute),
		pollLimiter:       newIPRateLimiter(maxInt(opts.Config.RateLimitPerMinute*3, 60), time.Minute),
	}
	if err := s.loadState(); err != nil {
		return nil, err
	}
	return s, nil
}

// Authenticate 实现 session.AuthProvider 接口，验证 OAuth 2.1 Bearer Access Token。
func (s *Server) Authenticate(r *http.Request) (*session.Principal, error) {
	rawToken, err := session.ExtractBearerToken(r)
	if err != nil {
		return nil, err
	}
	hash := sha256Hex(rawToken)
	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.accessTokens[hash]
	if !ok || rec.Revoked {
		return nil, errors.New("无效或已吊销的 OAuth 访问令牌")
	}
	if now.After(rec.ExpiresAt) {
		delete(s.accessTokens, hash)
		_ = s.saveStateLocked()
		return nil, errors.New("OAuth 访问令牌已过期，请使用 Refresh Token 刷新")
	}
	cli, ok := s.clients[rec.ClientID]
	if !ok || cli.Revoked {
		return nil, errors.New("该 OAuth 客户端授权已被撤销")
	}

	cli.LastUsedAt = now
	sessID := strings.TrimSpace(r.Header.Get("Mcp-Session-Id"))
	if sessID == "" {
		sessID = "oauth-" + cli.ClientID
	}

	return &session.Principal{
		SessionID:         sessID,
		Subject:           "device-owner:" + s.deviceID,
		ClientID:          cli.ClientID,
		ClientName:        cli.ClientName,
		ClientInfo:        fmt.Sprintf("%s (%s)", cli.ClientName, r.UserAgent()),
		AuthMethod:        "oauth2",
		IsRemote:          true,
		ReadOnly:          rec.ReadOnly || cli.ReadOnly,
		AllowedWorkspaces: append([]string(nil), rec.AllowedWorkspaces...),
		Scopes:            append([]string(nil), rec.Scopes...),
	}, nil
}

// CreatePairingCode 在本地生成一次性短期配对码，供用户在公网授权确认页安全输入。
func (s *Server) CreatePairingCode(readOnly bool, allowedWorkspaces []string, note string) (PairingCode, error) {
	code, err := randomHexToken("nb_pair_", 6)
	if err != nil {
		return PairingCode{}, err
	}
	// 格式化为便于人工抄录/复制的配对码（高熵 48-bit 十六进制）
	now := time.Now().UTC()
	pc := &PairingCode{
		Code:              code,
		ReadOnly:          readOnly,
		AllowedWorkspaces: cleanStringSlice(allowedWorkspaces),
		Note:              strings.TrimSpace(note),
		CreatedAt:         now,
		ExpiresAt:         now.Add(time.Duration(s.cfg.PairingCodeTTLSeconds) * time.Second),
	}

	s.mu.Lock()
	s.cleanupEphemeralLocked(now)
	s.pairingCodes[pc.Code] = pc
	s.broadcastLocked(Event{Type: "oauth_pairing_created", Payload: *pc})
	s.mu.Unlock()
	return *pc, nil
}

// ActivePairingCodes 返回尚未过期且未使用的配对码列表（仅本地管理 API 可见）。
func (s *Server) ActivePairingCodes() []PairingCode {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupEphemeralLocked(now)
	out := make([]PairingCode, 0, len(s.pairingCodes))
	for _, pc := range s.pairingCodes {
		if !pc.Used && now.Before(pc.ExpiresAt) {
			out = append(out, *pc)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// PendingAuthRequests 返回当前等待用户在本地控制台确认的 OAuth 客户端绑定请求。
func (s *Server) PendingAuthRequests() []PendingAuthRequest {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupEphemeralLocked(now)
	out := make([]PendingAuthRequest, 0, len(s.pendingAuths))
	for _, req := range s.pendingAuths {
		if req.Status == "pending" && now.Before(req.ExpiresAt) {
			out = append(out, *req)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// ResolveAuthRequest 由本地控制台或 CLI 调用，批准或拒绝挂起的 OAuth 客户端绑定请求。
func (s *Server) ResolveAuthRequest(reqID string, approve bool, readOnly bool, allowedWorkspaces []string, note string) (PendingAuthRequest, error) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupEphemeralLocked(now)

	req, ok := s.pendingAuths[strings.TrimSpace(reqID)]
	if !ok {
		return PendingAuthRequest{}, fmt.Errorf("授权请求 %q 不存在或已过期", reqID)
	}
	if req.Status != "pending" {
		return *req, fmt.Errorf("授权请求 %q 已处理（状态: %s）", reqID, req.Status)
	}

	if !approve {
		req.Status = "denied"
		req.ErrorMessage = strings.TrimSpace(note)
		if req.ErrorMessage == "" {
			req.ErrorMessage = "设备主人拒绝了该客户端绑定请求"
		}
		req.RedirectResult = buildErrorRedirect(req.RedirectURI, req.State, "access_denied", req.ErrorMessage)
		s.broadcastLocked(Event{Type: "oauth_auth_resolved", Payload: *req})
		return *req, nil
	}

	redirectURL, err := s.approveAuthRequestLocked(req, readOnly, cleanStringSlice(allowedWorkspaces), now)
	if err != nil {
		return PendingAuthRequest{}, err
	}
	req.Status = "approved"
	req.RedirectResult = redirectURL
	s.broadcastLocked(Event{Type: "oauth_auth_resolved", Payload: *req})
	s.broadcastLocked(Event{Type: "oauth_clients_updated", Payload: s.listClientsLocked(now)})
	return *req, nil
}

// ConfirmAuthWithPairingCode 在公网授权确认页验证一次性短期配对码并完成客户端绑定。
func (s *Server) ConfirmAuthWithPairingCode(reqID, pairingCode string) (string, error) {
	now := time.Now().UTC()
	pairingCode = strings.TrimSpace(pairingCode)
	if pairingCode == "" {
		return "", errors.New("配对码不能为空")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupEphemeralLocked(now)

	req, ok := s.pendingAuths[strings.TrimSpace(reqID)]
	if !ok || req.Status != "pending" || now.After(req.ExpiresAt) {
		return "", errors.New("授权请求不存在、已处理或已过期")
	}

	var matched *PairingCode
	for code, pc := range s.pairingCodes {
		if subtle.ConstantTimeCompare([]byte(code), []byte(pairingCode)) == 1 {
			matched = pc
			break
		}
	}
	if matched == nil || matched.Used || now.After(matched.ExpiresAt) {
		return "", errors.New("一次性配对码无效、已使用或已过期")
	}

	matched.Used = true
	delete(s.pairingCodes, matched.Code)

	redirectURL, err := s.approveAuthRequestLocked(req, matched.ReadOnly, matched.AllowedWorkspaces, now)
	if err != nil {
		return "", err
	}
	req.Status = "approved"
	req.RedirectResult = redirectURL
	s.broadcastLocked(Event{Type: "oauth_auth_resolved", Payload: *req})
	s.broadcastLocked(Event{Type: "oauth_clients_updated", Payload: s.listClientsLocked(now)})
	return redirectURL, nil
}

// DenyAuthRequestFromPublic 允许用户在公网确认页直接点击拒绝授权。
func (s *Server) DenyAuthRequestFromPublic(reqID string) (string, error) {
	req, err := s.ResolveAuthRequest(reqID, false, false, nil, "用户在授权页拒绝")
	if err != nil {
		return "", err
	}
	return req.RedirectResult, nil
}

// ListClients 返回全部已注册客户端的安全摘要清单。
func (s *Server) ListClients() []ClientSummary {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listClientsLocked(now)
}

func (s *Server) listClientsLocked(now time.Time) []ClientSummary {
	tokenCounts := make(map[string]int)
	for _, at := range s.accessTokens {
		if !at.Revoked && now.Before(at.ExpiresAt) {
			tokenCounts[at.ClientID]++
		}
	}
	for _, rt := range s.refreshTokens {
		if !rt.Revoked && !rt.Rotated && now.Before(rt.ExpiresAt) {
			tokenCounts[rt.ClientID]++
		}
	}
	out := make([]ClientSummary, 0, len(s.clients))
	for _, c := range s.clients {
		out = append(out, ClientSummary{
			ClientID:          c.ClientID,
			ClientName:        c.ClientName,
			RedirectURIs:      append([]string(nil), c.RedirectURIs...),
			ReadOnly:          c.ReadOnly,
			AllowedWorkspaces: append([]string(nil), c.AllowedWorkspaces...),
			Scopes:            append([]string(nil), c.Scopes...),
			ActiveTokens:      tokenCounts[c.ClientID],
			Authorized:        !c.AuthorizedAt.IsZero(),
			Revoked:           c.Revoked,
			CreatedAt:         c.CreatedAt,
			LastUsedAt:        c.LastUsedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// RevokeClient 吊销指定客户端及其全部 Access/Refresh Token。
func (s *Server) RevokeClient(clientID string) error {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	cli, ok := s.clients[strings.TrimSpace(clientID)]
	if !ok {
		return fmt.Errorf("客户端 %q 不存在", clientID)
	}
	s.revokeClientTokensLocked(cli.ClientID, now)
	cli.Revoked = true
	cli.RevokedAt = now
	if err := s.saveStateLocked(); err != nil {
		return err
	}
	s.broadcastLocked(Event{Type: "oauth_clients_updated", Payload: s.listClientsLocked(now)})
	return nil
}

// RevokeAllTokens 核按钮级吊销全部已签发远程 OAuth 令牌并作废全部客户端授权。
func (s *Server) RevokeAllTokens() (int, error) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	count := len(s.accessTokens) + len(s.refreshTokens)
	s.accessTokens = make(map[string]*AccessTokenRecord)
	s.refreshTokens = make(map[string]*RefreshTokenRecord)
	s.authCodes = make(map[string]*authCodeRecord)
	s.pairingCodes = make(map[string]*PairingCode)
	for _, cli := range s.clients {
		cli.Revoked = true
		cli.RevokedAt = now
	}
	for _, req := range s.pendingAuths {
		if req.Status == "pending" {
			req.Status = "denied"
			req.ErrorMessage = "管理员已吊销全部远程令牌"
			req.RedirectResult = buildErrorRedirect(req.RedirectURI, req.State, "access_denied", req.ErrorMessage)
		}
	}
	if err := s.saveStateLocked(); err != nil {
		return count, err
	}
	s.broadcastLocked(Event{Type: "oauth_clients_updated", Payload: s.listClientsLocked(now)})
	return count, nil
}

// Subscribe 订阅 OAuth 绑定与客户端状态实时事件。
func (s *Server) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 32)
	s.mu.Lock()
	s.listeners[ch] = struct{}{}
	s.mu.Unlock()
	return ch, func() {
		s.mu.Lock()
		if _, ok := s.listeners[ch]; ok {
			delete(s.listeners, ch)
			close(ch)
		}
		s.mu.Unlock()
	}
}

func (s *Server) approveAuthRequestLocked(req *PendingAuthRequest, readOnly bool, allowedWorkspaces []string, now time.Time) (string, error) {
	cli, ok := s.clients[req.ClientID]
	if !ok {
		return "", errors.New("客户端不存在")
	}
	rawCode, err := randomHexToken("nb_code_", 24)
	if err != nil {
		return "", err
	}
	scopes := normalizeScopes(req.Scopes, readOnly)
	cli.ReadOnly = readOnly
	cli.AllowedWorkspaces = allowedWorkspaces
	cli.Scopes = scopes
	cli.Revoked = false
	cli.RevokedAt = time.Time{}
	cli.AuthorizedAt = now

	codeHash := sha256Hex(rawCode)
	s.authCodes[codeHash] = &authCodeRecord{
		CodeHash:            codeHash,
		ClientID:            cli.ClientID,
		RedirectURI:         req.RedirectURI,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Resource:            req.Resource,
		Scopes:              scopes,
		ReadOnly:            readOnly,
		AllowedWorkspaces:   allowedWorkspaces,
		ExpiresAt:           now.Add(60 * time.Second),
	}
	if err := s.saveStateLocked(); err != nil {
		return "", err
	}

	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("code", rawCode)
	if req.State != "" {
		q.Set("state", req.State)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (s *Server) revokeClientTokensLocked(clientID string, now time.Time) {
	for h, at := range s.accessTokens {
		if at.ClientID == clientID {
			delete(s.accessTokens, h)
		}
	}
	for h, rt := range s.refreshTokens {
		if rt.ClientID == clientID {
			rt.Revoked = true
			delete(s.refreshTokens, h)
		}
	}
	for h, ac := range s.authCodes {
		if ac.ClientID == clientID || now.After(ac.ExpiresAt) {
			delete(s.authCodes, h)
		}
	}
}

func (s *Server) cleanupEphemeralLocked(now time.Time) {
	for id, req := range s.pendingAuths {
		if now.After(req.ExpiresAt) {
			if req.Status == "pending" {
				req.Status = "expired"
			}
			if now.After(req.ExpiresAt.Add(2 * time.Minute)) {
				delete(s.pendingAuths, id)
			}
		}
	}
	for code, pc := range s.pairingCodes {
		if pc.Used || now.After(pc.ExpiresAt) {
			delete(s.pairingCodes, code)
		}
	}
	for h, ac := range s.authCodes {
		if ac.Used || now.After(ac.ExpiresAt) {
			delete(s.authCodes, h)
		}
	}
}

const maxUnboundDCRClients = 64

// pruneUnboundClientsLocked 清理超过 1 小时仍未完成绑定授权的僵尸 DCR 客户端，并检查是否超过上限。
func (s *Server) pruneUnboundClientsLocked(now time.Time) error {
	unboundCount := 0
	for id, cli := range s.clients {
		if cli.AuthorizedAt.IsZero() && !cli.Revoked {
			if now.Sub(cli.CreatedAt) > time.Hour {
				delete(s.clients, id)
				continue
			}
			unboundCount++
		}
	}
	if unboundCount >= maxUnboundDCRClients {
		return errors.New("未完成授权的动态注册客户端数量已达上限，请先清理或稍后再试")
	}
	return nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (s *Server) loadState() error {
	raw, err := os.ReadFile(s.statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("读取 OAuth 状态失败: %w", err)
	}
	if len(raw) == 0 {
		return nil
	}
	var st persistedState
	if err := json.Unmarshal(raw, &st); err != nil {
		return fmt.Errorf("解析 OAuth 状态失败: %w", err)
	}
	if st.Clients != nil {
		s.clients = st.Clients
	}
	if st.AccessTokens != nil {
		s.accessTokens = st.AccessTokens
	}
	if st.RefreshTokens != nil {
		s.refreshTokens = st.RefreshTokens
	}
	return nil
}

func (s *Server) saveStateLocked() error {
	st := persistedState{
		Clients:       s.clients,
		AccessTokens:  s.accessTokens,
		RefreshTokens: s.refreshTokens,
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmpPath := s.statePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, s.statePath); err != nil {
		if wErr := os.WriteFile(s.statePath, data, 0o600); wErr != nil {
			return wErr
		}
		_ = os.Remove(tmpPath)
	}
	return nil
}

func (s *Server) broadcastLocked(ev Event) {
	for ch := range s.listeners {
		select {
		case ch <- ev:
		default:
		}
	}
}

// ValidateRedirectURI 校验 OAuth 回调地址，仅允许安全 HTTPS 或本地回环地址，防止开放重定向与 XSS。
func (s *Server) ValidateRedirectURI(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return errors.New("redirect_uri 不能为空")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("redirect_uri 格式无效: %w", err)
	}
	if u.Fragment != "" {
		return errors.New("redirect_uri 不允许包含 # fragment")
	}
	if len(s.cfg.AllowedRedirectURIs) > 0 {
		for _, allowed := range s.cfg.AllowedRedirectURIs {
			if strings.TrimSpace(allowed) == raw {
				return nil
			}
		}
		return fmt.Errorf("redirect_uri %q 不在允许白名单内", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if scheme == "https" && host != "" {
		return nil
	}
	if scheme == "http" && (host == "127.0.0.1" || host == "localhost" || host == "::1") {
		return nil
	}
	return fmt.Errorf("redirect_uri 必须使用 https:// 或本地回环 http://localhost，拒绝 %q", raw)
}

func normalizeScopes(requested []string, readOnly bool) []string {
	if readOnly {
		return []string{"mcp:read"}
	}
	if len(requested) == 0 {
		return []string{"mcp:tools", "mcp:read", "mcp:write"}
	}
	out := make([]string, 0, len(requested))
	seen := make(map[string]struct{})
	for _, sc := range requested {
		sc = strings.TrimSpace(sc)
		if sc == "" {
			continue
		}
		if _, dup := seen[sc]; !dup {
			seen[sc] = struct{}{}
			out = append(out, sc)
		}
	}
	if len(out) == 0 {
		return []string{"mcp:tools"}
	}
	return out
}

func verifyPKCES256(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

func buildErrorRedirect(redirectURI, state, errCode, desc string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("error", errCode)
	if desc != "" {
		q.Set("error_description", desc)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func sha256Hex(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func randomHexToken(prefix string, numBytes int) (string, error) {
	b := make([]byte, numBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + strings.ToLower(hex.EncodeToString(b)), nil
}

func cleanStringSlice(in []string) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; !dup {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}
