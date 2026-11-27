// Package session 管理 MCP 请求上下文中的调用身份、客户端权限范围与复合鉴权扩展接口。
// 阶段二支持 OAuth 2.1 Access Token 与本地静态 Bearer Token 复合鉴权。
package session

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
)

// Principal 描述通过鉴权的调用方身份及细粒度授权边界。
type Principal struct {
	SessionID         string   `json:"session_id"`
	Subject           string   `json:"subject"`
	ClientID          string   `json:"client_id,omitempty"`
	ClientName        string   `json:"client_name,omitempty"`
	ClientInfo        string   `json:"client_info,omitempty"`
	AuthMethod        string   `json:"auth_method,omitempty"` // static_bearer | oauth2 | anonymous
	IsRemote          bool     `json:"is_remote"`
	ReadOnly          bool     `json:"read_only"`
	AllowedWorkspaces []string `json:"allowed_workspaces,omitempty"`
	Scopes            []string `json:"scopes,omitempty"`
}

// CanAccessWorkspace 判断当前调用身份是否被授权访问指定工作区。
// AllowedWorkspaces 为空时表示允许访问配置文件中的全部工作区。
func (p *Principal) CanAccessWorkspace(workspaceID string) bool {
	if p == nil || len(p.AllowedWorkspaces) == 0 {
		return true
	}
	target := strings.TrimSpace(workspaceID)
	for _, ws := range p.AllowedWorkspaces {
		if strings.TrimSpace(ws) == target {
			return true
		}
	}
	return false
}

// HasWritePermission 判断当前调用身份是否允许执行写入或变更类命令操作。
func (p *Principal) HasWritePermission() bool {
	if p == nil {
		return true
	}
	if p.ReadOnly {
		return false
	}
	if len(p.Scopes) == 0 {
		return true
	}
	for _, s := range p.Scopes {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "mcp:write", "mcp:tools":
			return true
		}
	}
	return false
}

// AuthProvider 抽象身份认证器，支持静态 Bearer Token 与 OAuth 2.1 Access Token。
type AuthProvider interface {
	Authenticate(r *http.Request) (*Principal, error)
}

// BearerTokenAuthProvider 实现基于恒定时间比较的本地静态 Bearer Token 认证。
type BearerTokenAuthProvider struct {
	expectedToken string
}

// NewBearerTokenAuthProvider 创建静态 Bearer Token 认证器。
func NewBearerTokenAuthProvider(token string) *BearerTokenAuthProvider {
	return &BearerTokenAuthProvider{expectedToken: token}
}

// Authenticate 校验 Authorization: Bearer <token> 请求头。
func (a *BearerTokenAuthProvider) Authenticate(r *http.Request) (*Principal, error) {
	token, err := ExtractBearerToken(r)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(a.expectedToken)) != 1 {
		return nil, errors.New("无效的访问令牌")
	}
	sessID := r.Header.Get("Mcp-Session-Id")
	if sessID == "" {
		sessID = "local-session"
	}
	return &Principal{
		SessionID:  sessID,
		Subject:    "local-owner",
		ClientID:   "static-bearer",
		ClientName: "Static Bearer Client",
		ClientInfo: r.UserAgent(),
		AuthMethod: "static_bearer",
		IsRemote:   false,
		ReadOnly:   false,
		Scopes:     []string{"mcp:tools"},
	}, nil
}

// CompositeAuthProvider 串联多个认证器（例如 OAuth 2.1 优先，其次回退本地静态 Bearer Token）。
type CompositeAuthProvider struct {
	providers []AuthProvider
}

// NewCompositeAuthProvider 创建复合身份认证器。
func NewCompositeAuthProvider(providers ...AuthProvider) *CompositeAuthProvider {
	filtered := make([]AuthProvider, 0, len(providers))
	for _, p := range providers {
		if p != nil {
			filtered = append(filtered, p)
		}
	}
	return &CompositeAuthProvider{providers: filtered}
}

// Authenticate 依次尝试内部认证器，任一通过即返回认证主体。
func (c *CompositeAuthProvider) Authenticate(r *http.Request) (*Principal, error) {
	if _, err := ExtractBearerToken(r); err != nil {
		return nil, err
	}
	var lastErr error
	for _, p := range c.providers {
		principal, err := p.Authenticate(r)
		if err == nil && principal != nil {
			return principal, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("无效的访问令牌")
	}
	return nil, lastErr
}

// ExtractBearerToken 从 HTTP Authorization 头提取 Bearer 令牌。
func ExtractBearerToken(r *http.Request) (string, error) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		return "", errors.New("缺少 Authorization 请求头")
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", errors.New("Authorization 格式必须为 Bearer <token>")
	}
	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", errors.New("Bearer 令牌不能为空")
	}
	return token, nil
}

type ctxKey struct{}

// WithPrincipal 将已认证身份写入请求上下文。
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext 从上下文读取当前调用方身份。
func FromContext(ctx context.Context) *Principal {
	if p, ok := ctx.Value(ctxKey{}).(*Principal); ok && p != nil {
		return p
	}
	return &Principal{
		SessionID:  "anonymous-local",
		Subject:    "local-owner",
		AuthMethod: "anonymous",
		Scopes:     []string{"mcp:tools"},
	}
}
