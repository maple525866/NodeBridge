// Package session 管理 MCP 请求上下文中的调用身份与鉴权扩展接口。
// 阶段一采用高熵 Bearer Token 鉴权，并预留 AuthProvider 接口供阶段二无缝接入 OAuth 2.1。
package session

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
)

// Principal 描述通过鉴权的调用方身份信息。
type Principal struct {
	SessionID  string
	Subject    string
	ClientInfo string
	Scopes     []string
}

// AuthProvider 抽象身份认证器，阶段一实现静态 Bearer Token，阶段二可扩展 OAuth 2.1 / JWT。
type AuthProvider interface {
	Authenticate(r *http.Request) (*Principal, error)
}

// BearerTokenAuthProvider 实现基于恒定时间比较的本地 Bearer Token 认证。
type BearerTokenAuthProvider struct {
	expectedToken string
}

// NewBearerTokenAuthProvider 创建静态 Bearer Token 认证器。
func NewBearerTokenAuthProvider(token string) *BearerTokenAuthProvider {
	return &BearerTokenAuthProvider{expectedToken: token}
}

// Authenticate 校验 Authorization: Bearer <token> 请求头。
func (a *BearerTokenAuthProvider) Authenticate(r *http.Request) (*Principal, error) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		return nil, errors.New("缺少 Authorization 请求头")
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, errors.New("Authorization 格式必须为 Bearer <token>")
	}
	token := strings.TrimSpace(parts[1])
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
		ClientInfo: r.UserAgent(),
		Scopes:     []string{"mcp:tools"},
	}, nil
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
		SessionID: "anonymous-local",
		Subject:   "local-owner",
	}
}
