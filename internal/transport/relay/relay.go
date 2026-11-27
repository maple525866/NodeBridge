// Package relay 为阶段二预留安全隧道（如 Cloudflare Tunnel）与自建 Relay 出站连接抽象。
// 阶段一不启动任何外部公网隧道，仅保持接口契约稳定。
package relay

import (
	"context"
	"net/http"
)

// Status 表示远程连接通道的运行状态。
type Status struct {
	Enabled   bool   `json:"enabled"`
	Provider  string `json:"provider,omitempty"`
	Connected bool   `json:"connected"`
	PublicURL string `json:"public_url,omitempty"`
	LastError string `json:"last_error,omitempty"`
}

// Connector 定义阶段二将本地 MCP Handler 暴露给远端 Relay / 隧道的统一接口。
type Connector interface {
	Start(ctx context.Context, mcpHandler http.Handler) error
	Stop(ctx context.Context) error
	Status() Status
}

// DisabledConnector 为阶段一默认空实现，确保不暴露任何外部入口。
type DisabledConnector struct{}

// Start 在阶段一直接返回 nil。
func (DisabledConnector) Start(context.Context, http.Handler) error { return nil }

// Stop 在阶段一直接返回 nil。
func (DisabledConnector) Stop(context.Context) error { return nil }

// Status 返回未启用状态。
func (DisabledConnector) Status() Status {
	return Status{Enabled: false, Connected: false}
}
