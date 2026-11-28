package config

import (
	"path/filepath"
	"testing"
)

func TestDefaultConfigSaveAndLoad(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "nodebridge.yaml")

	cfg, err := DefaultConfig(tmp)
	if err != nil {
		t.Fatalf("DefaultConfig 失败: %v", err)
	}
	if cfg.Approval.TimeoutSeconds != 0 {
		t.Fatalf("期望默认审批超时为 0（无限等待），实际为 %d", cfg.Approval.TimeoutSeconds)
	}
	if err := Save(cfgPath, cfg); err != nil {
		t.Fatalf("Save 失败: %v", err)
	}

	loaded, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if loaded.Server.MCPToken != cfg.Server.MCPToken {
		t.Fatalf("MCPToken 不一致")
	}
	if loaded.OAuth.AllowDynamicRegistration == nil || !*loaded.OAuth.AllowDynamicRegistration {
		t.Fatal("新生成的配置应显式开启动态客户端注册")
	}
	if len(loaded.Workspaces) != 1 || loaded.Workspaces[0].ID != "default" {
		t.Fatalf("工作区加载异常: %+v", loaded.Workspaces)
	}
}

func TestConfigRejectsPlaceholderTokenAndWildcardListen(t *testing.T) {
	tmp := t.TempDir()
	cfg, _ := DefaultConfig(tmp)
	cfg.Server.MCPToken = "CHANGE_ME_MCP_TOKEN"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("应当拒绝占位符 MCPToken")
	}

	cfg, _ = DefaultConfig(tmp)
	cfg.Server.MCPListen = ":18765"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("应当拒绝隐式全网卡监听地址 :18765")
	}
}

func TestRelayAndOAuthConfigValidation(t *testing.T) {
	tmp := t.TempDir()

	// 1. external 模式必须为 https URL
	cfg, _ := DefaultConfig(tmp)
	cfg.Relay.Mode = RelayModeExternal
	cfg.Relay.PublicURL = "http://insecure.example.com"
	cfg.ApplyDefaults(tmp)
	if err := cfg.Validate(); err == nil {
		t.Fatalf("应当拒绝非 HTTPS 的 relay.public_url")
	}

	cfg.Relay.PublicURL = "https://mcp.example.com/"
	cfg.ApplyDefaults(tmp)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("合法 external 模式应校验通过: %v", err)
	}
	if cfg.Relay.PublicURL != "https://mcp.example.com" {
		t.Fatalf("应去除末尾斜杠，实际: %s", cfg.Relay.PublicURL)
	}
	if !cfg.OAuth.Enabled {
		t.Fatalf("开启远程通道后应自动启用内置 OAuth 2.1")
	}

	// 2. cloudflared_named 支持 env: 读取令牌
	t.Setenv("NB_TEST_CF_TOKEN", "cf-secret-token-123")
	cfg2, _ := DefaultConfig(tmp)
	cfg2.Relay.Mode = RelayModeCloudflaredNamed
	cfg2.Relay.PublicURL = "https://dev.example.com"
	cfg2.Relay.TunnelToken = "env:NB_TEST_CF_TOKEN"
	cfg2.ApplyDefaults(tmp)
	if err := cfg2.Validate(); err != nil {
		t.Fatalf("env: 令牌校验失败: %v", err)
	}
	if cfg2.Relay.ResolvedTunnelToken() != "cf-secret-token-123" {
		t.Fatalf("未正确解析环境变量令牌")
	}
	if !cfg2.Service.AutoRegisterEnabled() {
		t.Fatalf("默认应开启固定域名模式自动注册开机自启")
	}
	if cfg2.Service.Name != "nodebridge" || cfg2.Service.Scope != "auto" {
		t.Fatalf("Service 默认值异常: %+v", cfg2.Service)
	}
	cfg2.Service.Scope = "invalid_scope"
	if err := cfg2.Validate(); err == nil {
		t.Fatalf("应拒绝非法 service.scope")
	}
}
