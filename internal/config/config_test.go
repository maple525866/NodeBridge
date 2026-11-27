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
