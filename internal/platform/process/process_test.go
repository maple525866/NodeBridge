package process

import (
	"strings"
	"testing"
)

func TestProtectedEnvKeysBlockedFromEnvAllow(t *testing.T) {
	t.Setenv("CLOUDFLARE_TUNNEL_TOKEN", "cf-secret-token")
	t.Setenv("CUSTOM_SERVICE_SECRET", "top-secret-value")
	t.Setenv("SAFE_PUBLIC_VAR", "ok-value")

	ProtectEnvKeys("CUSTOM_SERVICE_SECRET")

	env := buildFilteredEnv([]string{"CLOUDFLARE_TUNNEL_TOKEN", "CUSTOM_SERVICE_SECRET", "SAFE_PUBLIC_VAR"}, nil)
	joined := "\n" + strings.Join(env, "\n") + "\n"

	if strings.Contains(joined, "cf-secret-token") || strings.Contains(joined, "CLOUDFLARE_TUNNEL_TOKEN=") {
		t.Fatalf("CLOUDFLARE_TUNNEL_TOKEN 不应通过 env_allow 透传给子进程: %v", env)
	}
	if strings.Contains(joined, "top-secret-value") || strings.Contains(joined, "CUSTOM_SERVICE_SECRET=") {
		t.Fatalf("受保护变量 CUSTOM_SERVICE_SECRET 不应通过 env_allow 透传给子进程: %v", env)
	}
	if !strings.Contains(joined, "SAFE_PUBLIC_VAR=ok-value") {
		t.Fatalf("普通允许变量 SAFE_PUBLIC_VAR 应正常透传: %v", env)
	}
}
