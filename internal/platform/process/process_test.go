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

func TestSafeBaseEnvIncludesProxyAndSDKVars(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:7890")
	t.Setenv("CARGO_HOME", "/tmp/cargo")
	t.Setenv("JAVA_HOME", "/tmp/jdk")
	t.Setenv("OPENAI_API_KEY", "sk-should-not-pass-by-default")

	env := buildFilteredEnv(nil, nil)
	joined := "\n" + strings.Join(env, "\n") + "\n"

	for _, want := range []string{"HTTP_PROXY=http://127.0.0.1:7890", "CARGO_HOME=/tmp/cargo", "JAVA_HOME=/tmp/jdk"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("期望默认透传开发环境变量 %q，实际 env=%v", want, env)
		}
	}
	if strings.Contains(joined, "OPENAI_API_KEY=") {
		t.Fatalf("未在白名单中的敏感凭据变量不应默认透传: %v", env)
	}
}

func TestAuthenticatedProxyIsNotPassedToSubprocess(t *testing.T) {
	for _, key := range []string{"HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"} {
		t.Setenv(key, "http://sample:password@proxy.local:8080")
	}
	env := buildFilteredEnv(nil, nil)
	for _, entry := range env {
		if strings.Contains(entry, "sample:password@proxy.local") {
			t.Fatal("subprocess received authenticated proxy URL")
		}
	}
}
