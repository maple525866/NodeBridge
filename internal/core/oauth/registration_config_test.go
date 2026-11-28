package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nodebridge/internal/config"
)

func TestRegistrationFromYAML(t *testing.T) {
	const base = `server:
  mcp_token: test-mcp-token
  admin_token: test-admin-token
workspaces:
  - id: test
    root: .
relay:
  mode: cloudflared_quick
`
	const allowlist = "  allowed_redirect_uris: [https://client.example/callback]\n"
	for _, tc := range []struct {
		name    string
		oauth   string
		enabled bool
	}{
		{"omitted", "", true},
		{"disabled", "oauth:\n  allow_dynamic_registration: false\n", false},
		{"allowlist only", "oauth:\n" + allowlist, false},
		{"enabled with allowlist", "oauth:\n  allow_dynamic_registration: true\n" + allowlist, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "nodebridge.yaml")
			if err := os.WriteFile(path, []byte(base+tc.oauth), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			srv, err := NewServer(Options{Config: cfg.OAuth, DataDir: dir})
			if err != nil {
				t.Fatal(err)
			}
			mux := http.NewServeMux()
			srv.RegisterRoutes(mux)
			metadata := httptest.NewRecorder()
			mux.ServeHTTP(metadata, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(metadata.Body.Bytes(), &fields); err != nil {
				t.Fatal(err)
			}
			if _, present := fields["registration_endpoint"]; present != tc.enabled {
				t.Errorf("metadata advertises registration = %t, want %t", present, tc.enabled)
			}
			result := httptest.NewRecorder()
			body := strings.NewReader(`{"redirect_uris":["https://client.example/callback"]}`)
			mux.ServeHTTP(result, httptest.NewRequest(http.MethodPost, "/oauth/register", body))
			wantStatus := http.StatusForbidden
			if tc.enabled {
				wantStatus = http.StatusCreated
			}
			if result.Code != wantStatus {
				t.Errorf("registration HTTP status = %d, want %d", result.Code, wantStatus)
			}
		})
	}
}
