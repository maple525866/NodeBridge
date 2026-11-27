package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"nodebridge/internal/config"
	"nodebridge/internal/core/approval"
	"nodebridge/internal/core/audit"
	"nodebridge/internal/core/policy"
	"nodebridge/internal/core/store"
	"nodebridge/internal/core/task"
	"nodebridge/internal/platform/capability"
	"nodebridge/internal/platform/filesystem"
	"nodebridge/internal/transport/relay"
)

func TestHandleSecurityModeValidationConcurrencyAndRollback(t *testing.T) {
	wsDir := t.TempDir()
	dataDir := t.TempDir()

	cfg, err := config.DefaultConfig(wsDir)
	if err != nil {
		t.Fatal(err)
	}
	fsMgr, err := filesystem.NewManager(cfg.Workspaces, cfg.Security.GlobalDenyGlobs)
	if err != nil {
		t.Fatal(err)
	}
	policyEng := policy.NewEngine(cfg.Security)
	broker := approval.NewBroker(0, 30, nil)
	taskMgr, _ := task.NewManager(nil, task.Options{})
	auditLog, _ := audit.NewLogger(dataDir, 5, 2)

	srv := NewServer("test-admin-token", "127.0.0.1:0", broker, taskMgr, auditLog, fsMgr, capability.Detect(), relay.DisabledConnector{})
	srv.AttachSecurityControl(policyEng, dataDir, store.SecurityMode{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	postMode := func(payload string) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/security/mode", bytes.NewBufferString(payload))
		req.Header.Set("Authorization", "Bearer test-admin-token")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("请求失败: %v", err)
		}
		return resp
	}

	// 1. 空对象（未提供任何字段）应返回 400
	resp := postMode(`{}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("期望空对象返回 400，实际 %d", resp.StatusCode)
	}

	// 2. 并发切换模式，验证无竞态且最终内存与磁盘完全一致
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		v := i%2 == 0
		go func(flag bool) {
			defer wg.Done()
			b, _ := json.Marshal(map[string]any{"full_permissions": flag, "allow_all_dirs": flag})
			r := postMode(string(b))
			r.Body.Close()
			if r.StatusCode != http.StatusOK {
				t.Errorf("并发切换期望 200，实际 %d", r.StatusCode)
			}
		}(v)
	}
	wg.Wait()

	loaded, err := store.LoadSecurityMode(dataDir, false, false)
	if err != nil {
		t.Fatalf("读取持久化状态失败: %v", err)
	}
	cur := srv.currentSecurityMode()
	if loaded.FullPermissions != cur.FullPermissions || loaded.AllowAllDirs != cur.AllowAllDirs {
		t.Fatalf("并发切换后磁盘与内存状态不一致: disk=%+v mem=%+v", loaded, cur)
	}

	// 3. 落盘目标路径不可写时（以普通文件冒充 dataDir），应返回 500 且不改变内存状态
	badDataFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(badDataFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv.AttachSecurityControl(policyEng, badDataFile, cur)
	targetFull := !cur.FullPermissions
	b, _ := json.Marshal(map[string]any{"full_permissions": targetFull})
	failResp := postMode(string(b))
	failResp.Body.Close()
	if failResp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("期望持久化失败返回 500，实际 %d", failResp.StatusCode)
	}
	if policyEng.FullPermissions() != cur.FullPermissions || broker.IsFullPermissions() != cur.FullPermissions {
		t.Fatalf("持久化失败时内存状态不应被修改")
	}
}
