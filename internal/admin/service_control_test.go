package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"nodebridge/internal/config"
	"nodebridge/internal/core/approval"
	"nodebridge/internal/core/audit"
	"nodebridge/internal/core/task"
	"nodebridge/internal/platform/capability"
	"nodebridge/internal/platform/filesystem"
	"nodebridge/internal/platform/service"
	"nodebridge/internal/transport/relay"
)

type fakeServiceController struct {
	mu           sync.Mutex
	status       service.Status
	restartErr   error
	uninstallErr error
	restarted    int
	uninstalled  int
	purgeEnv     bool
	shutdownCh   chan string
}

func (f *fakeServiceController) Status() service.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

func (f *fakeServiceController) Restart() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.restartErr != nil {
		return f.restartErr
	}
	f.restarted++
	return nil
}

func (f *fakeServiceController) Uninstall(purgeEnv bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.uninstallErr != nil {
		return f.uninstallErr
	}
	f.uninstalled++
	f.purgeEnv = purgeEnv
	return nil
}

func (f *fakeServiceController) Shutdown(reason string) {
	select {
	case f.shutdownCh <- reason:
	default:
	}
}

func TestServiceControlEndpoints(t *testing.T) {
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
	broker := approval.NewBroker(0, 30, nil)
	taskMgr, _ := task.NewManager(nil, task.Options{})
	auditLog, _ := audit.NewLogger(dataDir, 5, 2)

	fakeCtrl := &fakeServiceController{
		status: service.Status{
			ServiceName:     "nodebridge",
			Platform:        "windows",
			Scope:           service.ScopeSystem,
			Backend:         "windows-service",
			Installed:       true,
			Enabled:         true,
			Running:         true,
			State:           "running",
			BootBeforeLogin: true,
			Recommended:     true,
		},
		shutdownCh: make(chan string, 1),
	}

	srv := NewServer("tok-admin", "127.0.0.1:0", broker, taskMgr, auditLog, fsMgr, capability.Detect(), relay.DisabledConnector{})
	srv.AttachServiceControl(fakeCtrl)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	doReq := func(method, path, body string) *http.Response {
		req, _ := http.NewRequest(method, ts.URL+path, bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer tok-admin")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s 请求失败: %v", method, path, err)
		}
		return resp
	}

	// 1. /api/state 包含 autostart 状态
	resp := doReq(http.MethodGet, "/api/state", "")
	var st map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if st["autostart"] == nil {
		t.Fatalf("/api/state 应返回 autostart 字段")
	}

	// 2. /api/service/restart 成功返回 202
	resp = doReq(http.MethodPost, "/api/service/restart", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("期望重启返回 202，实际 %d", resp.StatusCode)
	}
	if fakeCtrl.restarted != 1 {
		t.Fatalf("期望调用 Restart 1 次，实际 %d", fakeCtrl.restarted)
	}

	// 3. 类型化错误映射：403 权限不足 / 400 未安装 / 409 并发冲突 / 500 内部错误，并验证失败写入审计
	fakeCtrl.restartErr = ErrServiceForbidden
	resp = doReq(http.MethodPost, "/api/service/restart", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("期望权限不足返回 403，实际 %d", resp.StatusCode)
	}

	fakeCtrl.restartErr = ErrServiceBadRequest
	resp = doReq(http.MethodPost, "/api/service/restart", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("期望未安装返回 400，实际 %d", resp.StatusCode)
	}

	fakeCtrl.restartErr = ErrServiceConflict
	resp = doReq(http.MethodPost, "/api/service/restart", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("期望并发冲突返回 409，实际 %d", resp.StatusCode)
	}

	fakeCtrl.restartErr = errors.New("未知内部错误")
	resp = doReq(http.MethodPost, "/api/service/restart", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("期望未知错误返回 500，实际 %d", resp.StatusCode)
	}
	fakeCtrl.restartErr = nil

	// 4. 畸形 JSON 应返回 400 而非静默按默认值执行
	resp = doReq(http.MethodPost, "/api/service/uninstall", `{"purge_env":"not-a-bool"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("期望畸形 JSON 返回 400，实际 %d", resp.StatusCode)
	}

	// 5. 未鉴权返回 401，非 POST 方法返回 405
	unauthReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/service/restart", nil)
	unauthResp, err := http.DefaultClient.Do(unauthReq)
	if err != nil {
		t.Fatal(err)
	}
	unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("期望未鉴权返回 401，实际 %d", unauthResp.StatusCode)
	}

	resp = doReq(http.MethodGet, "/api/service/restart", "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("期望 GET /api/service/restart 返回 405，实际 %d", resp.StatusCode)
	}

	// 6. /api/service/uninstall 返回 202 并传递 purge_env
	resp = doReq(http.MethodPost, "/api/service/uninstall", `{"purge_env":true}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("期望卸载返回 202，实际 %d", resp.StatusCode)
	}
	if fakeCtrl.uninstalled != 1 || !fakeCtrl.purgeEnv {
		t.Fatalf("期望调用 Uninstall(true)，实际 count=%d purge=%v", fakeCtrl.uninstalled, fakeCtrl.purgeEnv)
	}

	// 7. /api/system/shutdown 触发优雅停机回调
	resp = doReq(http.MethodPost, "/api/system/shutdown", `{"reason":"unit-test"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("期望停机返回 202，实际 %d", resp.StatusCode)
	}
	select {
	case reason := <-fakeCtrl.shutdownCh:
		if reason != "unit-test" {
			t.Fatalf("停机原因不匹配: %q", reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("超时未收到优雅停机回调")
	}

	// 8. 断言审计日志记录了成功与失败的服务控制事件
	recent := auditLog.Recent(20)
	var sawSuccess, sawFailed bool
	for _, ev := range recent {
		if ev.Tool == "admin.service.restart" && ev.Decision == "SERVICE_RESTARTING" {
			sawSuccess = true
		}
		if ev.Tool == "admin.service.restart" && ev.Decision == "SERVICE_RESTART_FAILED" {
			sawFailed = true
		}
	}
	if !sawSuccess || !sawFailed {
		t.Fatalf("期望审计日志同时包含重启成功与失败记录，实际: %+v", recent)
	}
}
