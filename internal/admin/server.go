// Package admin 提供本地管理 REST API、SSE 实时推送以及 Go 内嵌 Web 审批控制台。
package admin

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"nodebridge/internal/core/approval"
	"nodebridge/internal/core/audit"
	"nodebridge/internal/core/task"
	"nodebridge/internal/platform/capability"
	"nodebridge/internal/platform/filesystem"
	"nodebridge/internal/transport/relay"
)

//go:embed web/*
var webFiles embed.FS

// Server 封装本地管理 API 与内嵌控制台页面。
type Server struct {
	adminToken string
	broker     *approval.Broker
	taskMgr    *task.Manager
	auditLog   *audit.Logger
	fsMgr      *filesystem.Manager
	capInfo    capability.Info
	relayConn  relay.Connector
	mcpAddr    string
}

// NewServer 创建本地管理服务实例。
func NewServer(
	adminToken string,
	mcpAddr string,
	broker *approval.Broker,
	taskMgr *task.Manager,
	auditLog *audit.Logger,
	fsMgr *filesystem.Manager,
	capInfo capability.Info,
	relayConn relay.Connector,
) *Server {
	return &Server{
		adminToken: adminToken,
		mcpAddr:    mcpAddr,
		broker:     broker,
		taskMgr:    taskMgr,
		auditLog:   auditLog,
		fsMgr:      fsMgr,
		capInfo:    capInfo,
		relayConn:  relayConn,
	}
}

// Handler 返回挂载了静态控制台页面、REST API 与 SSE 事件流的 HTTP Handler。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	subFS, _ := fs.Sub(webFiles, "web")
	fileServer := http.FileServer(http.FS(subFS))
	mux.Handle("/", fileServer)

	mux.HandleFunc("/api/state", s.withAuth(s.handleState))
	mux.HandleFunc("/api/events", s.withAuth(s.handleSSE))
	mux.HandleFunc("/api/approvals/", s.withAuth(s.handleApprovalAction))
	mux.HandleFunc("/api/grants/revoke", s.withAuth(s.handleRevokeGrants))
	mux.HandleFunc("/api/kill-switch/pause", s.withAuth(s.handlePause))
	mux.HandleFunc("/api/kill-switch/kill-all", s.withAuth(s.handleKillAll))
	mux.HandleFunc("/api/kill-switch/resume", s.withAuth(s.handleResume))
	mux.HandleFunc("/api/tasks/", s.withAuth(s.handleTaskAction))

	return mux
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := extractAdminToken(r)
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.adminToken)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error": "管理令牌无效，请提供正确的 Admin Token",
			})
			return
		}
		next(w, r)
	}
}

func extractAdminToken(r *http.Request) string {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if parts := strings.SplitN(auth, " ", 2); len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return strings.TrimSpace(parts[1])
	}
	// EventSource 不支持自定义 Header，仅对 SSE 端点允许通过查询参数传递
	if r.URL.Path == "/api/events" {
		return strings.TrimSpace(r.URL.Query().Get("token"))
	}
	return ""
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"mcp_listen": s.mcpAddr,
		"capability": s.capInfo,
		"relay":      s.relayConn.Status(),
		"pause":      s.broker.IsPaused(),
		"workspaces": s.fsMgr.Workspaces(),
		"pending":    s.broker.Pending(),
		"grants":     s.broker.ActiveGrants(),
		"tasks":      s.taskMgr.List(),
		"audit":      s.auditLog.Recent(50),
	})
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	aprCh, unsubApr := s.broker.Subscribe()
	defer unsubApr()
	taskCh, unsubTask := s.taskMgr.Subscribe()
	defer unsubTask()
	auditCh, unsubAudit := s.auditLog.Subscribe()
	defer unsubAudit()

	sendEvent := func(eventName string, payload any) {
		data, err := json.Marshal(payload)
		if err != nil {
			return
		}
		_, _ = w.Write([]byte("event: " + eventName + "\ndata: " + string(data) + "\n\n"))
		flusher.Flush()
	}

	sendEvent("connected", map[string]any{"ts": time.Now().UTC()})

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-aprCh:
			sendEvent(ev.Type, ev.Payload)
		case rec := <-taskCh:
			sendEvent("task_updated", rec)
		case aev := <-auditCh:
			sendEvent("audit_recorded", aev)
		case <-ticker.C:
			_, _ = w.Write([]byte(": heartbeat\n\n"))
			flusher.Flush()
		}
	}
}

func (s *Server) handleApprovalAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/approvals/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "无效的审批路径"})
		return
	}
	id, action := parts[0], parts[1]

	var body struct {
		GrantMinutes int    `json:"grant_minutes"`
		Note         string `json:"note"`
		Approver     string `json:"approver"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Approver == "" {
		body.Approver = "web-console"
	}

	var approve bool
	switch action {
	case "approve":
		approve = true
	case "reject":
		approve = false
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "不支持的操作: " + action})
		return
	}

	req, err := s.broker.Resolve(id, approve, body.GrantMinutes, body.Approver, body.Note)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, req)
}

func (s *Server) handleRevokeGrants(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		WorkspaceID string `json:"workspace_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	active := s.broker.RevokeGrants(body.WorkspaceID)
	writeJSON(w, http.StatusOK, map[string]any{"grants": active})
}

func (s *Server) handlePause(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	st := s.broker.Pause(body.Reason)
	_ = s.auditLog.Record(audit.Event{
		Tool:     "admin.pause",
		Decision: "PAUSED",
		Approver: "admin",
		Status:   "SUCCEEDED",
		ArgsSummary: body.Reason,
	})
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleKillAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	st, killed := s.broker.KillAll(body.Reason)
	_ = s.auditLog.Record(audit.Event{
		Tool:        "admin.kill_all",
		Decision:    "KILL_SWITCH",
		Approver:    "admin",
		Status:      "SUCCEEDED",
		ArgsSummary: body.Reason,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"pause":        st,
		"killed_tasks": killed,
	})
}

func (s *Server) handleResume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	st := s.broker.Resume()
	_ = s.auditLog.Record(audit.Event{
		Tool:     "admin.resume",
		Decision: "RESUMED",
		Approver: "admin",
		Status:   "SUCCEEDED",
	})
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleTaskAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/tasks/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 || parts[1] != "cancel" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "无效的任务操作路径"})
		return
	}
	rec, err := s.taskMgr.Cancel(parts[0], "用户在本地控制台手动取消")
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
