// Package admin 提供本地管理 REST API、SSE 实时推送以及 Go 内嵌 Web 审批与远程安全管控控制台。
package admin

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"nodebridge/internal/core/approval"
	"nodebridge/internal/core/audit"
	"nodebridge/internal/core/oauth"
	"nodebridge/internal/core/task"
	"nodebridge/internal/platform/capability"
	"nodebridge/internal/platform/filesystem"
	"nodebridge/internal/transport/relay"
)

//go:embed web/*
var webFiles embed.FS

// Server 封装本地管理 API 与内嵌控制台页面。
type Server struct {
	adminToken              string
	broker                  *approval.Broker
	taskMgr                 *task.Manager
	auditLog                *audit.Logger
	fsMgr                   *filesystem.Manager
	capInfo                 capability.Info
	relayConn               relay.Connector
	oauthSrv                *oauth.Server
	deviceID                string
	killAllDisconnectTunnel bool
	mcpAddr                 string
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

// AttachRemoteGovernance 注入阶段二设备身份、内置 OAuth 2.1 服务器及急停联动配置。
func (s *Server) AttachRemoteGovernance(deviceID string, oauthSrv *oauth.Server, killAllDisconnectTunnel bool) {
	s.deviceID = deviceID
	s.oauthSrv = oauthSrv
	s.killAllDisconnectTunnel = killAllDisconnectTunnel
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

	// 阶段二：远程隧道控制与 OAuth 2.1 客户端绑定/吊销管理 API
	mux.HandleFunc("/api/relay/connect", s.withAuth(s.handleRelayConnect))
	mux.HandleFunc("/api/relay/disconnect", s.withAuth(s.handleRelayDisconnect))
	mux.HandleFunc("/api/oauth/pairing-codes", s.withAuth(s.handlePairingCodes))
	mux.HandleFunc("/api/oauth/requests/", s.withAuth(s.handleOAuthRequestAction))
	mux.HandleFunc("/api/oauth/clients/", s.withAuth(s.handleOAuthClientAction))
	mux.HandleFunc("/api/oauth/revoke-all", s.withAuth(s.handleOAuthRevokeAll))

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
	relaySt := relay.Status{}
	if s.relayConn != nil {
		relaySt = s.relayConn.Status()
	}
	var oauthPending []oauth.PendingAuthRequest
	var oauthClients []oauth.ClientSummary
	var pairingCodes []oauth.PairingCode
	if s.oauthSrv != nil {
		oauthPending = s.oauthSrv.PendingAuthRequests()
		oauthClients = s.oauthSrv.ListClients()
		pairingCodes = s.oauthSrv.ActivePairingCodes()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"device_id":     s.deviceID,
		"mcp_listen":    s.mcpAddr,
		"capability":    s.capInfo,
		"relay":         relaySt,
		"oauth_enabled": s.oauthSrv != nil,
		"oauth_pending": oauthPending,
		"oauth_clients": oauthClients,
		"pairing_codes": pairingCodes,
		"pause":         s.broker.IsPaused(),
		"workspaces":    s.fsMgr.Workspaces(),
		"pending":       s.broker.Pending(),
		"grants":        s.broker.ActiveGrants(),
		"tasks":         s.taskMgr.List(),
		"audit":         s.auditLog.Recent(50),
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

	var relayCh <-chan relay.Status
	if s.relayConn != nil {
		ch, unsubRelay := s.relayConn.Subscribe()
		relayCh = ch
		defer unsubRelay()
	}
	var oauthCh <-chan oauth.Event
	if s.oauthSrv != nil {
		ch, unsubOAuth := s.oauthSrv.Subscribe()
		oauthCh = ch
		defer unsubOAuth()
	}

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
		case st, ok := <-relayCh:
			if !ok {
				relayCh = nil
				continue
			}
			sendEvent("relay_updated", st)
		case oev, ok := <-oauthCh:
			if !ok {
				oauthCh = nil
				continue
			}
			sendEvent(oev.Type, oev.Payload)
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
		Tool:        "admin.pause",
		Decision:    "PAUSED",
		Approver:    "admin",
		Status:      "SUCCEEDED",
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
		Reason           string `json:"reason"`
		DisconnectTunnel bool   `json:"disconnect_tunnel"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	st, killed := s.broker.KillAll(body.Reason)

	tunnelDisconnected := false
	if (s.killAllDisconnectTunnel || body.DisconnectTunnel) && s.relayConn != nil && s.relayConn.Status().Enabled {
		_ = s.relayConn.Disconnect("触发一键急停自动断开隧道")
		tunnelDisconnected = true
	}

	_ = s.auditLog.Record(audit.Event{
		Tool:        "admin.kill_all",
		Decision:    "KILL_SWITCH",
		Approver:    "admin",
		Status:      "SUCCEEDED",
		ArgsSummary: body.Reason,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"pause":               st,
		"killed_tasks":        killed,
		"tunnel_disconnected": tunnelDisconnected,
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

func (s *Server) handleRelayConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.relayConn == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "未配置远程通道"})
		return
	}
	if err := s.relayConn.Connect(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	_ = s.auditLog.Record(audit.Event{
		Tool:     "admin.relay.connect",
		Decision: "RELAY_CONNECTED",
		Approver: "admin",
		Status:   "SUCCEEDED",
	})
	writeJSON(w, http.StatusOK, s.relayConn.Status())
}

func (s *Server) handleRelayDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.relayConn == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "未配置远程通道"})
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Reason == "" {
		body.Reason = "设备主人主动断开远程隧道"
	}
	if err := s.relayConn.Disconnect(body.Reason); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	_ = s.auditLog.Record(audit.Event{
		Tool:        "admin.relay.disconnect",
		Decision:    "RELAY_DISCONNECTED",
		Approver:    "admin",
		Status:      "SUCCEEDED",
		ArgsSummary: body.Reason,
	})
	writeJSON(w, http.StatusOK, s.relayConn.Status())
}

func (s *Server) handlePairingCodes(w http.ResponseWriter, r *http.Request) {
	if s.oauthSrv == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "内置 OAuth 2.1 未启用，请先开启 oauth.enabled 或配置 relay.mode"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"pairing_codes": s.oauthSrv.ActivePairingCodes()})
	case http.MethodPost:
		var body struct {
			ReadOnly          bool     `json:"read_only"`
			AllowedWorkspaces []string `json:"allowed_workspaces"`
			Note              string   `json:"note"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if err := s.validateAllowedWorkspaces(body.AllowedWorkspaces); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		pc, err := s.oauthSrv.CreatePairingCode(body.ReadOnly, body.AllowedWorkspaces, body.Note)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		_ = s.auditLog.Record(audit.Event{
			Tool:        "admin.oauth.create_pairing_code",
			Decision:    "CREATED",
			Approver:    "admin",
			Status:      "SUCCEEDED",
			ArgsSummary: audit.RedactSummary(map[string]any{"read_only": body.ReadOnly, "workspaces": body.AllowedWorkspaces, "note": body.Note}, 256),
		})
		writeJSON(w, http.StatusCreated, pc)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleOAuthRequestAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.oauthSrv == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "内置 OAuth 2.1 未启用"})
		return
	}
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/oauth/requests/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "无效的 OAuth 审批路径"})
		return
	}
	reqID, action := parts[0], parts[1]

	var body struct {
		ReadOnly          bool     `json:"read_only"`
		AllowedWorkspaces []string `json:"allowed_workspaces"`
		Note              string   `json:"note"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	approve := false
	switch action {
	case "approve":
		approve = true
	case "deny", "reject":
		approve = false
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "不支持的操作: " + action})
		return
	}

	if approve {
		if err := s.validateAllowedWorkspaces(body.AllowedWorkspaces); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
	}

	resolved, err := s.oauthSrv.ResolveAuthRequest(reqID, approve, body.ReadOnly, body.AllowedWorkspaces, body.Note)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	decision := "OAUTH_DENIED"
	if approve {
		decision = "OAUTH_APPROVED"
	}
	_ = s.auditLog.Record(audit.Event{
		Tool:        "admin.oauth.authorize",
		Decision:    decision,
		Approver:    "admin",
		Status:      "SUCCEEDED",
		ArgsSummary: audit.RedactSummary(map[string]any{"client_id": resolved.ClientID, "client_name": resolved.ClientName, "read_only": body.ReadOnly, "workspaces": body.AllowedWorkspaces}, 256),
	})
	writeJSON(w, http.StatusOK, resolved)
}

func (s *Server) handleOAuthClientAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.oauthSrv == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "内置 OAuth 2.1 未启用"})
		return
	}
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/oauth/clients/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 || parts[1] != "revoke" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "无效的客户端吊销路径"})
		return
	}
	clientID := parts[0]
	if err := s.oauthSrv.RevokeClient(clientID); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": err.Error()})
		return
	}
	_ = s.auditLog.Record(audit.Event{
		Tool:        "admin.oauth.revoke_client",
		Decision:    "REVOKED",
		Approver:    "admin",
		Status:      "SUCCEEDED",
		ArgsSummary: clientID,
	})
	writeJSON(w, http.StatusOK, map[string]any{"revoked": clientID, "clients": s.oauthSrv.ListClients()})
}

func (s *Server) handleOAuthRevokeAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.oauthSrv == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "内置 OAuth 2.1 未启用"})
		return
	}
	count, err := s.oauthSrv.RevokeAllTokens()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	_ = s.auditLog.Record(audit.Event{
		Tool:        "admin.oauth.revoke_all",
		Decision:    "REVOKED_ALL",
		Approver:    "admin",
		Status:      "SUCCEEDED",
		ArgsSummary: fmt.Sprintf("revoked_tokens=%d", count),
	})
	writeJSON(w, http.StatusOK, map[string]any{"revoked_tokens": count, "clients": s.oauthSrv.ListClients()})
}

func (s *Server) validateAllowedWorkspaces(ids []string) error {
	if len(ids) == 0 || s.fsMgr == nil {
		return nil
	}
	valid := make(map[string]struct{})
	for _, ws := range s.fsMgr.Workspaces() {
		valid[ws.ID] = struct{}{}
	}
	for _, id := range ids {
		trimmed := strings.TrimSpace(id)
		if trimmed == "" {
			continue
		}
		if _, ok := valid[trimmed]; !ok {
			return fmt.Errorf("工作区 %q 不存在，请检查配置中的工作区 ID", trimmed)
		}
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
