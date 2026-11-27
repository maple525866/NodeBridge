// Package admin 提供本地管理 REST API、SSE 实时推送以及 Go 内嵌 Web 审批与远程安全管控控制台。
package admin

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"time"

	"nodebridge/internal/core/approval"
	"nodebridge/internal/core/audit"
	"nodebridge/internal/core/oauth"
	"nodebridge/internal/core/policy"
	"nodebridge/internal/core/store"
	"nodebridge/internal/core/task"
	"nodebridge/internal/platform/capability"
	"nodebridge/internal/platform/filesystem"
	"nodebridge/internal/platform/service"
	"nodebridge/internal/transport/relay"
)

// 服务控制类型化错误哨兵，用于精确映射 Admin API HTTP 状态码（400 / 403 / 409）。
var (
	ErrServiceBadRequest = errors.New("invalid service control request")
	ErrServiceForbidden  = errors.New("insufficient privilege for service control")
	ErrServiceConflict   = errors.New("service control operation already in progress")
)

// ServiceController 抽象本地守护进程与开机自启动服务的受控运维能力（由 main 注入）。
type ServiceController interface {
	Status() service.Status
	Restart() error
	Uninstall(purgeEnv bool) error
	Shutdown(reason string)
}

//go:embed web/*
var webFiles embed.FS

// Server 封装本地管理 API 与内嵌控制台页面。
type Server struct {
	adminToken              string
	broker                  *approval.Broker
	taskMgr                 *task.Manager
	auditLog                *audit.Logger
	fsMgr                   *filesystem.Manager
	policyEng               *policy.Engine
	dataDir                 string
	capInfo                 capability.Info
	relayConn               relay.Connector
	oauthSrv                *oauth.Server
	deviceID                string
	killAllDisconnectTunnel bool
	mcpAddr                 string
	svcCtrl                 ServiceController

	modeMu            sync.Mutex
	securityUpdatedAt time.Time
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

// AttachSecurityControl 注入策略引擎与数据目录，支持控制台实时切换“全部权限”与“默认全部目录”模式并持久化。
func (s *Server) AttachSecurityControl(policyEng *policy.Engine, dataDir string, initial store.SecurityMode) {
	s.modeMu.Lock()
	defer s.modeMu.Unlock()
	s.policyEng = policyEng
	s.dataDir = dataDir
	s.securityUpdatedAt = initial.UpdatedAt
}

// AttachServiceControl 注入开机自启动与守护进程控制器，供控制台查询状态及受控重启/卸载。
func (s *Server) AttachServiceControl(ctrl ServiceController) {
	s.svcCtrl = ctrl
}

// Handler 返回挂载了静态控制台页面、REST API 与 SSE 事件流的 HTTP Handler。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	subFS, _ := fs.Sub(webFiles, "web")
	fileServer := http.FileServer(http.FS(subFS))
	mux.Handle("/", fileServer)

	mux.HandleFunc("/api/state", s.withAuth(s.handleState))
	mux.HandleFunc("/api/events", s.withAuth(s.handleSSE))
	mux.HandleFunc("/api/security/mode", s.withAuth(s.handleSecurityMode))
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

	// 开机自启动与守护进程受控管理 API（均受本机 admin_token 鉴权保护）
	mux.HandleFunc("/api/service/status", s.withAuth(s.handleServiceStatus))
	mux.HandleFunc("/api/service/restart", s.withAuth(s.handleServiceRestart))
	mux.HandleFunc("/api/service/uninstall", s.withAuth(s.handleServiceUninstall))
	mux.HandleFunc("/api/system/shutdown", s.withAuth(s.handleSystemShutdown))

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

	var autostart *service.Status
	if s.svcCtrl != nil {
		st := s.svcCtrl.Status()
		autostart = &st
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"device_id":     s.deviceID,
		"mcp_listen":    s.mcpAddr,
		"capability":    s.capInfo,
		"relay":         relaySt,
		"autostart":     autostart,
		"oauth_enabled": s.oauthSrv != nil,
		"oauth_pending": oauthPending,
		"oauth_clients": oauthClients,
		"pairing_codes": pairingCodes,
		"pause":         s.broker.IsPaused(),
		"security_mode": s.currentSecurityMode(),
		"workspaces":    s.fsMgr.Workspaces(),
		"pending":       s.broker.Pending(),
		"grants":        s.broker.ActiveGrants(),
		"tasks":         s.taskMgr.List(),
		"audit":         s.auditLog.Recent(50),
	})
}

func (s *Server) currentSecurityMode() store.SecurityMode {
	s.modeMu.Lock()
	updatedAt := s.securityUpdatedAt
	policyEng := s.policyEng
	s.modeMu.Unlock()

	fullPerms := false
	if s.broker != nil {
		fullPerms = s.broker.IsFullPermissions()
	} else if policyEng != nil {
		fullPerms = policyEng.FullPermissions()
	}
	allowAllDirs := false
	if s.fsMgr != nil {
		allowAllDirs = s.fsMgr.AllowAllDirs()
	}
	return store.SecurityMode{
		FullPermissions: fullPerms,
		AllowAllDirs:    allowAllDirs,
		UpdatedAt:       updatedAt,
	}
}

func (s *Server) handleSecurityMode(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.currentSecurityMode())
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
		var body struct {
			FullPermissions *bool `json:"full_permissions"`
			AllowAllDirs    *bool `json:"allow_all_dirs"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求体 JSON 格式无效"})
			return
		}
		if body.FullPermissions == nil && body.AllowAllDirs == nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "至少需要提供 full_permissions 或 allow_all_dirs 之一"})
			return
		}

		s.modeMu.Lock()
		if s.policyEng == nil {
			s.modeMu.Unlock()
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "策略引擎尚未挂载到管理服务，无法切换安全模式"})
			return
		}

		curFull := s.policyEng.FullPermissions()
		if s.broker != nil {
			curFull = s.broker.IsFullPermissions()
		}
		curAllDirs := false
		if s.fsMgr != nil {
			curAllDirs = s.fsMgr.AllowAllDirs()
		}

		nextFull := curFull
		if body.FullPermissions != nil {
			nextFull = *body.FullPermissions
		}
		nextAllDirs := curAllDirs
		if body.AllowAllDirs != nil {
			nextAllDirs = *body.AllowAllDirs
		}

		now := time.Now().UTC()
		mode := store.SecurityMode{
			FullPermissions: nextFull,
			AllowAllDirs:    nextAllDirs,
			UpdatedAt:       now,
		}

		// 在 modeMu 临界区内先原子持久化成功，再提交内存状态切换，防止并发乱序覆盖或落盘失败导致内存与磁盘/UI 割裂
		if s.dataDir != "" {
			if err := store.SaveSecurityMode(s.dataDir, mode); err != nil {
				s.modeMu.Unlock()
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
				return
			}
		}

		s.policyEng.SetFullPermissions(nextFull)
		if s.fsMgr != nil {
			s.fsMgr.SetFullPermissions(nextFull)
			s.fsMgr.SetAllowAllDirs(nextAllDirs)
		}
		autoApproved := 0
		if s.broker != nil {
			autoApproved = s.broker.SetFullPermissions(nextFull)
		}
		s.securityUpdatedAt = now
		s.modeMu.Unlock()

		if s.broker != nil {
			s.broker.EmitEvent("security_mode_changed", mode)
		}
		if s.auditLog != nil {
			_ = s.auditLog.Record(audit.Event{
				Tool:     "admin.security.mode",
				Decision: "MODE_UPDATED",
				Approver: "admin",
				Status:   "SUCCEEDED",
				ArgsSummary: audit.RedactSummary(map[string]any{
					"full_permissions": nextFull,
					"allow_all_dirs":   nextAllDirs,
					"auto_approved":    autoApproved,
				}, 256),
			})
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"security_mode": mode,
			"auto_approved": autoApproved,
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
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

func (s *Server) handleServiceStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.svcCtrl == nil {
		writeJSON(w, http.StatusOK, map[string]any{"installed": false, "state": "unattached"})
		return
	}
	writeJSON(w, http.StatusOK, s.svcCtrl.Status())
}

func (s *Server) handleServiceRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.svcCtrl == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "当前实例未挂载守护进程控制器"})
		return
	}
	if err := s.svcCtrl.Restart(); err != nil {
		if s.auditLog != nil {
			_ = s.auditLog.Record(audit.Event{
				Tool:        "admin.service.restart",
				Decision:    "SERVICE_RESTART_FAILED",
				Approver:    "admin",
				Status:      "FAILED",
				ArgsSummary: audit.RedactSummary(err.Error(), 256),
			})
		}
		writeJSON(w, mapServiceErrorStatus(err), map[string]any{"error": err.Error()})
		return
	}
	st := s.svcCtrl.Status()
	if s.auditLog != nil {
		_ = s.auditLog.Record(audit.Event{
			Tool:        "admin.service.restart",
			Decision:    "SERVICE_RESTARTING",
			Approver:    "admin",
			Status:      "SUCCEEDED",
			ArgsSummary: audit.RedactSummary(fmt.Sprintf("service=%s scope=%s backend=%s", st.ServiceName, st.Scope, st.Backend), 256),
		})
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":  "restarting",
		"message": "已下发守护进程重启指令，控制台将在数秒内自动重连。",
		"service": st,
	})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *Server) handleServiceUninstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.svcCtrl == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "当前实例未挂载守护进程控制器"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var body struct {
		PurgeEnv bool `json:"purge_env"`
	}
	if err := decodeOptionalJSON(r.Body, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求体 JSON 格式无效"})
		return
	}

	if err := s.svcCtrl.Uninstall(body.PurgeEnv); err != nil {
		if s.auditLog != nil {
			_ = s.auditLog.Record(audit.Event{
				Tool:        "admin.service.uninstall",
				Decision:    "SERVICE_UNINSTALL_FAILED",
				Approver:    "admin",
				Status:      "FAILED",
				ArgsSummary: audit.RedactSummary(err.Error(), 256),
			})
		}
		writeJSON(w, mapServiceErrorStatus(err), map[string]any{"error": err.Error()})
		return
	}
	st := s.svcCtrl.Status()
	if s.auditLog != nil {
		_ = s.auditLog.Record(audit.Event{
			Tool:        "admin.service.uninstall",
			Decision:    "SERVICE_UNINSTALLING",
			Approver:    "admin",
			Status:      "SUCCEEDED",
			ArgsSummary: audit.RedactSummary(fmt.Sprintf("service=%s scope=%s purge_env=%v", st.ServiceName, st.Scope, body.PurgeEnv), 256),
		})
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":  "uninstalling",
		"message": "已下发取消开机自启并停止守护进程指令，服务将在短暂延迟后安全退出。",
		"service": st,
	})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *Server) handleSystemShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.svcCtrl == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "当前实例不支持远程停机信号"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var body struct {
		Reason string `json:"reason"`
	}
	if err := decodeOptionalJSON(r.Body, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求体 JSON 格式无效"})
		return
	}
	if strings.TrimSpace(body.Reason) == "" {
		body.Reason = "本地管理请求优雅关闭"
	}
	if s.auditLog != nil {
		_ = s.auditLog.Record(audit.Event{
			Tool:        "admin.system.shutdown",
			Decision:    "SHUTTING_DOWN",
			Approver:    "admin",
			Status:      "SUCCEEDED",
			ArgsSummary: audit.RedactSummary(body.Reason, 256),
		})
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "shutting_down", "reason": body.Reason})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	go func() {
		time.Sleep(150 * time.Millisecond)
		s.svcCtrl.Shutdown(body.Reason)
	}()
}

func mapServiceErrorStatus(err error) int {
	switch {
	case errors.Is(err, ErrServiceBadRequest):
		return http.StatusBadRequest
	case errors.Is(err, ErrServiceForbidden):
		return http.StatusForbidden
	case errors.Is(err, ErrServiceConflict):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

func decodeOptionalJSON(r io.Reader, dst any) error {
	raw, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	return json.Unmarshal(raw, dst)
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
