// Command nodebridge 是 Personal Computer Agent Gateway 的本地跨平台常驻执行守护进程与管理 CLI。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"nodebridge/internal/admin"
	"nodebridge/internal/config"
	"nodebridge/internal/core/approval"
	"nodebridge/internal/core/audit"
	"nodebridge/internal/core/policy"
	"nodebridge/internal/core/session"
	"nodebridge/internal/core/store"
	"nodebridge/internal/core/task"
	"nodebridge/internal/mcpserver"
	"nodebridge/internal/mcpserver/tools"
	"nodebridge/internal/platform/capability"
	"nodebridge/internal/platform/filesystem"
	"nodebridge/internal/platform/git"
	"nodebridge/internal/transport/relay"
)

const appVersion = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch subcmd {
	case "init":
		err = runInit(args)
	case "daemon":
		err = runDaemon(args)
	case "stdio":
		err = runStdio(args)
	case "status":
		err = runStatus(args)
	case "approve":
		err = runApprovalDecision(args, true)
	case "reject":
		err = runApprovalDecision(args, false)
	case "stop-all":
		err = runKillSwitch(args, "kill-all")
	case "pause":
		err = runKillSwitch(args, "pause")
	case "resume":
		err = runKillSwitch(args, "resume")
	case "tasks":
		err = runTasks(args)
	case "version", "-v", "--version":
		fmt.Printf("nodebridge %s\n", appVersion)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "未知子命令: %s\n\n", subcmd)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`NodeBridge - 个人电脑智能体安全执行网关 (Local Agent Daemon)

用法:
  nodebridge <子命令> [参数]

子命令:
  init       生成包含随机高熵 Token 的默认配置文件 nodebridge.yaml
  daemon     启动本地常驻守护进程（Streamable HTTP MCP + 本地 Web 审批控制台）
  stdio      启动轻量 stdio 桥接模式，将 stdin/stdout MCP 请求转发到本地常驻 Daemon
  status     查看本地 Daemon 状态、急停状态与待审批摘要
  approve    在命令行批准指定审批单（支持 --grant-minutes 授予 L1 限时批量授权）
  reject     在命令行拒绝指定审批单
  pause      暂停接收新的写入与命令任务
  stop-all   触发一键急停（暂停新任务 + 强杀全部运行中任务 + 撤销限时授权）
  resume     解除急停/暂停状态
  tasks      列出当前与历史异步终端任务
  version    打印版本号`)
}

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	cfgPath := fs.String("config", "nodebridge.yaml", "输出配置文件路径")
	workspace := fs.String("workspace", ".", "默认授权工作区目录")
	force := fs.Bool("force", false, "覆盖已存在的配置文件")
	_ = fs.Parse(args)

	if !*force {
		if _, err := os.Stat(*cfgPath); err == nil {
			return fmt.Errorf("配置文件 %s 已存在（如需覆盖请加 --force）", *cfgPath)
		}
	}

	cfg, err := config.DefaultConfig(*workspace)
	if err != nil {
		return err
	}
	if err := config.Save(*cfgPath, cfg); err != nil {
		return err
	}

	absCfg, _ := filepath.Abs(*cfgPath)
	fmt.Printf("已生成配置文件: %s\n", absCfg)
	fmt.Printf("授权工作区 [default]: %s\n", cfg.Workspaces[0].Root)
	fmt.Printf("MCP 端点: http://%s/mcp\n", cfg.Server.MCPListen)
	fmt.Printf("本地审批控制台: http://%s/\n", cfg.Server.AdminListen)
	fmt.Println("提示：请妥善保管配置文件中的 mcp_token 与 admin_token，切勿提交到公开 Git 仓库。")
	return nil
}

func runDaemon(args []string) error {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	cfgPath := fs.String("config", "nodebridge.yaml", "YAML 配置文件路径")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	capInfo := capability.Detect()
	taskStore, err := store.NewJSONFileTaskStore(cfg.Storage.DataDir)
	if err != nil {
		return err
	}
	auditLog, err := audit.NewLogger(cfg.Storage.DataDir, cfg.Storage.AuditMaxSizeMB, cfg.Storage.AuditMaxBackups)
	if err != nil {
		return err
	}
	fsMgr, err := filesystem.NewManager(cfg.Workspaces, cfg.Security.GlobalDenyGlobs)
	if err != nil {
		return err
	}

	gitAdapter, gitErr := git.NewAdapter(fsMgr)
	if gitErr != nil {
		log.Printf("[警告] 未检测到 Git，git.* 工具将返回不可用提示: %v", gitErr)
	}

	taskMgr, err := task.NewManager(taskStore, task.Options{
		MaxConcurrent:  cfg.Tasks.MaxConcurrent,
		DefaultTimeout: time.Duration(cfg.Tasks.DefaultTimeoutSeconds) * time.Second,
		MaxTimeout:     time.Duration(cfg.Tasks.MaxTimeoutSeconds) * time.Second,
		MaxOutputBytes: cfg.Tasks.MaxOutputBytes,
	})
	if err != nil {
		return err
	}

	policyEng := policy.NewEngine(cfg.Security)
	broker := approval.NewBroker(cfg.Approval.TimeoutSeconds, cfg.Approval.MaxGrantMinutes, taskMgr.CancelAll)

	mcpSrv := mcpserver.NewMCPServer(appVersion, tools.Deps{
		FS:     fsMgr,
		Git:    gitAdapter,
		Tasks:  taskMgr,
		Policy: policyEng,
		Broker: broker,
		Audit:  auditLog,
	})

	authProvider := session.NewBearerTokenAuthProvider(cfg.Server.MCPToken)
	mcpHandler := mcpserver.NewHTTPHandler(mcpSrv, mcpserver.GatewayConfig{
		AuthProvider:   authProvider,
		AllowedOrigins: cfg.Server.AllowedOrigins,
		Version:        appVersion,
	})

	relayConn := relay.DisabledConnector{}
	adminSrv := admin.NewServer(
		cfg.Server.AdminToken,
		cfg.Server.MCPListen,
		broker,
		taskMgr,
		auditLog,
		fsMgr,
		capInfo,
		relayConn,
	)

	// 审批无限等待需要禁止固定 WriteTimeout 截断长连接响应
	mcpHTTP := &http.Server{
		Addr:              cfg.Server.MCPListen,
		Handler:           mcpHandler,
		ReadHeaderTimeout: 15 * time.Second,
	}
	adminHTTP := &http.Server{
		Addr:              cfg.Server.AdminListen,
		Handler:           adminSrv.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := relayConn.Start(ctx, mcpHandler); err != nil {
		return err
	}

	errCh := make(chan error, 2)
	go func() {
		log.Printf("[NodeBridge] MCP Streamable HTTP 已启动: http://%s/mcp", cfg.Server.MCPListen)
		if err := mcpHTTP.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("MCP HTTP 服务异常退出: %w", err)
		}
	}()
	go func() {
		log.Printf("[NodeBridge] 本地安全审批控制台已启动: http://%s/", cfg.Server.AdminListen)
		log.Printf("[NodeBridge] 宿主机能力: %s/%s | Git=%v | Shell=%s | 授权工作区数=%d",
			capInfo.OS, capInfo.Arch, capInfo.GitAvailable, capInfo.DefaultShell, len(cfg.Workspaces))
		if err := adminHTTP.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("Admin Web 服务异常退出: %w", err)
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Println("[NodeBridge] 收到退出信号，正在优雅关闭并终止所有活动子任务...")
	}

	broker.KillAll("Daemon 正在关闭")
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = relayConn.Stop(shutCtx)
	_ = mcpHTTP.Shutdown(shutCtx)
	_ = adminHTTP.Shutdown(shutCtx)
	log.Println("[NodeBridge] 已安全停止。")
	return nil
}

func runStdio(args []string) error {
	fs := flag.NewFlagSet("stdio", flag.ExitOnError)
	cfgPath := fs.String("config", "nodebridge.yaml", "YAML 配置文件路径")
	urlFlag := fs.String("url", "", "覆盖本地 Daemon MCP 端点 URL（默认读取配置文件）")
	tokenFlag := fs.String("token", "", "覆盖 MCP Bearer Token（默认读取配置文件）")
	_ = fs.Parse(args)

	mcpURL := strings.TrimSpace(*urlFlag)
	token := strings.TrimSpace(*tokenFlag)
	if mcpURL == "" || token == "" {
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		if mcpURL == "" {
			mcpURL = "http://" + cfg.Server.MCPListen + "/mcp"
		}
		if token == "" {
			token = cfg.Server.MCPToken
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return mcpserver.RunStdioBridge(ctx, mcpURL, token, appVersion)
}

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	cfgPath := fs.String("config", "nodebridge.yaml", "YAML 配置文件路径")
	_ = fs.Parse(args)

	data, err := callAdminAPI(*cfgPath, http.MethodGet, "/api/state", nil)
	if err != nil {
		return err
	}
	fmt.Println(prettyJSON(data))
	return nil
}

func runTasks(args []string) error {
	fs := flag.NewFlagSet("tasks", flag.ExitOnError)
	cfgPath := fs.String("config", "nodebridge.yaml", "YAML 配置文件路径")
	_ = fs.Parse(args)

	raw, err := callAdminAPI(*cfgPath, http.MethodGet, "/api/state", nil)
	if err != nil {
		return err
	}
	var st struct {
		Tasks []store.TaskRecord `json:"tasks"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return err
	}
	if len(st.Tasks) == 0 {
		fmt.Println("当前没有任务记录。")
		return nil
	}
	for _, t := range st.Tasks {
		fmt.Printf("%s\t%-10s\t[%s]\t%s %s\n", t.ID, t.Status, t.WorkspaceID, t.Executable, strings.Join(t.Args, " "))
	}
	return nil
}

func runApprovalDecision(args []string, approve bool) error {
	name := "approve"
	if !approve {
		name = "reject"
	}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	cfgPath := fs.String("config", "nodebridge.yaml", "YAML 配置文件路径")
	grantMins := fs.Int("grant-minutes", 0, "仅 approve 支持：顺带授予同一工作区 L1 限时批量授权分钟数")
	note := fs.String("note", "", "审批备注")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		return fmt.Errorf("用法: nodebridge %s [选项] <approval_id>", name)
	}
	id := fs.Arg(0)

	payload := map[string]any{
		"grant_minutes": *grantMins,
		"note":          *note,
		"approver":      "cli",
	}
	raw, err := callAdminAPI(*cfgPath, http.MethodPost, fmt.Sprintf("/api/approvals/%s/%s", id, name), payload)
	if err != nil {
		return err
	}
	fmt.Println(prettyJSON(raw))
	return nil
}

func runKillSwitch(args []string, action string) error {
	fs := flag.NewFlagSet(action, flag.ExitOnError)
	cfgPath := fs.String("config", "nodebridge.yaml", "YAML 配置文件路径")
	reason := fs.String("reason", "", "操作说明")
	_ = fs.Parse(args)

	var payload any
	if action != "resume" {
		payload = map[string]any{"reason": *reason}
	}
	raw, err := callAdminAPI(*cfgPath, http.MethodPost, "/api/kill-switch/"+action, payload)
	if err != nil {
		return err
	}
	fmt.Println(prettyJSON(raw))
	return nil
}

func callAdminAPI(cfgPath, method, path string, body any) ([]byte, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://"+cfg.Server.AdminListen+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Server.AdminToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("连接本地管理 API 失败（请确认 Daemon 正在运行）: %w", err)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("管理 API 返回 HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBytes)))
	}
	return respBytes, nil
}

func prettyJSON(raw []byte) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return string(raw)
	}
	return buf.String()
}
