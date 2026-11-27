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
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"nodebridge/internal/admin"
	"nodebridge/internal/config"
	"nodebridge/internal/core/approval"
	"nodebridge/internal/core/audit"
	"nodebridge/internal/core/oauth"
	"nodebridge/internal/core/policy"
	"nodebridge/internal/core/session"
	"nodebridge/internal/core/store"
	"nodebridge/internal/core/task"
	"nodebridge/internal/mcpserver"
	"nodebridge/internal/mcpserver/tools"
	"nodebridge/internal/platform/capability"
	"nodebridge/internal/platform/filesystem"
	"nodebridge/internal/platform/git"
	"nodebridge/internal/platform/service"
	"nodebridge/internal/transport/relay"
)

const appVersion = "0.2.0"

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
	case "pair":
		err = runPair(args)
	case "tunnel":
		err = runTunnel(args)
	case "clients":
		err = runClients(args)
	case "mode":
		err = runMode(args)
	case "service":
		err = runService(args)
	case "doctor":
		err = runDoctor(args)
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
  daemon     启动本地常驻守护进程（固定域名模式自动注册开机自启并交接后台守护；支持 --foreground 调试）
  service    管理开机自启动系统守护进程（install | uninstall | start | stop | restart | status | logs）
  stdio      启动轻量 stdio 桥接模式，将 stdin/stdout MCP 请求转发到本地常驻 Daemon
  status     查看本地 Daemon 状态、远程隧道、急停状态与待审批摘要
  pair       生成 5 分钟一次性 OAuth 2.1 配对码（支持 --readonly 与 --workspaces 限定范围）
  tunnel     查看、启动或一键断开远程公网隧道（status | connect | disconnect）
  clients    管理已绑定的远程 OAuth 2.1 客户端（list | revoke <client_id> | revoke-all）
  mode       查看或切换“全部权限（免审批）”与“默认全部目录”运行模式
  doctor     全面自检本地 Daemon、cloudflared、公网 HTTPS 隧道及 OAuth 2.1 发现元数据
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
	relayMode := fs.String("relay-mode", config.RelayModeDisabled, "远程通道模式: disabled | cloudflared_quick | cloudflared_named | external")
	publicURL := fs.String("public-url", "", "固定公网 HTTPS 地址（named/external 模式必填）")
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
	cfg.Relay.Mode = strings.TrimSpace(*relayMode)
	cfg.Relay.PublicURL = strings.TrimRight(strings.TrimSpace(*publicURL), "/")
	if cfg.Relay.EffectiveMode() != config.RelayModeDisabled {
		cfg.OAuth.Enabled = true
	}
	if err := config.Save(*cfgPath, cfg); err != nil {
		return err
	}

	absCfg, _ := filepath.Abs(*cfgPath)
	fmt.Printf("已生成配置文件: %s\n", absCfg)
	fmt.Printf("授权工作区 [default]: %s\n", cfg.Workspaces[0].Root)
	fmt.Printf("MCP 端点: http://%s/mcp\n", cfg.Server.MCPListen)
	fmt.Printf("本地审批控制台: http://%s/\n", cfg.Server.AdminListen)
	fmt.Printf("远程接入模式: %s (OAuth 2.1=%v)\n", cfg.Relay.EffectiveMode(), cfg.OAuth.Enabled)
	fmt.Println("提示：请妥善保管配置文件中的 mcp_token 与 admin_token，切勿提交到公开 Git 仓库。")
	return nil
}

func runDaemon(args []string) error {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	cfgPath := fs.String("config", "nodebridge.yaml", "YAML 配置文件路径")
	foreground := fs.Bool("foreground", false, "前台运行，不自动注册开机自启也不交接给系统守护进程（适合调试）")
	noAutostart := fs.Bool("no-autostart", false, "跳过固定域名模式的开机自启自动注册，直接在当前终端运行")
	managed := fs.Bool("managed", false, "内部标记：表示当前进程由系统守护管理器拉起")
	scopeFlag := fs.String("scope", "", "覆盖自动注册开机自启的作用域: auto | user | system")
	svcNameFlag := fs.String("service-name", "", "覆盖注册的服务名称（默认取配置 service.name）")
	envFile := fs.String("env-file", "", "启动前加载的受限环境变量文件路径（仅填补当前环境未设置的变量）")
	logFile := fs.String("log-file", "", "守护进程轮转日志输出文件路径")
	_ = fs.Parse(args)

	absCfg, err := filepath.Abs(*cfgPath)
	if err != nil {
		return err
	}

	// 启动配置加载前先注入受限环境变量文件（如重启后的 env:CLOUDFLARE_TUNNEL_TOKEN 与工具 PATH）
	if strings.TrimSpace(*envFile) != "" {
		if _, err := service.LoadIntoProcessEnv(*envFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("加载服务环境变量文件失败 (%s): %w", *envFile, err)
		}
	} else {
		// 若未显式传 --env-file，尝试兼容复用历史 service.env（不覆盖当前终端显式环境变量）
		if peekEnv := service.PeekServiceEnvPath(absCfg); peekEnv != "" {
			_, _ = service.LoadIntoProcessEnv(peekEnv)
		}
	}

	cfg, err := config.Load(absCfg)
	if err != nil {
		return err
	}

	svcName := resolveServiceName(*svcNameFlag, cfg)
	inWinSvc := isWindowsServiceProcess()

	// 固定域名（cloudflared_named / external）长期稳定使用模式：
	// 直接运行 `nodebridge daemon` 时自动注册开机自启并交接给系统守护进程后台运行（关终端不断、崩溃自动拉起、重启主机自动恢复）。
	if !*managed && !*foreground && !*noAutostart && !inWinSvc &&
		cfg.Service.AutoRegisterEnabled() && service.IsFixedDomainMode(cfg.Relay.EffectiveMode()) {
		scopeVal := strings.TrimSpace(*scopeFlag)
		if scopeVal == "" {
			scopeVal = cfg.Service.Scope
		}
		scope, err := service.ParseScope(scopeVal)
		if err != nil {
			return err
		}
		st, warnings, err := installServiceForConfig(cfg, absCfg, installServiceParams{
			ServiceName: svcName,
			Scope:       scope,
			StartNow:    true,
		})
		if err != nil {
			return fmt.Errorf("固定域名模式自动配置开机自启守护进程失败: %w（若仅需临时前台调试，请附加 --foreground 参数）", err)
		}
		fmt.Println("已检测到固定域名长期运行模式，已自动注册开机自启动并交接给系统守护进程在后台运行（关闭当前终端窗口不会中断服务）。")
		printServiceStatus(st, warnings, false)
		fmt.Printf("本地安全控制台: http://%s/\n", cfg.Server.AdminListen)
		fmt.Printf("常用运维: 查看日志 `%s service logs --config %s` | 前台调试请加 `--foreground`\n",
			filepath.Base(st.ExecutablePath), absCfg)
		return nil
	}

	// 配置守护进程轮转日志输出（Windows Service 下不写 stderr，其余模式同时输出到 stderr 与日志文件）
	var logCloser io.Closer
	effectiveLogPath := strings.TrimSpace(*logFile)
	if effectiveLogPath == "" && (inWinSvc || *managed) {
		effectiveLogPath = service.DefaultLogFilePath(cfg.Storage.DataDir, cfg.Service.LogFile)
	}
	if effectiveLogPath != "" {
		rotWriter, err := service.NewRotatingLogWriter(effectiveLogPath, cfg.Service.LogMaxSizeMB, cfg.Service.LogMaxBackups)
		if err != nil {
			return err
		}
		logCloser = rotWriter
		defer logCloser.Close()
		if inWinSvc {
			log.SetOutput(rotWriter)
		} else {
			log.SetOutput(io.MultiWriter(os.Stderr, rotWriter))
		}
	}

	return runDaemonWithPlatformHost(svcName, func(hostCtx context.Context, onReady func()) error {
		return executeDaemonRuntime(hostCtx, cfg, absCfg, svcName, onReady)
	})
}

func executeDaemonRuntime(hostCtx context.Context, cfg *config.Config, absCfg, svcName string, onReady func()) error {
	ctx, cancel := context.WithCancel(hostCtx)
	defer cancel()

	deviceIdent, err := store.LoadOrCreateDeviceIdentity(cfg.Storage.DataDir, cfg.Relay.DeviceID)
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

	secMode, err := store.LoadSecurityMode(cfg.Storage.DataDir, cfg.Security.FullPermissions, cfg.Security.AllowAllDirs)
	if err != nil {
		log.Printf("[警告] 读取历史安全模式失败，将使用配置文件默认值: %v", err)
	} else if store.SecurityModeExists(cfg.Storage.DataDir) &&
		(secMode.FullPermissions != cfg.Security.FullPermissions || secMode.AllowAllDirs != cfg.Security.AllowAllDirs) {
		log.Printf("[注意] 已从 %s/security_mode.json 加载上次控制台保存的安全模式（full_permissions=%v, allow_all_dirs=%v），覆盖了 YAML 中的默认配置",
			cfg.Storage.DataDir, secMode.FullPermissions, secMode.AllowAllDirs)
	}
	fsMgr.SetFullPermissions(secMode.FullPermissions)
	fsMgr.SetAllowAllDirs(secMode.AllowAllDirs)

	policyEng := policy.NewEngine(cfg.Security)
	policyEng.SetFullPermissions(secMode.FullPermissions)
	broker := approval.NewBroker(cfg.Approval.TimeoutSeconds, cfg.Approval.MaxGrantMinutes, taskMgr.CancelAll)
	broker.ConfigureRemote(cfg.Approval.RemoteWaitSeconds, cfg.Approval.PendingTTLSeconds, cfg.Approval.IdempotencyTTLSeconds)
	broker.SetFullPermissions(secMode.FullPermissions)

	relayConn, err := relay.NewConnector(cfg.Relay, cfg.Server.MCPListen, deviceIdent.DeviceID)
	if err != nil {
		return err
	}

	var oauthSrv *oauth.Server
	if cfg.OAuth.Enabled {
		oauthSrv, err = oauth.NewServer(oauth.Options{
			Config:            cfg.OAuth,
			DataDir:           cfg.Storage.DataDir,
			DeviceID:          deviceIdent.DeviceID,
			PublicURLProvider: relayConn.PublicURL,
		})
		if err != nil {
			return err
		}
	}

	mcpSrv := mcpserver.NewMCPServer(appVersion, tools.Deps{
		FS:     fsMgr,
		Git:    gitAdapter,
		Tasks:  taskMgr,
		Policy: policyEng,
		Broker: broker,
		Audit:  auditLog,
	})

	staticAuth := session.NewBearerTokenAuthProvider(cfg.Server.MCPToken)
	var authProvider session.AuthProvider = staticAuth
	if oauthSrv != nil {
		authProvider = session.NewCompositeAuthProvider(oauthSrv, staticAuth)
	}

	mcpHandler := mcpserver.NewHTTPHandler(mcpSrv, mcpserver.GatewayConfig{
		AuthProvider:   authProvider,
		OAuthServer:    oauthSrv,
		RelayConnector: relayConn,
		AllowedOrigins: cfg.Server.AllowedOrigins,
		Version:        appVersion,
	})

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
	adminSrv.AttachRemoteGovernance(deviceIdent.DeviceID, oauthSrv, cfg.Relay.KillAllDisconnectTunnel)
	adminSrv.AttachSecurityControl(policyEng, cfg.Storage.DataDir, secMode)
	adminSrv.AttachServiceControl(newDaemonServiceController(cfg, absCfg, svcName, func(reason string) {
		log.Printf("[NodeBridge] 收到受控停机指令 (%s)，即将优雅退出...", reason)
		cancel()
	}))

	mcpLn, err := net.Listen("tcp", cfg.Server.MCPListen)
	if err != nil {
		return fmt.Errorf("监听 MCP 地址 %s 失败（请检查是否已有另一个 NodeBridge 实例在运行）: %w", cfg.Server.MCPListen, err)
	}
	adminLn, err := net.Listen("tcp", cfg.Server.AdminListen)
	if err != nil {
		_ = mcpLn.Close()
		return fmt.Errorf("监听 Admin 控制台地址 %s 失败（请检查是否已有另一个 NodeBridge 实例在运行）: %w", cfg.Server.AdminListen, err)
	}

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

	if err := relayConn.Start(ctx, mcpHandler); err != nil {
		_ = mcpLn.Close()
		_ = adminLn.Close()
		return err
	}

	if onReady != nil {
		onReady()
	}

	errCh := make(chan error, 2)
	go func() {
		log.Printf("[NodeBridge] MCP Streamable HTTP 已启动: http://%s/mcp", cfg.Server.MCPListen)
		if err := mcpHTTP.Serve(mcpLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("MCP HTTP 服务异常退出: %w", err)
		}
	}()
	go func() {
		log.Printf("[NodeBridge] 本地安全审批控制台已启动: http://%s/", cfg.Server.AdminListen)
		log.Printf("[NodeBridge] 设备 ID=%s | %s/%s | Git=%v | Shell=%s | 工作区=%d | 全部权限=%v | 全部目录=%v | Relay=%s | OAuth2.1=%v",
			deviceIdent.DeviceID, capInfo.OS, capInfo.Arch, capInfo.GitAvailable, capInfo.DefaultShell,
			len(cfg.Workspaces), secMode.FullPermissions, secMode.AllowAllDirs, cfg.Relay.EffectiveMode(), oauthSrv != nil)
		if err := adminHTTP.Serve(adminLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	_ = relayConn.Stop(shutCtx)
	_ = mcpHTTP.Shutdown(shutCtx)
	_ = adminHTTP.Shutdown(shutCtx)
	log.Println("[NodeBridge] 已安全停止。")
	return nil
}

type daemonServiceController struct {
	cfg        *config.Config
	cfgPath    string
	svcName    string
	exePath    string
	shutdownFn func(reason string)

	mu        sync.Mutex
	cachedAt  time.Time
	cachedVal service.Status
}

func newDaemonServiceController(cfg *config.Config, cfgPath, svcName string, shutdownFn func(reason string)) *daemonServiceController {
	exe, _ := os.Executable()
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return &daemonServiceController{
		cfg:        cfg,
		cfgPath:    cfgPath,
		svcName:    svcName,
		exePath:    exe,
		shutdownFn: shutdownFn,
	}
}

func (d *daemonServiceController) Status() service.Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	if time.Since(d.cachedAt) < 3*time.Second && d.cachedVal.ServiceName != "" {
		return d.cachedVal
	}
	st := service.ProbeSummary(d.cfg, d.cfgPath)
	if strings.TrimSpace(d.svcName) != "" {
		st.ServiceName = d.svcName
	}
	d.cachedVal = st
	d.cachedAt = time.Now()
	return st
}

func (d *daemonServiceController) invalidateCache() {
	d.mu.Lock()
	d.cachedAt = time.Time{}
	d.mu.Unlock()
}

func (d *daemonServiceController) Restart() error {
	d.invalidateCache()
	st := d.Status()
	if !st.Installed {
		return errors.New("当前尚未安装开机自启动守护进程")
	}
	if st.Scope == service.ScopeSystem && !service.IsAdmin() {
		return errors.New("当前进程为非管理员权限，无法从 Web 控制台直接重启系统级服务；请使用管理员终端执行 `nodebridge service restart`")
	}
	if strings.TrimSpace(d.exePath) == "" {
		return errors.New("无法解析当前可执行文件路径，无法执行脱离重启")
	}
	args := []string{
		"service", "restart",
		"--config", d.cfgPath,
		"--scope", string(st.Scope),
		"--name", st.ServiceName,
		"--delay-ms", "400",
	}
	return service.LaunchDetachedCommand(d.exePath, args...)
}

func (d *daemonServiceController) Uninstall(purgeEnv bool) error {
	d.invalidateCache()
	st := d.Status()
	if !st.Installed {
		// 未注册系统开机自启时，直接优雅停止当前守护进程
		go func() {
			time.Sleep(250 * time.Millisecond)
			d.Shutdown("用户在控制台停止守护进程")
		}()
		return nil
	}
	if st.Scope == service.ScopeSystem && !service.IsAdmin() {
		return errors.New("当前进程为非管理员权限，无法从 Web 控制台直接卸载系统级服务；请使用管理员终端执行 `nodebridge service uninstall`")
	}
	if strings.TrimSpace(d.exePath) == "" {
		return errors.New("无法解析当前可执行文件路径，无法执行脱离卸载")
	}
	args := []string{
		"service", "uninstall",
		"--config", d.cfgPath,
		"--scope", string(st.Scope),
		"--name", st.ServiceName,
		"--delay-ms", "400",
	}
	if purgeEnv {
		args = append(args, "--purge-env")
	}
	return service.LaunchDetachedCommand(d.exePath, args...)
}

func (d *daemonServiceController) Shutdown(reason string) {
	if d.shutdownFn != nil {
		d.shutdownFn(reason)
	}
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

func runPair(args []string) error {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	cfgPath := fs.String("config", "nodebridge.yaml", "YAML 配置文件路径")
	readOnly := fs.Bool("readonly", false, "仅授予只读权限")
	workspaces := fs.String("workspaces", "", "限定允许访问的工作区 ID，逗号分隔（为空表示允许全部）")
	note := fs.String("note", "cli", "配对码备注")
	_ = fs.Parse(args)

	var wsList []string
	for _, s := range strings.Split(*workspaces, ",") {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			wsList = append(wsList, trimmed)
		}
	}

	raw, err := callAdminAPI(*cfgPath, http.MethodPost, "/api/oauth/pairing-codes", map[string]any{
		"read_only":          *readOnly,
		"allowed_workspaces": wsList,
		"note":               *note,
	})
	if err != nil {
		return err
	}
	var pc oauth.PairingCode
	if err := json.Unmarshal(raw, &pc); err != nil {
		fmt.Println(prettyJSON(raw))
		return nil
	}
	fmt.Printf("一次性 OAuth 配对码: %s\n", pc.Code)
	fmt.Printf("权限模式: %s | 允许工作区: %v\n", map[bool]string{true: "只读", false: "可读写(仍受本地审批约束)"}[pc.ReadOnly], pc.AllowedWorkspaces)
	fmt.Printf("有效期至: %s（单次有效）\n", pc.ExpiresAt.Local().Format(time.RFC3339))
	return nil
}

func runTunnel(args []string) error {
	action := "status"
	rest := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action = strings.ToLower(strings.TrimSpace(args[0]))
		rest = args[1:]
	}
	fs := flag.NewFlagSet("tunnel", flag.ExitOnError)
	cfgPath := fs.String("config", "nodebridge.yaml", "YAML 配置文件路径")
	reason := fs.String("reason", "CLI 手动断开隧道", "断开原因（仅 disconnect 使用）")
	_ = fs.Parse(rest)

	switch action {
	case "status":
		raw, err := callAdminAPI(*cfgPath, http.MethodGet, "/api/state", nil)
		if err != nil {
			return err
		}
		var st struct {
			DeviceID string       `json:"device_id"`
			Relay    relay.Status `json:"relay"`
		}
		_ = json.Unmarshal(raw, &st)
		out, _ := json.MarshalIndent(st, "", "  ")
		fmt.Println(string(out))
		return nil
	case "connect":
		raw, err := callAdminAPI(*cfgPath, http.MethodPost, "/api/relay/connect", nil)
		if err != nil {
			return err
		}
		fmt.Println(prettyJSON(raw))
		return nil
	case "disconnect":
		raw, err := callAdminAPI(*cfgPath, http.MethodPost, "/api/relay/disconnect", map[string]any{"reason": *reason})
		if err != nil {
			return err
		}
		fmt.Println(prettyJSON(raw))
		return nil
	default:
		return fmt.Errorf("用法: nodebridge tunnel [status|connect|disconnect] [--config nodebridge.yaml]")
	}
}

func runClients(args []string) error {
	action := "list"
	rest := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action = strings.ToLower(strings.TrimSpace(args[0]))
		rest = args[1:]
	}
	fs := flag.NewFlagSet("clients", flag.ExitOnError)
	cfgPath := fs.String("config", "nodebridge.yaml", "YAML 配置文件路径")
	_ = fs.Parse(rest)

	switch action {
	case "list":
		raw, err := callAdminAPI(*cfgPath, http.MethodGet, "/api/state", nil)
		if err != nil {
			return err
		}
		var st struct {
			Clients []oauth.ClientSummary `json:"oauth_clients"`
		}
		if err := json.Unmarshal(raw, &st); err != nil {
			return err
		}
		if len(st.Clients) == 0 {
			fmt.Println("当前没有已注册的远程 OAuth 2.1 客户端。")
			return nil
		}
		for _, c := range st.Clients {
			status := "ACTIVE"
			if c.Revoked {
				status = "REVOKED"
			} else if !c.Authorized {
				status = "UNBOUND"
			}
			perm := "RW"
			if c.ReadOnly {
				perm = "RO"
			}
			fmt.Printf("%s\t%-8s\t%-4s\ttokens=%d\t%s\n", c.ClientID, status, perm, c.ActiveTokens, c.ClientName)
		}
		return nil
	case "revoke":
		if fs.NArg() < 1 {
			return errors.New("用法: nodebridge clients revoke [--config nodebridge.yaml] <client_id>")
		}
		clientID := fs.Arg(0)
		raw, err := callAdminAPI(*cfgPath, http.MethodPost, "/api/oauth/clients/"+clientID+"/revoke", nil)
		if err != nil {
			return err
		}
		fmt.Println(prettyJSON(raw))
		return nil
	case "revoke-all":
		raw, err := callAdminAPI(*cfgPath, http.MethodPost, "/api/oauth/revoke-all", nil)
		if err != nil {
			return err
		}
		fmt.Println(prettyJSON(raw))
		return nil
	default:
		return errors.New("用法: nodebridge clients [list|revoke <client_id>|revoke-all] [--config nodebridge.yaml]")
	}
}

func runMode(args []string) error {
	fs := flag.NewFlagSet("mode", flag.ExitOnError)
	cfgPath := fs.String("config", "nodebridge.yaml", "YAML 配置文件路径")
	fullPerms := fs.String("full-permissions", "", "设置全部权限免审批模式: true | false")
	allowAllDirs := fs.String("allow-all-dirs", "", "设置默认全部目录模式: true | false")
	_ = fs.Parse(args)
	if fs.NArg() > 0 {
		return fmt.Errorf("不支持的位置参数 %v，用法: nodebridge mode [--config nodebridge.yaml] [--full-permissions=true|false] [--allow-all-dirs=true|false]", fs.Args())
	}

	payload := map[string]any{}
	if v := strings.TrimSpace(*fullPerms); v != "" {
		switch strings.ToLower(v) {
		case "true", "1", "on":
			payload["full_permissions"] = true
		case "false", "0", "off":
			payload["full_permissions"] = false
		default:
			return fmt.Errorf("无效的 --full-permissions 值 %q，可选 true/false", v)
		}
	}
	if v := strings.TrimSpace(*allowAllDirs); v != "" {
		switch strings.ToLower(v) {
		case "true", "1", "on":
			payload["allow_all_dirs"] = true
		case "false", "0", "off":
			payload["allow_all_dirs"] = false
		default:
			return fmt.Errorf("无效的 --allow-all-dirs 值 %q，可选 true/false", v)
		}
	}

	if len(payload) == 0 {
		raw, err := callAdminAPI(*cfgPath, http.MethodGet, "/api/security/mode", nil)
		if err != nil {
			return err
		}
		fmt.Println(prettyJSON(raw))
		return nil
	}

	raw, err := callAdminAPI(*cfgPath, http.MethodPost, "/api/security/mode", payload)
	if err != nil {
		return err
	}
	fmt.Println(prettyJSON(raw))
	return nil
}

func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	cfgPath := fs.String("config", "nodebridge.yaml", "YAML 配置文件路径")
	_ = fs.Parse(args)

	fmt.Println("=== NodeBridge 阶段二远程 MCP 接入自检 (doctor) ===")
	okAll := true
	check := func(passed bool, label, detail string) {
		icon := "[OK]"
		if !passed {
			icon = "[FAIL]"
			okAll = false
		}
		fmt.Printf("%-6s %s: %s\n", icon, label, detail)
	}

	absDoctorCfg, _ := filepath.Abs(*cfgPath)
	cfg, err := loadConfigOptional(absDoctorCfg)
	if err != nil {
		check(false, "配置文件校验", err.Error())
		return errors.New("自检未通过")
	}
	check(true, "配置文件校验", fmt.Sprintf("relay.mode=%s, oauth.enabled=%v, workspaces=%d", cfg.Relay.EffectiveMode(), cfg.OAuth.Enabled, len(cfg.Workspaces)))

	if service.IsFixedDomainMode(cfg.Relay.EffectiveMode()) {
		svcSt := service.ProbeSummary(cfg, absDoctorCfg)
		if svcSt.Installed && svcSt.Enabled {
			check(true, "开机自启守护", fmt.Sprintf("backend=%s, scope=%s, state=%s, boot_before_login=%v",
				svcSt.Backend, svcSt.Scope, svcSt.State, svcSt.BootBeforeLogin))
		} else {
			fmt.Printf("[WARN] 开机自启守护: 固定域名模式尚未配置开机自启动（主机重启后不会自动拉起），请直接运行 `%s` 或不带 --foreground 启动 daemon。\n", svcSt.InstallHint)
		}
	}

	if mode := cfg.Relay.EffectiveMode(); mode == config.RelayModeCloudflaredQuick || mode == config.RelayModeCloudflaredNamed {
		bin := cfg.Relay.CloudflaredBin
		if bin == "" {
			bin = "cloudflared"
		}
		path, lookErr := exec.LookPath(bin)
		if lookErr != nil {
			check(false, "cloudflared 检测", "未找到可执行文件，请安装 Cloudflare Tunnel CLI")
		} else {
			check(true, "cloudflared 检测", path)
		}
	}

	httpClient := &http.Client{Timeout: 8 * time.Second}

	// 1. 本地 MCP healthz
	localHealthURL := "http://" + cfg.Server.MCPListen + "/healthz"
	resp, err := httpClient.Get(localHealthURL)
	if err != nil {
		check(false, "本地 MCP 服务", fmt.Sprintf("无法连接 %s（请先启动 nodebridge daemon）: %v", localHealthURL, err))
		return errors.New("自检未通过")
	}
	resp.Body.Close()
	check(resp.StatusCode == http.StatusOK, "本地 MCP 服务", fmt.Sprintf("%s -> HTTP %d", localHealthURL, resp.StatusCode))

	// 2. 通过本地 Admin API 读取运行中公网 URL
	rawState, err := callAdminAPI(*cfgPath, http.MethodGet, "/api/state", nil)
	if err != nil {
		check(false, "本地 Admin API", err.Error())
		return errors.New("自检未通过")
	}
	var st struct {
		DeviceID     string       `json:"device_id"`
		OAuthEnabled bool         `json:"oauth_enabled"`
		Relay        relay.Status `json:"relay"`
	}
	_ = json.Unmarshal(rawState, &st)
	check(true, "设备身份与 Admin API", fmt.Sprintf("device_id=%s, oauth_enabled=%v", st.DeviceID, st.OAuthEnabled))

	// 3. 校验公网入口与标准 RFC 9728 / RFC 8414 / 401 引导头
	targetBase := strings.TrimRight(st.Relay.PublicURL, "/")
	if targetBase == "" {
		targetBase = "http://" + cfg.Server.MCPListen
		fmt.Println("[WARN] 当前无公网隧道 URL，改用本地回环地址验证 OAuth 2.1 元数据与 401 响应头。")
	} else {
		check(st.Relay.Connected && !st.Relay.DisconnectedByUser, "远程隧道状态", fmt.Sprintf("connected=%v, url=%s", st.Relay.Connected, targetBase))
	}

	if st.OAuthEnabled {
		prmResp, err := httpClient.Get(targetBase + "/.well-known/oauth-protected-resource")
		if err != nil {
			check(false, "RFC 9728 元数据", err.Error())
		} else {
			prmResp.Body.Close()
			check(prmResp.StatusCode == http.StatusOK, "RFC 9728 元数据", fmt.Sprintf("%s/.well-known/oauth-protected-resource -> HTTP %d", targetBase, prmResp.StatusCode))
		}

		asmResp, err := httpClient.Get(targetBase + "/.well-known/oauth-authorization-server")
		if err != nil {
			check(false, "RFC 8414 元数据", err.Error())
		} else {
			asmResp.Body.Close()
			check(asmResp.StatusCode == http.StatusOK, "RFC 8414 元数据", fmt.Sprintf("%s/.well-known/oauth-authorization-server -> HTTP %d", targetBase, asmResp.StatusCode))
		}
	}

	mcpReq, _ := http.NewRequest(http.MethodPost, targetBase+"/mcp", strings.NewReader(`{}`))
	mcpReq.Header.Set("Content-Type", "application/json")
	mcpResp, err := httpClient.Do(mcpReq)
	if err != nil {
		check(false, "MCP 端点鉴权引导", err.Error())
	} else {
		mcpResp.Body.Close()
		wwwAuth := mcpResp.Header.Get("WWW-Authenticate")
		pass401 := mcpResp.StatusCode == http.StatusUnauthorized && (!st.OAuthEnabled || strings.Contains(wwwAuth, "resource_metadata="))
		check(pass401, "MCP 端点鉴权引导", fmt.Sprintf("HTTP %d | WWW-Authenticate: %s", mcpResp.StatusCode, wwwAuth))
	}

	if !okAll {
		return errors.New("部分诊断项未通过，请根据上述 [FAIL] 提示排查")
	}
	fmt.Println("全部自检通过！您现在可以将公网 MCP URL 配置到 Gemini Web / ChatGPT Web / Claude Web。")
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
	disconnectTunnel := fs.Bool("disconnect-tunnel", false, "仅 stop-all 支持：同时强制断开远程隧道")
	_ = fs.Parse(args)

	var payload any
	if action != "resume" {
		payload = map[string]any{
			"reason":            *reason,
			"disconnect_tunnel": *disconnectTunnel,
		}
	}
	raw, err := callAdminAPI(*cfgPath, http.MethodPost, "/api/kill-switch/"+action, payload)
	if err != nil {
		return err
	}
	fmt.Println(prettyJSON(raw))
	return nil
}

func callAdminAPI(cfgPath, method, path string, body any) ([]byte, error) {
	absCfg, _ := filepath.Abs(cfgPath)
	cfg, err := loadConfigOptional(absCfg)
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
