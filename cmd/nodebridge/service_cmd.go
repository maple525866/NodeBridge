package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nodebridge/internal/config"
	"nodebridge/internal/platform/service"
)

type multiStringFlag []string

func (m *multiStringFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiStringFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func runService(args []string) error {
	action := "status"
	rest := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action = strings.ToLower(strings.TrimSpace(args[0]))
		rest = args[1:]
	}

	switch action {
	case "install":
		return runServiceInstall(rest)
	case "uninstall", "remove":
		return runServiceUninstall(rest)
	case "start":
		return runServiceStart(rest)
	case "stop":
		return runServiceStop(rest)
	case "restart":
		return runServiceRestart(rest)
	case "status":
		return runServiceStatus(rest)
	case "logs":
		return runServiceLogs(rest)
	case "help", "-h", "--help":
		printServiceUsage()
		return nil
	default:
		printServiceUsage()
		return fmt.Errorf("未知的 service 子操作: %s", action)
	}
}

func printServiceUsage() {
	fmt.Println(`用法:
  nodebridge service <子操作> [参数]

子操作:
  install    安装并立即启动开机自启动系统守护进程（固定域名模式下运行 daemon 也会自动执行）
  uninstall  停止并卸载开机自启动系统守护进程（可选 --purge-env 清理已保存的 service.env）
  start      启动已安装的守护进程
  stop       优雅停止已安装的守护进程
  restart    重启已安装的守护进程
  status     查看开机自启动配置状态、运行状态与本地健康探活（支持 --json）
  logs       查看后台守护进程轮转日志尾部（支持 --lines 100）`)
}

func runServiceInstall(args []string) error {
	fs := flag.NewFlagSet("service install", flag.ExitOnError)
	cfgPath := fs.String("config", "nodebridge.yaml", "YAML 配置文件路径")
	scopeFlag := fs.String("scope", "", "安装作用域: auto | user | system（留空取配置 service.scope）")
	nameFlag := fs.String("name", "", "注册的服务名称（留空取配置 service.name，默认 nodebridge）")
	runAsUser := fs.String("user", "", "仅 Linux/macOS system 模式：指定运行守护进程的普通系统账号")
	noStart := fs.Bool("no-start", false, "仅注册开机自启动项，不立即启动后台守护进程")
	allowQuick := fs.Bool("allow-quick-tunnel", false, "允许为 cloudflared_quick（临时随机域名）强制安装自启动")
	var extraEnvs multiStringFlag
	fs.Var(&extraEnvs, "env", "附加持久化到 service.env 的环境变量（格式 KEY=VALUE，可多次指定）")
	_ = fs.Parse(args)

	envMap, err := service.ParseEnvAssignments(extraEnvs)
	if err != nil {
		return err
	}

	absCfg, cfg, err := loadConfigForService(*cfgPath, envMap)
	if err != nil {
		return err
	}

	scopeVal := strings.TrimSpace(*scopeFlag)
	if scopeVal == "" {
		scopeVal = cfg.Service.Scope
	}
	scope, err := service.ParseScope(scopeVal)
	if err != nil {
		return err
	}

	svcName := strings.TrimSpace(*nameFlag)
	if svcName == "" {
		svcName = cfg.Service.Name
	}

	st, warnings, err := installServiceForConfig(cfg, absCfg, installServiceParams{
		ServiceName:      svcName,
		Scope:            scope,
		RunAsUser:        strings.TrimSpace(*runAsUser),
		StartNow:         !*noStart,
		AllowQuickTunnel: *allowQuick,
		ExtraEnv:         envMap,
	})
	if err != nil {
		return err
	}

	printServiceStatus(st, warnings, false)
	return nil
}

func runServiceUninstall(args []string) error {
	fs := flag.NewFlagSet("service uninstall", flag.ExitOnError)
	cfgPath := fs.String("config", "nodebridge.yaml", "YAML 配置文件路径")
	scopeFlag := fs.String("scope", "auto", "卸载作用域: auto | user | system")
	nameFlag := fs.String("name", "", "服务名称（留空取配置 service.name，默认 nodebridge）")
	purgeEnv := fs.Bool("purge-env", false, "同时删除持久化的 data/service/service.env 文件")
	delayMs := fs.Int("delay-ms", 0, "内部选项：延迟指定毫秒后再执行卸载（供 Web 控制台脱离调用）")
	_ = fs.Parse(args)

	if *delayMs > 0 {
		time.Sleep(time.Duration(*delayMs) * time.Millisecond)
	}

	scope, err := service.ParseScope(*scopeFlag)
	if err != nil {
		return err
	}

	absCfg, _ := filepath.Abs(*cfgPath)
	cfg, _ := loadConfigOptional(absCfg)
	svcName := resolveServiceName(*nameFlag, cfg)
	dataDir := ""
	if cfg != nil {
		dataDir = cfg.Storage.DataDir
	}

	ctrlOpts := service.ControlOptions{
		ServiceName: svcName,
		Scope:       scope,
		ConfigPath:  absCfg,
		DataDir:     dataDir,
		PurgeEnv:    *purgeEnv,
		GracefulStopFn: func() error {
			return requestGracefulShutdown(cfg)
		},
	}

	if err := service.Uninstall(ctrlOpts); err != nil {
		return err
	}
	// 确保在卸载开机自启后，如果本机仍有前台或残留守护进程，也发送优雅退出
	_ = requestGracefulShutdown(cfg)

	fmt.Printf("已卸载 NodeBridge 开机自启动守护进程（服务名: %s）。\n", svcName)
	if *purgeEnv {
		fmt.Println("已清理受限环境变量文件 service.env。")
	}
	return nil
}

func runServiceStart(args []string) error {
	fs := flag.NewFlagSet("service start", flag.ExitOnError)
	cfgPath := fs.String("config", "nodebridge.yaml", "YAML 配置文件路径")
	scopeFlag := fs.String("scope", "auto", "作用域: auto | user | system")
	nameFlag := fs.String("name", "", "服务名称")
	_ = fs.Parse(args)

	scope, err := service.ParseScope(*scopeFlag)
	if err != nil {
		return err
	}
	absCfg, _ := filepath.Abs(*cfgPath)
	cfg, _ := loadConfigOptional(absCfg)
	svcName := resolveServiceName(*nameFlag, cfg)
	dataDir := ""
	if cfg != nil {
		dataDir = cfg.Storage.DataDir
	}

	st, err := service.Start(service.ControlOptions{
		ServiceName: svcName,
		Scope:       scope,
		ConfigPath:  absCfg,
		DataDir:     dataDir,
	})
	if err != nil {
		return err
	}
	attachDaemonHealth(&st, cfg, 6*time.Second)
	printServiceStatus(st, nil, false)
	return nil
}

func runServiceStop(args []string) error {
	fs := flag.NewFlagSet("service stop", flag.ExitOnError)
	cfgPath := fs.String("config", "nodebridge.yaml", "YAML 配置文件路径")
	scopeFlag := fs.String("scope", "auto", "作用域: auto | user | system")
	nameFlag := fs.String("name", "", "服务名称")
	_ = fs.Parse(args)

	scope, err := service.ParseScope(*scopeFlag)
	if err != nil {
		return err
	}
	absCfg, _ := filepath.Abs(*cfgPath)
	cfg, _ := loadConfigOptional(absCfg)
	svcName := resolveServiceName(*nameFlag, cfg)
	dataDir := ""
	if cfg != nil {
		dataDir = cfg.Storage.DataDir
	}

	st, err := service.Stop(service.ControlOptions{
		ServiceName: svcName,
		Scope:       scope,
		ConfigPath:  absCfg,
		DataDir:     dataDir,
		GracefulStopFn: func() error {
			return requestGracefulShutdown(cfg)
		},
	})
	if err != nil {
		return err
	}
	printServiceStatus(st, nil, false)
	return nil
}

func runServiceRestart(args []string) error {
	fs := flag.NewFlagSet("service restart", flag.ExitOnError)
	cfgPath := fs.String("config", "nodebridge.yaml", "YAML 配置文件路径")
	scopeFlag := fs.String("scope", "auto", "作用域: auto | user | system")
	nameFlag := fs.String("name", "", "服务名称")
	delayMs := fs.Int("delay-ms", 0, "内部选项：延迟指定毫秒后再执行重启（供 Web 控制台脱离调用）")
	_ = fs.Parse(args)

	if *delayMs > 0 {
		time.Sleep(time.Duration(*delayMs) * time.Millisecond)
	}

	scope, err := service.ParseScope(*scopeFlag)
	if err != nil {
		return err
	}
	absCfg, _ := filepath.Abs(*cfgPath)
	cfg, _ := loadConfigOptional(absCfg)
	svcName := resolveServiceName(*nameFlag, cfg)
	dataDir := ""
	if cfg != nil {
		dataDir = cfg.Storage.DataDir
	}

	st, err := service.Restart(service.ControlOptions{
		ServiceName: svcName,
		Scope:       scope,
		ConfigPath:  absCfg,
		DataDir:     dataDir,
		GracefulStopFn: func() error {
			return requestGracefulShutdown(cfg)
		},
	})
	if err != nil {
		return err
	}
	attachDaemonHealth(&st, cfg, 8*time.Second)
	printServiceStatus(st, nil, false)
	return nil
}

func runServiceStatus(args []string) error {
	fs := flag.NewFlagSet("service status", flag.ExitOnError)
	cfgPath := fs.String("config", "nodebridge.yaml", "YAML 配置文件路径")
	scopeFlag := fs.String("scope", "auto", "作用域: auto | user | system")
	nameFlag := fs.String("name", "", "服务名称")
	asJSON := fs.Bool("json", false, "以 JSON 格式输出完整状态")
	_ = fs.Parse(args)

	scope, err := service.ParseScope(*scopeFlag)
	if err != nil {
		return err
	}
	absCfg, _ := filepath.Abs(*cfgPath)
	cfg, _ := loadConfigOptional(absCfg)
	svcName := resolveServiceName(*nameFlag, cfg)
	dataDir := ""
	if cfg != nil {
		dataDir = cfg.Storage.DataDir
	}

	st, err := service.QueryStatus(service.ControlOptions{
		ServiceName: svcName,
		Scope:       scope,
		ConfigPath:  absCfg,
		DataDir:     dataDir,
	})
	if err != nil {
		return err
	}
	if cfg != nil {
		st.RelayMode = cfg.Relay.EffectiveMode()
		st.PublicURL = cfg.Relay.PublicURL
		st.Recommended = service.IsFixedDomainMode(st.RelayMode)
		if st.LogFilePath == "" {
			st.LogFilePath = service.DefaultLogFilePath(cfg.Storage.DataDir, cfg.Service.LogFile)
		}
	}
	st.InstallHint = service.BuildInstallHint(absCfg)
	attachDaemonHealth(&st, cfg, 1500*time.Millisecond)

	printServiceStatus(st, nil, *asJSON)
	return nil
}

func runServiceLogs(args []string) error {
	fs := flag.NewFlagSet("service logs", flag.ExitOnError)
	cfgPath := fs.String("config", "nodebridge.yaml", "YAML 配置文件路径")
	lines := fs.Int("lines", 100, "显示末尾日志行数")
	_ = fs.Parse(args)

	absCfg, _ := filepath.Abs(*cfgPath)
	cfg, err := loadConfigOptional(absCfg)
	if err != nil || cfg == nil {
		return fmt.Errorf("读取配置文件 %s 失败，无法定位守护日志路径: %v", absCfg, err)
	}
	logPath := service.DefaultLogFilePath(cfg.Storage.DataDir, cfg.Service.LogFile)
	if meta, mErr := service.LoadMetadata(cfg.Storage.DataDir); mErr == nil && strings.TrimSpace(meta.LogFilePath) != "" {
		logPath = meta.LogFilePath
	}
	tail, err := service.TailFile(logPath, *lines)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Printf("尚未生成守护日志文件：%s（服务可能尚未在后台模式启动）\n", logPath)
			return nil
		}
		return fmt.Errorf("读取守护日志失败 (%s): %w", logPath, err)
	}
	fmt.Printf("=== NodeBridge 守护日志 (%s，末尾 %d 行) ===\n", logPath, len(tail))
	for _, line := range tail {
		fmt.Println(line)
	}
	return nil
}

type installServiceParams struct {
	ServiceName      string
	Scope            service.Scope
	RunAsUser        string
	StartNow         bool
	AllowQuickTunnel bool
	ExtraEnv         map[string]string
}

func installServiceForConfig(cfg *config.Config, absCfg string, params installServiceParams) (service.Status, []string, error) {
	warnings, err := service.ValidateRelayModeForAutostart(cfg.Relay.EffectiveMode(), params.AllowQuickTunnel)
	if err != nil {
		return service.Status{}, nil, err
	}

	rawExe, err := os.Executable()
	if err != nil {
		return service.Status{}, nil, fmt.Errorf("无法定位当前 nodebridge 可执行文件路径: %w", err)
	}
	absExe, err := service.ValidateExecutablePath(rawExe)
	if err != nil {
		return service.Status{}, nil, err
	}

	svcName, err := service.ValidateServiceName(params.ServiceName)
	if err != nil {
		return service.Status{}, nil, err
	}

	envPath := service.DefaultEnvFilePath(cfg.Storage.DataDir)
	envMap, err := service.BuildServiceEnv(cfg, envPath, params.ExtraEnv)
	if err != nil {
		return service.Status{}, nil, err
	}
	if err := service.WriteEnvFile(envPath, envMap); err != nil {
		return service.Status{}, nil, err
	}

	logPath := service.DefaultLogFilePath(cfg.Storage.DataDir, cfg.Service.LogFile)
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return service.Status{}, nil, fmt.Errorf("创建守护日志目录失败: %w", err)
	}

	// 若当前端口已被旧实例占用，先优雅关闭旧实例再交由系统守护进程接管，避免端口冲突
	if params.StartNow && checkDaemonHealth(cfg, 600*time.Millisecond) {
		_ = requestGracefulShutdown(cfg)
		waitDaemonStopped(cfg, 4*time.Second)
	}

	st, err := service.Install(service.InstallOptions{
		ServiceName:      svcName,
		Scope:            params.Scope,
		ExecutablePath:   absExe,
		ConfigPath:       absCfg,
		WorkingDir:       filepath.Dir(absCfg),
		DataDir:          cfg.Storage.DataDir,
		EnvFilePath:      envPath,
		LogFilePath:      logPath,
		RunAsUser:        params.RunAsUser,
		StartNow:         params.StartNow,
		AllowQuickTunnel: params.AllowQuickTunnel,
		ExtraEnv:         params.ExtraEnv,
		RelayMode:        cfg.Relay.EffectiveMode(),
		PublicURL:        cfg.Relay.PublicURL,
	})
	if err != nil {
		return service.Status{}, nil, err
	}

	st.RelayMode = cfg.Relay.EffectiveMode()
	st.PublicURL = cfg.Relay.PublicURL
	st.Recommended = service.IsFixedDomainMode(st.RelayMode)
	st.InstallHint = service.BuildInstallHint(absCfg)

	if params.StartNow {
		attachDaemonHealth(&st, cfg, 8*time.Second)
		if !st.DaemonHealthy {
			warnings = append(warnings, fmt.Sprintf("后台守护服务已启动，但 8 秒内暂未探测到 http://%s/healthz 响应，请运行 `nodebridge service logs --config %s` 查看启动详情。", cfg.Server.MCPListen, absCfg))
		}
	}
	return st, warnings, nil
}

// loadConfigForService 在加载配置文件前先尝试预加载历史 service.env 与 --env 显式覆盖项，
// 确保 relay.tunnel_token 为 "env:VAR" 时既可从当前终端读取，也可复用之前已保存的值。
func loadConfigForService(cfgPath string, extraEnv map[string]string) (string, *config.Config, error) {
	absCfg, err := filepath.Abs(cfgPath)
	if err != nil {
		return "", nil, err
	}
	for k, v := range extraEnv {
		if strings.TrimSpace(k) != "" && v != "" {
			_ = os.Setenv(k, v)
		}
	}
	// 先尝试加载对应 data_dir 下的 service.env（仅补缺不覆盖显式变量）
	if peekEnv := service.PeekServiceEnvPath(absCfg); peekEnv != "" {
		_, _ = service.LoadIntoProcessEnv(peekEnv)
	}

	cfg, err := config.Load(absCfg)
	if err != nil {
		return "", nil, err
	}
	return absCfg, cfg, nil
}

func loadConfigOptional(absCfg string) (*config.Config, error) {
	if strings.TrimSpace(absCfg) == "" {
		return nil, os.ErrNotExist
	}
	if peekEnv := service.PeekServiceEnvPath(absCfg); peekEnv != "" {
		_, _ = service.LoadIntoProcessEnv(peekEnv)
	}
	return config.Load(absCfg)
}

func resolveServiceName(flagName string, cfg *config.Config) string {
	if strings.TrimSpace(flagName) != "" {
		return strings.TrimSpace(flagName)
	}
	if cfg != nil && strings.TrimSpace(cfg.Service.Name) != "" {
		return strings.TrimSpace(cfg.Service.Name)
	}
	return service.DefaultServiceName
}

func checkDaemonHealth(cfg *config.Config, timeout time.Duration) bool {
	if cfg == nil || strings.TrimSpace(cfg.Server.MCPListen) == "" {
		return false
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get("http://" + cfg.Server.MCPListen + "/healthz")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func waitDaemonStopped(cfg *config.Config, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !checkDaemonHealth(cfg, 400*time.Millisecond) {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func attachDaemonHealth(st *service.Status, cfg *config.Config, waitTimeout time.Duration) {
	if cfg == nil || strings.TrimSpace(cfg.Server.MCPListen) == "" {
		return
	}
	deadline := time.Now().Add(waitTimeout)
	for {
		if checkDaemonHealth(cfg, 1200*time.Millisecond) {
			st.DaemonHealthy = true
			st.DaemonHealthInfo = fmt.Sprintf("http://%s/healthz -> OK", cfg.Server.MCPListen)
			return
		}
		if time.Now().After(deadline) {
			st.DaemonHealthy = false
			st.DaemonHealthInfo = fmt.Sprintf("未检测到本地 Daemon 监听 http://%s/healthz", cfg.Server.MCPListen)
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func requestGracefulShutdown(cfg *config.Config) error {
	if cfg == nil || strings.TrimSpace(cfg.Server.AdminListen) == "" || strings.TrimSpace(cfg.Server.AdminToken) == "" {
		return nil
	}
	req, err := http.NewRequest(http.MethodPost, "http://"+cfg.Server.AdminListen+"/api/system/shutdown", strings.NewReader(`{"reason":"service-stop"}`))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Server.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func printServiceStatus(st service.Status, extraWarnings []string, asJSON bool) {
	if len(extraWarnings) > 0 {
		st.Warnings = append(st.Warnings, extraWarnings...)
	}
	if asJSON {
		raw, _ := json.MarshalIndent(st, "", "  ")
		fmt.Println(string(raw))
		return
	}

	fmt.Println("=== NodeBridge 开机自启动与系统守护状态 ===")
	fmt.Printf("服务名称:       %s\n", st.ServiceName)
	fmt.Printf("运行平台/后端:  %s / %s\n", st.Platform, st.Backend)
	fmt.Printf("安装作用域:     %s (开机未登录即启动: %v)\n", st.Scope, st.BootBeforeLogin)
	fmt.Printf("已安装/已启用:  installed=%v | enabled=%v | running=%v (%s)\n", st.Installed, st.Enabled, st.Running, st.State)
	if st.UnitOrTaskPath != "" {
		fmt.Printf("系统守护项:     %s\n", st.UnitOrTaskPath)
	}
	if st.ConfigPath != "" {
		fmt.Printf("配置文件:       %s\n", st.ConfigPath)
	}
	if st.RelayMode != "" {
		if st.PublicURL != "" {
			fmt.Printf("远程通道模式:   %s (%s/mcp)\n", st.RelayMode, strings.TrimRight(st.PublicURL, "/"))
		} else {
			fmt.Printf("远程通道模式:   %s\n", st.RelayMode)
		}
	}
	if st.EnvFilePath != "" {
		fmt.Printf("持久化环境文件: %s (仅本机 0600 权限，受内核密钥红线保护)\n", st.EnvFilePath)
	}
	if st.LogFilePath != "" {
		fmt.Printf("守护日志文件:   %s\n", st.LogFilePath)
	}
	if st.DaemonHealthInfo != "" {
		healthTag := "未就绪"
		if st.DaemonHealthy {
			healthTag = "在线"
		}
		fmt.Printf("Daemon 探活:    [%s] %s\n", healthTag, st.DaemonHealthInfo)
	}
	for _, w := range st.Warnings {
		fmt.Printf("[提示] %s\n", w)
	}
}
