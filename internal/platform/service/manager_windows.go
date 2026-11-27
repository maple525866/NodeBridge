//go:build windows

package service

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	backendWindowsService       = "windows-service"
	backendWindowsTaskScheduler = "windows-task-scheduler"
)

// IsAdmin 返回当前 Windows 进程是否具备管理员权限。
func IsAdmin() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// Install 在 Windows 上安装开机自启动守护进程：
// - system 作用域：安装原生 Windows Service（支持开机未登录桌面即自动拉起 + SCM 崩溃自动重启 + 零黑框）；
// - user 作用域：安装 Windows 任务计划程序（免管理员权限，用户登录后无黑框自启动 + 失败自动重启）；
// - auto 作用域：管理员终端默认选 system，普通终端默认选 user。
func Install(opts InstallOptions) (Status, error) {
	name, err := ValidateServiceName(opts.ServiceName)
	if err != nil {
		return Status{}, err
	}
	opts.ServiceName = name

	scope := opts.Scope
	if scope == "" || scope == ScopeAuto {
		if IsAdmin() {
			scope = ScopeSystem
		} else {
			scope = ScopeUser
		}
	}

	switch scope {
	case ScopeSystem:
		if !IsAdmin() {
			return Status{}, errors.New("安装系统级 Windows 服务（支持主机重启未登录即自动启动）需要以管理员身份运行终端；或改用 `--scope user` 安装免管理员的当前用户登录自启动任务")
		}
		return installWindowsService(opts)
	case ScopeUser:
		return installWindowsTask(opts)
	default:
		return Status{}, fmt.Errorf("不支持的作用域: %s", scope)
	}
}

// Uninstall 停止并卸载 Windows 服务或计划任务。
func Uninstall(opts ControlOptions) error {
	name, err := ValidateServiceName(opts.ServiceName)
	if err != nil {
		return err
	}
	opts.ServiceName = name

	targetScope := resolveExistingScope(opts)
	var uninstallErr error
	switch targetScope {
	case ScopeSystem:
		if !IsAdmin() {
			return errors.New("卸载系统级 Windows 服务需要以管理员身份运行终端")
		}
		uninstallErr = uninstallWindowsService(name)
	case ScopeUser:
		uninstallErr = uninstallWindowsTask(opts)
	default:
		return fmt.Errorf("未检测到已安装的 NodeBridge 自启动服务（名称: %s）", name)
	}
	if uninstallErr != nil {
		return uninstallErr
	}

	RemoveMetadata(opts.DataDir)
	if opts.PurgeEnv && strings.TrimSpace(opts.DataDir) != "" {
		_ = os.Remove(DefaultEnvFilePath(opts.DataDir))
	}
	return nil
}

// Start 启动已安装的 Windows 服务或计划任务。
func Start(opts ControlOptions) (Status, error) {
	name, err := ValidateServiceName(opts.ServiceName)
	if err != nil {
		return Status{}, err
	}
	opts.ServiceName = name

	targetScope := resolveExistingScope(opts)
	switch targetScope {
	case ScopeSystem:
		if !IsAdmin() {
			return Status{}, errors.New("启动系统级 Windows 服务需要以管理员身份运行终端")
		}
		if err := startWindowsService(name); err != nil {
			return Status{}, err
		}
	case ScopeUser:
		if err := runSchtasks("/Run", "/TN", WindowsTaskName(name)); err != nil {
			return Status{}, fmt.Errorf("启动 Windows 计划任务失败: %w", err)
		}
	default:
		return Status{}, fmt.Errorf("未检测到已安装的 NodeBridge 自启动服务（名称: %s），请先运行 `nodebridge service install`", name)
	}
	return QueryStatus(ControlOptions{
		ServiceName: name,
		Scope:       targetScope,
		ConfigPath:  opts.ConfigPath,
		DataDir:     opts.DataDir,
	})
}

// Stop 优雅停止已安装的 Windows 服务或计划任务。
func Stop(opts ControlOptions) (Status, error) {
	name, err := ValidateServiceName(opts.ServiceName)
	if err != nil {
		return Status{}, err
	}
	opts.ServiceName = name

	targetScope := resolveExistingScope(opts)
	switch targetScope {
	case ScopeSystem:
		if !IsAdmin() {
			return Status{}, errors.New("停止系统级 Windows 服务需要以管理员身份运行终端")
		}
		if err := stopWindowsService(name); err != nil {
			return Status{}, err
		}
	case ScopeUser:
		stopWindowsTaskGracefully(opts)
	default:
		return Status{}, fmt.Errorf("未检测到已安装的 NodeBridge 自启动服务（名称: %s）", name)
	}
	return QueryStatus(ControlOptions{
		ServiceName: name,
		Scope:       targetScope,
		ConfigPath:  opts.ConfigPath,
		DataDir:     opts.DataDir,
	})
}

// Restart 重启已安装的 Windows 服务或计划任务。
func Restart(opts ControlOptions) (Status, error) {
	if _, err := Stop(opts); err != nil {
		return Status{}, err
	}
	if opts.WaitStoppedFn != nil {
		_ = opts.WaitStoppedFn(6 * time.Second)
	} else {
		time.Sleep(1 * time.Second)
	}
	return Start(opts)
}

// QueryStatus 只读查询 Windows 服务或计划任务的安装与运行状态（非管理员也可查询系统级服务）。
func QueryStatus(opts ControlOptions) (Status, error) {
	name, err := ValidateServiceName(opts.ServiceName)
	if err != nil {
		return Status{}, err
	}
	meta, _ := LoadMetadata(opts.DataDir)

	scope := opts.Scope
	if scope == "" || scope == ScopeAuto {
		// 优先探测系统级 Windows 服务，再探测用户级计划任务
		if st, ok := queryWindowsServiceReadOnly(name); ok {
			enrichStatusFromMetadata(&st, meta, opts)
			return st, nil
		}
		if st, ok := queryWindowsTask(name); ok {
			enrichStatusFromMetadata(&st, meta, opts)
			return st, nil
		}
		defaultScope := ScopeUser
		defaultBackend := backendWindowsTaskScheduler
		if IsAdmin() {
			defaultScope = ScopeSystem
			defaultBackend = backendWindowsService
		}
		st := Status{
			ServiceName: name,
			Platform:    runtime.GOOS,
			Scope:       defaultScope,
			Backend:     defaultBackend,
			Installed:   false,
			Enabled:     false,
			Running:     false,
			State:       "not_installed",
		}
		enrichStatusFromMetadata(&st, meta, opts)
		return st, nil
	}

	if scope == ScopeSystem {
		if st, ok := queryWindowsServiceReadOnly(name); ok {
			enrichStatusFromMetadata(&st, meta, opts)
			return st, nil
		}
		st := Status{
			ServiceName: name,
			Platform:    runtime.GOOS,
			Scope:       ScopeSystem,
			Backend:     backendWindowsService,
			Installed:   false,
			State:       "not_installed",
		}
		enrichStatusFromMetadata(&st, meta, opts)
		return st, nil
	}

	if st, ok := queryWindowsTask(name); ok {
		enrichStatusFromMetadata(&st, meta, opts)
		return st, nil
	}
	st := Status{
		ServiceName: name,
		Platform:    runtime.GOOS,
		Scope:       ScopeUser,
		Backend:     backendWindowsTaskScheduler,
		Installed:   false,
		State:       "not_installed",
	}
	enrichStatusFromMetadata(&st, meta, opts)
	return st, nil
}

func resolveExistingScope(opts ControlOptions) Scope {
	if opts.Scope == ScopeSystem || opts.Scope == ScopeUser {
		return opts.Scope
	}
	if meta, err := LoadMetadata(opts.DataDir); err == nil && (meta.Scope == ScopeSystem || meta.Scope == ScopeUser) {
		if meta.Scope == ScopeSystem {
			if _, ok := queryWindowsServiceReadOnly(opts.ServiceName); ok {
				return ScopeSystem
			}
		} else {
			if _, ok := queryWindowsTask(opts.ServiceName); ok {
				return ScopeUser
			}
		}
	}
	if _, ok := queryWindowsServiceReadOnly(opts.ServiceName); ok {
		return ScopeSystem
	}
	if _, ok := queryWindowsTask(opts.ServiceName); ok {
		return ScopeUser
	}
	return ""
}

func installWindowsService(opts InstallOptions) (Status, error) {
	m, err := mgr.Connect()
	if err != nil {
		return Status{}, fmt.Errorf("连接 Windows 服务控制管理器 (SCM) 失败: %w", err)
	}
	defer m.Disconnect()

	daemonArgs := BuildDaemonArgs(opts)
	svcCfg := mgr.Config{
		DisplayName:  fmt.Sprintf("NodeBridge Local Agent Gateway (%s)", opts.ServiceName),
		Description:  "NodeBridge 个人电脑智能体安全执行网关常驻守护进程（开机自动启动并托管公网隧道）",
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
	}

	var s *mgr.Service
	// 若同名服务已存在，优先原地停止并 UpdateConfig，避免 Delete+Create 触发 ERROR_SERVICE_MARKED_FOR_DELETE (1072) 竞态
	if existing, openErr := m.OpenService(opts.ServiceName); openErr == nil {
		if stopErr := stopServiceHandle(existing); stopErr != nil {
			_ = existing.Close()
			return Status{}, fmt.Errorf("停止已存在的 Windows 服务 %q 失败: %w", opts.ServiceName, stopErr)
		}
		curCfg, cfgErr := existing.Config()
		if cfgErr == nil {
			curCfg.DisplayName = svcCfg.DisplayName
			curCfg.Description = svcCfg.Description
			curCfg.StartType = svcCfg.StartType
			curCfg.ErrorControl = svcCfg.ErrorControl
			curCfg.BinaryPathName = quoteWindowsArg(opts.ExecutablePath) + " " + joinWindowsArgs(daemonArgs)
			if updErr := existing.UpdateConfig(curCfg); updErr == nil {
				s = existing
			}
		}
		if s == nil {
			// 原地更新失败时再回退删除重建
			_ = existing.Delete()
			_ = existing.Close()
			deadline := time.Now().Add(8 * time.Second)
			for time.Now().Before(deadline) {
				probe, err := m.OpenService(opts.ServiceName)
				if err != nil {
					break
				}
				_ = probe.Close()
				time.Sleep(250 * time.Millisecond)
			}
		}
	}

	if s == nil {
		created, err := m.CreateService(opts.ServiceName, opts.ExecutablePath, svcCfg, daemonArgs...)
		if err != nil {
			return Status{}, fmt.Errorf("创建 Windows 系统服务失败: %w", err)
		}
		s = created
	}
	defer s.Close()

	// 配置 SCM 故障自动恢复（崩溃或非零退出码均自动重启：5s -> 15s -> 30s，重置周期 1 天）
	recovery := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}
	_ = s.SetRecoveryActions(recovery, 86400)
	_ = s.SetRecoveryActionsOnNonCrashFailures(true)

	meta := Metadata{
		ServiceName:    opts.ServiceName,
		Scope:          ScopeSystem,
		Backend:        backendWindowsService,
		ExecutablePath: opts.ExecutablePath,
		ConfigPath:     opts.ConfigPath,
		EnvFilePath:    opts.EnvFilePath,
		LogFilePath:    opts.LogFilePath,
		UnitOrTaskPath: "SCM:\\" + opts.ServiceName,
		InstalledAt:    time.Now().UTC(),
	}
	_ = SaveMetadata(opts.DataDir, meta)

	if opts.StartNow {
		if err := s.Start(); err != nil {
			return Status{}, fmt.Errorf("Windows 服务已注册，但立即启动失败（请查看日志 %s）: %w", opts.LogFilePath, err)
		}
		if err := waitServiceRunning(s, 10*time.Second); err != nil {
			return Status{}, fmt.Errorf("Windows 服务启动未就绪（请查看日志 %s）: %w", opts.LogFilePath, err)
		}
	}

	st, err := QueryStatus(ControlOptions{
		ServiceName: opts.ServiceName,
		Scope:       ScopeSystem,
		ConfigPath:  opts.ConfigPath,
		DataDir:     opts.DataDir,
	})
	if err == nil {
		st.Warnings = append(st.Warnings,
			"当前以 Windows 系统服务（LocalSystem）运行，支持主机重启未登录桌面自动拉起。注意：LocalSystem 具备本机最高系统权限，且操作用户目录 Git 仓库时若遇 safe.directory 提示，可执行 `git config --system --add safe.directory '*'`，或改用 `--scope user` 以当前用户身份运行。")
	}
	return st, err
}

func uninstallWindowsService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("连接 Windows 服务控制管理器失败: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("打开 Windows 服务 %q 失败: %w", name, err)
	}
	defer s.Close()

	_ = stopServiceHandle(s)
	if err := s.Delete(); err != nil {
		return fmt.Errorf("删除 Windows 服务 %q 失败: %w", name, err)
	}
	return nil
}

func startWindowsService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("连接 Windows 服务控制管理器失败: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("打开 Windows 服务 %q 失败: %w", name, err)
	}
	defer s.Close()

	if st, err := s.Query(); err == nil && st.State == svc.Running {
		return nil
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("启动 Windows 服务 %q 失败: %w", name, err)
	}
	return waitServiceRunning(s, 10*time.Second)
}

func stopWindowsService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("连接 Windows 服务控制管理器失败: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("打开 Windows 服务 %q 失败: %w", name, err)
	}
	defer s.Close()

	return stopServiceHandle(s)
}

func stopServiceHandle(s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	if st.State != svc.StopPending {
		if _, err := s.Control(svc.Stop); err != nil {
			return err
		}
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		cur, err := s.Query()
		if err != nil || cur.State == svc.Stopped {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("等待 Windows 服务停止超时（15s），请稍后检查服务管理器或守护日志")
}

func waitServiceRunning(s *mgr.Service, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == svc.Running {
			return nil
		}
		if st.State == svc.Stopped {
			return errors.New("服务启动后立即退出（State=Stopped）")
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("等待 Windows 服务进入 Running 状态超时")
}

// queryWindowsServiceReadOnly 使用最小只读权限查询 Windows 服务状态，普通非管理员用户也能正常查询。
func queryWindowsServiceReadOnly(name string) (Status, bool) {
	scmHandle, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return Status{}, false
	}
	defer windows.CloseServiceHandle(scmHandle)

	svcNamePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return Status{}, false
	}
	svcHandle, err := windows.OpenService(scmHandle, svcNamePtr, windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return Status{}, false
	}
	defer windows.CloseServiceHandle(svcHandle)

	var ss windows.SERVICE_STATUS
	running := false
	stateStr := "unknown"
	if err := windows.QueryServiceStatus(svcHandle, &ss); err == nil {
		running = ss.CurrentState == windows.SERVICE_RUNNING
		stateStr = windowsServiceStateName(ss.CurrentState)
	}

	enabled := false
	if startType, cfgErr := queryServiceStartTypeReadOnly(svcHandle); cfgErr == nil {
		enabled = startType == windows.SERVICE_AUTO_START
	}

	return Status{
		ServiceName:     name,
		Platform:        runtime.GOOS,
		Scope:           ScopeSystem,
		Backend:         backendWindowsService,
		Installed:       true,
		Enabled:         enabled,
		Running:         running,
		State:           stateStr,
		BootBeforeLogin: true,
		UnitOrTaskPath:  "SCM:\\" + name,
	}, true
}

func queryServiceStartTypeReadOnly(h windows.Handle) (uint32, error) {
	var needed uint32
	_ = windows.QueryServiceConfig(h, nil, 0, &needed)
	if needed == 0 {
		return 0, errors.New("无法获取服务配置大小")
	}
	buf := make([]byte, needed)
	cfg := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0]))
	if err := windows.QueryServiceConfig(h, cfg, needed, &needed); err != nil {
		return 0, err
	}
	return cfg.StartType, nil
}

func windowsServiceStateName(state uint32) string {
	switch state {
	case windows.SERVICE_STOPPED:
		return "stopped"
	case windows.SERVICE_START_PENDING:
		return "starting"
	case windows.SERVICE_STOP_PENDING:
		return "stopping"
	case windows.SERVICE_RUNNING:
		return "running"
	case windows.SERVICE_CONTINUE_PENDING:
		return "continuing"
	case windows.SERVICE_PAUSE_PENDING:
		return "pausing"
	case windows.SERVICE_PAUSED:
		return "paused"
	default:
		return fmt.Sprintf("state(%d)", state)
	}
}

func installWindowsTask(opts InstallOptions) (Status, error) {
	taskName := WindowsTaskName(opts.ServiceName)
	// 若同名计划任务已在运行，先停止旧任务，防止 <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy> 导致重装后 /Run 被静默跳过
	if existing, ok := queryWindowsTask(opts.ServiceName); ok && existing.Running {
		_ = runSchtasks("/End", "/TN", taskName)
		waitWindowsTaskNotRunning(opts.ServiceName, 5*time.Second)
	}

	userID := currentWindowsUserID()
	conhostPath := detectConhostPath()

	xmlContent := RenderWindowsTaskXML(opts, userID, conhostPath)
	xmlPath := filepath.Join(opts.DataDir, ServiceSubDir, opts.ServiceName+"-task.xml")
	if err := os.MkdirAll(filepath.Dir(xmlPath), 0o700); err != nil {
		return Status{}, fmt.Errorf("创建计划任务目录失败: %w", err)
	}
	if err := writeUTF16LEFile(xmlPath, xmlContent); err != nil {
		return Status{}, fmt.Errorf("写入计划任务 XML 失败: %w", err)
	}

	if err := runSchtasks("/Create", "/TN", taskName, "/XML", xmlPath, "/F"); err != nil {
		return Status{}, fmt.Errorf("注册 Windows 计划任务失败: %w", err)
	}

	meta := Metadata{
		ServiceName:    opts.ServiceName,
		Scope:          ScopeUser,
		Backend:        backendWindowsTaskScheduler,
		ExecutablePath: opts.ExecutablePath,
		ConfigPath:     opts.ConfigPath,
		EnvFilePath:    opts.EnvFilePath,
		LogFilePath:    opts.LogFilePath,
		UnitOrTaskPath: `\` + taskName,
		InstalledAt:    time.Now().UTC(),
	}
	_ = SaveMetadata(opts.DataDir, meta)

	if opts.StartNow {
		if err := runSchtasks("/Run", "/TN", taskName); err != nil {
			return Status{}, fmt.Errorf("Windows 计划任务已注册，但立即启动失败: %w", err)
		}
		time.Sleep(1200 * time.Millisecond)
	}

	st, err := QueryStatus(ControlOptions{
		ServiceName: opts.ServiceName,
		Scope:       ScopeUser,
		ConfigPath:  opts.ConfigPath,
		DataDir:     opts.DataDir,
	})
	if err == nil {
		st.Warnings = append(st.Warnings, "当前以用户级计划任务运行（登录后自动无黑框启动）。如需主机重启后未登录桌面也自动拉起，请以管理员身份运行 `--scope system` 安装为 Windows 系统服务。")
	}
	return st, err
}

func stopWindowsTaskGracefully(opts ControlOptions) {
	taskName := WindowsTaskName(opts.ServiceName)
	if opts.GracefulStopFn != nil {
		_ = opts.GracefulStopFn()
	}
	// 等待 Daemon 完成优雅关闭（含 150ms 响应延迟 + relay/HTTP 停止）及计划任务退出，避免过早 /End 遗留孤儿进程
	if opts.WaitStoppedFn != nil {
		_ = opts.WaitStoppedFn(6 * time.Second)
	}
	waitWindowsTaskNotRunning(opts.ServiceName, 5*time.Second)

	// 兜底：若任务仍显示 Running，再执行 schtasks /End 并确认退出
	if st, ok := queryWindowsTask(opts.ServiceName); ok && st.Running {
		_ = runSchtasks("/End", "/TN", taskName)
		waitWindowsTaskNotRunning(opts.ServiceName, 3*time.Second)
	}
}

func waitWindowsTaskNotRunning(name string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, ok := queryWindowsTask(name)
		if !ok || !st.Running {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func uninstallWindowsTask(opts ControlOptions) error {
	taskName := WindowsTaskName(opts.ServiceName)
	stopWindowsTaskGracefully(opts)
	if err := runSchtasks("/Delete", "/TN", taskName, "/F"); err != nil {
		return fmt.Errorf("删除 Windows 计划任务失败: %w", err)
	}
	if strings.TrimSpace(opts.DataDir) != "" {
		_ = os.Remove(filepath.Join(opts.DataDir, ServiceSubDir, opts.ServiceName+"-task.xml"))
	}
	return nil
}

func queryWindowsTask(name string) (Status, bool) {
	taskName := WindowsTaskName(name)
	// 单次无窗口 PowerShell 查询跨语言标准枚举 State 与 Settings.Enabled，避免 UTF-16LE XML 解析误差与黑框闪烁
	psScript := fmt.Sprintf(
		`$t = Get-ScheduledTask -TaskName '%s' -ErrorAction SilentlyContinue; if ($t) { @{State=$t.State.ToString(); Enabled=[bool]$t.Settings.Enabled} | ConvertTo-Json -Compress }`,
		strings.ReplaceAll(taskName, "'", "''"),
	)
	psCmd := hiddenExecCommand("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	if psOut, psErr := psCmd.Output(); psErr == nil {
		trimmed := strings.TrimSpace(string(psOut))
		if trimmed != "" {
			var parsed struct {
				State   string `json:"State"`
				Enabled bool   `json:"Enabled"`
			}
			if json.Unmarshal([]byte(trimmed), &parsed) == nil && parsed.State != "" {
				stateStr := strings.ToLower(strings.TrimSpace(parsed.State))
				enabled := parsed.Enabled && !strings.EqualFold(parsed.State, "Disabled")
				return Status{
					ServiceName:     name,
					Platform:        runtime.GOOS,
					Scope:           ScopeUser,
					Backend:         backendWindowsTaskScheduler,
					Installed:       true,
					Enabled:         enabled,
					Running:         strings.EqualFold(parsed.State, "Running"),
					State:           stateStr,
					BootBeforeLogin: false,
					UnitOrTaskPath:  `\` + taskName,
				}, true
			}
		}
		// PowerShell 正常执行但输出为空，说明任务不存在
		return Status{}, false
	}

	// PowerShell 不可用时降级使用 schtasks 检查存在性
	if err := runSchtasks("/Query", "/TN", taskName); err != nil {
		return Status{}, false
	}
	return Status{
		ServiceName:     name,
		Platform:        runtime.GOOS,
		Scope:           ScopeUser,
		Backend:         backendWindowsTaskScheduler,
		Installed:       true,
		Enabled:         true,
		Running:         false,
		State:           "ready",
		BootBeforeLogin: false,
		UnitOrTaskPath:  `\` + taskName,
	}, true
}

func hiddenExecCommand(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: winCreateNoWindow,
		HideWindow:    true,
	}
	return cmd
}

func runSchtasks(args ...string) error {
	cmd := hiddenExecCommand("schtasks", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return errors.New(msg)
	}
	return nil
}

func currentWindowsUserID() string {
	if u, err := user.Current(); err == nil {
		// 优先使用 SID，兼容本地账号、Microsoft Account 与 Azure AD 账号
		if strings.TrimSpace(u.Uid) != "" {
			return strings.TrimSpace(u.Uid)
		}
		if strings.TrimSpace(u.Username) != "" {
			return strings.TrimSpace(u.Username)
		}
	}
	dom := strings.TrimSpace(os.Getenv("USERDOMAIN"))
	usr := strings.TrimSpace(os.Getenv("USERNAME"))
	if dom != "" && usr != "" {
		return dom + `\` + usr
	}
	return usr
}

func detectConhostPath() string {
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	p := filepath.Join(sysRoot, "System32", "conhost.exe")
	if info, err := os.Stat(p); err == nil && !info.IsDir() {
		return p
	}
	return ""
}

func writeUTF16LEFile(path, content string) error {
	encoded := utf16.Encode([]rune(content))
	buf := make([]byte, 2+len(encoded)*2)
	buf[0] = 0xFF
	buf[1] = 0xFE
	for i, r := range encoded {
		binary.LittleEndian.PutUint16(buf[2+i*2:], r)
	}
	return os.WriteFile(path, buf, 0o600)
}

func enrichStatusFromMetadata(st *Status, meta *Metadata, opts ControlOptions) {
	if meta != nil && (meta.ServiceName == "" || meta.ServiceName == st.ServiceName) {
		if st.ExecutablePath == "" {
			st.ExecutablePath = meta.ExecutablePath
		}
		if st.ConfigPath == "" {
			st.ConfigPath = meta.ConfigPath
		}
		if st.EnvFilePath == "" {
			st.EnvFilePath = meta.EnvFilePath
		}
		if st.LogFilePath == "" {
			st.LogFilePath = meta.LogFilePath
		}
	}
	if st.ConfigPath == "" {
		st.ConfigPath = opts.ConfigPath
	}
}
