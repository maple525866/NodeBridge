//go:build darwin

package service

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const backendLaunchd = "launchd"

// IsAdmin 返回当前 macOS 进程是否为 root 用户。
func IsAdmin() bool {
	return os.Geteuid() == 0
}

// Install 在 macOS 上安装 launchd 开机自启动守护进程（LaunchAgent / LaunchDaemon）。
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
	if scope == ScopeSystem {
		if !IsAdmin() {
			return Status{}, errors.New("安装系统级 LaunchDaemon（支持开机未登录自启）需要 root 权限（请使用 sudo 运行），或改用 `--scope user` 安装用户级 LaunchAgent")
		}
		if strings.TrimSpace(opts.RunAsUser) == "" {
			if sudoUser := strings.TrimSpace(os.Getenv("SUDO_USER")); sudoUser != "" && sudoUser != "root" {
				opts.RunAsUser = sudoUser
			}
		}
		validatedUser, err := ValidateRunAsUser(opts.RunAsUser)
		if err != nil {
			return Status{}, err
		}
		opts.RunAsUser = validatedUser
	}

	plistPath, err := launchdPlistPath(name, scope)
	if err != nil {
		return Status{}, err
	}
	if err := os.MkdirAll(filepath.Dir(plistPath), 0o755); err != nil {
		return Status{}, fmt.Errorf("创建 LaunchAgents/LaunchDaemons 目录失败: %w", err)
	}

	// 若之前已加载，先卸载并等待 launchd 彻底完成 bootout，防止 bootstrap 出现 EIO (error 5) 竞态
	_ = launchctlUnload(scope, name, plistPath)
	waitLaunchdUnloaded(scope, name, 5*time.Second)

	plistContent := RenderLaunchdPlist(opts, scope)
	if err := os.WriteFile(plistPath, []byte(plistContent), 0o644); err != nil {
		return Status{}, fmt.Errorf("写入 plist 文件失败 (%s): %w", plistPath, err)
	}

	meta := Metadata{
		ServiceName:    name,
		Scope:          scope,
		Backend:        backendLaunchd,
		ExecutablePath: opts.ExecutablePath,
		ConfigPath:     opts.ConfigPath,
		EnvFilePath:    opts.EnvFilePath,
		LogFilePath:    opts.LogFilePath,
		UnitOrTaskPath: plistPath,
		InstalledAt:    time.Now().UTC(),
	}
	_ = SaveMetadata(opts.DataDir, meta)

	// 在 sudo 系统级安装且指定了普通运行用户时，修正受限目录、service.env、metadata.json 与日志目录归属权
	if scope == ScopeSystem && opts.RunAsUser != "" {
		crashLog := ""
		if strings.TrimSpace(opts.LogFilePath) != "" {
			crashLog = strings.TrimSuffix(opts.LogFilePath, ".log") + ".launchd.log"
		}
		if err := fixOwnershipForUser(
			opts.RunAsUser,
			opts.DataDir,
			filepath.Join(opts.DataDir, ServiceSubDir),
			opts.EnvFilePath,
			MetadataPath(opts.DataDir),
			filepath.Dir(opts.LogFilePath),
			opts.LogFilePath,
			crashLog,
		); err != nil {
			return Status{}, err
		}
	}

	if opts.StartNow {
		if err := launchctlLoad(scope, name, plistPath); err != nil {
			return Status{}, fmt.Errorf("加载并启动 launchd 服务失败: %w", err)
		}
	}

	return QueryStatus(ControlOptions{
		ServiceName: name,
		Scope:       scope,
		ConfigPath:  opts.ConfigPath,
		DataDir:     opts.DataDir,
	})
}

// Uninstall 卸载 macOS launchd 守护进程并移除 plist 文件。
func Uninstall(opts ControlOptions) error {
	name, err := ValidateServiceName(opts.ServiceName)
	if err != nil {
		return err
	}
	opts.ServiceName = name

	scope := resolveDarwinExistingScope(opts)
	if scope == "" {
		return fmt.Errorf("未检测到已安装的 macOS launchd 服务（名称: %s）", name)
	}
	if scope == ScopeSystem && !IsAdmin() {
		return errors.New("卸载系统级 LaunchDaemon 需要 root 权限（请使用 sudo 运行）")
	}

	plistPath, err := launchdPlistPath(name, scope)
	if err != nil {
		return err
	}
	_ = launchctlUnload(scope, name, plistPath)
	waitLaunchdUnloaded(scope, name, 5*time.Second)
	_ = os.Remove(plistPath)

	RemoveMetadata(opts.DataDir)
	if opts.PurgeEnv && strings.TrimSpace(opts.DataDir) != "" {
		_ = os.Remove(DefaultEnvFilePath(opts.DataDir))
	}
	return nil
}

// Start 启动 macOS launchd 守护进程。
func Start(opts ControlOptions) (Status, error) {
	name, err := ValidateServiceName(opts.ServiceName)
	if err != nil {
		return Status{}, err
	}
	opts.ServiceName = name
	scope := resolveDarwinExistingScope(opts)
	if scope == "" {
		return Status{}, fmt.Errorf("未检测到已安装的 macOS launchd 服务（名称: %s）", name)
	}
	if scope == ScopeSystem && !IsAdmin() {
		return Status{}, errors.New("启动系统级 LaunchDaemon 需要 root 权限（请使用 sudo 运行）")
	}
	plistPath, err := launchdPlistPath(name, scope)
	if err != nil {
		return Status{}, err
	}
	if err := launchctlLoad(scope, name, plistPath); err != nil {
		return Status{}, err
	}
	return QueryStatus(ControlOptions{ServiceName: name, Scope: scope, ConfigPath: opts.ConfigPath, DataDir: opts.DataDir})
}

// Stop 停止 macOS launchd 守护进程。
func Stop(opts ControlOptions) (Status, error) {
	name, err := ValidateServiceName(opts.ServiceName)
	if err != nil {
		return Status{}, err
	}
	opts.ServiceName = name
	scope := resolveDarwinExistingScope(opts)
	if scope == "" {
		return Status{}, fmt.Errorf("未检测到已安装的 macOS launchd 服务（名称: %s）", name)
	}
	if scope == ScopeSystem && !IsAdmin() {
		return Status{}, errors.New("停止系统级 LaunchDaemon 需要 root 权限（请使用 sudo 运行）")
	}
	plistPath, err := launchdPlistPath(name, scope)
	if err != nil {
		return Status{}, err
	}
	if err := launchctlUnload(scope, name, plistPath); err != nil {
		return Status{}, err
	}
	waitLaunchdUnloaded(scope, name, 5*time.Second)
	return QueryStatus(ControlOptions{ServiceName: name, Scope: scope, ConfigPath: opts.ConfigPath, DataDir: opts.DataDir})
}

// Restart 重启 macOS launchd 守护进程（优先使用原生的 kickstart -k 原子重启，避免 bootout/bootstrap 竞态）。
func Restart(opts ControlOptions) (Status, error) {
	name, err := ValidateServiceName(opts.ServiceName)
	if err != nil {
		return Status{}, err
	}
	opts.ServiceName = name
	scope := resolveDarwinExistingScope(opts)
	if scope == "" {
		return Status{}, fmt.Errorf("未检测到已安装的 macOS launchd 服务（名称: %s）", name)
	}
	if scope == ScopeSystem && !IsAdmin() {
		return Status{}, errors.New("重启系统级 LaunchDaemon 需要 root 权限（请使用 sudo 运行）")
	}
	kCmd := exec.Command("launchctl", "kickstart", "-k", launchdTarget(scope, name))
	if err := kCmd.Run(); err == nil {
		return QueryStatus(ControlOptions{ServiceName: name, Scope: scope, ConfigPath: opts.ConfigPath, DataDir: opts.DataDir})
	}
	_, _ = Stop(opts)
	return Start(opts)
}

// QueryStatus 查询 macOS launchd 服务的安装与运行状态。
func QueryStatus(opts ControlOptions) (Status, error) {
	name, err := ValidateServiceName(opts.ServiceName)
	if err != nil {
		return Status{}, err
	}
	meta, _ := LoadMetadata(opts.DataDir)

	scope := opts.Scope
	if scope == "" || scope == ScopeAuto {
		scope = resolveDarwinExistingScope(ControlOptions{ServiceName: name, DataDir: opts.DataDir})
		if scope == "" {
			if IsAdmin() {
				scope = ScopeSystem
			} else {
				scope = ScopeUser
			}
		}
	}

	plistPath, _ := launchdPlistPath(name, scope)
	_, statErr := os.Stat(plistPath)
	installed := statErr == nil

	st := Status{
		ServiceName:     name,
		Platform:        runtime.GOOS,
		Scope:           scope,
		Backend:         backendLaunchd,
		Installed:       installed,
		Enabled:         installed,
		State:           "not_installed",
		BootBeforeLogin: scope == ScopeSystem,
		UnitOrTaskPath:  plistPath,
	}

	if installed {
		target := launchdTarget(scope, name)
		cmd := exec.Command("launchctl", "print", target)
		out, err := cmd.CombinedOutput()
		if err == nil {
			text := string(out)
			if strings.Contains(text, "state = running") {
				st.Running = true
				st.State = "running"
			} else {
				st.State = "loaded"
			}
		} else {
			st.State = "stopped"
		}
	}

	if meta != nil && (meta.ServiceName == "" || meta.ServiceName == name) {
		st.ExecutablePath = meta.ExecutablePath
		st.ConfigPath = meta.ConfigPath
		st.EnvFilePath = meta.EnvFilePath
		st.LogFilePath = meta.LogFilePath
	}
	if st.ConfigPath == "" {
		st.ConfigPath = opts.ConfigPath
	}
	return st, nil
}

func resolveDarwinExistingScope(opts ControlOptions) Scope {
	if opts.Scope == ScopeUser || opts.Scope == ScopeSystem {
		return opts.Scope
	}
	if meta, err := LoadMetadata(opts.DataDir); err == nil && (meta.Scope == ScopeUser || meta.Scope == ScopeSystem) {
		if p, err := launchdPlistPath(opts.ServiceName, meta.Scope); err == nil {
			if _, err := os.Stat(p); err == nil {
				return meta.Scope
			}
		}
	}
	if p, err := launchdPlistPath(opts.ServiceName, ScopeSystem); err == nil {
		if _, err := os.Stat(p); err == nil {
			return ScopeSystem
		}
	}
	if p, err := launchdPlistPath(opts.ServiceName, ScopeUser); err == nil {
		if _, err := os.Stat(p); err == nil {
			return ScopeUser
		}
	}
	return ""
}

func launchdPlistPath(name string, scope Scope) (string, error) {
	fileName := LaunchdLabel(name) + ".plist"
	if scope == ScopeSystem {
		return filepath.Join("/Library/LaunchDaemons", fileName), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("无法获取用户主目录: %w", err)
	}
	return filepath.Join(home, "Library", "LaunchAgents", fileName), nil
}

func launchdDomain(scope Scope) string {
	if scope == ScopeSystem {
		return "system"
	}
	return "gui/" + strconv.Itoa(os.Getuid())
}

func launchdTarget(scope Scope, name string) string {
	return launchdDomain(scope) + "/" + LaunchdLabel(name)
}

func waitLaunchdUnloaded(scope Scope, name string, timeout time.Duration) {
	target := launchdTarget(scope, name)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := exec.Command("launchctl", "print", target).Run(); err != nil {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func launchctlLoad(scope Scope, name, plistPath string) error {
	domain := launchdDomain(scope)
	target := launchdTarget(scope, name)
	// 先确保未被 overrides 标记禁用
	_ = exec.Command("launchctl", "enable", target).Run()

	cmd := exec.Command("launchctl", "bootstrap", domain, plistPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		// 若已 bootstrap 则尝试 kickstart
		kCmd := exec.Command("launchctl", "kickstart", "-k", target)
		if kOut, kErr := kCmd.CombinedOutput(); kErr != nil {
			// 兼容旧版 macOS 回退 load（不带 -w 避免污染 overrides）
			lCmd := exec.Command("launchctl", "load", plistPath)
			if lOut, lErr := lCmd.CombinedOutput(); lErr != nil {
				return fmt.Errorf("%s / %s / %s",
					strings.TrimSpace(string(out)),
					strings.TrimSpace(string(kOut)),
					strings.TrimSpace(string(lOut)))
			}
		}
	}
	return nil
}

func launchctlUnload(scope Scope, name, plistPath string) error {
	cmd := exec.Command("launchctl", "bootout", launchdTarget(scope, name))
	if out, err := cmd.CombinedOutput(); err != nil {
		// 兼容旧版 macOS 回退 unload（不使用 -w，避免把服务写入永久 disabled overrides）
		lCmd := exec.Command("launchctl", "unload", plistPath)
		if lOut, lErr := lCmd.CombinedOutput(); lErr != nil {
			msg := strings.TrimSpace(string(out))
			if msg == "" {
				msg = strings.TrimSpace(string(lOut))
			}
			if msg != "" {
				return errors.New(msg)
			}
			return lErr
		}
	}
	return nil
}
