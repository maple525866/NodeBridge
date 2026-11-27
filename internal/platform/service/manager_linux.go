//go:build linux

package service

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const backendSystemd = "systemd"

// IsAdmin 返回当前 Linux 进程是否为 root 用户。
func IsAdmin() bool {
	return os.Geteuid() == 0
}

// Install 在 Linux 上安装 systemd 开机自启动守护服务（支持 user 与 system 作用域）。
func Install(opts InstallOptions) (Status, error) {
	name, err := ValidateServiceName(opts.ServiceName)
	if err != nil {
		return Status{}, err
	}
	opts.ServiceName = name

	if _, err := exec.LookPath("systemctl"); err != nil {
		return Status{}, errors.New("未检测到 systemctl，当前 Linux 系统不支持 systemd 自动安装")
	}

	scope := opts.Scope
	if scope == "" || scope == ScopeAuto {
		if IsAdmin() && strings.TrimSpace(os.Getenv("XDG_RUNTIME_DIR")) == "" {
			scope = ScopeSystem
		} else {
			scope = ScopeUser
		}
	}

	if scope == ScopeSystem {
		if !IsAdmin() {
			return Status{}, errors.New("安装系统级 systemd 服务需要 root 权限（请使用 sudo 运行），或改用 `--scope user` 安装用户级服务")
		}
		if strings.TrimSpace(opts.RunAsUser) == "" {
			if sudoUser := strings.TrimSpace(os.Getenv("SUDO_USER")); sudoUser != "" && sudoUser != "root" {
				opts.RunAsUser = sudoUser
			}
		}
	}

	unitPath, err := systemdUnitPath(name, scope)
	if err != nil {
		return Status{}, err
	}
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o755); err != nil {
		return Status{}, fmt.Errorf("创建 systemd 单元目录失败: %w", err)
	}

	content := RenderSystemdUnit(opts, scope)
	if err := os.WriteFile(unitPath, []byte(content), 0o644); err != nil {
		return Status{}, fmt.Errorf("写入 systemd 单元文件失败 (%s): %w", unitPath, err)
	}

	if err := runSystemctl(scope, "daemon-reload"); err != nil {
		return Status{}, fmt.Errorf("执行 systemctl daemon-reload 失败: %w", err)
	}
	unitName := name + ".service"
	if opts.StartNow {
		if err := runSystemctl(scope, "enable", "--now", unitName); err != nil {
			return Status{}, fmt.Errorf("启用并启动 %s 失败: %w", unitName, err)
		}
	} else {
		if err := runSystemctl(scope, "enable", unitName); err != nil {
			return Status{}, fmt.Errorf("启用开机自启 %s 失败: %w", unitName, err)
		}
	}

	meta := Metadata{
		ServiceName:    name,
		Scope:          scope,
		Backend:        backendSystemd,
		ExecutablePath: opts.ExecutablePath,
		ConfigPath:     opts.ConfigPath,
		EnvFilePath:    opts.EnvFilePath,
		LogFilePath:    opts.LogFilePath,
		UnitOrTaskPath: unitPath,
		InstalledAt:    time.Now().UTC(),
	}
	_ = SaveMetadata(opts.DataDir, meta)

	return QueryStatus(ControlOptions{
		ServiceName: name,
		Scope:       scope,
		ConfigPath:  opts.ConfigPath,
		DataDir:     opts.DataDir,
	})
}

// Uninstall 停止并移除 systemd 服务单元。
func Uninstall(opts ControlOptions) error {
	name, err := ValidateServiceName(opts.ServiceName)
	if err != nil {
		return err
	}
	opts.ServiceName = name

	scope := resolveLinuxExistingScope(opts)
	if scope == "" {
		return fmt.Errorf("未检测到已安装的 systemd 服务（名称: %s）", name)
	}
	if scope == ScopeSystem && !IsAdmin() {
		return errors.New("卸载系统级 systemd 服务需要 root 权限（请使用 sudo 运行）")
	}

	unitName := name + ".service"
	_ = runSystemctl(scope, "disable", "--now", unitName)
	if unitPath, err := systemdUnitPath(name, scope); err == nil {
		_ = os.Remove(unitPath)
	}
	_ = runSystemctl(scope, "daemon-reload")

	RemoveMetadata(opts.DataDir)
	if opts.PurgeEnv && strings.TrimSpace(opts.DataDir) != "" {
		_ = os.Remove(DefaultEnvFilePath(opts.DataDir))
	}
	return nil
}

// Start 启动已安装的 systemd 服务。
func Start(opts ControlOptions) (Status, error) {
	name, err := ValidateServiceName(opts.ServiceName)
	if err != nil {
		return Status{}, err
	}
	opts.ServiceName = name
	scope := resolveLinuxExistingScope(opts)
	if scope == "" {
		return Status{}, fmt.Errorf("未检测到已安装的 systemd 服务（名称: %s）", name)
	}
	if err := runSystemctl(scope, "start", name+".service"); err != nil {
		return Status{}, err
	}
	return QueryStatus(ControlOptions{ServiceName: name, Scope: scope, ConfigPath: opts.ConfigPath, DataDir: opts.DataDir})
}

// Stop 停止已安装的 systemd 服务。
func Stop(opts ControlOptions) (Status, error) {
	name, err := ValidateServiceName(opts.ServiceName)
	if err != nil {
		return Status{}, err
	}
	opts.ServiceName = name
	scope := resolveLinuxExistingScope(opts)
	if scope == "" {
		return Status{}, fmt.Errorf("未检测到已安装的 systemd 服务（名称: %s）", name)
	}
	if err := runSystemctl(scope, "stop", name+".service"); err != nil {
		return Status{}, err
	}
	return QueryStatus(ControlOptions{ServiceName: name, Scope: scope, ConfigPath: opts.ConfigPath, DataDir: opts.DataDir})
}

// Restart 重启已安装的 systemd 服务。
func Restart(opts ControlOptions) (Status, error) {
	name, err := ValidateServiceName(opts.ServiceName)
	if err != nil {
		return Status{}, err
	}
	opts.ServiceName = name
	scope := resolveLinuxExistingScope(opts)
	if scope == "" {
		return Status{}, fmt.Errorf("未检测到已安装的 systemd 服务（名称: %s）", name)
	}
	if err := runSystemctl(scope, "restart", name+".service"); err != nil {
		return Status{}, err
	}
	return QueryStatus(ControlOptions{ServiceName: name, Scope: scope, ConfigPath: opts.ConfigPath, DataDir: opts.DataDir})
}

// QueryStatus 查询 Linux systemd 服务的安装、启用与运行状态。
func QueryStatus(opts ControlOptions) (Status, error) {
	name, err := ValidateServiceName(opts.ServiceName)
	if err != nil {
		return Status{}, err
	}
	meta, _ := LoadMetadata(opts.DataDir)

	scope := opts.Scope
	if scope == "" || scope == ScopeAuto {
		scope = resolveLinuxExistingScope(ControlOptions{ServiceName: name, DataDir: opts.DataDir})
		if scope == "" {
			scope = ScopeUser
		}
	}

	unitPath, _ := systemdUnitPath(name, scope)
	_, statErr := os.Stat(unitPath)
	installed := statErr == nil

	st := Status{
		ServiceName:     name,
		Platform:        runtime.GOOS,
		Scope:           scope,
		Backend:         backendSystemd,
		Installed:       installed,
		State:           "not_installed",
		BootBeforeLogin: scope == ScopeSystem,
		UnitOrTaskPath:  unitPath,
	}

	if installed {
		unitName := name + ".service"
		if out, err := outputSystemctl(scope, "is-enabled", unitName); err == nil {
			st.Enabled = strings.TrimSpace(out) == "enabled"
		}
		activeOut, _ := outputSystemctl(scope, "is-active", unitName)
		state := strings.TrimSpace(activeOut)
		if state == "" {
			state = "inactive"
		}
		st.State = state
		st.Running = state == "active"

		if scope == ScopeUser {
			lingerOn, username := checkLinuxLinger()
			st.BootBeforeLogin = lingerOn
			if !lingerOn && username != "" {
				st.Warnings = append(st.Warnings,
					fmt.Sprintf("当前用户级 systemd 未开启 linger（主机重启后需登录后才会拉起）。执行 `sudo loginctl enable-linger %s` 即可实现重启未登录自动拉起。", username))
			}
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

func resolveLinuxExistingScope(opts ControlOptions) Scope {
	if opts.Scope == ScopeUser || opts.Scope == ScopeSystem {
		return opts.Scope
	}
	if meta, err := LoadMetadata(opts.DataDir); err == nil && (meta.Scope == ScopeUser || meta.Scope == ScopeSystem) {
		if p, err := systemdUnitPath(opts.ServiceName, meta.Scope); err == nil {
			if _, err := os.Stat(p); err == nil {
				return meta.Scope
			}
		}
	}
	if p, err := systemdUnitPath(opts.ServiceName, ScopeSystem); err == nil {
		if _, err := os.Stat(p); err == nil {
			return ScopeSystem
		}
	}
	if p, err := systemdUnitPath(opts.ServiceName, ScopeUser); err == nil {
		if _, err := os.Stat(p); err == nil {
			return ScopeUser
		}
	}
	return ""
}

func systemdUnitPath(name string, scope Scope) (string, error) {
	if scope == ScopeSystem {
		return filepath.Join("/etc/systemd/system", name+".service"), nil
	}
	if xdg := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); xdg != "" {
		return filepath.Join(xdg, "systemd", "user", name+".service"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("无法获取用户主目录: %w", err)
	}
	return filepath.Join(home, ".config", "systemd", "user", name+".service"), nil
}

func runSystemctl(scope Scope, args ...string) error {
	fullArgs := args
	if scope == ScopeUser {
		fullArgs = append([]string{"--user"}, args...)
	}
	cmd := exec.Command("systemctl", fullArgs...)
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

func outputSystemctl(scope Scope, args ...string) (string, error) {
	fullArgs := args
	if scope == ScopeUser {
		fullArgs = append([]string{"--user"}, args...)
	}
	cmd := exec.Command("systemctl", fullArgs...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func checkLinuxLinger() (bool, string) {
	u, err := user.Current()
	if err != nil || strings.TrimSpace(u.Username) == "" {
		return false, ""
	}
	_, statErr := os.Stat(filepath.Join("/var/lib/systemd/linger", u.Username))
	return statErr == nil, u.Username
}
