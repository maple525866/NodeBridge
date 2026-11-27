// Package service 提供跨平台（Windows / Linux / macOS）的 NodeBridge 开机自启动与系统守护进程管理能力。
package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"nodebridge/internal/config"
)

// Scope 表示自启动守护进程的安装作用域。
type Scope string

const (
	// ScopeAuto 根据当前平台与权限自动选择最合适的作用域。
	ScopeAuto Scope = "auto"
	// ScopeUser 安装为当前用户级自启动守护（免管理员/root 权限）。
	ScopeUser Scope = "user"
	// ScopeSystem 安装为系统级服务（支持主机重启后未登录桌面即自动拉起，通常需要管理员/root 权限）。
	ScopeSystem Scope = "system"
)

const (
	// DefaultServiceName 是默认注册的守护服务名称。
	DefaultServiceName = "nodebridge"
	// ServiceSubDir 是 data_dir 下存放服务元数据与受限环境变量文件的子目录。
	ServiceSubDir = "service"
	// LogsSubDir 是 data_dir 下存放守护进程日志的子目录。
	LogsSubDir = "logs"
)

var serviceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}$`)

// InstallOptions 定义安装开机自启动守护进程所需的完整参数。
type InstallOptions struct {
	ServiceName      string
	Scope            Scope
	ExecutablePath   string
	ConfigPath       string
	WorkingDir       string
	DataDir          string
	EnvFilePath      string
	LogFilePath      string
	RunAsUser        string // 仅 Linux/macOS system 模式可选指定运行账号
	StartNow         bool
	AllowQuickTunnel bool
	ExtraEnv         map[string]string
	RelayMode        string
	PublicURL        string
}

// ControlOptions 定义查询、启停与卸载守护进程的参数。
type ControlOptions struct {
	ServiceName string
	Scope       Scope
	ConfigPath  string
	DataDir     string
	PurgeEnv    bool
	// GracefulStopFn 可选注入：在停止用户级计划任务前优先通知运行中的 Daemon 优雅退出。
	GracefulStopFn func() error
}

// Status 描述本机 NodeBridge 开机自启动与守护进程的综合状态。
type Status struct {
	ServiceName      string   `json:"service_name"`
	Platform         string   `json:"platform"`
	Scope            Scope    `json:"scope"`
	Backend          string   `json:"backend"`
	Installed        bool     `json:"installed"`
	Enabled          bool     `json:"enabled"`
	Running          bool     `json:"running"`
	State            string   `json:"state"`
	BootBeforeLogin  bool     `json:"boot_before_login"`
	UnitOrTaskPath   string   `json:"unit_or_task_path,omitempty"`
	ExecutablePath   string   `json:"executable_path,omitempty"`
	ConfigPath       string   `json:"config_path,omitempty"`
	EnvFilePath      string   `json:"env_file_path,omitempty"`
	LogFilePath      string   `json:"log_file_path,omitempty"`
	RelayMode        string   `json:"relay_mode,omitempty"`
	PublicURL        string   `json:"public_url,omitempty"`
	Recommended      bool     `json:"recommended"`
	InstallHint      string   `json:"install_hint,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
	DaemonHealthy    bool     `json:"daemon_healthy,omitempty"`
	DaemonHealthInfo string   `json:"daemon_health_info,omitempty"`
}

// Metadata 持久化记录最近一次安装时的服务元数据，方便 status / uninstall 准确追踪。
type Metadata struct {
	ServiceName    string    `json:"service_name"`
	Scope          Scope     `json:"scope"`
	Backend        string    `json:"backend"`
	ExecutablePath string    `json:"executable_path"`
	ConfigPath     string    `json:"config_path"`
	EnvFilePath    string    `json:"env_file_path"`
	LogFilePath    string    `json:"log_file_path"`
	UnitOrTaskPath string    `json:"unit_or_task_path"`
	InstalledAt    time.Time `json:"installed_at"`
}

// ParseScope 校验并解析作用域字符串。
func ParseScope(raw string) (Scope, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", string(ScopeAuto):
		return ScopeAuto, nil
	case string(ScopeUser):
		return ScopeUser, nil
	case string(ScopeSystem):
		return ScopeSystem, nil
	default:
		return "", fmt.Errorf("无效的 --scope 值 %q（可选: auto | user | system）", raw)
	}
}

// ValidateServiceName 校验服务名称，防止路径穿越、XML/Unit/命令行注入。
func ValidateServiceName(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return DefaultServiceName, nil
	}
	if !serviceNamePattern.MatchString(trimmed) {
		return "", fmt.Errorf("无效的服务名 %q：仅允许字母、数字、连字符(-)与下划线(_)，且长度需在 1~48 之间", name)
	}
	return trimmed, nil
}

// IsFixedDomainMode 判断当前配置是否处于长期稳定的固定域名远程接入模式。
func IsFixedDomainMode(relayMode string) bool {
	switch strings.ToLower(strings.TrimSpace(relayMode)) {
	case config.RelayModeCloudflaredNamed, config.RelayModeExternal:
		return true
	default:
		return false
	}
}

// DefaultEnvFilePath 返回默认受限环境变量文件路径（位于 data_dir/service/service.env）。
func DefaultEnvFilePath(dataDir string) string {
	return filepath.Join(dataDir, ServiceSubDir, "service.env")
}

// DefaultLogFilePath 返回默认守护进程日志路径（位于 data_dir/logs/daemon.log）。
func DefaultLogFilePath(dataDir, configured string) string {
	if strings.TrimSpace(configured) != "" {
		return configured
	}
	return filepath.Join(dataDir, LogsSubDir, "daemon.log")
}

// MetadataPath 返回服务安装元数据的本地存储路径。
func MetadataPath(dataDir string) string {
	return filepath.Join(dataDir, ServiceSubDir, "metadata.json")
}

// SaveMetadata 将服务安装元数据以最小权限写入磁盘。
func SaveMetadata(dataDir string, meta Metadata) error {
	if strings.TrimSpace(dataDir) == "" {
		return nil
	}
	p := MetadataPath(dataDir)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("创建服务元数据目录失败: %w", err)
	}
	raw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, raw, 0o600)
}

// LoadMetadata 读取已持久化的服务安装元数据。
func LoadMetadata(dataDir string) (*Metadata, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, os.ErrNotExist
	}
	raw, err := os.ReadFile(MetadataPath(dataDir))
	if err != nil {
		return nil, err
	}
	var m Metadata
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// RemoveMetadata 删除已持久化的服务安装元数据。
func RemoveMetadata(dataDir string) {
	if strings.TrimSpace(dataDir) == "" {
		return
	}
	_ = os.Remove(MetadataPath(dataDir))
}

// ValidateExecutablePath 校验用于安装开机自启动的可执行文件路径是否长期稳定（拦截 `go run` 临时构建目录）。
func ValidateExecutablePath(exePath string) (string, error) {
	trimmed := strings.TrimSpace(exePath)
	if trimmed == "" {
		return "", errors.New("可执行文件路径不能为空")
	}
	absExe, err := filepath.Abs(trimmed)
	if err != nil {
		return "", fmt.Errorf("解析可执行文件路径失败: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(absExe); err == nil {
		absExe = resolved
	}
	info, err := os.Stat(absExe)
	if err != nil {
		return "", fmt.Errorf("可执行文件不可访问 (%s): %w", absExe, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("可执行文件路径不能是目录: %s", absExe)
	}
	if isTemporaryBuildPath(absExe) {
		return "", fmt.Errorf("检测到当前可执行文件位于临时编译目录 (%s)，请先执行 `go build -o nodebridge%s ./cmd/nodebridge` 编译固定二进制后再安装开机自启动",
			absExe, exeExtension())
	}
	return absExe, nil
}

func isTemporaryBuildPath(absPath string) bool {
	norm := strings.ToLower(filepath.ToSlash(filepath.Clean(absPath)))
	if strings.Contains(norm, "/go-build") {
		return true
	}
	tmpDir := strings.ToLower(filepath.ToSlash(filepath.Clean(os.TempDir())))
	if tmpDir != "" && tmpDir != "/" && strings.HasPrefix(norm, tmpDir+"/") && strings.Contains(norm, "exe/") {
		return true
	}
	return false
}

func exeExtension() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// ValidateRelayModeForAutostart 校验当前远程通道模式是否适合配置开机自启动。
func ValidateRelayModeForAutostart(relayMode string, allowQuick bool) ([]string, error) {
	mode := strings.ToLower(strings.TrimSpace(relayMode))
	switch mode {
	case config.RelayModeCloudflaredNamed, config.RelayModeExternal:
		return nil, nil
	case config.RelayModeCloudflaredQuick:
		if !allowQuick {
			return nil, errors.New("当前配置为 cloudflared_quick（临时随机域名），重启主机后公网地址会变化并导致云端 OAuth 绑定失效。建议切换为固定域名模式（cloudflared_named 或 external）后再配置开机自启动；若确需强制安装，请追加 --allow-quick-tunnel")
		}
		return []string{"已强制为 cloudflared_quick 模式安装开机自启动：每次主机重启后临时 trycloudflare.com 域名都会变化，建议尽快切换为固定域名（cloudflared_named / external）。"}, nil
	case config.RelayModeDisabled, "":
		return []string{"当前 relay.mode=disabled，仅在开机后拉起本机回环 MCP 与 Web 控制台，不建立公网隧道。"}, nil
	default:
		return nil, nil
	}
}

// BuildDaemonArgs 构造供系统守护管理器调用的 nodebridge daemon 标准参数数组（携带 --managed 防止递归交接）。
func BuildDaemonArgs(opts InstallOptions) []string {
	args := []string{
		"daemon",
		"--managed",
		"--config", opts.ConfigPath,
	}
	if strings.TrimSpace(opts.EnvFilePath) != "" {
		args = append(args, "--env-file", opts.EnvFilePath)
	}
	if strings.TrimSpace(opts.LogFilePath) != "" {
		args = append(args, "--log-file", opts.LogFilePath)
	}
	if strings.TrimSpace(opts.ServiceName) != "" {
		args = append(args, "--service-name", opts.ServiceName)
	}
	return args
}

// BuildInstallHint 为指定配置路径生成一条可直接复制执行的安装建议命令。
func BuildInstallHint(cfgPath string) string {
	bin := "./nodebridge"
	if runtime.GOOS == "windows" {
		bin = `.\nodebridge.exe`
	}
	cfg := strings.TrimSpace(cfgPath)
	if cfg == "" {
		cfg = "nodebridge.yaml"
	}
	if strings.ContainsAny(cfg, " \t") {
		cfg = `"` + cfg + `"`
	}
	return fmt.Sprintf("%s service install --config %s", bin, cfg)
}

// ProbeSummary 供 Admin API 与 doctor 只读查询当前开机自启守护状态。
func ProbeSummary(cfg *config.Config, cfgPath string) Status {
	svcName := DefaultServiceName
	dataDir := ""
	relayMode := ""
	publicURL := ""
	if cfg != nil {
		if strings.TrimSpace(cfg.Service.Name) != "" {
			svcName = strings.TrimSpace(cfg.Service.Name)
		}
		dataDir = cfg.Storage.DataDir
		relayMode = cfg.Relay.EffectiveMode()
		publicURL = cfg.Relay.PublicURL
	}
	st, err := QueryStatus(ControlOptions{
		ServiceName: svcName,
		Scope:       ScopeAuto,
		ConfigPath:  cfgPath,
		DataDir:     dataDir,
	})
	if err != nil {
		st = Status{
			ServiceName: svcName,
			Platform:    runtime.GOOS,
			Scope:       ScopeAuto,
			State:       "unknown",
			Warnings:    []string{err.Error()},
		}
	}
	st.RelayMode = relayMode
	st.PublicURL = publicURL
	st.Recommended = IsFixedDomainMode(relayMode)
	if st.ConfigPath == "" {
		st.ConfigPath = cfgPath
	}
	if st.LogFilePath == "" && cfg != nil {
		st.LogFilePath = DefaultLogFilePath(cfg.Storage.DataDir, cfg.Service.LogFile)
	}
	st.InstallHint = BuildInstallHint(cfgPath)
	return st
}
