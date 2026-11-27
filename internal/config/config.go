// Package config 负责加载、校验与生成 NodeBridge 的 YAML 配置。
package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config 表示 NodeBridge 的完整配置结构。
type Config struct {
	Server     ServerConfig      `yaml:"server"`
	Storage    StorageConfig     `yaml:"storage"`
	Approval   ApprovalConfig    `yaml:"approval"`
	Tasks      TasksConfig       `yaml:"tasks"`
	Security   SecurityConfig    `yaml:"security"`
	Workspaces []WorkspaceConfig `yaml:"workspaces"`
	Relay      RelayConfig       `yaml:"relay"`
}

// ServerConfig 定义本地 MCP 服务与管理控制台监听配置。
type ServerConfig struct {
	MCPListen      string   `yaml:"mcp_listen"`
	AdminListen    string   `yaml:"admin_listen"`
	MCPToken       string   `yaml:"mcp_token"`
	AdminToken     string   `yaml:"admin_token"`
	AllowedOrigins []string `yaml:"allowed_origins"`
}

// StorageConfig 定义本地持久化与审计轮转参数。
type StorageConfig struct {
	DataDir         string `yaml:"data_dir"`
	AuditMaxSizeMB  int    `yaml:"audit_max_size_mb"`
	AuditMaxBackups int    `yaml:"audit_max_backups"`
}

// ApprovalConfig 定义人工审批等待与限时授权策略。
type ApprovalConfig struct {
	// TimeoutSeconds 为审批等待超时秒数。0 表示无限等待用户批准或拒绝。
	TimeoutSeconds  int `yaml:"timeout_seconds"`
	MaxGrantMinutes int `yaml:"max_grant_minutes"`
}

// TasksConfig 定义异步终端任务并发、超时与输出截断上限。
type TasksConfig struct {
	MaxConcurrent         int `yaml:"max_concurrent"`
	DefaultTimeoutSeconds int `yaml:"default_timeout_seconds"`
	MaxTimeoutSeconds     int `yaml:"max_timeout_seconds"`
	MaxOutputBytes        int `yaml:"max_output_bytes"`
}

// SecurityConfig 定义全局敏感文件拒绝规则与命令分层白名单策略。
type SecurityConfig struct {
	GlobalDenyGlobs []string            `yaml:"global_deny_globs"`
	CommandPolicy   CommandPolicyConfig `yaml:"command_policy"`
}

// CommandRule 描述特定可执行程序及允许的子命令集合。
type CommandRule struct {
	Executable         string   `yaml:"executable"`
	AllowedSubcommands []string `yaml:"allowed_subcommands"`
}

// CommandPolicyConfig 描述 L0/L1/L2/L3 分层命令执行策略。
type CommandPolicyConfig struct {
	AllowExplicitShell  bool          `yaml:"allow_explicit_shell"`
	L0Rules             []CommandRule `yaml:"l0_rules"`
	L1Rules             []CommandRule `yaml:"l1_rules"`
	L2Executables       []string      `yaml:"l2_executables"`
	HardDenyExecutables []string      `yaml:"hard_deny_executables"`
}

// WorkspaceConfig 定义单个被授权的本地工作区。
type WorkspaceConfig struct {
	ID        string   `yaml:"id"`
	Root      string   `yaml:"root"`
	ReadOnly  bool     `yaml:"read_only"`
	DenyGlobs []string `yaml:"deny_globs"`
}

// RelayConfig 预留阶段二远程隧道/Relay 接入配置。
type RelayConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Provider string `yaml:"provider"`
	Endpoint string `yaml:"endpoint"`
	DeviceID string `yaml:"device_id"`
}

// DefaultGlobalDenyGlobs 返回默认禁止访问的敏感文件通配符列表。
func DefaultGlobalDenyGlobs() []string {
	return []string{
		"**/.env",
		"**/.env.*",
		"**/*.pem",
		"**/*.key",
		"**/*.p12",
		"**/*.pfx",
		"**/id_rsa*",
		"**/id_ed25519*",
		"**/.ssh/**",
		"**/.aws/**",
		"**/.gnupg/**",
		"**/.npmrc",
		"**/.pypirc",
		"**/credentials.json",
		"**/*secret*",
	}
}

// DefaultConfig 生成安全基线默认配置（含高熵随机 Token）。
func DefaultConfig(workspaceRoot string) (*Config, error) {
	mcpTok, err := GenerateToken(24)
	if err != nil {
		return nil, fmt.Errorf("生成 MCP Token 失败: %w", err)
	}
	adminTok, err := GenerateToken(24)
	if err != nil {
		return nil, fmt.Errorf("生成 Admin Token 失败: %w", err)
	}
	if workspaceRoot == "" {
		workspaceRoot = "."
	}
	absRoot, err := filepath.Abs(workspaceRoot)
	if err != nil {
		return nil, fmt.Errorf("解析默认工作区路径失败: %w", err)
	}

	return &Config{
		Server: ServerConfig{
			MCPListen:   "127.0.0.1:18765",
			AdminListen: "127.0.0.1:18766",
			MCPToken:    mcpTok,
			AdminToken:  adminTok,
			AllowedOrigins: []string{
				"http://127.0.0.1:18766",
				"http://localhost:18766",
			},
		},
		Storage: StorageConfig{
			DataDir:         "./data",
			AuditMaxSizeMB:  10,
			AuditMaxBackups: 10,
		},
		Approval: ApprovalConfig{
			TimeoutSeconds:  0,
			MaxGrantMinutes: 60,
		},
		Tasks: TasksConfig{
			MaxConcurrent:         4,
			DefaultTimeoutSeconds: 300,
			MaxTimeoutSeconds:     1800,
			MaxOutputBytes:        1024 * 1024,
		},
		Security: SecurityConfig{
			GlobalDenyGlobs: DefaultGlobalDenyGlobs(),
			CommandPolicy: CommandPolicyConfig{
				AllowExplicitShell: true,
				L0Rules: []CommandRule{
					{Executable: "git", AllowedSubcommands: []string{"status", "diff", "log", "branch", "rev-parse", "show"}},
					{Executable: "go", AllowedSubcommands: []string{"version", "env", "list"}},
				},
				L1Rules: []CommandRule{
					{Executable: "go", AllowedSubcommands: []string{"test", "vet", "build", "fmt", "mod"}},
					{Executable: "npm", AllowedSubcommands: []string{"test", "run"}},
					{Executable: "pnpm", AllowedSubcommands: []string{"test", "run"}},
					{Executable: "pytest", AllowedSubcommands: []string{}},
					{Executable: "python", AllowedSubcommands: []string{"-m"}},
				},
				L2Executables: []string{"npm", "pnpm", "yarn", "pip", "pip3", "curl", "wget", "rm", "del"},
				HardDenyExecutables: []string{
					"sudo", "su", "runas", "gsudo",
					"shutdown", "reboot", "diskpart", "format", "mkfs",
					"reg", "regedit", "netsh", "iptables", "ufw", "sc", "schtasks",
				},
			},
		},
		Workspaces: []WorkspaceConfig{
			{
				ID:        "default",
				Root:      absRoot,
				ReadOnly:  false,
				DenyGlobs: []string{},
			},
		},
		Relay: RelayConfig{
			Enabled: false,
		},
	}, nil
}

// GenerateToken 生成指定字节数的高熵十六进制随机令牌。
func GenerateToken(numBytes int) (string, error) {
	if numBytes <= 0 {
		numBytes = 24
	}
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// Load 从指定 YAML 文件加载配置，填充安全默认值并校验合法性。
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件 %s 失败: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("解析 YAML 配置失败: %w", err)
	}
	baseDir := filepath.Dir(path)
	cfg.ApplyDefaults(baseDir)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Save 将配置序列化为 YAML 并以最小权限写入目标路径。
func Save(path string, cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("创建配置目录失败: %w", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}
	return os.WriteFile(path, data, 0o600)
}

// ApplyDefaults 对缺省字段应用安全基线，并将相对路径解析为基于配置文件目录的绝对路径。
func (c *Config) ApplyDefaults(baseDir string) {
	if c.Server.MCPListen == "" {
		c.Server.MCPListen = "127.0.0.1:18765"
	}
	if c.Server.AdminListen == "" {
		c.Server.AdminListen = "127.0.0.1:18766"
	}
	if c.Storage.DataDir == "" {
		c.Storage.DataDir = "./data"
	}
	if !filepath.IsAbs(c.Storage.DataDir) && baseDir != "" {
		c.Storage.DataDir = filepath.Join(baseDir, c.Storage.DataDir)
	}
	if absData, err := filepath.Abs(c.Storage.DataDir); err == nil {
		c.Storage.DataDir = absData
	}
	if c.Storage.AuditMaxSizeMB <= 0 {
		c.Storage.AuditMaxSizeMB = 10
	}
	if c.Storage.AuditMaxBackups <= 0 {
		c.Storage.AuditMaxBackups = 10
	}
	if c.Approval.MaxGrantMinutes <= 0 {
		c.Approval.MaxGrantMinutes = 60
	}
	if c.Tasks.MaxConcurrent <= 0 {
		c.Tasks.MaxConcurrent = 4
	}
	if c.Tasks.DefaultTimeoutSeconds <= 0 {
		c.Tasks.DefaultTimeoutSeconds = 300
	}
	if c.Tasks.MaxTimeoutSeconds <= 0 {
		c.Tasks.MaxTimeoutSeconds = 1800
	}
	if c.Tasks.MaxOutputBytes <= 0 {
		c.Tasks.MaxOutputBytes = 1024 * 1024
	}
	if len(c.Security.GlobalDenyGlobs) == 0 {
		c.Security.GlobalDenyGlobs = DefaultGlobalDenyGlobs()
	}

	for i := range c.Workspaces {
		root := c.Workspaces[i].Root
		if root != "" && !filepath.IsAbs(root) && baseDir != "" {
			root = filepath.Join(baseDir, root)
		}
		if absRoot, err := filepath.Abs(root); err == nil {
			c.Workspaces[i].Root = absRoot
		}
	}
}

// Validate 校验配置关键安全约束（如禁止默认占位 Token、禁止空工作区等）。
func (c *Config) Validate() error {
	if err := validateListenAddr("server.mcp_listen", c.Server.MCPListen); err != nil {
		return err
	}
	if err := validateListenAddr("server.admin_listen", c.Server.AdminListen); err != nil {
		return err
	}
	if c.Server.MCPToken == "" || strings.HasPrefix(c.Server.MCPToken, "CHANGE_ME") {
		return errors.New("server.mcp_token 不能为空或保留占位符，请使用 nodebridge init 生成")
	}
	if c.Server.AdminToken == "" || strings.HasPrefix(c.Server.AdminToken, "CHANGE_ME") {
		return errors.New("server.admin_token 不能为空或保留占位符，请使用 nodebridge init 生成")
	}
	if c.Approval.TimeoutSeconds < 0 {
		return errors.New("approval.timeout_seconds 不能为负数")
	}
	if len(c.Workspaces) == 0 {
		return errors.New("至少需要配置一个授权工作区 (workspaces)")
	}
	seen := make(map[string]struct{}, len(c.Workspaces))
	for _, ws := range c.Workspaces {
		if strings.TrimSpace(ws.ID) == "" {
			return errors.New("工作区 id 不能为空")
		}
		if _, dup := seen[ws.ID]; dup {
			return fmt.Errorf("工作区 id 重复: %s", ws.ID)
		}
		seen[ws.ID] = struct{}{}
		if strings.TrimSpace(ws.Root) == "" {
			return fmt.Errorf("工作区 %s 的 root 路径不能为空", ws.ID)
		}
	}
	return nil
}

func validateListenAddr(field, addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s 地址格式无效 (%s): %w", field, addr, err)
	}
	if port == "" {
		return fmt.Errorf("%s 端口不能为空", field)
	}
	if host == "" {
		return fmt.Errorf("%s 必须显式指定监听主机（例如 127.0.0.1），禁止隐式全网卡监听", field)
	}
	return nil
}
