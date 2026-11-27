package service

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"nodebridge/internal/config"
)

// PeekServiceEnvPath 轻量级读取配置文件中的 storage.data_dir，返回对应的 service.env 绝对路径。
// 用于在 config.Load 校验 relay.tunnel_token 之前精准预加载受限环境变量文件。
func PeekServiceEnvPath(cfgPath string) string {
	absCfg, err := filepath.Abs(cfgPath)
	if err != nil {
		return ""
	}
	baseDir := filepath.Dir(absCfg)
	dataDir := "./data"
	if raw, err := os.ReadFile(absCfg); err == nil {
		var partial struct {
			Storage struct {
				DataDir string `yaml:"data_dir"`
			} `yaml:"storage"`
		}
		if yaml.Unmarshal(raw, &partial) == nil && strings.TrimSpace(partial.Storage.DataDir) != "" {
			dataDir = strings.TrimSpace(partial.Storage.DataDir)
		}
	}
	if !filepath.IsAbs(dataDir) {
		dataDir = filepath.Join(baseDir, dataDir)
	}
	if absData, err := filepath.Abs(dataDir); err == nil {
		dataDir = absData
	}
	return DefaultEnvFilePath(dataDir)
}

// ParseEnvFile 解析标准 KEY=VALUE 格式的受限环境变量文件（支持 # 注释与 Go/Shell 双引号转义）。
func ParseEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	res := make(map[string]string)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 16*1024), 256*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			return nil, fmt.Errorf("环境变量文件第 %d 行格式无效: 缺少 '='", lineNo)
		}
		key := strings.TrimSpace(line[:idx])
		valRaw := strings.TrimSpace(line[idx+1:])
		if !isValidEnvKey(key) {
			return nil, fmt.Errorf("环境变量文件第 %d 行变量名非法: %q", lineNo, key)
		}
		val, err := unquoteEnvValue(valRaw)
		if err != nil {
			return nil, fmt.Errorf("环境变量文件第 %d 行值解析失败: %w", lineNo, err)
		}
		res[key] = val
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return res, nil
}

// WriteEnvFile 将环境变量映射以最小权限（Unix 0600 / Windows 受保护 NTFS DACL）原子写入目标文件。
func WriteEnvFile(path string, values map[string]string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("创建服务环境目录失败: %w", err)
	}
	_ = restrictPrivatePathACL(dir)

	keys := make([]string, 0, len(values))
	for k := range values {
		if !isValidEnvKey(k) {
			return fmt.Errorf("非法环境变量名: %q", k)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	sb.WriteString("# NodeBridge 开机自启动守护进程环境变量文件（由 nodebridge service install 生成，切勿提交或外泄）\n")
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(strconv.Quote(values[k]))
		sb.WriteByte('\n')
	}

	tmpFile, err := os.CreateTemp(dir, ".service-env-*.tmp")
	if err != nil {
		return fmt.Errorf("创建临时环境文件失败: %w", err)
	}
	tmpPath := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	_ = tmpFile.Chmod(0o600)
	if _, err := tmpFile.WriteString(sb.String()); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("写入临时环境文件失败: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("刷盘临时环境文件失败: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("关闭临时环境文件失败: %w", err)
	}
	_ = restrictPrivatePathACL(tmpPath)

	if err := atomicReplaceFile(tmpPath, path); err != nil {
		return fmt.Errorf("原子替换服务环境文件失败: %w", err)
	}
	cleanup = false
	if err := restrictPrivatePathACL(path); err != nil {
		return fmt.Errorf("加固服务环境文件访问权限失败: %w", err)
	}
	return nil
}

// LoadIntoProcessEnv 加载受限环境文件并注入当前进程环境，返回本次新注入的非 PATH 变量键名列表（便于上层清理与保护）。
// 规则：
// 1. 普通变量仅在当前进程未设置或为空时注入（显式环境优先）。
// 2. PATH 变量执行去重追加合并，确保后台系统服务既保留系统默认 PATH，也能找到用户安装的 cloudflared / git / go 等工具。
func LoadIntoProcessEnv(path string) ([]string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil, nil
	}
	entries, err := ParseEnvFile(trimmed)
	if err != nil {
		return nil, err
	}
	var injectedKeys []string
	for k, v := range entries {
		if strings.EqualFold(k, "PATH") {
			merged := mergePathList(os.Getenv("PATH"), v)
			if merged != os.Getenv("PATH") {
				_ = os.Setenv("PATH", merged)
			}
			continue
		}
		if strings.TrimSpace(os.Getenv(k)) == "" && v != "" {
			if err := os.Setenv(k, v); err == nil {
				injectedKeys = append(injectedKeys, k)
			}
		}
	}
	sort.Strings(injectedKeys)
	return injectedKeys, nil
}

// BuildServiceEnv 为开机自启动收集需要持久化的关键环境变量：
// - 自动继承已有 service.env 中的历史项；
// - 捕获 relay.tunnel_token 引用的 "env:VAR_NAME"（优先级：extraEnv > 当前终端 env > 历史 service.env）；
// - 捕获用户通过 --env 显式传入的变量；
// - 捕获当前 PATH 及探测到的 cloudflared 所在目录，防止后台服务丢 PATH。
func BuildServiceEnv(cfg *config.Config, existingEnvFile string, extraEnv map[string]string) (map[string]string, error) {
	prev := make(map[string]string)
	if strings.TrimSpace(existingEnvFile) != "" {
		if parsed, err := ParseEnvFile(existingEnvFile); err == nil {
			prev = parsed
		}
	}

	out := make(map[string]string, len(prev)+len(extraEnv)+2)
	for k, v := range prev {
		out[k] = v
	}

	// 合并用户显式传入的 --env KEY=VALUE（最高优先级）
	for k, v := range extraEnv {
		key := strings.TrimSpace(k)
		if !isValidEnvKey(key) {
			return nil, fmt.Errorf("无效的环境变量名: %q", k)
		}
		out[key] = v
	}

	// 若配置了 env:VAR_NAME 格式的隧道 Token，严格按优先级解析：extraEnv -> 当前进程 env -> 历史 service.env
	if cfg != nil && cfg.Relay.EffectiveMode() == config.RelayModeCloudflaredNamed {
		rawTok := strings.TrimSpace(cfg.Relay.TunnelToken)
		if strings.HasPrefix(rawTok, "env:") {
			envKey := strings.TrimSpace(strings.TrimPrefix(rawTok, "env:"))
			if envKey == "" || !isValidEnvKey(envKey) {
				return nil, fmt.Errorf("relay.tunnel_token 中的环境变量名无效: %q", rawTok)
			}
			val := ""
			if extraEnv != nil {
				val = strings.TrimSpace(extraEnv[envKey])
			}
			if val == "" {
				val = strings.TrimSpace(os.Getenv(envKey))
			}
			if val == "" {
				val = strings.TrimSpace(prev[envKey])
			}
			if val == "" {
				return nil, fmt.Errorf("relay.tunnel_token 配置为 %q，但当前终端环境与历史服务环境中均未检测到该变量值；请先设置环境变量 %s 或通过 --env %s=<token> 传入后再安装自启动",
					rawTok, envKey, envKey)
			}
			out[envKey] = val
		}
	}

	// 捕获并合并当前 PATH（以及 cloudflared 所在目录），确保开机后台服务能定位 cloudflared / git / go 等工具
	pathVal := mergePathList(os.Getenv("PATH"), out["PATH"])
	if cfg != nil {
		bin := strings.TrimSpace(cfg.Relay.CloudflaredBin)
		if bin == "" && (cfg.Relay.EffectiveMode() == config.RelayModeCloudflaredNamed || cfg.Relay.EffectiveMode() == config.RelayModeCloudflaredQuick) {
			bin = "cloudflared"
		}
		if bin != "" {
			if fullBin, err := exec.LookPath(bin); err == nil {
				pathVal = mergePathList(pathVal, filepath.Dir(fullBin))
			}
		}
	}
	if pathVal != "" {
		out["PATH"] = pathVal
	}

	return out, nil
}

// ParseEnvAssignments 解析多个 "KEY=VALUE" 命令行参数为映射表。
func ParseEnvAssignments(items []string) (map[string]string, error) {
	out := make(map[string]string, len(items))
	for _, item := range items {
		idx := strings.IndexByte(item, '=')
		if idx <= 0 {
			return nil, fmt.Errorf("无效的 --env 参数 %q，格式应为 KEY=VALUE", item)
		}
		k := strings.TrimSpace(item[:idx])
		v := item[idx+1:]
		if !isValidEnvKey(k) {
			return nil, fmt.Errorf("无效的环境变量名 %q", k)
		}
		out[k] = v
	}
	return out, nil
}

func isValidEnvKey(k string) bool {
	if k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if i == 0 && c >= '0' && c <= '9' {
			return false
		}
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

func unquoteEnvValue(raw string) (string, error) {
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		return strconv.Unquote(raw)
	}
	if len(raw) >= 2 && raw[0] == '\'' && raw[len(raw)-1] == '\'' {
		return raw[1 : len(raw)-1], nil
	}
	return raw, nil
}

func mergePathList(primary, fallback string) string {
	sep := string(os.PathListSeparator)
	seen := make(map[string]struct{})
	var merged []string
	addList := func(list string) {
		for _, part := range strings.Split(list, sep) {
			p := strings.TrimSpace(part)
			if p == "" {
				continue
			}
			key := p
			if runtime.GOOS == "windows" {
				key = strings.ToLower(p)
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			merged = append(merged, p)
		}
	}
	addList(primary)
	addList(fallback)
	return strings.Join(merged, sep)
}
