// Package process 屏蔽 Windows Job Objects 与 Unix Process Group 差异，提供可靠的进程树启动与终止能力。
package process

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

// Spec 描述受策略与审批放行后的命令执行参数。
type Spec struct {
	Executable string
	Args       []string
	Cwd        string
	EnvAllow   []string          // 允许从宿主机透传的额外环境变量名
	ExtraEnv   map[string]string // 额外注入的环境变量
	UseShell   bool
	Stdout     io.Writer
	Stderr     io.Writer
}

// Handle 表示一个已启动的跨平台进程树句柄。
type Handle interface {
	PID() int
	Wait() (exitCode int, err error)
	KillTree() error
}

// 默认允许透传给子进程的基础无害环境变量名（防止泄露宿主机 API Key、云凭据等）
var safeBaseEnvKeys = map[string]struct{}{
	"PATH":          {},
	"PATHEXT":       {},
	"SYSTEMROOT":    {},
	"WINDIR":        {},
	"COMSPEC":       {},
	"TEMP":          {},
	"TMP":           {},
	"TMPDIR":        {},
	"HOME":          {},
	"USERPROFILE":   {},
	"HOMEDRIVE":     {},
	"HOMEPATH":      {},
	"APPDATA":       {},
	"LOCALAPPDATA":  {},
	"LANG":          {},
	"LC_ALL":        {},
	"TERM":          {},
	"GOROOT":        {},
	"GOPATH":        {},
	"GOCACHE":       {},
	"GOMODCACHE":    {},
	"GOPROXY":       {},
	"GOTOOLCHAIN":   {},
	"NODE_ENV":         {},
	"PYTHONIOENCODING": {},
}

var (
	protectedEnvMu   sync.RWMutex
	protectedEnvKeys = map[string]struct{}{
		"CLOUDFLARE_TUNNEL_TOKEN": {},
		"TUNNEL_TOKEN":            {},
	}
)

// ProtectEnvKeys 将指定环境变量名加入进程透传硬黑名单，禁止终端工具通过 env_allow 窃取宿主机敏感凭据。
func ProtectEnvKeys(keys ...string) {
	protectedEnvMu.Lock()
	defer protectedEnvMu.Unlock()
	for _, k := range keys {
		upper := strings.ToUpper(strings.TrimSpace(k))
		if upper == "" || upper == "PATH" {
			continue
		}
		protectedEnvKeys[upper] = struct{}{}
	}
}

func isProtectedEnvKey(upperKey string) bool {
	protectedEnvMu.RLock()
	_, blocked := protectedEnvKeys[upperKey]
	protectedEnvMu.RUnlock()
	return blocked
}

// BuildCommand 根据 Spec 构造受控的 *exec.Cmd（默认使用参数数组，严禁隐式 Shell 拼接）。
func BuildCommand(spec Spec) (*exec.Cmd, error) {
	if strings.TrimSpace(spec.Executable) == "" && !spec.UseShell {
		return nil, errors.New("executable 不能为空")
	}

	var cmd *exec.Cmd
	if spec.UseShell {
		shellCmd := strings.TrimSpace(spec.Executable)
		if len(spec.Args) > 0 {
			if shellCmd != "" {
				shellCmd = shellCmd + " " + strings.Join(spec.Args, " ")
			} else {
				shellCmd = strings.Join(spec.Args, " ")
			}
		}
		if shellCmd == "" {
			return nil, errors.New("显式 Shell 模式下命令内容不能为空")
		}
		if runtime.GOOS == "windows" {
			shellBin := "powershell"
			if p, err := exec.LookPath("pwsh"); err == nil {
				shellBin = p
			}
			cmd = exec.Command(shellBin, "-NoProfile", "-NonInteractive", "-Command", shellCmd)
		} else {
			cmd = exec.Command("/bin/sh", "-c", shellCmd)
		}
	} else {
		cmd = exec.Command(spec.Executable, spec.Args...)
	}

	cmd.Dir = spec.Cwd
	cmd.Env = buildFilteredEnv(spec.EnvAllow, spec.ExtraEnv)
	cmd.Stdout = spec.Stdout
	cmd.Stderr = spec.Stderr
	return cmd, nil
}

func buildFilteredEnv(allowList []string, extra map[string]string) []string {
	allowed := make(map[string]struct{}, len(safeBaseEnvKeys)+len(allowList))
	for k := range safeBaseEnvKeys {
		allowed[k] = struct{}{}
	}
	for _, k := range allowList {
		upper := strings.ToUpper(strings.TrimSpace(k))
		if upper != "" && !isProtectedEnvKey(upper) {
			allowed[upper] = struct{}{}
		}
	}

	var env []string
	for _, kv := range os.Environ() {
		idx := strings.IndexByte(kv, '=')
		if idx <= 0 {
			continue
		}
		key := kv[:idx]
		upper := strings.ToUpper(key)
		if isProtectedEnvKey(upper) {
			continue
		}
		if _, ok := allowed[upper]; ok {
			env = append(env, kv)
		}
	}
	for k, v := range extra {
		if strings.TrimSpace(k) != "" {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
	}
	return env
}
