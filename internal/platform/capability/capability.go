// Package capability 在 Daemon 启动时探测本机真实能力，而非硬编码假设操作系统环境。
package capability

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ToolInfo 描述本机单个开发工具链的探测结果。
type ToolInfo struct {
	Available bool   `json:"available"`
	Version   string `json:"version,omitempty"`
}

// Info 描述当前宿主机探测到的平台能力。
type Info struct {
	OS              string              `json:"os"`
	Arch            string              `json:"arch"`
	GitAvailable    bool                `json:"git_available"`
	GitPath         string              `json:"git_path,omitempty"`
	GitVersion      string              `json:"git_version,omitempty"`
	DefaultShell    string              `json:"default_shell,omitempty"`
	DefaultShellBin string              `json:"default_shell_bin,omitempty"`
	DesktopEnabled  bool                `json:"desktop_enabled"`
	RipgrepPath     string              `json:"ripgrep_path,omitempty"`
	Tools           map[string]ToolInfo `json:"tools,omitempty"`
}

type probeSpec struct {
	name string
	bin  string
	args []string
}

var defaultToolProbes = []probeSpec{
	{name: "git", bin: "git", args: []string{"--version"}},
	{name: "go", bin: "go", args: []string{"version"}},
	{name: "node", bin: "node", args: []string{"--version"}},
	{name: "npm", bin: "npm", args: []string{"--version"}},
	{name: "pnpm", bin: "pnpm", args: []string{"--version"}},
	{name: "yarn", bin: "yarn", args: []string{"--version"}},
	{name: "bun", bin: "bun", args: []string{"--version"}},
	{name: "python", bin: "python", args: []string{"--version"}},
	{name: "python3", bin: "python3", args: []string{"--version"}},
	{name: "pytest", bin: "pytest", args: []string{"--version"}},
	{name: "cargo", bin: "cargo", args: []string{"--version"}},
	{name: "rustc", bin: "rustc", args: []string{"--version"}},
	{name: "rg", bin: "rg", args: []string{"--version"}},
	{name: "make", bin: "make", args: []string{"--version"}},
	{name: "cmake", bin: "cmake", args: []string{"--version"}},
	{name: "java", bin: "java", args: []string{"-version"}},
	{name: "mvn", bin: "mvn", args: []string{"--version"}},
	{name: "gradle", bin: "gradle", args: []string{"--version"}},
	{name: "dotnet", bin: "dotnet", args: []string{"--version"}},
}

// Detect 探测本机 Git、默认 Shell、ripgrep、常用开发工具链与操作系统信息。
func Detect() Info {
	info := Info{
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		DesktopEnabled: false, // 暂不启用桌面自动化
		Tools:          make(map[string]ToolInfo, len(defaultToolProbes)),
	}

	if gitPath, err := exec.LookPath("git"); err == nil {
		info.GitAvailable = true
		info.GitPath = gitPath
	}
	if rgPath, err := exec.LookPath("rg"); err == nil {
		info.RipgrepPath = rgPath
	}

	// 并行轻量探测各常用开发工具链版本，单工具硬限时 1.5s 避免阻塞启动
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, spec := range defaultToolProbes {
		binPath, err := exec.LookPath(spec.bin)
		if err != nil {
			continue
		}
		wg.Add(1)
		go func(s probeSpec, resolved string) {
			defer wg.Done()
			ver := probeVersionLine(resolved, s.args...)
			mu.Lock()
			info.Tools[s.name] = ToolInfo{
				Available: true,
				Version:   ver,
			}
			if s.name == "git" && ver != "" {
				info.GitVersion = ver
			}
			mu.Unlock()
		}(spec, binPath)
	}
	wg.Wait()

	switch runtime.GOOS {
	case "windows":
		if p, err := exec.LookPath("pwsh"); err == nil {
			info.DefaultShell = "pwsh"
			info.DefaultShellBin = p
		} else if p, err := exec.LookPath("powershell"); err == nil {
			info.DefaultShell = "powershell"
			info.DefaultShellBin = p
		} else if p, err := exec.LookPath("cmd"); err == nil {
			info.DefaultShell = "cmd"
			info.DefaultShellBin = p
		}
	case "darwin":
		if p, err := exec.LookPath("zsh"); err == nil {
			info.DefaultShell = "zsh"
			info.DefaultShellBin = p
		} else if p, err := exec.LookPath("bash"); err == nil {
			info.DefaultShell = "bash"
			info.DefaultShellBin = p
		}
	default:
		if p, err := exec.LookPath("bash"); err == nil {
			info.DefaultShell = "bash"
			info.DefaultShellBin = p
		} else if p, err := exec.LookPath("sh"); err == nil {
			info.DefaultShell = "sh"
			info.DefaultShellBin = p
		}
	}

	return info
}

func probeVersionLine(binPath string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return ""
	}
	norm := strings.ReplaceAll(string(out), "\r\n", "\n")
	for _, line := range strings.Split(norm, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			if len(trimmed) > 120 {
				return trimmed[:120]
			}
			return trimmed
		}
	}
	return ""
}
