// Package capability 在 Daemon 启动时探测本机真实能力，而非硬编码假设操作系统环境。
package capability

import (
	"os/exec"
	"runtime"
	"strings"
)

// Info 描述当前宿主机探测到的平台能力。
type Info struct {
	OS              string `json:"os"`
	Arch            string `json:"arch"`
	GitAvailable    bool   `json:"git_available"`
	GitPath         string `json:"git_path,omitempty"`
	GitVersion      string `json:"git_version,omitempty"`
	DefaultShell    string `json:"default_shell,omitempty"`
	DefaultShellBin string `json:"default_shell_bin,omitempty"`
	DesktopEnabled  bool   `json:"desktop_enabled"`
}

// Detect 探测本机 Git、默认 Shell 与操作系统信息。
func Detect() Info {
	info := Info{
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		DesktopEnabled: false, // 阶段一暂不启用桌面自动化
	}

	if gitPath, err := exec.LookPath("git"); err == nil {
		info.GitAvailable = true
		info.GitPath = gitPath
		if out, err := exec.Command(gitPath, "--version").Output(); err == nil {
			info.GitVersion = strings.TrimSpace(string(out))
		}
	}

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
