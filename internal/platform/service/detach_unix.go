//go:build !windows

package service

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
)

// LaunchDetachedCommand 启动一个脱离当前会话与 systemd cgroup 的后台辅助子进程，
// 用于在 Web 控制台触发“重启服务”或“卸载并停止守护”时，避免 systemd KillMode=mixed 或父进程退出连带腰斩控制命令。
func LaunchDetachedCommand(exePath string, args ...string) error {
	// Linux systemd 托管环境下，Setsid 无法移出当前 cgroup，优先借助 systemd-run 创建独立 transient unit 执行
	if runtime.GOOS == "linux" && os.Getenv("INVOCATION_ID") != "" {
		if sdRun, err := exec.LookPath("systemd-run"); err == nil {
			sdArgs := []string{}
			if os.Geteuid() != 0 {
				sdArgs = append(sdArgs, "--user")
			}
			sdArgs = append(sdArgs, "--no-block", "--quiet", "--collect", "--", exePath)
			sdArgs = append(sdArgs, args...)
			cmd := exec.Command(sdRun, sdArgs...)
			if err := cmd.Run(); err == nil {
				return nil
			}
		}
	}

	cmd := exec.Command(exePath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动独立服务控制进程失败: %w", err)
	}
	_ = cmd.Process.Release()
	return nil
}
