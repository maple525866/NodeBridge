//go:build !windows

package service

import (
	"fmt"
	"os/exec"
	"syscall"
)

// LaunchDetachedCommand 启动一个独立会话（Setsid）的后台辅助子进程，
// 用于在 Web 控制台触发“重启服务”或“卸载并停止守护”时，避免父进程退出连带中断服务控制动作。
func LaunchDetachedCommand(exePath string, args ...string) error {
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
