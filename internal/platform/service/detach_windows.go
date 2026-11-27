//go:build windows

package service

import (
	"fmt"
	"os/exec"
	"syscall"
)

const (
	winDetachedProcess       = 0x00000008
	winCreateNewProcessGroup = 0x00000200
	winCreateNoWindow        = 0x08000000
)

// LaunchDetachedCommand 启动一个脱离当前进程树、无控制台窗口的独立辅助子进程，
// 用于在 Web 控制台触发“重启服务”或“卸载并停止守护”时，避免父进程退出连带杀死控制命令本身。
func LaunchDetachedCommand(exePath string, args ...string) error {
	cmd := exec.Command(exePath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: winCreateNewProcessGroup | winDetachedProcess | winCreateNoWindow,
		HideWindow:    true,
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动独立服务控制进程失败: %w", err)
	}
	_ = cmd.Process.Release()
	return nil
}
