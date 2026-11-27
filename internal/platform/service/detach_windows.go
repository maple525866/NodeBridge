//go:build windows

package service

import (
	"fmt"
	"os/exec"
	"syscall"
)

const (
	winDetachedProcess        = 0x00000008
	winCreateNewProcessGroup  = 0x00000200
	winCreateBreakawayFromJob = 0x01000000
	winCreateNoWindow         = 0x08000000
)

// LaunchDetachedCommand 启动一个脱离当前进程树与 Job Object、无控制台窗口的独立辅助子进程，
// 用于在 Web 控制台触发“重启服务”或“卸载并停止守护”时，避免 Task Scheduler Job Object 或父进程退出连带杀死控制命令本身。
func LaunchDetachedCommand(exePath string, args ...string) error {
	baseFlags := uint32(winCreateNewProcessGroup | winDetachedProcess | winCreateNoWindow)
	if err := startHiddenWithFlags(exePath, args, baseFlags|winCreateBreakawayFromJob); err == nil {
		return nil
	}
	// 若当前 Job Object 策略不允许 BREAKAWAY，降级使用标准脱离标志重试
	if err := startHiddenWithFlags(exePath, args, baseFlags); err != nil {
		return fmt.Errorf("启动独立服务控制进程失败: %w", err)
	}
	return nil
}

func startHiddenWithFlags(exePath string, args []string, flags uint32) error {
	cmd := exec.Command(exePath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: flags,
		HideWindow:    true,
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = cmd.Process.Release()
	return nil
}
