//go:build !windows

package process

import (
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

type unixHandle struct {
	cmd *exec.Cmd
}

// Start 在 macOS / Linux 上启动独立进程组（Setpgid=true），便于取消时终止完整子进程树。
func Start(spec Spec) (Handle, error) {
	cmd, err := BuildCommand(spec)
	if err != nil {
		return nil, err
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("启动进程失败: %w", err)
	}
	return &unixHandle{cmd: cmd}, nil
}

func (h *unixHandle) PID() int {
	if h.cmd == nil || h.cmd.Process == nil {
		return 0
	}
	return h.cmd.Process.Pid
}

func (h *unixHandle) Wait() (int, error) {
	err := h.cmd.Wait()
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), err
	}
	return -1, err
}

func (h *unixHandle) KillTree() error {
	pid := h.PID()
	if pid <= 0 {
		return nil
	}
	// 先发送优雅 SIGTERM 到整个进程组，宽限 1.5s 后强制 SIGKILL
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	time.Sleep(1500 * time.Millisecond)
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}
