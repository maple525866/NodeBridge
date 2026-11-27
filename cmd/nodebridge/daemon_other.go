//go:build !windows

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func isWindowsServiceProcess() bool {
	return false
}

// runDaemonWithPlatformHost 在 Linux / macOS 上使用标准 OS 信号（SIGINT / SIGTERM）控制守护进程生命周期。
func runDaemonWithPlatformHost(_ string, runFn func(ctx context.Context, onReady func()) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runFn(ctx, nil)
}
