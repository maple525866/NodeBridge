//go:build windows

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"
)

func isWindowsServiceProcess() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// runDaemonWithPlatformHost 在 Windows 上自动检测是否由服务控制管理器 (SCM) 启动：
// - 若为 Windows Service 进程，则注册原生 svc.Handler，汇报 Running/StopPending 并支持关机优雅退出；
// - 若为普通交互/计划任务进程，则监听标准中断信号优雅退出。
func runDaemonWithPlatformHost(serviceName string, runFn func(ctx context.Context, onReady func()) error) error {
	if isWindowsServiceProcess() {
		h := &windowsDaemonService{runFn: runFn}
		return svc.Run(serviceName, h)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runFn(ctx, nil)
}

type windowsDaemonService struct {
	runFn func(ctx context.Context, onReady func()) error
}

func (w *windowsDaemonService) Execute(_ []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	readyCh := make(chan struct{}, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- w.runFn(ctx, func() {
			select {
			case readyCh <- struct{}{}:
			default:
			}
		})
	}()

	currentState := svc.StartPending
	// 兜底定时器：即使初始化耗时较短或回调先触发，确保尽快向 SCM 汇报 Running
	readyFallback := time.NewTimer(500 * time.Millisecond)
	defer readyFallback.Stop()

	for {
		select {
		case <-readyCh:
			if currentState == svc.StartPending {
				currentState = svc.Running
				status <- svc.Status{State: svc.Running, Accepts: accepted}
			}
		case <-readyFallback.C:
			if currentState == svc.StartPending {
				currentState = svc.Running
				status <- svc.Status{State: svc.Running, Accepts: accepted}
			}
		case err := <-errCh:
			if err != nil {
				log.Printf("[NodeBridge/Service] Windows 服务异常退出: %v", err)
				// 返回非零退出码触发 SCM SetRecoveryActionsOnNonCrashFailures 自动拉起
				return true, 1
			}
			return false, 0
		case req := <-r:
			switch req.Cmd {
			case svc.Interrogate:
				status <- svc.Status{State: currentState, Accepts: accepted}
			case svc.Stop, svc.Shutdown:
				currentState = svc.StopPending
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case err := <-errCh:
					if err != nil {
						log.Printf("[NodeBridge/Service] 停止过程中返回错误: %v", err)
					}
				case <-time.After(12 * time.Second):
					log.Printf("[NodeBridge/Service] 等待优雅停止超时，强制退出")
				}
				return false, 0
			}
		}
	}
}
