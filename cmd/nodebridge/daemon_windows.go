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
// - 若为 Windows Service 进程，则注册原生 svc.Handler，初始化期间定期上报 StartPending CheckPoint，
//   仅在监听端口就绪（onReady）后才上报 Running，并支持 Stop/Shutdown 优雅停机；
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
	var checkPoint uint32 = 1
	status <- svc.Status{State: svc.StartPending, CheckPoint: checkPoint, WaitHint: 5000}

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
	// 初始化期间每 2 秒递增 CheckPoint 告知 SCM 正在启动，绝不在就绪前假报 Running
	pendingTicker := time.NewTicker(2 * time.Second)
	defer pendingTicker.Stop()

	for {
		select {
		case <-readyCh:
			if currentState == svc.StartPending {
				currentState = svc.Running
				pendingTicker.Stop()
				status <- svc.Status{State: svc.Running, Accepts: accepted}
			}
		case <-pendingTicker.C:
			if currentState == svc.StartPending {
				checkPoint++
				status <- svc.Status{State: svc.StartPending, CheckPoint: checkPoint, WaitHint: 5000}
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
				if currentState == svc.Running {
					status <- svc.Status{State: svc.Running, Accepts: accepted}
				} else {
					status <- svc.Status{State: currentState, CheckPoint: checkPoint, WaitHint: 5000}
				}
			case svc.Stop, svc.Shutdown:
				currentState = svc.StopPending
				status <- svc.Status{State: svc.StopPending, CheckPoint: 1, WaitHint: 12000}
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
