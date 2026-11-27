package approval

import (
	"context"
	"testing"
	"time"

	"nodebridge/internal/core/policy"
)

func TestApprovalInfiniteWaitGrantAndKillSwitch(t *testing.T) {
	killedCount := 0
	broker := NewBroker(0, 30, func(reason string) int {
		killedCount++
		return 2
	})

	// 1. 发起 L1 审批并授予 10 分钟工作区批授
	done := make(chan Decision, 1)
	go func() {
		dec, err := broker.RequestApproval(context.Background(), Request{
			Tool:          "workspace.patch",
			WorkspaceID:   "demo",
			RiskLevel:     policy.RiskL1,
			AllowBatchTTL: true,
			Summary:       "修改 main.go",
		})
		if err != nil {
			t.Errorf("期望批准成功，实际 err=%v", err)
		}
		done <- dec
	}()

	// 等待进入待审批队列
	var pending []Request
	for i := 0; i < 40; i++ {
		pending = broker.Pending()
		if len(pending) == 1 {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if len(pending) != 1 {
		t.Fatalf("期望 1 条待审批记录，实际 %d", len(pending))
	}

	if _, err := broker.Resolve(pending[0].ID, true, 10, "tester", "ok"); err != nil {
		t.Fatalf("Resolve 失败: %v", err)
	}
	dec := <-done
	if !dec.Approved || dec.DecisionTag != "APPROVED_ONCE" {
		t.Fatalf("首次审批结论异常: %+v", dec)
	}

	// 2. 同一工作区 L1 再次调用应自动命中限时批授
	dec2, err := broker.RequestApproval(context.Background(), Request{
		Tool:          "workspace.patch",
		WorkspaceID:   "demo",
		RiskLevel:     policy.RiskL1,
		AllowBatchTTL: true,
	})
	if err != nil || !dec2.Approved || !dec2.ViaGrant {
		t.Fatalf("期望命中工作区限时授权: dec=%+v err=%v", dec2, err)
	}

	// 3. L2 操作绝不能享受 L1 批量授权，应挂起等待并在 KillAll 时立刻被中止
	errCh := make(chan error, 1)
	go func() {
		_, err := broker.RequestApproval(context.Background(), Request{
			Tool:          "terminal.start",
			WorkspaceID:   "demo",
			RiskLevel:     policy.RiskL2,
			AllowBatchTTL: false,
		})
		errCh <- err
	}()
	for i := 0; i < 40 && len(broker.Pending()) == 0; i++ {
		time.Sleep(15 * time.Millisecond)
	}
	state, killed := broker.KillAll("紧急停止")
	if !state.Paused || killed != 2 || killedCount != 1 {
		t.Fatalf("KillAll 返回异常: state=%+v killed=%d hookCalls=%d", state, killed, killedCount)
	}
	if err := <-errCh; err == nil {
		t.Fatalf("期望 KillAll 中止挂起的 L2 审批请求")
	}
	if len(broker.ActiveGrants()) != 0 {
		t.Fatalf("期望 KillAll 清空全部限时批量授权")
	}
}
