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

func TestRemoteHybridApprovalAsyncContinuationAndIdempotency(t *testing.T) {
	broker := NewBroker(0, 30, nil)
	broker.ConfigureRemote(1, 60, 60) // 1 秒短窗口方便快速验证超时续接

	execCalls := 0
	fp := ComputeFingerprint("cli_1", "workspace.patch", "demo", map[string]any{"path": "a.go"})

	// 1. 首次远程调用：等待 1s 后无人审批 -> 不销毁审批单，返回 Pending=true
	out1, err := broker.ExecuteWithApproval(context.Background(), Request{
		ClientID:      "cli_1",
		IsRemote:      true,
		Fingerprint:   fp,
		Tool:          "workspace.patch",
		WorkspaceID:   "demo",
		RiskLevel:     policy.RiskL1,
		AllowBatchTTL: true,
		Summary:       "修改 a.go",
	}, func() (any, error) {
		execCalls++
		return map[string]any{"patched": true, "calls": execCalls}, nil
	}, nil)
	if err != nil {
		t.Fatalf("远程短等待超时不应返回硬错误，应返回 Pending 状态: %v", err)
	}
	if !out1.Pending || out1.ApprovalID == "" {
		t.Fatalf("期望返回 Pending=true 且携带 ApprovalID，实际: %+v", out1)
	}
	if len(broker.Pending()) != 1 {
		t.Fatalf("超时后审批单必须继续留在本地控制台等待用户操作，实际 pending=%d", len(broker.Pending()))
	}

	// 2. 模拟云端超时后立即重发同指纹请求：不应创建第二个审批单
	ctxShort, cancelShort := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancelShort()
	outDup, _ := broker.ExecuteWithApproval(ctxShort, Request{
		ClientID:    "cli_1",
		IsRemote:    true,
		Fingerprint: fp,
		Tool:        "workspace.patch",
		WorkspaceID: "demo",
		RiskLevel:   policy.RiskL1,
	}, func() (any, error) {
		execCalls++
		return nil, nil
	}, nil)
	if !outDup.ReusedIdempotent || outDup.ApprovalID != out1.ApprovalID || len(broker.Pending()) != 1 {
		t.Fatalf("重复请求应复用同一审批单而非新建弹窗: outDup=%+v pending=%d", outDup, len(broker.Pending()))
	}

	// 3. 用户事后在本地控制台点击批准 -> 后台自动执行且仅执行一次
	if _, err := broker.Resolve(out1.ApprovalID, true, 0, "web-console", "批准"); err != nil {
		t.Fatalf("Resolve 失败: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	var rec Request
	for time.Now().Before(deadline) {
		var ok bool
		rec, ok = broker.GetRecord(out1.ApprovalID)
		if ok && rec.ExecStatus == "SUCCEEDED" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if rec.ExecStatus != "SUCCEEDED" || execCalls != 1 {
		t.Fatalf("期望后台自动执行一次成功: rec=%+v execCalls=%d", rec, execCalls)
	}

	// 4. 云端再次重发同指纹请求 -> 直接返回缓存结果，execCalls 仍为 1
	outReplay, err := broker.ExecuteWithApproval(context.Background(), Request{
		ClientID:    "cli_1",
		IsRemote:    true,
		Fingerprint: fp,
		Tool:        "workspace.patch",
		WorkspaceID: "demo",
		RiskLevel:   policy.RiskL1,
	}, func() (any, error) {
		execCalls++
		return nil, nil
	}, nil)
	if err != nil || !outReplay.ReusedIdempotent || execCalls != 1 {
		t.Fatalf("期望幂等命中缓存且不再重复执行: err=%v out=%+v execCalls=%d", err, outReplay, execCalls)
	}
}

func TestFullPermissionsAutoApproveAndRespectsPause(t *testing.T) {
	broker := NewBroker(0, 30, nil)

	// 1. 先挂起一条 L2 待审批请求
	pendingDone := make(chan Decision, 1)
	go func() {
		dec, err := broker.RequestApproval(context.Background(), Request{
			Tool:        "terminal.start",
			WorkspaceID: "demo",
			RiskLevel:   policy.RiskL2,
		})
		if err != nil {
			t.Errorf("开启全权限自动放行时不应报错: %v", err)
		}
		pendingDone <- dec
	}()
	for i := 0; i < 40 && len(broker.Pending()) == 0; i++ {
		time.Sleep(15 * time.Millisecond)
	}
	if len(broker.Pending()) != 1 {
		t.Fatalf("期望存在 1 条挂起审批单")
	}

	// 2. 开启全权限模式 -> 自动批准当前挂起队列
	autoApproved := broker.SetFullPermissions(true)
	if autoApproved != 1 {
		t.Fatalf("期望自动批准 1 条挂起审批，实际 %d", autoApproved)
	}
	dec := <-pendingDone
	if !dec.Approved || dec.DecisionTag != "AUTO_ALLOW_FULL_PERMISSIONS" {
		t.Fatalf("期望挂起审批单被全权限自动放行，实际: %+v", dec)
	}

	// 3. 远程 L3 操作也直接免审批执行，不进入等待队列
	out, err := broker.ExecuteWithApproval(context.Background(), Request{
		ClientID:    "cli_remote",
		IsRemote:    true,
		Fingerprint: ComputeFingerprint("cli_remote", "terminal.start", "demo", "cmd"),
		Tool:        "terminal.start",
		WorkspaceID: "demo",
		RiskLevel:   policy.RiskL3,
	}, func() (any, error) {
		return "executed", nil
	}, nil)
	if err != nil || out.Pending || out.Result != "executed" || out.Decision.DecisionTag != "AUTO_ALLOW_FULL_PERMISSIONS" {
		t.Fatalf("全权限模式下远程调用应直接放行执行: err=%v out=%+v", err, out)
	}

	// 4. 急停暂停仍然高于全权限模式
	broker.Pause("紧急暂停")
	if _, err := broker.RequestApproval(context.Background(), Request{Tool: "workspace.patch", RiskLevel: policy.RiskL1}); err == nil {
		t.Fatalf("急停暂停状态必须仍然拦截请求")
	}

	// 5. 已过期的历史待审批单在开启全权限时绝不能被误批执行
	broker2 := NewBroker(0, 30, nil)
	broker2.ConfigureRemote(1, 1, 60)
	executed := false
	_, _ = broker2.ExecuteWithApproval(context.Background(), Request{
		ClientID:    "cli_expire",
		IsRemote:    true,
		Fingerprint: "fp_expire",
		Tool:        "workspace.patch",
		WorkspaceID: "demo",
		RiskLevel:   policy.RiskL1,
	}, func() (any, error) {
		executed = true
		return "should-not-run", nil
	}, nil)
	time.Sleep(1100 * time.Millisecond)
	if n := broker2.SetFullPermissions(true); n != 0 {
		t.Fatalf("已过期审批单不应被 SetFullPermissions 自动批准，实际 n=%d", n)
	}
	time.Sleep(50 * time.Millisecond)
	if executed {
		t.Fatalf("已过期审批单的回调绝不能被执行")
	}
}
