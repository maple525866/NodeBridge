package task

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"nodebridge/internal/core/store"
)

func TestTaskLifecycleTimeoutCancelAndRecovery(t *testing.T) {
	dataDir := t.TempDir()
	st, err := store.NewJSONFileTaskStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}

	mgr, err := NewManager(st, Options{
		MaxConcurrent:  2,
		DefaultTimeout: 10 * time.Second,
		MaxTimeout:     30 * time.Second,
		MaxOutputBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. 正常执行短任务并验证增量读取
	var exe string
	var args []string
	if runtime.GOOS == "windows" {
		exe = "cmd"
		args = []string{"/c", "echo hello_nodebridge"}
	} else {
		exe = "/bin/sh"
		args = []string{"-c", "echo hello_nodebridge"}
	}

	rec, err := mgr.Start(StartRequest{
		WorkspaceID: "default",
		ToolName:    "terminal.start",
		Executable:  exe,
		Args:        args,
		Cwd:         dataDir,
	})
	if err != nil {
		t.Fatalf("Start 失败: %v", err)
	}

	res, err := mgr.WaitForTerminal(rec.ID, 5*time.Second)
	if err != nil {
		t.Fatalf("WaitForTerminal 失败: %v", err)
	}
	if res.Status != StatusSucceeded || !strings.Contains(res.StdoutChunk, "hello_nodebridge") {
		t.Fatalf("短任务结果异常: %+v", res)
	}

	// 2. 启动长任务并通过 Cancel 立即强杀
	var sleepCmd string
	if runtime.GOOS == "windows" {
		sleepCmd = "Start-Sleep -Seconds 30"
	} else {
		sleepCmd = "sleep 30"
	}
	longRec, err := mgr.Start(StartRequest{
		WorkspaceID: "default",
		ToolName:    "terminal.start",
		Executable:  sleepCmd,
		Cwd:         dataDir,
		UseShell:    true,
	})
	if err != nil {
		t.Fatalf("Start 长任务失败: %v", err)
	}
	time.Sleep(250 * time.Millisecond)
	if _, err := mgr.Cancel(longRec.ID, "测试手动取消"); err != nil {
		t.Fatalf("Cancel 失败: %v", err)
	}
	cancelled, err := mgr.WaitForTerminal(longRec.ID, 5*time.Second)
	if err != nil {
		t.Fatalf("等待取消终态失败: %v", err)
	}
	if cancelled.Status != StatusCancelled {
		t.Fatalf("期望状态 CANCELLED，实际 %s", cancelled.Status)
	}

	// 3. 测试超时 TIMED_OUT
	toRec, err := mgr.Start(StartRequest{
		WorkspaceID:    "default",
		ToolName:       "terminal.start",
		Executable:     sleepCmd,
		Cwd:            dataDir,
		UseShell:       true,
		TimeoutSeconds: 1,
	})
	if err != nil {
		t.Fatalf("Start 超时任务失败: %v", err)
	}
	toRes, err := mgr.WaitForTerminal(toRec.ID, 6*time.Second)
	if err != nil {
		t.Fatalf("等待超时终态失败: %v", err)
	}
	if toRes.Status != StatusTimedOut {
		t.Fatalf("期望状态 TIMED_OUT，实际 %s", toRes.Status)
	}

	// 4. 测试 Daemon 重启后遗留 RUNNING 任务自动收敛为 FAILED
	if err := st.SaveAll([]store.TaskRecord{
		{ID: "tsk_orphan", Status: string(StatusRunning), CreatedAt: time.Now().UTC()},
	}); err != nil {
		t.Fatal(err)
	}
	mgr2, err := NewManager(st, Options{})
	if err != nil {
		t.Fatal(err)
	}
	orphan, err := mgr2.Poll("tsk_orphan", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if orphan.Status != StatusFailed || !strings.Contains(orphan.ErrorMessage, "重启") {
		t.Fatalf("遗留任务未正确收敛: %+v", orphan)
	}
}
