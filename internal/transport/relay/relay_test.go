package relay

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"nodebridge/internal/config"
)

func TestExternalConnectorLifecycle(t *testing.T) {
	conn := NewExternalConnector("https://mcp.demo.example/", "dev_123")
	if err := conn.Start(context.Background(), nil); err != nil {
		t.Fatalf("Start 失败: %v", err)
	}
	if !conn.AllowRemoteTraffic() || conn.PublicURL() != "https://mcp.demo.example" {
		t.Fatalf("状态异常: %+v", conn.Status())
	}

	ch, unsub := conn.Subscribe()
	defer unsub()

	if err := conn.Disconnect("安全维护"); err != nil {
		t.Fatalf("Disconnect 失败: %v", err)
	}
	if conn.AllowRemoteTraffic() {
		t.Fatalf("断开后必须拒绝远程流量")
	}
	select {
	case st := <-ch:
		if st.Connected || !st.DisconnectedByUser {
			t.Fatalf("订阅状态异常: %+v", st)
		}
	case <-time.After(time.Second):
		t.Fatalf("未收到断连状态事件")
	}

	if err := conn.Connect(); err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}
	if !conn.AllowRemoteTraffic() {
		t.Fatalf("重连后应恢复远程流量")
	}
}

func TestCloudflaredQuickURLDiscoveryAndDisconnect(t *testing.T) {
	conn := NewCloudflaredConnector(CloudflaredOptions{
		Mode:        config.RelayModeCloudflaredQuick,
		MCPListen:   "127.0.0.1:18765",
		DeviceID:    "dev_quick",
		BaseBackoff: 50 * time.Millisecond,
		MaxBackoff:  100 * time.Millisecond,
		CommandFactory: func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestHelperCloudflaredProcess", "--", "quick")
			cmd.Env = append(os.Environ(), "GO_WANT_CLOUDFLARED_HELPER=1")
			return cmd
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, unsub := conn.Subscribe()
	defer unsub()

	if err := conn.Start(ctx, nil); err != nil {
		t.Fatalf("Start 失败: %v", err)
	}

	deadline := time.After(5 * time.Second)
	for !conn.Status().Connected {
		select {
		case <-ch:
		case <-deadline:
			t.Fatalf("等待 Quick Tunnel 解析公网 URL 超时，当前状态: %+v", conn.Status())
		}
	}

	st := conn.Status()
	if st.PublicURL != "https://unit-test-tunnel.trycloudflare.com" {
		t.Fatalf("未正确提取 Quick Tunnel URL: %+v", st)
	}
	if st.MCPEndpoint != "https://unit-test-tunnel.trycloudflare.com/mcp" {
		t.Fatalf("MCPEndpoint 异常: %s", st.MCPEndpoint)
	}
	if !conn.AllowRemoteTraffic() {
		t.Fatalf("连接就绪后应允许远程流量")
	}

	if err := conn.Disconnect("人工断开测试"); err != nil {
		t.Fatalf("Disconnect 失败: %v", err)
	}
	if conn.AllowRemoteTraffic() || !conn.Status().DisconnectedByUser {
		t.Fatalf("断开后状态应为 DisconnectedByUser=true，实际: %+v", conn.Status())
	}
}

func TestCloudflaredAutoReconnectOnCrash(t *testing.T) {
	attempts := 0
	conn := NewCloudflaredConnector(CloudflaredOptions{
		Mode:        config.RelayModeCloudflaredQuick,
		MCPListen:   "127.0.0.1:18765",
		DeviceID:    "dev_crash",
		BaseBackoff: 40 * time.Millisecond,
		MaxBackoff:  80 * time.Millisecond,
		CommandFactory: func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
			attempts++
			mode := "crash"
			if attempts >= 2 {
				mode = "quick"
			}
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestHelperCloudflaredProcess", "--", mode)
			cmd.Env = append(os.Environ(), "GO_WANT_CLOUDFLARED_HELPER=1")
			return cmd
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := conn.Start(ctx, nil); err != nil {
		t.Fatalf("Start 失败: %v", err)
	}
	defer conn.Stop(context.Background())

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st := conn.Status()
		if st.Connected && st.ReconnectCount >= 1 {
			return
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("期望崩溃后自动重连并就绪，当前状态: %+v", conn.Status())
}

// TestHelperCloudflaredProcess 供上方单元测试作为跨平台模拟子进程执行。
func TestHelperCloudflaredProcess(t *testing.T) {
	if os.Getenv("GO_WANT_CLOUDFLARED_HELPER") != "1" {
		return
	}
	mode := "quick"
	for i, arg := range os.Args {
		if arg == "--" && i+1 < len(os.Args) {
			mode = os.Args[i+1]
			break
		}
	}
	if mode == "crash" {
		fmt.Fprintln(os.Stderr, "simulated tunnel crash")
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "INF |  https://unit-test-tunnel.trycloudflare.com  |")
	time.Sleep(30 * time.Second)
	os.Exit(0)
}
