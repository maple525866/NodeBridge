// Package relay 实现阶段二安全隧道（Cloudflare Tunnel）与外部 HTTPS 反代的远程连接抽象、生命周期管理与一键断连控制。
package relay

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"nodebridge/internal/config"
)

var tryCloudflareURLPattern = regexp.MustCompile(`https://[a-zA-Z0-9-]+\.trycloudflare\.com`)

// Status 表示远程连接通道的实时运行状态。
type Status struct {
	Enabled            bool      `json:"enabled"`
	Mode               string    `json:"mode"`
	Provider           string    `json:"provider,omitempty"`
	DeviceID           string    `json:"device_id,omitempty"`
	Connected          bool      `json:"connected"`
	DisconnectedByUser bool      `json:"disconnected_by_user,omitempty"`
	PublicURL          string    `json:"public_url,omitempty"`
	MCPEndpoint        string    `json:"mcp_endpoint,omitempty"`
	LastError          string    `json:"last_error,omitempty"`
	ReconnectCount     int       `json:"reconnect_count,omitempty"`
	UpdatedAt          time.Time `json:"updated_at,omitempty"`
}

// Connector 定义将本地 MCP 网关安全暴露给云端 AI 的统一通道控制契约。
type Connector interface {
	Start(ctx context.Context, mcpHandler http.Handler) error
	Stop(ctx context.Context) error
	Connect() error
	Disconnect(reason string) error
	Status() Status
	PublicURL() string
	AllowRemoteTraffic() bool
	Subscribe() (<-chan Status, func())
}

// NewConnector 根据配置创建对应的远程通道连接器实例。
func NewConnector(cfg config.RelayConfig, mcpListen, deviceID string) (Connector, error) {
	mode := cfg.EffectiveMode()
	switch mode {
	case config.RelayModeDisabled:
		return &DisabledConnector{deviceID: deviceID}, nil
	case config.RelayModeExternal:
		if strings.TrimSpace(cfg.PublicURL) == "" {
			return nil, errors.New("external 模式必须提供 relay.public_url")
		}
		return NewExternalConnector(cfg.PublicURL, deviceID), nil
	case config.RelayModeCloudflaredQuick, config.RelayModeCloudflaredNamed:
		return NewCloudflaredConnector(CloudflaredOptions{
			Mode:           mode,
			MCPListen:      mcpListen,
			PublicURL:      cfg.PublicURL,
			TunnelToken:    cfg.ResolvedTunnelToken(),
			CloudflaredBin: cfg.CloudflaredBin,
			DeviceID:       deviceID,
		}), nil
	default:
		return nil, fmt.Errorf("不支持的远程通道模式: %s", mode)
	}
}

// DisabledConnector 为默认空实现，确保不暴露任何外部入口。
type DisabledConnector struct {
	deviceID string
}

func (d DisabledConnector) Start(context.Context, http.Handler) error { return nil }
func (d DisabledConnector) Stop(context.Context) error                { return nil }
func (d DisabledConnector) Connect() error {
	return errors.New("远程通道处于 disabled 状态，请在配置中设置 relay.mode 后重启")
}
func (d DisabledConnector) Disconnect(string) error { return nil }
func (d DisabledConnector) PublicURL() string       { return "" }
func (d DisabledConnector) AllowRemoteTraffic() bool {
	return false
}
func (d DisabledConnector) Status() Status {
	return Status{
		Enabled:   false,
		Mode:      config.RelayModeDisabled,
		DeviceID:  d.deviceID,
		Connected: false,
	}
}
func (d DisabledConnector) Subscribe() (<-chan Status, func()) {
	ch := make(chan Status)
	return ch, func() { close(ch) }
}

// ExternalConnector 适配用户自有的 HTTPS 反向代理（如 Tailscale Funnel、Caddy、Nginx、FRP）。
type ExternalConnector struct {
	mu        sync.Mutex
	status    Status
	listeners map[chan Status]struct{}
}

// NewExternalConnector 创建外部 HTTPS 反代通道控制器。
func NewExternalConnector(publicURL, deviceID string) *ExternalConnector {
	norm := strings.TrimRight(strings.TrimSpace(publicURL), "/")
	return &ExternalConnector{
		status: Status{
			Enabled:     true,
			Mode:        config.RelayModeExternal,
			Provider:    "external",
			DeviceID:    deviceID,
			Connected:   true,
			PublicURL:   norm,
			MCPEndpoint: norm + "/mcp",
			UpdatedAt:   time.Now().UTC(),
		},
		listeners: make(map[chan Status]struct{}),
	}
}

func (e *ExternalConnector) Start(context.Context, http.Handler) error {
	e.mu.Lock()
	e.status.Connected = true
	e.status.DisconnectedByUser = false
	e.status.LastError = ""
	e.status.UpdatedAt = time.Now().UTC()
	st := e.status
	e.broadcastLocked(st)
	e.mu.Unlock()
	return nil
}

func (e *ExternalConnector) Stop(context.Context) error {
	return e.Disconnect("Daemon 正在停止")
}

func (e *ExternalConnector) Connect() error {
	e.mu.Lock()
	e.status.Connected = true
	e.status.DisconnectedByUser = false
	e.status.LastError = ""
	e.status.UpdatedAt = time.Now().UTC()
	st := e.status
	e.broadcastLocked(st)
	e.mu.Unlock()
	return nil
}

func (e *ExternalConnector) Disconnect(reason string) error {
	e.mu.Lock()
	e.status.Connected = false
	e.status.DisconnectedByUser = true
	e.status.LastError = strings.TrimSpace(reason)
	e.status.UpdatedAt = time.Now().UTC()
	st := e.status
	e.broadcastLocked(st)
	e.mu.Unlock()
	return nil
}

func (e *ExternalConnector) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.status
}

func (e *ExternalConnector) PublicURL() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.status.PublicURL
}

func (e *ExternalConnector) AllowRemoteTraffic() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.status.Enabled && e.status.Connected && !e.status.DisconnectedByUser
}

func (e *ExternalConnector) Subscribe() (<-chan Status, func()) {
	ch := make(chan Status, 16)
	e.mu.Lock()
	e.listeners[ch] = struct{}{}
	e.mu.Unlock()
	return ch, func() {
		e.mu.Lock()
		if _, ok := e.listeners[ch]; ok {
			delete(e.listeners, ch)
			close(ch)
		}
		e.mu.Unlock()
	}
}

func (e *ExternalConnector) broadcastLocked(st Status) {
	for ch := range e.listeners {
		select {
		case ch <- st:
		default:
		}
	}
}

// CloudflaredOptions 定义 Cloudflare Tunnel 子进程托管参数。
type CloudflaredOptions struct {
	Mode           string
	MCPListen      string
	PublicURL      string
	TunnelToken    string
	CloudflaredBin string
	DeviceID       string
	BaseBackoff    time.Duration
	MaxBackoff     time.Duration
	// CommandFactory 仅用于单元测试注入模拟子进程，生产环境为 nil。
	CommandFactory func(ctx context.Context, bin string, args ...string) *exec.Cmd
}

// CloudflaredConnector 编排本机 cloudflared 子进程，支持 Quick/Named 隧道、自动重连与一键断连。
type CloudflaredConnector struct {
	opts CloudflaredOptions

	mu          sync.Mutex
	status      Status
	parentCtx   context.Context
	runCancel   context.CancelFunc
	runningDone chan struct{}
	listeners   map[chan Status]struct{}
}

// NewCloudflaredConnector 创建 Cloudflare Tunnel 托管连接器。
func NewCloudflaredConnector(opts CloudflaredOptions) *CloudflaredConnector {
	if opts.BaseBackoff <= 0 {
		opts.BaseBackoff = 2 * time.Second
	}
	if opts.MaxBackoff <= 0 {
		opts.MaxBackoff = 30 * time.Second
	}
	pub := strings.TrimRight(strings.TrimSpace(opts.PublicURL), "/")
	endpoint := ""
	if pub != "" {
		endpoint = pub + "/mcp"
	}
	return &CloudflaredConnector{
		opts: opts,
		status: Status{
			Enabled:     true,
			Mode:        opts.Mode,
			Provider:    "cloudflared",
			DeviceID:    opts.DeviceID,
			Connected:   false,
			PublicURL:   pub,
			MCPEndpoint: endpoint,
			UpdatedAt:   time.Now().UTC(),
		},
		listeners: make(map[chan Status]struct{}),
	}
}

// Start 启动隧道托管循环；若本机未安装 cloudflared，仅记录状态警告而不阻断本地 Daemon 启动。
func (c *CloudflaredConnector) Start(ctx context.Context, _ http.Handler) error {
	c.mu.Lock()
	c.parentCtx = ctx
	c.mu.Unlock()
	return c.Connect()
}

// Connect 启动或重新拉起 cloudflared 隧道进程。
func (c *CloudflaredConnector) Connect() error {
	c.mu.Lock()
	if c.parentCtx == nil {
		c.parentCtx = context.Background()
	}
	// 若已在运行则直接返回
	if c.runCancel != nil {
		c.mu.Unlock()
		return nil
	}

	bin, err := c.resolveBinary()
	if err != nil {
		c.status.Connected = false
		c.status.DisconnectedByUser = false
		c.status.LastError = err.Error()
		c.status.UpdatedAt = time.Now().UTC()
		st := c.status
		c.broadcastLocked(st)
		c.mu.Unlock()
		log.Printf("[NodeBridge/Relay] %v（本地回环 MCP 仍可正常使用）", err)
		return nil
	}

	runCtx, cancel := context.WithCancel(c.parentCtx)
	done := make(chan struct{})
	c.runCancel = cancel
	c.runningDone = done
	c.status.DisconnectedByUser = false
	c.status.LastError = ""
	c.status.UpdatedAt = time.Now().UTC()
	st := c.status
	c.broadcastLocked(st)
	c.mu.Unlock()

	go c.superviseLoop(runCtx, bin, done)
	return nil
}

// Disconnect 立即断开公网隧道、终止 cloudflared 子进程并停止自动重连。
func (c *CloudflaredConnector) Disconnect(reason string) error {
	c.mu.Lock()
	cancel := c.runCancel
	done := c.runningDone
	c.runCancel = nil
	c.runningDone = nil
	c.status.Connected = false
	c.status.DisconnectedByUser = true
	if strings.TrimSpace(reason) != "" {
		c.status.LastError = strings.TrimSpace(reason)
	}
	c.status.UpdatedAt = time.Now().UTC()
	st := c.status
	c.broadcastLocked(st)
	c.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}
	return nil
}

// Stop 在 Daemon 退出时优雅关闭隧道子进程。
func (c *CloudflaredConnector) Stop(context.Context) error {
	return c.Disconnect("Daemon 正在关闭")
}

func (c *CloudflaredConnector) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

func (c *CloudflaredConnector) PublicURL() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status.PublicURL
}

func (c *CloudflaredConnector) AllowRemoteTraffic() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status.Enabled && c.status.Connected && !c.status.DisconnectedByUser
}

func (c *CloudflaredConnector) Subscribe() (<-chan Status, func()) {
	ch := make(chan Status, 16)
	c.mu.Lock()
	c.listeners[ch] = struct{}{}
	c.mu.Unlock()
	return ch, func() {
		c.mu.Lock()
		if _, ok := c.listeners[ch]; ok {
			delete(c.listeners, ch)
			close(ch)
		}
		c.mu.Unlock()
	}
}

func (c *CloudflaredConnector) resolveBinary() (string, error) {
	if c.opts.CommandFactory != nil {
		if c.opts.CloudflaredBin != "" {
			return c.opts.CloudflaredBin, nil
		}
		return "cloudflared", nil
	}
	if strings.TrimSpace(c.opts.CloudflaredBin) != "" {
		return exec.LookPath(strings.TrimSpace(c.opts.CloudflaredBin))
	}
	path, err := exec.LookPath("cloudflared")
	if err != nil {
		return "", errors.New("未在系统 PATH 中检测到 cloudflared，请安装 Cloudflare Tunnel CLI 或在配置中指定 relay.cloudflared_bin")
	}
	return path, nil
}

func (c *CloudflaredConnector) buildArgs() []string {
	if c.opts.Mode == config.RelayModeCloudflaredNamed {
		return []string{"tunnel", "--no-autoupdate", "run", "--token", c.opts.TunnelToken}
	}
	target := c.opts.MCPListen
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}
	return []string{"tunnel", "--no-autoupdate", "--url", target}
}

func (c *CloudflaredConnector) superviseLoop(ctx context.Context, bin string, done chan struct{}) {
	defer func() {
		c.mu.Lock()
		if c.runningDone == done {
			c.runCancel = nil
			c.runningDone = nil
		}
		c.mu.Unlock()
		close(done)
	}()

	backoff := c.opts.BaseBackoff
	attempt := 0

	for {
		if ctx.Err() != nil {
			return
		}
		attempt++
		err := c.runOnce(ctx, bin)
		if ctx.Err() != nil {
			return
		}

		c.mu.Lock()
		c.status.Connected = false
		c.status.ReconnectCount++
		if err != nil {
			c.status.LastError = fmt.Sprintf("隧道进程已退出（第 %d 次重连）: %v", c.status.ReconnectCount, err)
		} else {
			c.status.LastError = fmt.Sprintf("隧道进程意外退出（第 %d 次重连）", c.status.ReconnectCount)
		}
		c.status.UpdatedAt = time.Now().UTC()
		st := c.status
		c.broadcastLocked(st)
		c.mu.Unlock()

		log.Printf("[NodeBridge/Relay] %s，%s 后自动重连...", st.LastError, backoff)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff *= 2
		if backoff > c.opts.MaxBackoff {
			backoff = c.opts.MaxBackoff
		}
	}
}

func (c *CloudflaredConnector) runOnce(ctx context.Context, bin string) error {
	args := c.buildArgs()
	var cmd *exec.Cmd
	if c.opts.CommandFactory != nil {
		cmd = c.opts.CommandFactory(ctx, bin, args...)
	} else {
		cmd = exec.CommandContext(ctx, bin, args...)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	var wg sync.WaitGroup
	wg.Add(2)
	scanPipe := func(r io.Reader) {
		defer wg.Done()
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 16*1024), 256*1024)
		for sc.Scan() {
			c.inspectLogLine(sc.Text())
		}
	}
	go scanPipe(stdout)
	go scanPipe(stderr)

	// Named 模式在进程稳定运行短时间后即可标记为 Connected（若日志尚未匹配关键词）
	if c.opts.Mode == config.RelayModeCloudflaredNamed && strings.TrimSpace(c.opts.PublicURL) != "" {
		go func() {
			t := time.NewTimer(1500 * time.Millisecond)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				c.markConnected(strings.TrimRight(strings.TrimSpace(c.opts.PublicURL), "/"))
			}
		}()
	}

	wg.Wait()
	return cmd.Wait()
}

func (c *CloudflaredConnector) inspectLogLine(line string) {
	if c.opts.Mode == config.RelayModeCloudflaredQuick {
		if match := tryCloudflareURLPattern.FindString(line); match != "" {
			c.markConnected(strings.TrimRight(match, "/"))
			return
		}
	}
	lower := strings.ToLower(line)
	if strings.Contains(lower, "registered tunnel connection") || strings.Contains(lower, "connection registered") {
		if c.opts.Mode == config.RelayModeCloudflaredNamed && strings.TrimSpace(c.opts.PublicURL) != "" {
			c.markConnected(strings.TrimRight(strings.TrimSpace(c.opts.PublicURL), "/"))
		}
	}
}

func (c *CloudflaredConnector) markConnected(pubURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.status.DisconnectedByUser || c.runCancel == nil {
		return
	}
	changed := !c.status.Connected || c.status.PublicURL != pubURL || c.status.LastError != ""
	c.status.Connected = true
	if pubURL != "" {
		c.status.PublicURL = pubURL
		c.status.MCPEndpoint = pubURL + "/mcp"
	}
	c.status.LastError = ""
	c.status.UpdatedAt = time.Now().UTC()
	if changed {
		log.Printf("[NodeBridge/Relay] 公网隧道已就绪: %s", c.status.MCPEndpoint)
		c.broadcastLocked(c.status)
	}
}

func (c *CloudflaredConnector) broadcastLocked(st Status) {
	for ch := range c.listeners {
		select {
		case ch <- st:
		default:
		}
	}
}
