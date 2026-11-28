// Package task 实现异步终端任务状态机、并发队列、增量输出缓冲、超时取消与本地快照持久化。
package task

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"nodebridge/internal/core/audit"
	"nodebridge/internal/core/store"
	"nodebridge/internal/platform/process"
)

// Status 定义任务状态机枚举。
type Status string

const (
	StatusCreated   Status = "CREATED"
	StatusQueued    Status = "QUEUED"
	StatusRunning   Status = "RUNNING"
	StatusSucceeded Status = "SUCCEEDED"
	StatusFailed    Status = "FAILED"
	StatusCancelled Status = "CANCELLED"
	StatusTimedOut  Status = "TIMED_OUT"
)

// IsTerminal 判断任务是否已进入终态。
func (s Status) IsTerminal() bool {
	switch s {
	case StatusSucceeded, StatusFailed, StatusCancelled, StatusTimedOut:
		return true
	default:
		return false
	}
}

// StartRequest 描述启动异步终端任务的参数。
type StartRequest struct {
	SessionID      string
	WorkspaceID    string
	ToolName       string
	Executable     string
	Args           []string
	Cwd            string
	EnvAllow       []string
	UseShell       bool
	TimeoutSeconds int
}

// PollResult 表示 terminal.poll 返回的增量状态与输出。
type PollResult struct {
	Source          string `json:"source"`
	TaskID          string `json:"task_id"`
	WorkspaceID     string `json:"workspace_id"`
	Status          Status `json:"status"`
	ExitCode        *int   `json:"exit_code,omitempty"`
	ErrorMessage    string `json:"error_message,omitempty"`
	StdoutChunk     string `json:"stdout_chunk"`
	StderrChunk     string `json:"stderr_chunk"`
	StdoutNextOff   int    `json:"stdout_next_offset"`
	StderrNextOff   int    `json:"stderr_next_offset"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
	StdoutTail      string `json:"stdout_tail,omitempty"`
	StderrTail      string `json:"stderr_tail,omitempty"`
	ElapsedMs       int64  `json:"elapsed_ms"`
}

var (
	rePEMBegin   = regexp.MustCompile(`(?i)-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----`)
	rePEMEnd     = regexp.MustCompile(`(?i)-----END [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----`)
	rePuTTYBegin = regexp.MustCompile(`^PuTTY-User-Key-File-\d+:`)
	rePuTTYEnd   = regexp.MustCompile(`^Private-MAC:\s*[0-9a-fA-F]+`)
	reBase64Line = regexp.MustCompile(`^[A-Za-z0-9+/=_,:.\s\-]+$`)
)

const (
	maxPrivateKeyBlockLines = 256
	defaultTailBytes        = 64 * 1024 // 超长日志截断时额外保留末尾 64KB 已脱敏输出
)

// cappedBuffer 为单任务提供线程安全、带容量上限、单调递增流式私钥脱敏、增量偏移读取与截断尾部保留的输出缓冲区。
// 通过行缓冲 + 私钥块状态机，在写入端单调追加至 buf，彻底避免分片明文泄露、偏移收缩丢数据、UTF-8 截断与 O(N^2) 重复扫描；
// 当输出超过 maxBytes 发生截断后，同步维护独立的已脱敏尾部窗口 tail，确保编译/测试末尾报错始终可见。
type cappedBuffer struct {
	mu                sync.Mutex
	maxBytes          int
	tailMaxBytes      int
	buf               []byte // 已脱敏确认安全且单调只增的输出缓冲区
	tail              []byte // 触发截断后持续保留的最新尾部已脱敏输出
	tailStart         int    // 尾部环形缓冲区最旧字节的位置
	written           uint64 // 已脱敏输出的总字节数，包含截断后写入尾部的内容
	pending           []byte // 当前尚未收到换行符的行尾待定缓冲
	truncated         bool
	inPEMKeyBlock     bool
	inPuTTYKeyBlock   bool
	keyBlockLineCount int
	onChange          func()
}

func newCappedBuffer(maxBytes int, onChange func()) *cappedBuffer {
	if maxBytes <= 0 {
		maxBytes = 1024 * 1024
	}
	tailMax := defaultTailBytes
	if maxBytes < tailMax {
		tailMax = maxBytes
	}
	return &cappedBuffer{
		maxBytes:     maxBytes,
		tailMaxBytes: tailMax,
		onChange:     onChange,
	}
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	b.mu.Lock()
	before := b.written
	b.pending = append(b.pending, p...)
	for {
		idx := bytes.IndexByte(b.pending, '\n')
		if idx < 0 {
			break
		}
		line := string(b.pending[:idx+1])
		b.pending = b.pending[idx+1:]
		b.processLineLocked(line)
	}
	// 防止超长无换行输出撑爆 pending 内存（保留末尾 64 字节跨分片敏感前缀检测窗口）
	const maxPendingLine = 16 * 1024
	if len(b.pending) > maxPendingLine {
		cut := len(b.pending) - 64
		// 对齐到 UTF-8 字符边界，避免切碎多字节中文
		for cut > 0 && !utf8.RuneStart(b.pending[cut]) {
			cut--
		}
		if cut > 0 {
			chunk := string(b.pending[:cut])
			b.pending = b.pending[cut:]
			b.processLineLocked(chunk)
		}
	}
	changed := b.written != before
	cb := b.onChange
	b.mu.Unlock()
	if changed && cb != nil {
		cb()
	}
	return len(p), nil
}

// Flush 在任务结束时冲刷最后一行无换行符的残余输出（确保经过完整脱敏）。
func (b *cappedBuffer) Flush() {
	b.mu.Lock()
	if len(b.pending) == 0 {
		b.mu.Unlock()
		return
	}
	line := string(b.pending)
	b.pending = nil
	before := b.written
	b.processLineLocked(line)
	changed := b.written != before
	cb := b.onChange
	b.mu.Unlock()
	if changed && cb != nil {
		cb()
	}
}

func (b *cappedBuffer) processLineLocked(line string) {
	trimmed := strings.TrimSpace(line)

	// 1. 若正处于 PEM / OpenSSH / PGP 私钥块内部
	if b.inPEMKeyBlock {
		b.keyBlockLineCount++
		if rePEMEnd.MatchString(trimmed) {
			b.inPEMKeyBlock = false
			b.keyBlockLineCount = 0
			return
		}
		// 防止未闭合私钥头吞噬后续全部正常日志：遇到明显非 Base64/Header 正文或超过上限自动退出块状态
		if b.keyBlockLineCount > maxPrivateKeyBlockLines || (trimmed != "" && !reBase64Line.MatchString(trimmed)) {
			b.inPEMKeyBlock = false
			b.keyBlockLineCount = 0
			// 当前行已是正常日志，继续向下脱敏并输出
		} else {
			return
		}
	}

	// 2. 若正处于 PuTTY 私钥块内部
	if b.inPuTTYKeyBlock {
		b.keyBlockLineCount++
		if rePuTTYEnd.MatchString(trimmed) {
			b.inPuTTYKeyBlock = false
			b.keyBlockLineCount = 0
			return
		}
		if b.keyBlockLineCount > maxPrivateKeyBlockLines || (trimmed != "" && !reBase64Line.MatchString(trimmed)) {
			b.inPuTTYKeyBlock = false
			b.keyBlockLineCount = 0
		} else {
			return
		}
	}

	// 3. 检测新进入私钥块
	if rePEMBegin.MatchString(line) {
		if rePEMEnd.MatchString(line) {
			b.appendSanitizedLocked(audit.RedactPrivateSecrets(line))
			return
		}
		b.inPEMKeyBlock = true
		b.keyBlockLineCount = 0
		loc := rePEMBegin.FindStringIndex(line)
		prefix := ""
		if loc != nil && loc[0] > 0 {
			prefix = audit.RedactHighConfidenceTokens(line[:loc[0]])
		}
		suffix := ""
		if strings.HasSuffix(line, "\n") {
			suffix = "\n"
		}
		b.appendSanitizedLocked(prefix + "[REDACTED_PRIVATE_KEY]" + suffix)
		return
	}
	if rePuTTYBegin.MatchString(trimmed) {
		b.inPuTTYKeyBlock = true
		b.keyBlockLineCount = 0
		suffix := ""
		if strings.HasSuffix(line, "\n") {
			suffix = "\n"
		}
		b.appendSanitizedLocked("[REDACTED_PRIVATE_KEY]" + suffix)
		return
	}

	// 4. 普通行：仅做高置信度 Token 脱敏后追加
	b.appendSanitizedLocked(audit.RedactHighConfidenceTokens(line))
}

func (b *cappedBuffer) appendSanitizedLocked(s string) {
	if s == "" {
		return
	}
	b.written += uint64(len(s))
	if b.truncated {
		b.appendTailLocked(s)
		return
	}
	rem := b.maxBytes - len(b.buf)
	if len(s) > rem {
		// 按 UTF-8 字符边界截断，防止多字节字符乱码
		cut := rem
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		b.buf = append(b.buf, s[:cut]...)
		b.truncated = true
		start := max(0, len(b.buf)-b.tailMaxBytes)
		b.tail = make([]byte, len(b.buf)-start, b.tailMaxBytes)
		copy(b.tail, b.buf[start:])
		b.appendTailLocked(s[cut:])
		return
	}
	b.buf = append(b.buf, s...)
}

func (b *cappedBuffer) appendTailLocked(s string) {
	if len(s) >= b.tailMaxBytes {
		b.tail = b.tail[:b.tailMaxBytes]
		copy(b.tail, s[len(s)-b.tailMaxBytes:])
		b.tailStart = 0
		return
	}
	fill := min(len(s), b.tailMaxBytes-len(b.tail))
	b.tail = append(b.tail, s[:fill]...)
	s = s[fill:]
	if len(s) > 0 {
		n := copy(b.tail[b.tailStart:], s)
		copy(b.tail, s[n:])
		b.tailStart = (b.tailStart + len(s)) % b.tailMaxBytes
	}
}

func (b *cappedBuffer) tailLocked() string {
	var out strings.Builder
	out.Grow(len(b.tail))
	out.Write(b.tail[b.tailStart:])
	out.Write(b.tail[:b.tailStart])
	s := out.String()
	for len(s) > 0 && !utf8.RuneStart(s[0]) {
		s = s[1:]
	}
	return s
}

func (b *cappedBuffer) ReadFrom(offset int) (chunk string, nextOffset int, truncated bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if offset < 0 {
		offset = 0
	}
	if offset > len(b.buf) {
		offset = len(b.buf)
	}
	return string(b.buf[offset:]), len(b.buf), b.truncated
}

// Tail 返回截断发生后保留的末尾已脱敏输出；未发生截断时返回空字符串。
func (b *cappedBuffer) Tail() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.truncated || len(b.tail) == 0 {
		return ""
	}
	return b.tailLocked()
}

func (b *cappedBuffer) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}

func (b *cappedBuffer) Summary(maxChars int) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var s string
	if b.truncated {
		s = b.tailLocked()
	} else {
		s = string(b.buf)
	}
	if len(s) > maxChars {
		start := len(s) - maxChars
		for start < len(s) && !utf8.RuneStart(s[start]) {
			start++
		}
		return s[start:]
	}
	return s
}

type managedTask struct {
	mu           sync.Mutex
	record       store.TaskRecord
	stdout       *cappedBuffer
	stderr       *cappedBuffer
	handle       process.Handle
	cancelSignal chan struct{}
	cancelOnce   sync.Once
	cancelReason string
	timedOut     bool
	timeout      time.Duration
	spec         process.Spec
	updateCh     chan struct{}
	done         chan struct{}
}

func (mt *managedTask) broadcastUpdate() {
	mt.mu.Lock()
	if mt.updateCh != nil {
		close(mt.updateCh)
		mt.updateCh = nil
	}
	mt.mu.Unlock()
}

func (mt *managedTask) watchCh() <-chan struct{} {
	mt.mu.Lock()
	if mt.updateCh == nil {
		mt.updateCh = make(chan struct{})
	}
	ch := mt.updateCh
	mt.mu.Unlock()
	return ch
}

// Manager 负责管理所有异步终端任务的生命周期、并发配额、急停清理与持久化快照。
type Manager struct {
	mu             sync.RWMutex
	persistMu      sync.Mutex // serialize snapshot collection and publication
	tasks          map[string]*managedTask
	order          []string
	store          store.TaskStore
	sem            chan struct{}
	defaultTimeout time.Duration
	maxTimeout     time.Duration
	maxOutputBytes int
	listeners      map[chan store.TaskRecord]struct{}
}

// Options 定义任务管理器配置项。
type Options struct {
	MaxConcurrent  int
	DefaultTimeout time.Duration
	MaxTimeout     time.Duration
	MaxOutputBytes int
}

// NewManager 初始化任务管理器，并自动收敛上次异常重启前遗留的未完成任务状态。
func NewManager(taskStore store.TaskStore, opts Options) (*Manager, error) {
	if opts.MaxConcurrent <= 0 {
		opts.MaxConcurrent = 4
	}
	if opts.DefaultTimeout <= 0 {
		opts.DefaultTimeout = 300 * time.Second
	}
	if opts.MaxTimeout <= 0 {
		opts.MaxTimeout = 1800 * time.Second
	}
	if opts.MaxOutputBytes <= 0 {
		opts.MaxOutputBytes = 1024 * 1024
	}

	m := &Manager{
		tasks:          make(map[string]*managedTask),
		store:          taskStore,
		sem:            make(chan struct{}, opts.MaxConcurrent),
		defaultTimeout: opts.DefaultTimeout,
		maxTimeout:     opts.MaxTimeout,
		maxOutputBytes: opts.MaxOutputBytes,
		listeners:      make(map[chan store.TaskRecord]struct{}),
	}

	if taskStore != nil {
		loaded, err := taskStore.LoadAll()
		if err != nil {
			return nil, err
		}
		dirty := false
		now := time.Now().UTC()
		for _, rec := range loaded {
			st := Status(rec.Status)
			if !st.IsTerminal() {
				rec.Status = string(StatusFailed)
				rec.ErrorMessage = "Daemon 重启导致任务中断（状态已自动收敛）"
				rec.FinishedAt = now
				dirty = true
			}
			mt := &managedTask{
				record: rec,
				stdout: newCappedBuffer(opts.MaxOutputBytes, nil),
				stderr: newCappedBuffer(opts.MaxOutputBytes, nil),
			}
			m.tasks[rec.ID] = mt
			m.order = append(m.order, rec.ID)
		}
		if dirty {
			_ = m.persist()
		}
	}

	return m, nil
}

// Start 创建并异步调度一个终端任务，立即返回 task_id 与初始快照。
func (m *Manager) Start(req StartRequest) (store.TaskRecord, error) {
	timeout := m.defaultTimeout
	if req.TimeoutSeconds > 0 {
		timeout = time.Duration(req.TimeoutSeconds) * time.Second
		if timeout > m.maxTimeout {
			timeout = m.maxTimeout
		}
	}

	id := newTaskID()

	rec := store.TaskRecord{
		ID:          id,
		SessionID:   req.SessionID,
		WorkspaceID: req.WorkspaceID,
		ToolName:    req.ToolName,
		Executable:  req.Executable,
		Args:        append([]string(nil), req.Args...),
		Cwd:         req.Cwd,
		Status:      string(StatusQueued),
		CreatedAt:   time.Now().UTC(),
	}

	mt := &managedTask{
		record:       rec,
		cancelSignal: make(chan struct{}),
		timeout:      timeout,
		done:         make(chan struct{}),
	}
	stdoutBuf := newCappedBuffer(m.maxOutputBytes, mt.broadcastUpdate)
	stderrBuf := newCappedBuffer(m.maxOutputBytes, mt.broadcastUpdate)
	mt.stdout = stdoutBuf
	mt.stderr = stderrBuf
	mt.spec = process.Spec{
		Executable: req.Executable,
		Args:       append([]string(nil), req.Args...),
		Cwd:        req.Cwd,
		EnvAllow:   append([]string(nil), req.EnvAllow...),
		UseShell:   req.UseShell,
		Stdout:     stdoutBuf,
		Stderr:     stderrBuf,
	}

	m.mu.Lock()
	m.tasks[id] = mt
	m.order = append(m.order, id)
	m.mu.Unlock()

	_ = m.persist()
	m.notify(rec)

	go m.runTask(mt)
	return rec, nil
}

func (m *Manager) runTask(mt *managedTask) {
	// 等待并发槽位，同时支持排队期间被取消
	select {
	case m.sem <- struct{}{}:
		defer func() { <-m.sem }()
	case <-mt.cancelSignal:
		m.finishTask(mt, StatusCancelled, nil, mt.getCancelReason("任务在排队期间被取消"))
		return
	}

	// 二次检查避免刚拿到槽位就被取消
	select {
	case <-mt.cancelSignal:
		m.finishTask(mt, StatusCancelled, nil, mt.getCancelReason("任务在启动前被取消"))
		return
	default:
	}

	handle, err := process.Start(mt.spec)
	if err != nil {
		m.finishTask(mt, StatusFailed, nil, fmt.Sprintf("启动进程失败: %v", err))
		return
	}

	mt.mu.Lock()
	mt.handle = handle
	mt.record.Status = string(StatusRunning)
	mt.record.StartedAt = time.Now().UTC()
	snap := mt.record
	mt.mu.Unlock()

	_ = m.persist()
	m.notify(snap)

	doneCh := make(chan struct{})
	var exitCode int
	var waitErr error
	go func() {
		exitCode, waitErr = handle.Wait()
		close(doneCh)
	}()

	timer := time.NewTimer(mt.timeout)
	defer timer.Stop()

	select {
	case <-doneCh:
		code := exitCode
		if waitErr == nil && exitCode == 0 {
			m.finishTask(mt, StatusSucceeded, &code, "")
		} else {
			errMsg := ""
			if waitErr != nil {
				errMsg = waitErr.Error()
			}
			m.finishTask(mt, StatusFailed, &code, errMsg)
		}
	case <-timer.C:
		mt.mu.Lock()
		mt.timedOut = true
		mt.mu.Unlock()
		_ = handle.KillTree()
		<-doneCh
		code := exitCode
		m.finishTask(mt, StatusTimedOut, &code, fmt.Sprintf("任务执行超过超时限制 (%s)", mt.timeout))
	case <-mt.cancelSignal:
		_ = handle.KillTree()
		<-doneCh
		code := exitCode
		m.finishTask(mt, StatusCancelled, &code, mt.getCancelReason("任务已被用户取消"))
	}
}

func (m *Manager) finishTask(mt *managedTask, st Status, exitCode *int, errMsg string) {
	mt.stdout.Flush()
	mt.stderr.Flush()

	mt.mu.Lock()
	mt.record.Status = string(st)
	mt.record.ExitCode = exitCode
	mt.record.ErrorMessage = errMsg
	mt.record.FinishedAt = time.Now().UTC()
	mt.record.StdoutTruncated = mt.stdout.Truncated()
	mt.record.StderrTruncated = mt.stderr.Truncated()
	summary := mt.stdout.Summary(512)
	if summary == "" {
		summary = mt.stderr.Summary(512)
	}
	mt.record.OutputSummary = summary
	snap := mt.record
	mt.mu.Unlock()

	_ = m.persist()
	m.notify(snap)
	close(mt.done)
}

func (mt *managedTask) getCancelReason(fallback string) string {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	if mt.cancelReason != "" {
		return mt.cancelReason
	}
	return fallback
}

// WorkspaceID returns the task's authorization scope without reading its output.
func (m *Manager) WorkspaceID(taskID string) (string, error) {
	m.mu.RLock()
	mt, ok := m.tasks[taskID]
	m.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("任务 %q 不存在", taskID)
	}
	mt.mu.Lock()
	defer mt.mu.Unlock()
	return mt.record.WorkspaceID, nil
}

// Poll 查询任务状态及增量 stdout/stderr 输出。
func (m *Manager) Poll(taskID string, stdoutOffset, stderrOffset int) (*PollResult, error) {
	m.mu.RLock()
	mt, ok := m.tasks[taskID]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("任务 %q 不存在", taskID)
	}

	mt.mu.Lock()
	rec := mt.record
	mt.mu.Unlock()

	outChunk, outNext, outTrunc := mt.stdout.ReadFrom(stdoutOffset)
	errChunk, errNext, errTrunc := mt.stderr.ReadFrom(stderrOffset)

	var elapsed int64
	if !rec.StartedAt.IsZero() {
		end := rec.FinishedAt
		if end.IsZero() {
			end = time.Now().UTC()
		}
		elapsed = end.Sub(rec.StartedAt).Milliseconds()
	}

	return &PollResult{
		Source:          "terminal_output",
		TaskID:          rec.ID,
		WorkspaceID:     rec.WorkspaceID,
		Status:          Status(rec.Status),
		ExitCode:        rec.ExitCode,
		ErrorMessage:    rec.ErrorMessage,
		StdoutChunk:     outChunk,
		StderrChunk:     errChunk,
		StdoutNextOff:   outNext,
		StderrNextOff:   errNext,
		StdoutTruncated: outTrunc,
		StderrTruncated: errTrunc,
		StdoutTail:      mt.stdout.Tail(),
		StderrTail:      mt.stderr.Tail(),
		ElapsedMs:       elapsed,
	}, nil
}

// PollWait 带长轮询等待地查询任务增量输出：若 waitDur > 0 且当前尚无新输出且任务未结束，
// 则阻塞等待直到出现新输出、任务进入终态、超时或上下文取消。
func (m *Manager) PollWait(ctx context.Context, taskID string, stdoutOffset, stderrOffset int, waitDur time.Duration) (*PollResult, error) {
	if waitDur <= 0 {
		return m.Poll(taskID, stdoutOffset, stderrOffset)
	}
	m.mu.RLock()
	mt, ok := m.tasks[taskID]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("任务 %q 不存在", taskID)
	}

	timer := time.NewTimer(waitDur)
	defer timer.Stop()

	watch := mt.watchCh()
	res, err := m.Poll(taskID, stdoutOffset, stderrOffset)
	if err != nil || res.Status.IsTerminal() || res.StdoutChunk != "" || res.StderrChunk != "" {
		return res, err
	}
	select {
	case <-watch:
	case <-mt.done:
	case <-timer.C:
	case <-ctx.Done():
	}
	return m.Poll(taskID, stdoutOffset, stderrOffset)
}

// WaitUntilTerminal 等待指定任务进入终态，或到达 waitDur / ctx 取消时返回当前完整快照。
// 主要供 terminal.start 的短等待直出模式使用。
func (m *Manager) WaitUntilTerminal(ctx context.Context, taskID string, waitDur time.Duration) (*PollResult, error) {
	res, _, err := m.waitForCompletion(ctx, taskID, waitDur)
	return res, err
}

func (m *Manager) waitForCompletion(ctx context.Context, taskID string, waitDur time.Duration) (*PollResult, bool, error) {
	m.mu.RLock()
	mt, ok := m.tasks[taskID]
	m.mu.RUnlock()
	if !ok {
		return nil, false, fmt.Errorf("任务 %q 不存在", taskID)
	}

	// 恢复自持久化的历史任务均已进入终态，没有完成通知。
	if mt.done != nil && waitDur > 0 {
		timer := time.NewTimer(waitDur)
		defer timer.Stop()
		select {
		case <-mt.done:
		case <-timer.C:
		case <-ctx.Done():
		}
	}
	completed := mt.done == nil
	select {
	case <-mt.done:
		completed = true
	default:
	}
	res, err := m.Poll(taskID, 0, 0)
	return res, completed, err
}

// Cancel 取消指定任务（若正在运行则强杀整个进程树）。
func (m *Manager) Cancel(taskID, reason string) (store.TaskRecord, error) {
	m.mu.RLock()
	mt, ok := m.tasks[taskID]
	m.mu.RUnlock()
	if !ok {
		return store.TaskRecord{}, fmt.Errorf("任务 %q 不存在", taskID)
	}

	mt.mu.Lock()
	if Status(mt.record.Status).IsTerminal() {
		snap := mt.record
		mt.mu.Unlock()
		return snap, nil
	}
	if reason != "" {
		mt.cancelReason = reason
	}
	mt.cancelOnce.Do(func() {
		close(mt.cancelSignal)
	})
	snap := mt.record
	mt.mu.Unlock()
	return snap, nil
}

// CancelAll 立即终止全部排队与运行中的任务（用于一键急停 Kill Switch）。
func (m *Manager) CancelAll(reason string) int {
	if reason == "" {
		reason = "触发一键急停（Kill Switch），所有任务已强制终止"
	}
	m.mu.RLock()
	list := make([]*managedTask, 0, len(m.tasks))
	for _, mt := range m.tasks {
		list = append(list, mt)
	}
	m.mu.RUnlock()

	killed := 0
	for _, mt := range list {
		mt.mu.Lock()
		active := !Status(mt.record.Status).IsTerminal()
		if active {
			mt.cancelReason = reason
			mt.cancelOnce.Do(func() {
				close(mt.cancelSignal)
			})
			killed++
		}
		mt.mu.Unlock()
	}
	return killed
}

// List 按创建时间倒序返回全部任务记录。
func (m *Manager) List() []store.TaskRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]store.TaskRecord, 0, len(m.order))
	for i := len(m.order) - 1; i >= 0; i-- {
		if mt, ok := m.tasks[m.order[i]]; ok {
			mt.mu.Lock()
			out = append(out, mt.record)
			mt.mu.Unlock()
		}
	}
	return out
}

// Subscribe 订阅任务状态变更事件流（供 Web 控制台 SSE 使用）。
func (m *Manager) Subscribe() (<-chan store.TaskRecord, func()) {
	ch := make(chan store.TaskRecord, 32)
	m.mu.Lock()
	m.listeners[ch] = struct{}{}
	m.mu.Unlock()
	return ch, func() {
		m.mu.Lock()
		if _, ok := m.listeners[ch]; ok {
			delete(m.listeners, ch)
			close(ch)
		}
		m.mu.Unlock()
	}
}

func (m *Manager) notify(rec store.TaskRecord) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for ch := range m.listeners {
		select {
		case ch <- rec:
		default:
		}
	}
}

func (m *Manager) persist() error {
	if m.store == nil {
		return nil
	}
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	records := m.List()
	// 保持按正序持久化，避免重加载后顺序反转
	for i, j := 0, len(records)-1; i < j; i, j = i+1, j-1 {
		records[i], records[j] = records[j], records[i]
	}
	return m.store.SaveAll(records)
}

func newTaskID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "tsk_" + strings.ToLower(hex.EncodeToString(b))
}

// WaitForTerminal 辅助方法：等待任务到达终态或超时（主要用于测试与 CLI）。
func (m *Manager) WaitForTerminal(taskID string, maxWait time.Duration) (*PollResult, error) {
	res, completed, err := m.waitForCompletion(context.Background(), taskID, maxWait)
	if err == nil && !completed {
		return res, errors.New("等待任务完成超时")
	}
	return res, err
}
