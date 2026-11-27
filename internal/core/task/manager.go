// Package task 实现异步终端任务状态机、并发队列、增量输出缓冲、超时取消与本地快照持久化。
package task

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

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
	ElapsedMs       int64  `json:"elapsed_ms"`
}

// cappedBuffer 为单任务提供线程安全、带容量上限与增量偏移读取的输出缓冲区。
type cappedBuffer struct {
	mu        sync.Mutex
	maxBytes  int
	buf       []byte
	truncated bool
}

func newCappedBuffer(maxBytes int) *cappedBuffer {
	if maxBytes <= 0 {
		maxBytes = 1024 * 1024
	}
	return &cappedBuffer{maxBytes: maxBytes}
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	rem := b.maxBytes - len(b.buf)
	if rem <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if len(p) > rem {
		b.buf = append(b.buf, p[:rem]...)
		b.truncated = true
	} else {
		b.buf = append(b.buf, p...)
	}
	return len(p), nil
}

func (b *cappedBuffer) ReadFrom(offset int) (chunk string, nextOffset int, truncated bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	sanitized := audit.RedactPrivateSecrets(string(b.buf))
	if offset < 0 {
		offset = 0
	}
	if offset > len(sanitized) {
		offset = len(sanitized)
	}
	return sanitized[offset:], len(sanitized), b.truncated
}

func (b *cappedBuffer) Summary(maxChars int) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.buf) == 0 {
		return ""
	}
	s := audit.RedactPrivateSecrets(string(b.buf))
	if len(s) > maxChars {
		return s[len(s)-maxChars:]
	}
	return s
}

type managedTask struct {
	mu            sync.Mutex
	record        store.TaskRecord
	stdout        *cappedBuffer
	stderr        *cappedBuffer
	handle        process.Handle
	cancelSignal  chan struct{}
	cancelOnce    sync.Once
	cancelReason  string
	timedOut      bool
	timeout       time.Duration
	spec          process.Spec
}

// Manager 负责管理所有异步终端任务的生命周期、并发配额、急停清理与持久化快照。
type Manager struct {
	mu             sync.RWMutex
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
				stdout: newCappedBuffer(opts.MaxOutputBytes),
				stderr: newCappedBuffer(opts.MaxOutputBytes),
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
	stdoutBuf := newCappedBuffer(m.maxOutputBytes)
	stderrBuf := newCappedBuffer(m.maxOutputBytes)

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
		stdout:       stdoutBuf,
		stderr:       stderrBuf,
		cancelSignal: make(chan struct{}),
		timeout:      timeout,
		spec: process.Spec{
			Executable: req.Executable,
			Args:       append([]string(nil), req.Args...),
			Cwd:        req.Cwd,
			EnvAllow:   append([]string(nil), req.EnvAllow...),
			UseShell:   req.UseShell,
			Stdout:     stdoutBuf,
			Stderr:     stderrBuf,
		},
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
	mt.mu.Lock()
	mt.record.Status = string(st)
	mt.record.ExitCode = exitCode
	mt.record.ErrorMessage = errMsg
	mt.record.FinishedAt = time.Now().UTC()
	_, _, stdoutTrunc := mt.stdout.ReadFrom(0)
	_, _, stderrTrunc := mt.stderr.ReadFrom(0)
	mt.record.StdoutTruncated = stdoutTrunc
	mt.record.StderrTruncated = stderrTrunc
	summary := mt.stdout.Summary(512)
	if summary == "" {
		summary = mt.stderr.Summary(512)
	}
	mt.record.OutputSummary = summary
	snap := mt.record
	mt.mu.Unlock()

	_ = m.persist()
	m.notify(snap)
}

func (mt *managedTask) getCancelReason(fallback string) string {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	if mt.cancelReason != "" {
		return mt.cancelReason
	}
	return fallback
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
		ElapsedMs:       elapsed,
	}, nil
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
	deadline := time.Now().Add(maxWait)
	for {
		res, err := m.Poll(taskID, 0, 0)
		if err != nil {
			return nil, err
		}
		if res.Status.IsTerminal() {
			return res, nil
		}
		if time.Now().After(deadline) {
			return res, errors.New("等待任务完成超时")
		}
		time.Sleep(30 * time.Millisecond)
	}
}
