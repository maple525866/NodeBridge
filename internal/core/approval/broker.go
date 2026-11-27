// Package approval 实现人工审批队列、无限等待 Broker、工作区限时批量授权与一键急停（Kill Switch）。
package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"nodebridge/internal/core/policy"
)

// Status 表示单个审批请求的当前状态。
type Status string

const (
	StatusPending   Status = "PENDING"
	StatusApproved  Status = "APPROVED"
	StatusRejected  Status = "REJECTED"
	StatusCancelled Status = "CANCELLED"
	StatusTimedOut  Status = "TIMED_OUT"
)

// Request 描述展示给人工审阅的完整审批单信息。
type Request struct {
	ID             string           `json:"id"`
	SessionID      string           `json:"session_id,omitempty"`
	Tool           string           `json:"tool"`
	WorkspaceID    string           `json:"workspace_id"`
	RiskLevel      policy.RiskLevel `json:"risk_level"`
	AllowBatchTTL  bool             `json:"allow_batch_ttl"`
	TargetPath     string           `json:"target_path,omitempty"`
	CommandPreview string           `json:"command_preview,omitempty"`
	DiffPreview    string           `json:"diff_preview,omitempty"`
	Summary        string           `json:"summary"`
	Reason         string           `json:"reason"`
	Status         Status           `json:"status"`
	Approver       string           `json:"approver,omitempty"`
	DecisionNote   string           `json:"decision_note,omitempty"`
	CreatedAt      time.Time        `json:"created_at"`
	ResolvedAt     time.Time        `json:"resolved_at,omitempty"`
}

// Decision 表示审批完成后返回给工具调用方的结论。
type Decision struct {
	Approved    bool   `json:"approved"`
	ViaGrant    bool   `json:"via_grant"`
	Approver    string `json:"approver"`
	Note        string `json:"note,omitempty"`
	ApprovalID  string `json:"approval_id,omitempty"`
	DecisionTag string `json:"decision_tag"` // APPROVED_ONCE / APPROVED_BY_GRANT / REJECTED / CANCELLED / PAUSED
}

// WorkspaceGrant 表示授予特定工作区的 L1 限时批量授权。
type WorkspaceGrant struct {
	WorkspaceID string    `json:"workspace_id"`
	RiskLevel   string    `json:"risk_level"`
	GrantedBy   string    `json:"granted_by"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// PauseState 描述急停与暂停状态。
type PauseState struct {
	Paused    bool      `json:"paused"`
	Reason    string    `json:"reason,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// Event 用于向本地 Web 控制台通过 SSE 推送实时审批与急停状态变化。
type Event struct {
	Type    string `json:"type"` // approval_created / approval_resolved / grants_updated / pause_changed
	Payload any    `json:"payload"`
}

type pendingItem struct {
	req      Request
	resultCh chan Decision
}

// Broker 协调 MCP 工具调用与人工审批界面/CLI 之间的实时同步。
type Broker struct {
	mu              sync.Mutex
	timeout         time.Duration // 0 表示无限等待用户批准或拒绝
	maxGrantMinutes int
	pending         map[string]*pendingItem
	pendingOrder    []string
	history         []Request
	grants          map[string]WorkspaceGrant
	pauseState      PauseState
	killHook        func(reason string) int
	listeners       map[chan Event]struct{}
}

// NewBroker 创建审批协调器。timeoutSeconds <= 0 表示无限等待用户操作。
func NewBroker(timeoutSeconds, maxGrantMinutes int, killHook func(reason string) int) *Broker {
	if maxGrantMinutes <= 0 {
		maxGrantMinutes = 60
	}
	var timeout time.Duration
	if timeoutSeconds > 0 {
		timeout = time.Duration(timeoutSeconds) * time.Second
	}
	return &Broker{
		timeout:         timeout,
		maxGrantMinutes: maxGrantMinutes,
		pending:         make(map[string]*pendingItem),
		grants:          make(map[string]WorkspaceGrant),
		killHook:        killHook,
		listeners:       make(map[chan Event]struct{}),
	}
}

// RequestApproval 发起人工审批并等待结果；默认无限等待直到用户批准/拒绝、客户端取消或触发急停。
func (b *Broker) RequestApproval(ctx context.Context, req Request) (Decision, error) {
	b.mu.Lock()
	// 1. 急停暂停拦截
	if b.pauseState.Paused {
		reason := b.pauseState.Reason
		if reason == "" {
			reason = "系统已处于急停暂停状态"
		}
		b.mu.Unlock()
		return Decision{
			Approved:    false,
			DecisionTag: "PAUSED",
			Note:        reason,
		}, fmt.Errorf("操作被拦截：%s", reason)
	}

	// 2. 仅允许 L1 操作命中有效的工作区限时批量授权
	if req.AllowBatchTTL && req.RiskLevel == policy.RiskL1 && req.WorkspaceID != "" {
		if g, ok := b.grants[req.WorkspaceID]; ok {
			if time.Now().UTC().Before(g.ExpiresAt) {
				b.mu.Unlock()
				return Decision{
					Approved:    true,
					ViaGrant:    true,
					Approver:    g.GrantedBy,
					DecisionTag: "APPROVED_BY_GRANT",
					Note:        fmt.Sprintf("命中工作区 %s 限时批量授权（有效期至 %s）", req.WorkspaceID, g.ExpiresAt.Format(time.RFC3339)),
				}, nil
			}
			delete(b.grants, req.WorkspaceID)
		}
	}

	// 3. 加入待审批队列并推送 SSE 事件
	req.ID = newApprovalID()
	req.Status = StatusPending
	req.CreatedAt = time.Now().UTC()

	item := &pendingItem{
		req:      req,
		resultCh: make(chan Decision, 1),
	}
	b.pending[req.ID] = item
	b.pendingOrder = append(b.pendingOrder, req.ID)
	b.broadcastLocked(Event{Type: "approval_created", Payload: req})
	b.mu.Unlock()

	var timerC <-chan time.Time
	var timer *time.Timer
	if b.timeout > 0 {
		timer = time.NewTimer(b.timeout)
		defer timer.Stop()
		timerC = timer.C
	}

	select {
	case dec := <-item.resultCh:
		if !dec.Approved {
			return dec, fmt.Errorf("用户拒绝操作 (%s): %s", req.ID, dec.Note)
		}
		return dec, nil
	case <-ctx.Done():
		b.cancelPending(req.ID, StatusCancelled, "调用方已取消请求或连接断开")
		return Decision{
			Approved:    false,
			ApprovalID:  req.ID,
			DecisionTag: "CANCELLED",
			Note:        "调用方取消请求",
		}, ctx.Err()
	case <-timerC:
		b.cancelPending(req.ID, StatusTimedOut, "审批等待超时")
		return Decision{
			Approved:    false,
			ApprovalID:  req.ID,
			DecisionTag: "TIMED_OUT",
			Note:        "审批等待超时",
		}, errors.New("审批等待超时")
	}
}

// Resolve 由 Web 控制台或 CLI 调用，完成指定审批单的批准或拒绝。
func (b *Broker) Resolve(id string, approve bool, grantMinutes int, approver, note string) (Request, error) {
	if strings.TrimSpace(approver) == "" {
		approver = "local-owner"
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	item, ok := b.pending[id]
	if !ok {
		return Request{}, fmt.Errorf("审批单 %q 不存在或已处理", id)
	}
	delete(b.pending, id)
	b.removeOrderLocked(id)

	now := time.Now().UTC()
	item.req.Approver = approver
	item.req.DecisionNote = note
	item.req.ResolvedAt = now

	dec := Decision{
		Approved:   approve,
		Approver:   approver,
		Note:       note,
		ApprovalID: id,
	}

	if approve {
		item.req.Status = StatusApproved
		dec.DecisionTag = "APPROVED_ONCE"
		// 仅允许 L1 操作授予工作区限时批量授权
		if grantMinutes > 0 && item.req.AllowBatchTTL && item.req.RiskLevel == policy.RiskL1 && item.req.WorkspaceID != "" {
			if grantMinutes > b.maxGrantMinutes {
				grantMinutes = b.maxGrantMinutes
			}
			b.grants[item.req.WorkspaceID] = WorkspaceGrant{
				WorkspaceID: item.req.WorkspaceID,
				RiskLevel:   string(policy.RiskL1),
				GrantedBy:   approver,
				CreatedAt:   now,
				ExpiresAt:   now.Add(time.Duration(grantMinutes) * time.Minute),
			}
			b.broadcastLocked(Event{Type: "grants_updated", Payload: b.activeGrantsLocked()})
		}
	} else {
		item.req.Status = StatusRejected
		dec.DecisionTag = "REJECTED"
		if dec.Note == "" {
			dec.Note = "用户手动拒绝"
		}
	}

	b.appendHistoryLocked(item.req)
	b.broadcastLocked(Event{Type: "approval_resolved", Payload: item.req})

	select {
	case item.resultCh <- dec:
	default:
	}
	return item.req, nil
}

// Pause 暂停接受所有新写入与执行审批请求，并自动取消当前待审批队列。
func (b *Broker) Pause(reason string) PauseState {
	if strings.TrimSpace(reason) == "" {
		reason = "用户手动暂停所有新任务"
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	b.pauseState = PauseState{
		Paused:    true,
		Reason:    reason,
		UpdatedAt: time.Now().UTC(),
	}
	b.rejectAllPendingLocked("触发暂停：" + reason)
	b.broadcastLocked(Event{Type: "pause_changed", Payload: b.pauseState})
	return b.pauseState
}

// KillAll 执行一键急停：暂停新任务、驳回待审批请求、清空所有限时授权并终止全部运行中任务。
func (b *Broker) KillAll(reason string) (PauseState, int) {
	if strings.TrimSpace(reason) == "" {
		reason = "用户触发一键急停（Kill Switch）"
	}
	b.mu.Lock()
	b.pauseState = PauseState{
		Paused:    true,
		Reason:    reason,
		UpdatedAt: time.Now().UTC(),
	}
	b.rejectAllPendingLocked(reason)
	b.grants = make(map[string]WorkspaceGrant)
	b.broadcastLocked(Event{Type: "grants_updated", Payload: []WorkspaceGrant{}})
	b.broadcastLocked(Event{Type: "pause_changed", Payload: b.pauseState})
	hook := b.killHook
	state := b.pauseState
	b.mu.Unlock()

	killed := 0
	if hook != nil {
		killed = hook(reason)
	}
	return state, killed
}

// Resume 解除急停暂停状态，恢复工具调用审批。
func (b *Broker) Resume() PauseState {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pauseState = PauseState{
		Paused:    false,
		Reason:    "",
		UpdatedAt: time.Now().UTC(),
	}
	b.broadcastLocked(Event{Type: "pause_changed", Payload: b.pauseState})
	return b.pauseState
}

// IsPaused 返回当前是否处于急停暂停状态。
func (b *Broker) IsPaused() PauseState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pauseState
}

// RevokeGrants 撤销指定工作区（或全部工作区当 workspaceID 为空时）的限时批量授权。
func (b *Broker) RevokeGrants(workspaceID string) []WorkspaceGrant {
	b.mu.Lock()
	defer b.mu.Unlock()
	if workspaceID == "" {
		b.grants = make(map[string]WorkspaceGrant)
	} else {
		delete(b.grants, workspaceID)
	}
	active := b.activeGrantsLocked()
	b.broadcastLocked(Event{Type: "grants_updated", Payload: active})
	return active
}

// Pending 返回当前等待人工确认的所有审批单。
func (b *Broker) Pending() []Request {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Request, 0, len(b.pendingOrder))
	for _, id := range b.pendingOrder {
		if item, ok := b.pending[id]; ok {
			out = append(out, item.req)
		}
	}
	return out
}

// ActiveGrants 返回尚未过期的限时工作区批量授权列表。
func (b *Broker) ActiveGrants() []WorkspaceGrant {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.activeGrantsLocked()
}

// Subscribe 订阅审批与急停实时事件。
func (b *Broker) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 32)
	b.mu.Lock()
	b.listeners[ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		if _, ok := b.listeners[ch]; ok {
			delete(b.listeners, ch)
			close(ch)
		}
		b.mu.Unlock()
	}
}

func (b *Broker) cancelPending(id string, st Status, note string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	item, ok := b.pending[id]
	if !ok {
		return
	}
	delete(b.pending, id)
	b.removeOrderLocked(id)
	item.req.Status = st
	item.req.DecisionNote = note
	item.req.ResolvedAt = time.Now().UTC()
	b.appendHistoryLocked(item.req)
	b.broadcastLocked(Event{Type: "approval_resolved", Payload: item.req})
}

func (b *Broker) rejectAllPendingLocked(reason string) {
	now := time.Now().UTC()
	for _, id := range b.pendingOrder {
		if item, ok := b.pending[id]; ok {
			item.req.Status = StatusCancelled
			item.req.DecisionNote = reason
			item.req.ResolvedAt = now
			b.appendHistoryLocked(item.req)
			b.broadcastLocked(Event{Type: "approval_resolved", Payload: item.req})
			select {
			case item.resultCh <- Decision{
				Approved:    false,
				ApprovalID:  id,
				DecisionTag: "PAUSED",
				Note:        reason,
			}:
			default:
			}
		}
	}
	b.pending = make(map[string]*pendingItem)
	b.pendingOrder = nil
}

func (b *Broker) activeGrantsLocked() []WorkspaceGrant {
	now := time.Now().UTC()
	out := make([]WorkspaceGrant, 0, len(b.grants))
	for id, g := range b.grants {
		if now.Before(g.ExpiresAt) {
			out = append(out, g)
		} else {
			delete(b.grants, id)
		}
	}
	return out
}

func (b *Broker) removeOrderLocked(id string) {
	for i, v := range b.pendingOrder {
		if v == id {
			b.pendingOrder = append(b.pendingOrder[:i], b.pendingOrder[i+1:]...)
			return
		}
	}
}

func (b *Broker) appendHistoryLocked(req Request) {
	b.history = append(b.history, req)
	if len(b.history) > 100 {
		b.history = b.history[len(b.history)-100:]
	}
}

func (b *Broker) broadcastLocked(ev Event) {
	for ch := range b.listeners {
		select {
		case ch <- ev:
		default:
		}
	}
}

func newApprovalID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "apr_" + strings.ToLower(hex.EncodeToString(b))
}
