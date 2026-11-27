// Package approval 实现人工审批队列、本地无限等待、远程混合短等待异步续接、
// 请求指纹幂等去重、工作区限时批量授权与一键急停（Kill Switch）。
package approval

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

// Request 描述展示给人工审阅及异步状态查询的完整审批单信息。
type Request struct {
	ID             string           `json:"id"`
	SessionID      string           `json:"session_id,omitempty"`
	ClientID       string           `json:"client_id,omitempty"`
	IsRemote       bool             `json:"is_remote,omitempty"`
	Fingerprint    string           `json:"fingerprint,omitempty"`
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
	ExecStatus     string           `json:"exec_status,omitempty"` // PENDING | RUNNING | SUCCEEDED | FAILED
	ExecResult     any              `json:"exec_result,omitempty"`
	ExecError      string           `json:"exec_error,omitempty"`
	CreatedAt      time.Time        `json:"created_at"`
	ExpiresAt      time.Time        `json:"expires_at,omitempty"`
	ResolvedAt     time.Time        `json:"resolved_at,omitempty"`
}

// Decision 表示审批完成后返回给工具调用方的结论。
type Decision struct {
	Approved    bool   `json:"approved"`
	ViaGrant    bool   `json:"via_grant"`
	Approver    string `json:"approver"`
	Note        string `json:"note,omitempty"`
	ApprovalID  string `json:"approval_id,omitempty"`
	DecisionTag string `json:"decision_tag"` // APPROVED_ONCE / APPROVED_BY_GRANT / REJECTED / CANCELLED / PAUSED / APPROVAL_PENDING / IDEMPOTENT_REPLAY
}

// ExecutionOutcome 表示经过审批并执行（或挂起等待异步续接）后的统一结果。
type ExecutionOutcome struct {
	Pending          bool     `json:"pending"`
	ReusedIdempotent bool     `json:"reused_idempotent"`
	ApprovalID       string   `json:"approval_id,omitempty"`
	Decision         Decision `json:"decision"`
	Result           any      `json:"result,omitempty"`
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
	req               Request
	decision          Decision
	decisionDone      chan struct{}
	decisionCloseOnce sync.Once
	execFn            func() (any, error)
	execOnce          sync.Once
	execDone          chan struct{}
	execCloseOnce     sync.Once
}

func (p *pendingItem) closeDecision() {
	p.decisionCloseOnce.Do(func() {
		close(p.decisionDone)
	})
}

func (p *pendingItem) closeExec() {
	p.execCloseOnce.Do(func() {
		close(p.execDone)
	})
}

type idempotencyEntry struct {
	approvalID string
	expiresAt  time.Time
}

// Broker 协调 MCP 工具调用与人工审批界面/CLI 之间的实时同步与异步续接。
type Broker struct {
	mu              sync.Mutex
	timeout         time.Duration // 0 表示本地直连无限等待
	maxGrantMinutes int
	remoteWait      time.Duration // 远程短等待窗口（超时转为异步续接）
	pendingTTL      time.Duration // 远程异步续接审批单最大存活时间
	idempotencyTTL  time.Duration // 远程请求指纹幂等去重窗口
	pending         map[string]*pendingItem
	pendingOrder    []string
	records         map[string]*pendingItem // 包含待处理与近期已处理的完整记录（供 approval.status 查询）
	fingerprints    map[string]idempotencyEntry
	history         []Request
	grants          map[string]WorkspaceGrant
	pauseState      PauseState
	killHook        func(reason string) int
	listeners       map[chan Event]struct{}
}

// NewBroker 创建审批协调器。timeoutSeconds <= 0 表示本地直连无限等待用户操作。
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
		remoteWait:      45 * time.Second,
		pendingTTL:      15 * time.Minute,
		idempotencyTTL:  5 * time.Minute,
		pending:         make(map[string]*pendingItem),
		records:         make(map[string]*pendingItem),
		fingerprints:    make(map[string]idempotencyEntry),
		grants:          make(map[string]WorkspaceGrant),
		killHook:        killHook,
		listeners:       make(map[chan Event]struct{}),
	}
}

// ConfigureRemote 配置远程混合审批短等待窗口、异步续接存活时间与指纹幂等窗口。
func (b *Broker) ConfigureRemote(remoteWaitSec, pendingTTLSec, idempotencyTTLSec int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if remoteWaitSec > 0 {
		b.remoteWait = time.Duration(remoteWaitSec) * time.Second
	}
	if pendingTTLSec > 0 {
		b.pendingTTL = time.Duration(pendingTTLSec) * time.Second
	}
	if idempotencyTTLSec > 0 {
		b.idempotencyTTL = time.Duration(idempotencyTTLSec) * time.Second
	}
}

// ComputeFingerprint 为工具调用计算确定性幂等指纹，避免云端网络重试导致重复弹窗或重复执行。
func ComputeFingerprint(clientID, tool, workspaceID string, args any) string {
	raw, _ := json.Marshal(args)
	sum := sha256.Sum256([]byte(clientID + "|" + tool + "|" + workspaceID + "|" + string(raw)))
	return hex.EncodeToString(sum[:16])
}

// RequestApproval 发起人工审批并等待结果（阶段一兼容接口，默认本地无限等待）。
func (b *Broker) RequestApproval(ctx context.Context, req Request) (Decision, error) {
	b.mu.Lock()
	b.expireStaleLocked(time.Now().UTC())

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
		req:          req,
		decisionDone: make(chan struct{}),
		execDone:     make(chan struct{}),
	}
	item.closeExec()
	b.pending[req.ID] = item
	b.records[req.ID] = item
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
	case <-item.decisionDone:
		b.mu.Lock()
		dec := item.decision
		b.mu.Unlock()
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

// ExecuteWithApproval 统一编排本地无限等待与远程“混合短等待 + 异步续接 + 幂等去重”执行模型。
func (b *Broker) ExecuteWithApproval(
	ctx context.Context,
	req Request,
	execFn func() (any, error),
	progressFn func(elapsed time.Duration),
) (ExecutionOutcome, error) {
	// 本地调用完全沿用阶段一无限等待模型
	if !req.IsRemote {
		dec, err := b.RequestApproval(ctx, req)
		if err != nil {
			return ExecutionOutcome{ApprovalID: dec.ApprovalID, Decision: dec}, err
		}
		res, execErr := execFn()
		return ExecutionOutcome{
			ApprovalID: dec.ApprovalID,
			Decision:   dec,
			Result:     res,
		}, execErr
	}

	now := time.Now().UTC()
	b.mu.Lock()
	b.expireStaleLocked(now)

	// 1. 急停暂停检查
	if b.pauseState.Paused {
		reason := b.pauseState.Reason
		if reason == "" {
			reason = "系统已处于急停暂停状态"
		}
		b.mu.Unlock()
		dec := Decision{Approved: false, DecisionTag: "PAUSED", Note: reason}
		return ExecutionOutcome{Decision: dec}, fmt.Errorf("操作被拦截：%s", reason)
	}

	// 2. 指纹幂等去重：防云端超时重发造成重复弹窗或重复执行
	if req.Fingerprint != "" {
		if entry, ok := b.fingerprints[req.Fingerprint]; ok && now.Before(entry.expiresAt) {
			if existing, exists := b.records[entry.approvalID]; exists {
				switch existing.req.Status {
				case StatusPending:
					// 审批单仍在等待中：复用同一审批单继续短等待，不创建新弹窗
					waitDur := b.remoteWait
					b.mu.Unlock()
					return b.waitRemoteItem(ctx, existing, waitDur, true, progressFn)
				case StatusApproved:
					// 已批准：若执行结束直接返缓存；若正在执行则等待完成
					execStatus := existing.req.ExecStatus
					execRes := existing.req.ExecResult
					execErrStr := existing.req.ExecError
					dec := existing.decision
					dec.DecisionTag = "IDEMPOTENT_REPLAY"
					if execStatus == "SUCCEEDED" {
						b.mu.Unlock()
						return ExecutionOutcome{
							ReusedIdempotent: true,
							ApprovalID:       existing.req.ID,
							Decision:         dec,
							Result:           execRes,
						}, nil
					}
					if execStatus == "FAILED" {
						b.mu.Unlock()
						return ExecutionOutcome{
							ReusedIdempotent: true,
							ApprovalID:       existing.req.ID,
							Decision:         dec,
						}, errors.New(execErrStr)
					}
					waitDur := b.remoteWait
					b.mu.Unlock()
					return b.waitRemoteItem(ctx, existing, waitDur, true, progressFn)
				}
			}
		}
	}

	// 3. 检查 L1 工作区限时批量授权（命中后同样写入幂等缓存防重复写入）
	if req.AllowBatchTTL && req.RiskLevel == policy.RiskL1 && req.WorkspaceID != "" {
		if g, ok := b.grants[req.WorkspaceID]; ok {
			if now.Before(g.ExpiresAt) {
				req.ID = newApprovalID()
				req.Status = StatusApproved
				req.Approver = g.GrantedBy
				req.CreatedAt = now
				req.ResolvedAt = now
				req.ExecStatus = "RUNNING"
				dec := Decision{
					Approved:    true,
					ViaGrant:    true,
					Approver:    g.GrantedBy,
					ApprovalID:  req.ID,
					DecisionTag: "APPROVED_BY_GRANT",
					Note:        fmt.Sprintf("命中工作区 %s 限时批量授权", req.WorkspaceID),
				}
				item := &pendingItem{
					req:          req,
					decision:     dec,
					decisionDone: make(chan struct{}),
					execFn:       execFn,
					execDone:     make(chan struct{}),
				}
				item.closeDecision()
				b.records[req.ID] = item
				if req.Fingerprint != "" {
					b.fingerprints[req.Fingerprint] = idempotencyEntry{
						approvalID: req.ID,
						expiresAt:  now.Add(b.idempotencyTTL),
					}
				}
				b.mu.Unlock()

				b.runExecOnce(item)
				b.mu.Lock()
				res := item.req.ExecResult
				errStr := item.req.ExecError
				b.mu.Unlock()
				if errStr != "" {
					return ExecutionOutcome{ApprovalID: req.ID, Decision: dec}, errors.New(errStr)
				}
				return ExecutionOutcome{ApprovalID: req.ID, Decision: dec, Result: res}, nil
			}
			delete(b.grants, req.WorkspaceID)
		}
	}

	// 4. 创建新的远程待审批单（挂载后台执行闭包，即使本次短窗口超时也不会被销毁）
	req.ID = newApprovalID()
	req.Status = StatusPending
	req.ExecStatus = "PENDING"
	req.CreatedAt = now
	req.ExpiresAt = now.Add(b.pendingTTL)

	item := &pendingItem{
		req:          req,
		decisionDone: make(chan struct{}),
		execFn:       execFn,
		execDone:     make(chan struct{}),
	}
	b.pending[req.ID] = item
	b.records[req.ID] = item
	b.pendingOrder = append(b.pendingOrder, req.ID)
	if req.Fingerprint != "" {
		b.fingerprints[req.Fingerprint] = idempotencyEntry{
			approvalID: req.ID,
			expiresAt:  now.Add(b.idempotencyTTL),
		}
	}
	b.broadcastLocked(Event{Type: "approval_created", Payload: req})
	waitDur := b.remoteWait
	b.mu.Unlock()

	return b.waitRemoteItem(ctx, item, waitDur, false, progressFn)
}

func (b *Broker) waitRemoteItem(
	ctx context.Context,
	item *pendingItem,
	waitDur time.Duration,
	reused bool,
	progressFn func(elapsed time.Duration),
) (ExecutionOutcome, error) {
	if waitDur <= 0 {
		waitDur = 45 * time.Second
	}
	start := time.Now()
	timer := time.NewTimer(waitDur)
	defer timer.Stop()

	var ticker *time.Ticker
	var tickC <-chan time.Time
	if progressFn != nil {
		ticker = time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		tickC = ticker.C
	}

	// 阶段 A：等待人工审批结论（或短窗口到期）
	for {
		select {
		case <-item.decisionDone:
			b.mu.Lock()
			dec := item.decision
			approved := dec.Approved
			id := item.req.ID
			b.mu.Unlock()
			if !approved {
				return ExecutionOutcome{
					ReusedIdempotent: reused,
					ApprovalID:       id,
					Decision:         dec,
				}, fmt.Errorf("用户拒绝操作 (%s): %s", id, dec.Note)
			}
			// 审批通过：等待后台闭包执行完成（若短窗口已逼近，最多再宽限等待结果）
			goto waitExec
		case <-tickC:
			progressFn(time.Since(start))
		case <-timer.C:
			// 短窗口超时：保留审批单继续等待用户在本地控制台点击确认，不销毁！
			b.mu.Lock()
			id := item.req.ID
			b.mu.Unlock()
			return ExecutionOutcome{
				Pending:          true,
				ReusedIdempotent: reused,
				ApprovalID:       id,
				Decision: Decision{
					Approved:    false,
					ApprovalID:  id,
					DecisionTag: "APPROVAL_PENDING",
					Note:        "等待用户在本地 NodeBridge 控制台确认",
				},
			}, nil
		case <-ctx.Done():
			// 云端 HTTP 连接提前断开：同样不销毁远程审批单，允许用户稍后批准并用 approval.status 续接！
			b.mu.Lock()
			id := item.req.ID
			b.mu.Unlock()
			return ExecutionOutcome{
				Pending:          true,
				ReusedIdempotent: reused,
				ApprovalID:       id,
				Decision: Decision{
					Approved:    false,
					ApprovalID:  id,
					DecisionTag: "APPROVAL_PENDING",
					Note:        "远程连接中断，审批单已保留在本地控制台等待确认",
				},
			}, ctx.Err()
		}
	}

waitExec:
	select {
	case <-item.execDone:
		b.mu.Lock()
		res := item.req.ExecResult
		errStr := item.req.ExecError
		dec := item.decision
		id := item.req.ID
		b.mu.Unlock()
		if reused {
			dec.DecisionTag = "IDEMPOTENT_REPLAY"
		}
		if errStr != "" {
			return ExecutionOutcome{
				ReusedIdempotent: reused,
				ApprovalID:       id,
				Decision:         dec,
			}, errors.New(errStr)
		}
		return ExecutionOutcome{
			ReusedIdempotent: reused,
			ApprovalID:       id,
			Decision:         dec,
			Result:           res,
		}, nil
	case <-ctx.Done():
		b.mu.Lock()
		id := item.req.ID
		dec := item.decision
		b.mu.Unlock()
		return ExecutionOutcome{
			Pending:    true,
			ApprovalID: id,
			Decision:   dec,
		}, ctx.Err()
	}
}

func (b *Broker) runExecOnce(item *pendingItem) {
	item.execOnce.Do(func() {
		defer item.closeExec()
		if item.execFn == nil {
			return
		}
		b.mu.Lock()
		item.req.ExecStatus = "RUNNING"
		b.mu.Unlock()

		res, err := item.execFn()

		b.mu.Lock()
		if err != nil {
			item.req.ExecStatus = "FAILED"
			item.req.ExecError = err.Error()
		} else {
			item.req.ExecStatus = "SUCCEEDED"
			item.req.ExecResult = res
		}
		snapshot := item.req
		b.broadcastLocked(Event{Type: "approval_resolved", Payload: snapshot})
		b.mu.Unlock()
	})
}

// GetRecord 返回指定审批单的实时状态与异步执行结果（供只读工具 approval.status 使用）。
func (b *Broker) GetRecord(id string) (Request, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.expireStaleLocked(time.Now().UTC())
	item, ok := b.records[strings.TrimSpace(id)]
	if !ok {
		return Request{}, false
	}
	return item.req, true
}

// LookupIdempotent 只读查询指定请求指纹是否已命中近期成功执行的幂等缓存（绝不创建新审批单）。
func (b *Broker) LookupIdempotent(fingerprint string) (ExecutionOutcome, bool) {
	fingerprint = strings.TrimSpace(fingerprint)
	if fingerprint == "" {
		return ExecutionOutcome{}, false
	}
	now := time.Now().UTC()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.expireStaleLocked(now)

	entry, ok := b.fingerprints[fingerprint]
	if !ok || !now.Before(entry.expiresAt) {
		return ExecutionOutcome{}, false
	}
	existing, exists := b.records[entry.approvalID]
	if !exists || existing.req.Status != StatusApproved || existing.req.ExecStatus != "SUCCEEDED" {
		return ExecutionOutcome{}, false
	}
	dec := existing.decision
	dec.DecisionTag = "IDEMPOTENT_REPLAY"
	return ExecutionOutcome{
		ReusedIdempotent: true,
		ApprovalID:       existing.req.ID,
		Decision:         dec,
		Result:           existing.req.ExecResult,
	}, true
}

// Resolve 由 Web 控制台或 CLI 调用，完成指定审批单的批准或拒绝。
func (b *Broker) Resolve(id string, approve bool, grantMinutes int, approver, note string) (Request, error) {
	if strings.TrimSpace(approver) == "" {
		approver = "local-owner"
	}

	b.mu.Lock()
	b.expireStaleLocked(time.Now().UTC())
	item, ok := b.pending[id]
	if !ok {
		b.mu.Unlock()
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

	shouldAsyncExec := false
	if approve {
		item.req.Status = StatusApproved
		dec.DecisionTag = "APPROVED_ONCE"
		if item.execFn != nil {
			item.req.ExecStatus = "RUNNING"
			shouldAsyncExec = true
		}
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
		item.req.ExecStatus = "FAILED"
		dec.DecisionTag = "REJECTED"
		if dec.Note == "" {
			dec.Note = "用户手动拒绝"
		}
		item.req.ExecError = dec.Note
		if item.req.Fingerprint != "" {
			delete(b.fingerprints, item.req.Fingerprint)
		}
		item.closeExec()
	}

	item.decision = dec
	b.appendHistoryLocked(item.req)
	b.broadcastLocked(Event{Type: "approval_resolved", Payload: item.req})
	item.closeDecision()
	snapshot := item.req
	b.mu.Unlock()

	// 若为远程异步续接模式，批准后立刻在后台触发唯一一次执行，无论原 HTTP 连接是否已超时返回！
	if shouldAsyncExec {
		go b.runExecOnce(item)
	}

	return snapshot, nil
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
	b.expireStaleLocked(time.Now().UTC())
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

func (b *Broker) expireStaleLocked(now time.Time) {
	for fp, entry := range b.fingerprints {
		if now.After(entry.expiresAt) {
			delete(b.fingerprints, fp)
		}
	}
	for _, id := range append([]string(nil), b.pendingOrder...) {
		item, ok := b.pending[id]
		if !ok {
			continue
		}
		if !item.req.ExpiresAt.IsZero() && now.After(item.req.ExpiresAt) {
			delete(b.pending, id)
			b.removeOrderLocked(id)
			item.req.Status = StatusTimedOut
			item.req.ExecStatus = "FAILED"
			item.req.DecisionNote = "审批单已超过最大保留时间自动过期"
			item.req.ExecError = item.req.DecisionNote
			item.req.ResolvedAt = now
			item.decision = Decision{
				Approved:    false,
				ApprovalID:  id,
				DecisionTag: "TIMED_OUT",
				Note:        item.req.DecisionNote,
			}
			if item.req.Fingerprint != "" {
				delete(b.fingerprints, item.req.Fingerprint)
			}
			b.appendHistoryLocked(item.req)
			b.broadcastLocked(Event{Type: "approval_resolved", Payload: item.req})
			item.closeDecision()
			item.closeExec()
		}
	}
	// 控制内存记录数量，避免长时间运行内存无限增长
	if len(b.records) > 500 {
		for id, item := range b.records {
			if item.req.Status != StatusPending && now.Sub(item.req.ResolvedAt) > time.Hour {
				delete(b.records, id)
			}
		}
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
	item.decision = Decision{
		Approved:    false,
		ApprovalID:  id,
		DecisionTag: string(st),
		Note:        note,
	}
	if item.req.Fingerprint != "" {
		delete(b.fingerprints, item.req.Fingerprint)
	}
	b.appendHistoryLocked(item.req)
	b.broadcastLocked(Event{Type: "approval_resolved", Payload: item.req})
	item.closeDecision()
	item.closeExec()
}

func (b *Broker) rejectAllPendingLocked(reason string) {
	now := time.Now().UTC()
	for _, id := range b.pendingOrder {
		if item, ok := b.pending[id]; ok {
			item.req.Status = StatusCancelled
			item.req.ExecStatus = "FAILED"
			item.req.DecisionNote = reason
			item.req.ExecError = reason
			item.req.ResolvedAt = now
			item.decision = Decision{
				Approved:    false,
				ApprovalID:  id,
				DecisionTag: "PAUSED",
				Note:        reason,
			}
			if item.req.Fingerprint != "" {
				delete(b.fingerprints, item.req.Fingerprint)
			}
			b.appendHistoryLocked(item.req)
			b.broadcastLocked(Event{Type: "approval_resolved", Payload: item.req})
			item.closeDecision()
			item.closeExec()
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
