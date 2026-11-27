// Package tools 注册全部 MCP 工具（10 个 P0 核心工具 + 阶段二 approval.status），
// 并在工具执行前统一串联客户端级权限护栏、策略引擎、混合人工审批（支持远程异步续接与幂等去重）与审计日志。
package tools

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"nodebridge/internal/core/approval"
	"nodebridge/internal/core/audit"
	"nodebridge/internal/core/policy"
	"nodebridge/internal/core/session"
	"nodebridge/internal/core/task"
	"nodebridge/internal/platform/filesystem"
	"nodebridge/internal/platform/git"
)

// Deps 汇总工具层运行所需的全部本地能力与安全治理组件。
type Deps struct {
	FS     *filesystem.Manager
	Git    *git.Adapter // 若宿主机未安装 Git 可为 nil，工具将返回清晰能力缺失提示
	Tasks  *task.Manager
	Policy *policy.Engine
	Broker *approval.Broker
	Audit  *audit.Logger
}

// --- 工具输入参数 Schema 定义 ---

type WorkspaceListInput struct {
	WorkspaceID string `json:"workspace_id" jsonschema:"授权工作区 ID，例如 default"`
	Path        string `json:"path,omitempty" jsonschema:"相对于工作区根目录的子目录路径，默认根目录"`
	MaxDepth    int    `json:"max_depth,omitempty" jsonschema:"最大遍历深度，默认 3"`
	Limit       int    `json:"limit,omitempty" jsonschema:"返回最大条目数，默认 200"`
}

type WorkspaceReadInput struct {
	WorkspaceID string `json:"workspace_id" jsonschema:"授权工作区 ID"`
	Path        string `json:"path" jsonschema:"相对于工作区根目录的文件路径"`
	StartLine   int    `json:"start_line,omitempty" jsonschema:"起始行号（从 1 开始），默认 1"`
	EndLine     int    `json:"end_line,omitempty" jsonschema:"结束行号（含），默认从起始行起读取 400 行"`
}

type WorkspaceSearchInput struct {
	WorkspaceID string `json:"workspace_id" jsonschema:"授权工作区 ID"`
	Query       string `json:"query" jsonschema:"搜索关键词或正则表达式"`
	IsRegex     bool   `json:"is_regex,omitempty" jsonschema:"是否按正则表达式匹配，默认 false"`
	Glob        string `json:"glob,omitempty" jsonschema:"限定文件通配符，例如 **/*.go"`
	MaxResults  int    `json:"max_results,omitempty" jsonschema:"最大命中行数，默认 100"`
}

type PatchEditInput struct {
	OldText    string `json:"old_text" jsonschema:"待替换的原文本块（新建文件时可为空）"`
	NewText    string `json:"new_text" jsonschema:"替换后的新文本块"`
	ReplaceAll bool   `json:"replace_all,omitempty" jsonschema:"是否替换全部匹配项，默认 false 仅允许唯一匹配"`
}

type WorkspacePatchInput struct {
	WorkspaceID     string           `json:"workspace_id" jsonschema:"授权工作区 ID"`
	Path            string           `json:"path" jsonschema:"目标文件相对路径"`
	ExpectedSHA256  string           `json:"expected_sha256,omitempty" jsonschema:"修改前通过 workspace.read 获取的 SHA256 乐观锁校验值"`
	CreateIfMissing bool             `json:"create_if_missing,omitempty" jsonschema:"目标文件不存在时是否允许新建"`
	Edits           []PatchEditInput `json:"edits" jsonschema:"按顺序执行的 Search/Replace 编辑块列表"`
}

type GitStatusInput struct {
	WorkspaceID string `json:"workspace_id" jsonschema:"授权工作区 ID"`
}

type GitDiffInput struct {
	WorkspaceID string   `json:"workspace_id" jsonschema:"授权工作区 ID"`
	Staged      bool     `json:"staged,omitempty" jsonschema:"是否查看暂存区（--cached）差异"`
	Paths       []string `json:"paths,omitempty" jsonschema:"限定查看的文件路径列表"`
	MaxBytes    int      `json:"max_bytes,omitempty" jsonschema:"最大输出字节数，默认 262144"`
}

type GitApplyPatchInput struct {
	WorkspaceID string `json:"workspace_id" jsonschema:"授权工作区 ID"`
	Patch       string `json:"patch" jsonschema:"标准 Unified Diff / Git Patch 文本内容"`
}

type TerminalStartInput struct {
	WorkspaceID    string   `json:"workspace_id" jsonschema:"授权工作区 ID"`
	Executable     string   `json:"executable" jsonschema:"可执行程序名或命令（默认按参数数组执行，不拼接 Shell）"`
	Args           []string `json:"args,omitempty" jsonschema:"命令行参数数组"`
	Cwd            string   `json:"cwd,omitempty" jsonschema:"相对于工作区根目录的工作目录，默认工作区根目录"`
	EnvAllow       []string `json:"env_allow,omitempty" jsonschema:"允许从宿主机透传的额外环境变量名列表"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty" jsonschema:"任务超时秒数"`
	UseShell       bool     `json:"use_shell,omitempty" jsonschema:"是否显式通过系统 Shell 解释执行（强制 L2 人工审批）"`
}

type TerminalStartOutput struct {
	Source      string `json:"source"`
	TaskID      string `json:"task_id,omitempty"`
	WorkspaceID string `json:"workspace_id"`
	Status      string `json:"status"`
	RiskLevel   string `json:"risk_level"`
	Cwd         string `json:"cwd,omitempty"`
	Pending     bool   `json:"pending,omitempty"`
	ApprovalID  string `json:"approval_id,omitempty"`
	Message     string `json:"message,omitempty"`
}

type TerminalPollInput struct {
	TaskID       string `json:"task_id" jsonschema:"terminal.start 返回的任务 ID"`
	StdoutOffset int    `json:"stdout_offset,omitempty" jsonschema:"增量读取 stdout 的起始字节偏移"`
	StderrOffset int    `json:"stderr_offset,omitempty" jsonschema:"增量读取 stderr 的起始字节偏移"`
}

type TerminalCancelInput struct {
	TaskID string `json:"task_id" jsonschema:"要取消的任务 ID"`
	Reason string `json:"reason,omitempty" jsonschema:"取消原因说明"`
}

type TerminalCancelOutput struct {
	Source string `json:"source"`
	TaskID string `json:"task_id"`
	Status string `json:"status"`
}

type ApprovalStatusInput struct {
	ApprovalID string `json:"approval_id" jsonschema:"挂起的审批单 ID（例如 apr_xxxxxxxxxxxx）"`
}

type ApprovalStatusOutput struct {
	Source       string `json:"source"`
	ApprovalID   string `json:"approval_id"`
	Tool         string `json:"tool"`
	WorkspaceID  string `json:"workspace_id"`
	Status       string `json:"status"`
	ExecStatus   string `json:"exec_status,omitempty"`
	DecisionNote string `json:"decision_note,omitempty"`
	Result       any    `json:"result,omitempty"`
	Error        string `json:"error,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
	Message      string `json:"message,omitempty"`
}

// RegisterAll 将全部 MCP 工具注册到指定 MCP Server。
func RegisterAll(srv *mcp.Server, deps Deps) {
	registerWorkspaceTools(srv, deps)
	registerGitTools(srv, deps)
	registerTerminalTools(srv, deps)
	registerApprovalTools(srv, deps)
}

func registerWorkspaceTools(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "workspace.list",
		Description: "列出授权工作区内的目录和源码文件（自动过滤敏感文件与忽略目录）",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in WorkspaceListInput) (*mcp.CallToolResult, *filesystem.ListResult, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("workspace.list")
		if err := authorizePrincipal(ctx, d.Audit, "workspace.list", in.WorkspaceID, string(ev.RiskLevel), false, in, start); err != nil {
			return nil, nil, err
		}
		res, err := d.FS.List(in.WorkspaceID, in.Path, in.MaxDepth, in.Limit)
		recordAudit(ctx, d.Audit, "workspace.list", in.WorkspaceID, string(ev.RiskLevel), in, "AUTO_ALLOW", "", start, err)
		return nil, res, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "workspace.read",
		Description: "读取授权工作区内的文本文件内容，同时返回整文件 sha256 供 workspace.patch 乐观锁校验",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in WorkspaceReadInput) (*mcp.CallToolResult, *filesystem.ReadResult, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("workspace.read")
		if err := authorizePrincipal(ctx, d.Audit, "workspace.read", in.WorkspaceID, string(ev.RiskLevel), false, in, start); err != nil {
			return nil, nil, err
		}
		res, err := d.FS.Read(in.WorkspaceID, in.Path, in.StartLine, in.EndLine)
		recordAudit(ctx, d.Audit, "workspace.read", in.WorkspaceID, string(ev.RiskLevel), in, "AUTO_ALLOW", "", start, err)
		return nil, res, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "workspace.search",
		Description: "在授权工作区内按文本或正则表达式搜索代码（自动跳过敏感与二进制文件）",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in WorkspaceSearchInput) (*mcp.CallToolResult, *filesystem.SearchResult, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("workspace.search")
		if err := authorizePrincipal(ctx, d.Audit, "workspace.search", in.WorkspaceID, string(ev.RiskLevel), false, in, start); err != nil {
			return nil, nil, err
		}
		res, err := d.FS.Search(in.WorkspaceID, in.Query, in.IsRegex, in.Glob, in.MaxResults)
		recordAudit(ctx, d.Audit, "workspace.search", in.WorkspaceID, string(ev.RiskLevel), in, "AUTO_ALLOW", "", start, err)
		return nil, res, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "workspace.patch",
		Description: "使用 Search/Replace 结构化编辑块安全修改或新建授权工作区文件（支持 SHA256 乐观锁、人工 Diff 审批与远程异步续接）",
	}, func(ctx context.Context, callReq *mcp.CallToolRequest, in WorkspacePatchInput) (*mcp.CallToolResult, *filesystem.PatchResult, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("workspace.patch")
		if err := authorizePrincipal(ctx, d.Audit, "workspace.patch", in.WorkspaceID, string(ev.RiskLevel), true, map[string]any{"path": in.Path}, start); err != nil {
			return nil, nil, err
		}

		edits := make([]filesystem.PatchEdit, 0, len(in.Edits))
		for _, e := range in.Edits {
			edits = append(edits, filesystem.PatchEdit{
				OldText:    e.OldText,
				NewText:    e.NewText,
				ReplaceAll: e.ReplaceAll,
			})
		}
		patchReq := filesystem.PatchRequest{
			WorkspaceID:     in.WorkspaceID,
			Path:            in.Path,
			ExpectedSHA256:  in.ExpectedSHA256,
			CreateIfMissing: in.CreateIfMissing,
			Edits:           edits,
		}

		// 先预检并生成 Unified Diff，避免无效补丁或越权路径打扰人工审批
		preview, err := d.FS.PreviewPatch(patchReq)
		if err != nil {
			// 注意：远程幂等重发可能命中已经成功应用的补丁（文件已变导致预检失败），先检查是否命中幂等缓存！
			p := session.FromContext(ctx)
			if p.IsRemote {
				fp := approval.ComputeFingerprint(p.ClientID, "workspace.patch", in.WorkspaceID, in)
				if replayOut, rErr := d.Broker.ExecuteWithApproval(ctx, approval.Request{
					ClientID:    p.ClientID,
					IsRemote:    true,
					Fingerprint: fp,
					Tool:        "workspace.patch",
					WorkspaceID: in.WorkspaceID,
				}, func() (any, error) { return nil, err }, nil); rErr == nil && replayOut.ReusedIdempotent {
					if cached, ok := replayOut.Result.(*filesystem.PatchResult); ok && cached != nil {
						recordAudit(ctx, d.Audit, "workspace.patch", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"path": in.Path}, "IDEMPOTENT_REPLAY", replayOut.Decision.Approver, start, nil)
						return nil, cached, nil
					}
				}
			}
			recordAudit(ctx, d.Audit, "workspace.patch", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"path": in.Path}, "DENIED_PRECHECK", "", start, err)
			return nil, nil, err
		}

		// 若调用方未显式传 expected_sha256，在审批等待后自动锁定预检时的旧版本，防审批期间人工编辑被覆盖
		if patchReq.ExpectedSHA256 == "" && !preview.IsNewFile {
			patchReq.ExpectedSHA256 = preview.OldSHA256
		}

		p := session.FromContext(ctx)
		fp := approval.ComputeFingerprint(p.ClientID, "workspace.patch", in.WorkspaceID, in)
		outcome, err := d.Broker.ExecuteWithApproval(ctx, approval.Request{
			SessionID:     p.SessionID,
			ClientID:      p.ClientID,
			IsRemote:      p.IsRemote,
			Fingerprint:   fp,
			Tool:          "workspace.patch",
			WorkspaceID:   in.WorkspaceID,
			RiskLevel:     ev.RiskLevel,
			AllowBatchTTL: ev.AllowBatchTTL,
			TargetPath:    preview.Resolved.RelPath,
			DiffPreview:   preview.UnifiedDiff,
			Summary:       fmt.Sprintf("修改工作区 %s 中的文件 %s", in.WorkspaceID, preview.Resolved.RelPath),
			Reason:        ev.Reason,
		}, func() (any, error) {
			return d.FS.ApplyPatch(patchReq)
		}, makeProgressNotifier(ctx, callReq, "正在等待用户在本地 NodeBridge 控制台审批文件补丁..."))

		if err != nil {
			recordAudit(ctx, d.Audit, "workspace.patch", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"path": preview.Resolved.RelPath}, outcome.Decision.DecisionTag, outcome.Decision.Approver, start, err)
			return nil, nil, err
		}
		if outcome.Pending {
			recordAudit(ctx, d.Audit, "workspace.patch", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"path": preview.Resolved.RelPath, "approval_id": outcome.ApprovalID}, "APPROVAL_PENDING", "", start, nil)
			return nil, &filesystem.PatchResult{
				Source:      "local_workspace_file",
				WorkspaceID: in.WorkspaceID,
				Path:        preview.Resolved.RelPath,
				Pending:     true,
				ApprovalID:  outcome.ApprovalID,
				Message:     fmt.Sprintf("审批单 %s 正在等待用户在本地 NodeBridge 控制台确认。请提示用户批准后，调用 approval.status 查询最终执行结果。", outcome.ApprovalID),
			}, nil
		}

		res, _ := outcome.Result.(*filesystem.PatchResult)
		recordAudit(ctx, d.Audit, "workspace.patch", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"path": preview.Resolved.RelPath, "created": preview.IsNewFile}, outcome.Decision.DecisionTag, outcome.Decision.Approver, start, nil)
		return nil, res, nil
	})
}

func registerGitTools(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "git.status",
		Description: "查看授权工作区的 Git 分支及变更状态",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in GitStatusInput) (*mcp.CallToolResult, *git.StatusResult, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("git.status")
		if err := authorizePrincipal(ctx, d.Audit, "git.status", in.WorkspaceID, string(ev.RiskLevel), false, in, start); err != nil {
			return nil, nil, err
		}
		if d.Git == nil {
			err := errors.New("当前宿主机未检测到 Git 可执行程序")
			recordAudit(ctx, d.Audit, "git.status", in.WorkspaceID, string(ev.RiskLevel), in, "UNAVAILABLE", "", start, err)
			return nil, nil, err
		}
		res, err := d.Git.Status(ctx, in.WorkspaceID)
		recordAudit(ctx, d.Audit, "git.status", in.WorkspaceID, string(ev.RiskLevel), in, "AUTO_ALLOW", "", start, err)
		return nil, res, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "git.diff",
		Description: "查看授权工作区或暂存区的 Git 变更差异",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in GitDiffInput) (*mcp.CallToolResult, *git.DiffResult, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("git.diff")
		if err := authorizePrincipal(ctx, d.Audit, "git.diff", in.WorkspaceID, string(ev.RiskLevel), false, in, start); err != nil {
			return nil, nil, err
		}
		if d.Git == nil {
			err := errors.New("当前宿主机未检测到 Git 可执行程序")
			recordAudit(ctx, d.Audit, "git.diff", in.WorkspaceID, string(ev.RiskLevel), in, "UNAVAILABLE", "", start, err)
			return nil, nil, err
		}
		res, err := d.Git.Diff(ctx, in.WorkspaceID, in.Staged, in.Paths, in.MaxBytes)
		recordAudit(ctx, d.Audit, "git.diff", in.WorkspaceID, string(ev.RiskLevel), in, "AUTO_ALLOW", "", start, err)
		return nil, res, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "git.apply_patch",
		Description: "在路径安全校验与人工审批后，向授权工作区应用标准 Unified Diff Git 补丁（支持远程异步续接）",
	}, func(ctx context.Context, callReq *mcp.CallToolRequest, in GitApplyPatchInput) (*mcp.CallToolResult, *git.ApplyPatchResult, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("git.apply_patch")
		if err := authorizePrincipal(ctx, d.Audit, "git.apply_patch", in.WorkspaceID, string(ev.RiskLevel), true, map[string]any{"workspace_id": in.WorkspaceID}, start); err != nil {
			return nil, nil, err
		}
		if d.Git == nil {
			err := errors.New("当前宿主机未检测到 Git 可执行程序")
			recordAudit(ctx, d.Audit, "git.apply_patch", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"workspace_id": in.WorkspaceID}, "UNAVAILABLE", "", start, err)
			return nil, nil, err
		}

		affected, err := d.Git.ValidatePatch(ctx, in.WorkspaceID, in.Patch)
		if err != nil {
			recordAudit(ctx, d.Audit, "git.apply_patch", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"workspace_id": in.WorkspaceID}, "DENIED_PRECHECK", "", start, err)
			return nil, nil, err
		}

		p := session.FromContext(ctx)
		fp := approval.ComputeFingerprint(p.ClientID, "git.apply_patch", in.WorkspaceID, in)
		outcome, err := d.Broker.ExecuteWithApproval(ctx, approval.Request{
			SessionID:     p.SessionID,
			ClientID:      p.ClientID,
			IsRemote:      p.IsRemote,
			Fingerprint:   fp,
			Tool:          "git.apply_patch",
			WorkspaceID:   in.WorkspaceID,
			RiskLevel:     ev.RiskLevel,
			AllowBatchTTL: ev.AllowBatchTTL,
			TargetPath:    strings.Join(affected, ", "),
			DiffPreview:   in.Patch,
			Summary:       fmt.Sprintf("向工作区 %s 应用 Git 补丁（涉及 %d 个文件）", in.WorkspaceID, len(affected)),
			Reason:        ev.Reason,
		}, func() (any, error) {
			return d.Git.ApplyPatch(context.Background(), in.WorkspaceID, in.Patch)
		}, makeProgressNotifier(ctx, callReq, "正在等待用户在本地 NodeBridge 控制台审批 Git 补丁..."))

		if err != nil {
			recordAudit(ctx, d.Audit, "git.apply_patch", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"files": affected}, outcome.Decision.DecisionTag, outcome.Decision.Approver, start, err)
			return nil, nil, err
		}
		if outcome.Pending {
			recordAudit(ctx, d.Audit, "git.apply_patch", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"files": affected, "approval_id": outcome.ApprovalID}, "APPROVAL_PENDING", "", start, nil)
			return nil, &git.ApplyPatchResult{
				Source:        "git_output",
				WorkspaceID:   in.WorkspaceID,
				AffectedFiles: affected,
				Pending:       true,
				ApprovalID:    outcome.ApprovalID,
				Message:       fmt.Sprintf("审批单 %s 正在等待用户在本地控制台确认。请提示用户批准后，调用 approval.status 查询结果。", outcome.ApprovalID),
			}, nil
		}

		res, _ := outcome.Result.(*git.ApplyPatchResult)
		recordAudit(ctx, d.Audit, "git.apply_patch", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"files": affected}, outcome.Decision.DecisionTag, outcome.Decision.Approver, start, nil)
		return nil, res, nil
	})
}

func registerTerminalTools(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "terminal.start",
		Description: "在授权工作区内异步启动受分层安全策略和人工审批约束的命令行任务，立即返回 task_id（或远程等待审批时的 approval_id）",
	}, func(ctx context.Context, callReq *mcp.CallToolRequest, in TerminalStartInput) (*mcp.CallToolResult, *TerminalStartOutput, error) {
		start := time.Now()
		// 1. 策略预估 + 客户端级工作区/只读权限校验
		ev := d.Policy.EvaluateCommand(in.Executable, in.Args, in.UseShell)
		requiresWrite := ev.RiskLevel != policy.RiskL0
		if err := authorizePrincipal(ctx, d.Audit, "terminal.start", in.WorkspaceID, string(ev.RiskLevel), requiresWrite, in, start); err != nil {
			return nil, nil, err
		}

		// 2. 校验工作目录严格位于授权工作区内
		resolvedCwd, err := d.FS.Resolve(in.WorkspaceID, in.Cwd, false)
		if err != nil {
			recordAudit(ctx, d.Audit, "terminal.start", in.WorkspaceID, "L3", in, "DENIED_PATH", "", start, err)
			return nil, nil, err
		}

		if ev.Action == policy.ActionDeny {
			denyErr := fmt.Errorf("命令被安全策略拒绝 [%s]: %s", ev.RiskLevel, ev.Reason)
			recordAudit(ctx, d.Audit, "terminal.start", in.WorkspaceID, string(ev.RiskLevel), in, "POLICY_DENY", "", start, denyErr)
			return nil, nil, denyErr
		}

		p := session.FromContext(ctx)
		startTaskFn := func() (any, error) {
			rec, startErr := d.Tasks.Start(task.StartRequest{
				SessionID:      p.SessionID,
				WorkspaceID:    in.WorkspaceID,
				ToolName:       "terminal.start",
				Executable:     in.Executable,
				Args:           in.Args,
				Cwd:            resolvedCwd.AbsPath,
				EnvAllow:       in.EnvAllow,
				UseShell:       in.UseShell,
				TimeoutSeconds: in.TimeoutSeconds,
			})
			if startErr != nil {
				return nil, startErr
			}
			return &TerminalStartOutput{
				Source:      "terminal_task",
				TaskID:      rec.ID,
				WorkspaceID: rec.WorkspaceID,
				Status:      rec.Status,
				RiskLevel:   string(ev.RiskLevel),
				Cwd:         resolvedCwd.RelPath,
			}, nil
		}

		// 3. 急停检查与按需混合人工审批
		if ev.Action == policy.ActionRequireApproval {
			cmdPreview := formatCommandPreview(in)
			fp := approval.ComputeFingerprint(p.ClientID, "terminal.start", in.WorkspaceID, in)
			outcome, err := d.Broker.ExecuteWithApproval(ctx, approval.Request{
				SessionID:      p.SessionID,
				ClientID:       p.ClientID,
				IsRemote:       p.IsRemote,
				Fingerprint:    fp,
				Tool:           "terminal.start",
				WorkspaceID:    in.WorkspaceID,
				RiskLevel:      ev.RiskLevel,
				AllowBatchTTL:  ev.AllowBatchTTL,
				TargetPath:     resolvedCwd.RelPath,
				CommandPreview: cmdPreview,
				Summary:        fmt.Sprintf("在工作区 %s 执行命令: %s", in.WorkspaceID, in.Executable),
				Reason:         ev.Reason,
			}, startTaskFn, makeProgressNotifier(ctx, callReq, "正在等待用户在本地 NodeBridge 控制台审批命令执行..."))

			if err != nil {
				recordAudit(ctx, d.Audit, "terminal.start", in.WorkspaceID, string(ev.RiskLevel), in, outcome.Decision.DecisionTag, outcome.Decision.Approver, start, err)
				return nil, nil, err
			}
			if outcome.Pending {
				recordAudit(ctx, d.Audit, "terminal.start", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"executable": in.Executable, "approval_id": outcome.ApprovalID}, "APPROVAL_PENDING", "", start, nil)
				return nil, &TerminalStartOutput{
					Source:      "terminal_task",
					WorkspaceID: in.WorkspaceID,
					Status:      "APPROVAL_PENDING",
					RiskLevel:   string(ev.RiskLevel),
					Cwd:         resolvedCwd.RelPath,
					Pending:     true,
					ApprovalID:  outcome.ApprovalID,
					Message:     fmt.Sprintf("命令审批单 %s 正在等待用户在本地控制台确认。请提示用户批准后，调用 approval.status 获取 task_id。", outcome.ApprovalID),
				}, nil
			}
			out, _ := outcome.Result.(*TerminalStartOutput)
			recordAudit(ctx, d.Audit, "terminal.start", in.WorkspaceID, string(ev.RiskLevel), in, outcome.Decision.DecisionTag, outcome.Decision.Approver, start, nil)
			return nil, out, nil
		}

		if pause := d.Broker.IsPaused(); pause.Paused {
			pauseErr := fmt.Errorf("系统处于急停暂停状态，拒绝启动新命令：%s", pause.Reason)
			recordAudit(ctx, d.Audit, "terminal.start", in.WorkspaceID, string(ev.RiskLevel), in, "PAUSED", "", start, pauseErr)
			return nil, nil, pauseErr
		}

		rawRes, err := startTaskFn()
		recordAudit(ctx, d.Audit, "terminal.start", in.WorkspaceID, string(ev.RiskLevel), in, "AUTO_ALLOW", "", start, err)
		if err != nil {
			return nil, nil, err
		}
		out, _ := rawRes.(*TerminalStartOutput)
		return nil, out, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "terminal.poll",
		Description: "查询异步终端任务的运行状态、退出码及增量 stdout/stderr 输出",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in TerminalPollInput) (*mcp.CallToolResult, *task.PollResult, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("terminal.poll")
		res, err := d.Tasks.Poll(in.TaskID, in.StdoutOffset, in.StderrOffset)
		wsID := ""
		if res != nil {
			wsID = res.WorkspaceID
			if authErr := authorizePrincipal(ctx, d.Audit, "terminal.poll", wsID, string(ev.RiskLevel), false, in, start); authErr != nil {
				return nil, nil, authErr
			}
		}
		recordAudit(ctx, d.Audit, "terminal.poll", wsID, string(ev.RiskLevel), in, "AUTO_ALLOW", "", start, err)
		return nil, res, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "terminal.cancel",
		Description: "立即取消正在排队或运行中的终端任务并终止其完整子进程树",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in TerminalCancelInput) (*mcp.CallToolResult, *TerminalCancelOutput, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("terminal.cancel")
		if existing, pollErr := d.Tasks.Poll(in.TaskID, 0, 0); pollErr == nil && existing != nil {
			if authErr := authorizePrincipal(ctx, d.Audit, "terminal.cancel", existing.WorkspaceID, string(ev.RiskLevel), true, in, start); authErr != nil {
				return nil, nil, authErr
			}
		}
		rec, err := d.Tasks.Cancel(in.TaskID, in.Reason)
		recordAudit(ctx, d.Audit, "terminal.cancel", rec.WorkspaceID, string(ev.RiskLevel), in, "AUTO_ALLOW", "", start, err)
		if err != nil {
			return nil, nil, err
		}
		return nil, &TerminalCancelOutput{
			Source: "terminal_task",
			TaskID: rec.ID,
			Status: rec.Status,
		}, nil
	})
}

func registerApprovalTools(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "approval.status",
		Description: "查询挂起的远程人工审批单当前状态与批准后的异步执行结果（仅返回当前客户端所属审批单）",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ApprovalStatusInput) (*mcp.CallToolResult, *ApprovalStatusOutput, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("approval.status")
		rec, ok := d.Broker.GetRecord(in.ApprovalID)
		if !ok {
			err := fmt.Errorf("未找到审批单 %q（可能不存在或已过期清理）", in.ApprovalID)
			recordAudit(ctx, d.Audit, "approval.status", "", string(ev.RiskLevel), in, "NOT_FOUND", "", start, err)
			return nil, nil, err
		}

		p := session.FromContext(ctx)
		// 严格防跨客户端越权读取审批单详情与结果
		if p.AuthMethod == "oauth2" && rec.ClientID != "" && rec.ClientID != p.ClientID {
			err := errors.New("无权查看其他客户端发起的审批单")
			recordAudit(ctx, d.Audit, "approval.status", rec.WorkspaceID, string(ev.RiskLevel), in, "CLIENT_APPROVAL_DENIED", "", start, err)
			return nil, nil, err
		}
		if err := authorizePrincipal(ctx, d.Audit, "approval.status", rec.WorkspaceID, string(ev.RiskLevel), false, in, start); err != nil {
			return nil, nil, err
		}

		out := &ApprovalStatusOutput{
			Source:       "approval_broker",
			ApprovalID:   rec.ID,
			Tool:         rec.Tool,
			WorkspaceID:  rec.WorkspaceID,
			Status:       string(rec.Status),
			ExecStatus:   rec.ExecStatus,
			DecisionNote: rec.DecisionNote,
			Result:       rec.ExecResult,
			Error:        rec.ExecError,
		}
		if !rec.ExpiresAt.IsZero() {
			out.ExpiresAt = rec.ExpiresAt.Format(time.RFC3339)
		}
		switch rec.Status {
		case approval.StatusPending:
			out.Message = "用户尚未处理该审批单，请提醒用户在本地 NodeBridge 控制台点击批准或拒绝。"
		case approval.StatusApproved:
			if rec.ExecStatus == "RUNNING" {
				out.Message = "用户已批准，操作正在后台执行中，请稍后再次调用 approval.status。"
			} else if rec.ExecStatus == "SUCCEEDED" {
				out.Message = "用户已批准且操作已执行成功，结果见 result 字段。"
			} else if rec.ExecStatus == "FAILED" {
				out.Message = "用户已批准，但后台执行失败，原因见 error 字段。"
			}
		case approval.StatusRejected:
			out.Message = "用户已拒绝该操作。"
		case approval.StatusCancelled, approval.StatusTimedOut:
			out.Message = "审批单已取消或超时过期。"
		}

		recordAudit(ctx, d.Audit, "approval.status", rec.WorkspaceID, string(ev.RiskLevel), in, "AUTO_ALLOW", "", start, nil)
		return nil, out, nil
	})
}

// authorizePrincipal 执行阶段二客户端级工作区子集与只读权限护栏校验。
func authorizePrincipal(
	ctx context.Context,
	logger *audit.Logger,
	toolName, workspaceID, risk string,
	requiresWrite bool,
	args any,
	start time.Time,
) error {
	p := session.FromContext(ctx)
	if workspaceID != "" && !p.CanAccessWorkspace(workspaceID) {
		err := fmt.Errorf("当前远程客户端（%s）未被授权访问工作区 %q", p.ClientName, workspaceID)
		recordAudit(ctx, logger, toolName, workspaceID, risk, args, "CLIENT_WORKSPACE_DENIED", "", start, err)
		return err
	}
	if requiresWrite && !p.HasWritePermission() {
		err := fmt.Errorf("当前远程客户端（%s）处于只读授权模式，禁止执行写入或变更类操作 %q", p.ClientName, toolName)
		recordAudit(ctx, logger, toolName, workspaceID, risk, args, "CLIENT_READONLY_DENIED", "", start, err)
		return err
	}
	return nil
}

// makeProgressNotifier 构造等待审批期间向 MCP 客户端推送保活进度的回调，降低云端代理断连概率。
func makeProgressNotifier(ctx context.Context, callReq *mcp.CallToolRequest, msg string) func(elapsed time.Duration) {
	if callReq == nil || callReq.Session == nil || callReq.Params == nil {
		return nil
	}
	tok := callReq.Params.GetProgressToken()
	if tok == nil {
		return nil
	}
	return func(elapsed time.Duration) {
		_ = callReq.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
			ProgressToken: tok,
			Progress:      elapsed.Seconds(),
			Message:       msg,
		})
	}
}

func formatCommandPreview(in TerminalStartInput) string {
	mode := "argv（无 Shell 拼接）"
	if in.UseShell {
		mode = "显式 Shell（高风险）"
	}
	cwd := in.Cwd
	if cwd == "" {
		cwd = "."
	}
	return fmt.Sprintf("执行模式: %s\n工作目录: %s\n可执行文件: %s\n参数数组: %q\n透传环境变量: %v\n超时(秒): %d",
		mode, cwd, in.Executable, in.Args, in.EnvAllow, in.TimeoutSeconds)
}

func recordAudit(ctx context.Context, logger *audit.Logger, tool, wsID, risk string, args any, decision, approver string, start time.Time, err error) {
	if logger == nil {
		return
	}
	p := session.FromContext(ctx)
	status := "SUCCEEDED"
	errStr := ""
	if err != nil {
		status = "FAILED"
		errStr = err.Error()
	}
	clientLabel := p.ClientInfo
	if p.ClientID != "" && p.AuthMethod == "oauth2" {
		clientLabel = fmt.Sprintf("oauth:%s (%s)", p.ClientID, p.ClientName)
	}
	_ = logger.Record(audit.Event{
		SessionID:   p.SessionID,
		ClientInfo:  clientLabel,
		Tool:        tool,
		WorkspaceID: wsID,
		RiskLevel:   risk,
		ArgsSummary: audit.RedactSummary(args, 400),
		Decision:    decision,
		Approver:    approver,
		Status:      status,
		DurationMs:  time.Since(start).Milliseconds(),
		Error:       errStr,
	})
}
