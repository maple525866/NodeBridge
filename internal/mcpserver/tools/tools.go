// Package tools 注册阶段一全部 10 个 P0 MCP 工具，并在工具执行前统一串联策略引擎、人工审批与审计日志。
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
	TaskID      string `json:"task_id"`
	WorkspaceID string `json:"workspace_id"`
	Status      string `json:"status"`
	RiskLevel   string `json:"risk_level"`
	Cwd         string `json:"cwd"`
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

// RegisterAll 将全部 10 个 P0 工具注册到指定 MCP Server。
func RegisterAll(srv *mcp.Server, deps Deps) {
	registerWorkspaceTools(srv, deps)
	registerGitTools(srv, deps)
	registerTerminalTools(srv, deps)
}

func registerWorkspaceTools(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "workspace.list",
		Description: "列出授权工作区内的目录和源码文件（自动过滤敏感文件与忽略目录）",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in WorkspaceListInput) (*mcp.CallToolResult, *filesystem.ListResult, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("workspace.list")
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
		res, err := d.FS.Search(in.WorkspaceID, in.Query, in.IsRegex, in.Glob, in.MaxResults)
		recordAudit(ctx, d.Audit, "workspace.search", in.WorkspaceID, string(ev.RiskLevel), in, "AUTO_ALLOW", "", start, err)
		return nil, res, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "workspace.patch",
		Description: "使用 Search/Replace 结构化编辑块安全修改或新建授权工作区文件（支持 SHA256 乐观锁与人工 Diff 审批）",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in WorkspacePatchInput) (*mcp.CallToolResult, *filesystem.PatchResult, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("workspace.patch")
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
			recordAudit(ctx, d.Audit, "workspace.patch", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"path": in.Path}, "DENIED_PRECHECK", "", start, err)
			return nil, nil, err
		}

		p := session.FromContext(ctx)
		dec, err := d.Broker.RequestApproval(ctx, approval.Request{
			SessionID:     p.SessionID,
			Tool:          "workspace.patch",
			WorkspaceID:   in.WorkspaceID,
			RiskLevel:     ev.RiskLevel,
			AllowBatchTTL: ev.AllowBatchTTL,
			TargetPath:    preview.Resolved.RelPath,
			DiffPreview:   preview.UnifiedDiff,
			Summary:       fmt.Sprintf("修改工作区 %s 中的文件 %s", in.WorkspaceID, preview.Resolved.RelPath),
			Reason:        ev.Reason,
		})
		if err != nil {
			recordAudit(ctx, d.Audit, "workspace.patch", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"path": preview.Resolved.RelPath}, dec.DecisionTag, dec.Approver, start, err)
			return nil, nil, err
		}

		// 若调用方未显式传 expected_sha256，在审批等待后自动锁定预检时的旧版本，防审批期间人工编辑被覆盖
		if patchReq.ExpectedSHA256 == "" && !preview.IsNewFile {
			patchReq.ExpectedSHA256 = preview.OldSHA256
		}
		res, err := d.FS.ApplyPatch(patchReq)
		recordAudit(ctx, d.Audit, "workspace.patch", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"path": preview.Resolved.RelPath, "created": preview.IsNewFile}, dec.DecisionTag, dec.Approver, start, err)
		return nil, res, err
	})
}

func registerGitTools(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "git.status",
		Description: "查看授权工作区的 Git 分支及变更状态",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in GitStatusInput) (*mcp.CallToolResult, *git.StatusResult, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("git.status")
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
		Description: "在路径安全校验与人工审批后，向授权工作区应用标准 Unified Diff Git 补丁",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in GitApplyPatchInput) (*mcp.CallToolResult, *git.ApplyPatchResult, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("git.apply_patch")
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
		dec, err := d.Broker.RequestApproval(ctx, approval.Request{
			SessionID:     p.SessionID,
			Tool:          "git.apply_patch",
			WorkspaceID:   in.WorkspaceID,
			RiskLevel:     ev.RiskLevel,
			AllowBatchTTL: ev.AllowBatchTTL,
			TargetPath:    strings.Join(affected, ", "),
			DiffPreview:   in.Patch,
			Summary:       fmt.Sprintf("向工作区 %s 应用 Git 补丁（涉及 %d 个文件）", in.WorkspaceID, len(affected)),
			Reason:        ev.Reason,
		})
		if err != nil {
			recordAudit(ctx, d.Audit, "git.apply_patch", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"files": affected}, dec.DecisionTag, dec.Approver, start, err)
			return nil, nil, err
		}

		res, err := d.Git.ApplyPatch(ctx, in.WorkspaceID, in.Patch)
		recordAudit(ctx, d.Audit, "git.apply_patch", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"files": affected}, dec.DecisionTag, dec.Approver, start, err)
		return nil, res, err
	})
}

func registerTerminalTools(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "terminal.start",
		Description: "在授权工作区内异步启动受分层安全策略和人工审批约束的命令行任务，立即返回 task_id",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in TerminalStartInput) (*mcp.CallToolResult, *TerminalStartOutput, error) {
		start := time.Now()
		// 1. 校验工作目录严格位于授权工作区内
		resolvedCwd, err := d.FS.Resolve(in.WorkspaceID, in.Cwd, false)
		if err != nil {
			recordAudit(ctx, d.Audit, "terminal.start", in.WorkspaceID, "L3", in, "DENIED_PATH", "", start, err)
			return nil, nil, err
		}

		// 2. 分层命令策略评估
		ev := d.Policy.EvaluateCommand(in.Executable, in.Args, in.UseShell)
		if ev.Action == policy.ActionDeny {
			denyErr := fmt.Errorf("命令被安全策略拒绝 [%s]: %s", ev.RiskLevel, ev.Reason)
			recordAudit(ctx, d.Audit, "terminal.start", in.WorkspaceID, string(ev.RiskLevel), in, "POLICY_DENY", "", start, denyErr)
			return nil, nil, denyErr
		}

		// 3. 急停检查与按需人工审批
		decisionTag := "AUTO_ALLOW"
		approver := ""
		if ev.Action == policy.ActionRequireApproval {
			p := session.FromContext(ctx)
			cmdPreview := formatCommandPreview(in)
			dec, err := d.Broker.RequestApproval(ctx, approval.Request{
				SessionID:      p.SessionID,
				Tool:           "terminal.start",
				WorkspaceID:    in.WorkspaceID,
				RiskLevel:      ev.RiskLevel,
				AllowBatchTTL:  ev.AllowBatchTTL,
				TargetPath:     resolvedCwd.RelPath,
				CommandPreview: cmdPreview,
				Summary:        fmt.Sprintf("在工作区 %s 执行命令: %s", in.WorkspaceID, in.Executable),
				Reason:         ev.Reason,
			})
			if err != nil {
				recordAudit(ctx, d.Audit, "terminal.start", in.WorkspaceID, string(ev.RiskLevel), in, dec.DecisionTag, dec.Approver, start, err)
				return nil, nil, err
			}
			decisionTag = dec.DecisionTag
			approver = dec.Approver
		} else if pause := d.Broker.IsPaused(); pause.Paused {
			pauseErr := fmt.Errorf("系统处于急停暂停状态，拒绝启动新命令：%s", pause.Reason)
			recordAudit(ctx, d.Audit, "terminal.start", in.WorkspaceID, string(ev.RiskLevel), in, "PAUSED", "", start, pauseErr)
			return nil, nil, pauseErr
		}

		p := session.FromContext(ctx)
		rec, err := d.Tasks.Start(task.StartRequest{
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
		recordAudit(ctx, d.Audit, "terminal.start", in.WorkspaceID, string(ev.RiskLevel), in, decisionTag, approver, start, err)
		if err != nil {
			return nil, nil, err
		}

		return nil, &TerminalStartOutput{
			Source:      "terminal_task",
			TaskID:      rec.ID,
			WorkspaceID: rec.WorkspaceID,
			Status:      rec.Status,
			RiskLevel:   string(ev.RiskLevel),
			Cwd:         resolvedCwd.RelPath,
		}, nil
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
	_ = logger.Record(audit.Event{
		SessionID:   p.SessionID,
		ClientInfo:  p.ClientInfo,
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
