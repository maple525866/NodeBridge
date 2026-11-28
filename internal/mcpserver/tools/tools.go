// Package tools 注册全部 19 个 MCP 工具（系统自发现、文件系统读写建移删搜、Git 全套只读与补丁、异步/短等待终端与远程审批续接），
// 并在工具执行前统一串联客户端级权限护栏、策略引擎、混合人工审批（支持远程异步续接与幂等去重）与审计日志。
package tools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"nodebridge/internal/core/approval"
	"nodebridge/internal/core/audit"
	"nodebridge/internal/core/policy"
	"nodebridge/internal/core/session"
	"nodebridge/internal/core/task"
	"nodebridge/internal/platform/capability"
	"nodebridge/internal/platform/filesystem"
	"nodebridge/internal/platform/git"
)

const (
	defaultTerminalStartWaitSec = 10
	maxTerminalWaitSec          = 30
)

// Deps 汇总工具层运行所需的全部本地能力与安全治理组件。
type Deps struct {
	FS     *filesystem.Manager
	Git    *git.Adapter // 若宿主机未安装 Git 可为 nil，工具将返回清晰能力缺失提示
	Tasks  *task.Manager
	Policy *policy.Engine
	Broker *approval.Broker
	Audit  *audit.Logger
	Cap    *capability.Info // 可选：Daemon 启动时探测并缓存的宿主机能力（为空时按需惰性探测）
}

// --- 工具输入/输出 Schema 定义 ---

type SystemInfoInput struct{}

type SystemWorkspaceInfo struct {
	ID       string `json:"id"`
	ReadOnly bool   `json:"read_only"`
	Root     string `json:"root,omitempty"` // 仅在开启「默认全部目录模式」时返回，避免默认隔离模式下泄露宿主机绝对路径
}

type SystemInfoOutput struct {
	Source           string                         `json:"source"`
	OS               string                         `json:"os"`
	Arch             string                         `json:"arch"`
	DefaultShell     string                         `json:"default_shell,omitempty"`
	GitAvailable     bool                           `json:"git_available"`
	GitVersion       string                         `json:"git_version,omitempty"`
	RipgrepAvailable bool                           `json:"ripgrep_available"`
	Tools            map[string]capability.ToolInfo `json:"tools,omitempty"`
	FullPermissions  bool                           `json:"full_permissions"`
	AllowAllDirs     bool                           `json:"allow_all_dirs"`
	ClientReadOnly   bool                           `json:"client_read_only"`
	Cwd              string                         `json:"cwd,omitempty"` // 仅在开启「默认全部目录模式」时返回
	Workspaces       []SystemWorkspaceInfo          `json:"workspaces"`
}

type WorkspaceListInput struct {
	WorkspaceID string `json:"workspace_id" jsonschema:"授权工作区 ID，例如 default（开启全部目录模式时可留空或直接传入任意绝对目录路径）"`
	Path        string `json:"path,omitempty" jsonschema:"相对路径或宿主机绝对目录路径（开启全部目录模式时支持任意目录），默认工作区根目录"`
	MaxDepth    int    `json:"max_depth,omitempty" jsonschema:"最大遍历深度，默认 3"`
	Limit       int    `json:"limit,omitempty" jsonschema:"返回最大条目数，默认 200"`
}

type WorkspaceGlobInput struct {
	WorkspaceID      string `json:"workspace_id" jsonschema:"授权工作区 ID，例如 default（开启全部目录模式时可留空）"`
	Path             string `json:"path,omitempty" jsonschema:"可选：起始查找目录（默认工作区根目录；开启全部目录模式时可为宿主机任意绝对路径）"`
	Pattern          string `json:"pattern" jsonschema:"文件名或通配符模式，例如 **/*.go、*_test.go、*auth*"`
	RespectGitignore *bool  `json:"respect_gitignore,omitempty" jsonschema:"是否遵循 .gitignore 规则，默认 true"`
	IncludeDirs      bool   `json:"include_dirs,omitempty" jsonschema:"是否包含目录条目，默认 false 仅返回文件"`
	Limit            int    `json:"limit,omitempty" jsonschema:"返回最大条目数，默认 200，上限 2000"`
}

type WorkspaceReadInput struct {
	WorkspaceID string `json:"workspace_id" jsonschema:"授权工作区 ID，例如 default（开启全部目录模式时可留空）"`
	Path        string `json:"path" jsonschema:"文件相对路径，或开启全部目录模式时的宿主机任意绝对路径"`
	StartLine   int    `json:"start_line,omitempty" jsonschema:"起始行号（从 1 开始），默认 1"`
	EndLine     int    `json:"end_line,omitempty" jsonschema:"结束行号（含），默认从起始行起读取 400 行"`
}

type WorkspaceSearchInput struct {
	WorkspaceID      string `json:"workspace_id" jsonschema:"授权工作区 ID，例如 default（开启全部目录模式时可留空）"`
	Path             string `json:"path,omitempty" jsonschema:"可选：起始搜索目录或文件路径（默认工作区根目录；开启全部目录模式时可为宿主机任意绝对路径）"`
	Query            string `json:"query" jsonschema:"搜索关键词或正则表达式"`
	IsRegex          bool   `json:"is_regex,omitempty" jsonschema:"是否按正则表达式匹配，默认 false"`
	Glob             string `json:"glob,omitempty" jsonschema:"限定文件通配符，例如 **/*.go"`
	IgnoreCase       bool   `json:"ignore_case,omitempty" jsonschema:"是否忽略大小写，默认 false"`
	ContextLines     int    `json:"context_lines,omitempty" jsonschema:"命中行前后返回的上下文行数（0-5），默认 0"`
	RespectGitignore *bool  `json:"respect_gitignore,omitempty" jsonschema:"是否遵循 .gitignore 规则，默认 true"`
	MaxResults       int    `json:"max_results,omitempty" jsonschema:"最大命中行数，默认 100，上限 500"`
}

type PatchEditInput struct {
	OldText    string `json:"old_text" jsonschema:"待替换的原文本块（新建文件时可为空）"`
	NewText    string `json:"new_text" jsonschema:"替换后的新文本块"`
	ReplaceAll bool   `json:"replace_all,omitempty" jsonschema:"是否替换全部匹配项，默认 false 仅允许唯一匹配"`
}

type WorkspacePatchInput struct {
	WorkspaceID     string           `json:"workspace_id" jsonschema:"授权工作区 ID，例如 default（开启全部目录模式时可留空）"`
	Path            string           `json:"path" jsonschema:"目标文件相对路径，或开启全部目录模式时的宿主机任意绝对路径"`
	ExpectedSHA256  string           `json:"expected_sha256,omitempty" jsonschema:"修改前通过 workspace.read 获取的 SHA256 乐观锁校验值"`
	CreateIfMissing bool             `json:"create_if_missing,omitempty" jsonschema:"目标文件不存在时是否允许新建"`
	Edits           []PatchEditInput `json:"edits" jsonschema:"按顺序执行的 Search/Replace 编辑块列表"`
}

type WorkspaceWriteInput struct {
	WorkspaceID    string `json:"workspace_id" jsonschema:"授权工作区 ID，例如 default（开启全部目录模式时可留空）"`
	Path           string `json:"path" jsonschema:"目标文件相对路径，或开启全部目录模式时的宿主机任意绝对路径"`
	Content        string `json:"content" jsonschema:"待写入的完整文本内容（最大 2MB，仅支持文本文件）"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty" jsonschema:"可选：覆写已有文件时的 SHA256 乐观锁校验值"`
	Overwrite      *bool  `json:"overwrite,omitempty" jsonschema:"目标文件已存在时是否允许覆盖，默认 true"`
}

type WorkspaceMkdirInput struct {
	WorkspaceID string `json:"workspace_id" jsonschema:"授权工作区 ID，例如 default（开启全部目录模式时可留空）"`
	Path        string `json:"path" jsonschema:"待创建的目录相对路径，或开启全部目录模式时的宿主机任意绝对路径"`
	Parents     *bool  `json:"parents,omitempty" jsonschema:"是否递归创建缺失的父目录（类似 mkdir -p），默认 true；传 false 时要求父目录已存在且目标尚未存在"`
}

type WorkspaceMoveInput struct {
	WorkspaceID     string `json:"workspace_id" jsonschema:"授权工作区 ID，例如 default（开启全部目录模式时可留空）"`
	SourcePath      string `json:"source_path" jsonschema:"源文件或目录路径"`
	DestinationPath string `json:"destination_path" jsonschema:"目标文件或目录路径"`
	Overwrite       bool   `json:"overwrite,omitempty" jsonschema:"目标文件已存在时是否允许覆盖（不允许覆盖已存在目录），默认 false"`
}

type WorkspaceDeleteInput struct {
	WorkspaceID string `json:"workspace_id" jsonschema:"授权工作区 ID，例如 default（开启全部目录模式时可留空）"`
	Path        string `json:"path" jsonschema:"待删除的文件、符号链接或目录路径"`
	Recursive   bool   `json:"recursive,omitempty" jsonschema:"是否递归删除非空目录（true 且目录非空时将自动升级为 L2 强确认），默认 false"`
}

type GitStatusInput struct {
	WorkspaceID string `json:"workspace_id" jsonschema:"授权工作区 ID，例如 default（开启全部目录模式时可留空或直接传入仓库目录路径）"`
	Path        string `json:"path,omitempty" jsonschema:"可选：Git 仓库目录路径（默认工作区根目录；开启全部目录模式时可为宿主机任意绝对路径）"`
}

type GitDiffInput struct {
	WorkspaceID string   `json:"workspace_id" jsonschema:"授权工作区 ID，例如 default（开启全部目录模式时可留空）"`
	Path        string   `json:"path,omitempty" jsonschema:"可选：Git 仓库目录路径（默认工作区根目录；开启全部目录模式时可为宿主机任意绝对路径）"`
	Staged      bool     `json:"staged,omitempty" jsonschema:"是否查看暂存区（--cached）差异"`
	Base        string   `json:"base,omitempty" jsonschema:"可选：对比基准引用或范围，例如 HEAD~1、main 或 main...HEAD"`
	Target      string   `json:"target,omitempty" jsonschema:"可选：对比目标引用，例如 HEAD 或特性分支名（与 base 搭配使用）"`
	Paths       []string `json:"paths,omitempty" jsonschema:"限定查看的文件路径列表"`
	MaxBytes    int      `json:"max_bytes,omitempty" jsonschema:"最大输出字节数，默认 262144"`
}

type GitLogInput struct {
	WorkspaceID string `json:"workspace_id" jsonschema:"授权工作区 ID，例如 default（开启全部目录模式时可留空）"`
	Path        string `json:"path,omitempty" jsonschema:"可选：Git 仓库目录路径（默认工作区根目录；开启全部目录模式时可为宿主机任意绝对路径）"`
	Ref         string `json:"ref,omitempty" jsonschema:"可选：分支、标签或提交范围，例如 main、HEAD~5..HEAD"`
	FilePath    string `json:"file_path,omitempty" jsonschema:"可选：限定查看某个文件或目录的提交历史"`
	Limit       int    `json:"limit,omitempty" jsonschema:"最大返回提交条数，默认 20，上限 100"`
}

type GitShowInput struct {
	WorkspaceID string `json:"workspace_id" jsonschema:"授权工作区 ID，例如 default（开启全部目录模式时可留空）"`
	Path        string `json:"path,omitempty" jsonschema:"可选：Git 仓库目录路径（默认工作区根目录；开启全部目录模式时可为宿主机任意绝对路径）"`
	Ref         string `json:"ref,omitempty" jsonschema:"提交哈希、分支或标签名，默认 HEAD"`
	StatOnly    bool   `json:"stat_only,omitempty" jsonschema:"是否仅返回变更文件统计（--stat），默认 false 返回完整 Diff"`
	MaxBytes    int    `json:"max_bytes,omitempty" jsonschema:"最大 Diff 输出字节数，默认 262144"`
}

type GitApplyPatchInput struct {
	WorkspaceID string `json:"workspace_id" jsonschema:"授权工作区 ID，例如 default（开启全部目录模式时可留空）"`
	Path        string `json:"path,omitempty" jsonschema:"可选：Git 仓库目录路径（默认工作区根目录；开启全部目录模式时可为宿主机任意绝对路径）"`
	Patch       string `json:"patch" jsonschema:"标准 Unified Diff / Git Patch 文本内容"`
}

type TerminalStartInput struct {
	WorkspaceID    string   `json:"workspace_id" jsonschema:"授权工作区 ID，例如 default（开启全部目录模式时可留空）"`
	Executable     string   `json:"executable" jsonschema:"可执行程序名或命令（默认按参数数组执行，不拼接 Shell）"`
	Args           []string `json:"args,omitempty" jsonschema:"命令行参数数组"`
	Cwd            string   `json:"cwd,omitempty" jsonschema:"工作目录（相对路径，或开启全部目录模式时的宿主机任意绝对目录路径），默认工作区根目录"`
	EnvAllow       []string `json:"env_allow,omitempty" jsonschema:"允许从宿主机透传的额外环境变量名列表"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty" jsonschema:"任务超时秒数"`
	UseShell       bool     `json:"use_shell,omitempty" jsonschema:"是否显式通过系统 Shell 解释执行（默认模式强制 L2 人工审批，全部权限模式自动放行）"`
	WaitSeconds    *int     `json:"wait_seconds,omitempty" jsonschema:"启动后最多同步等待秒数（默认 10 秒，上限 30 秒；传 0 立即异步返回 task_id）。短命令在等待期内结束将直接返回输出与退出码"`
}

type TerminalStartOutput struct {
	Source          string `json:"source"`
	TaskID          string `json:"task_id,omitempty"`
	WorkspaceID     string `json:"workspace_id"`
	Status          string `json:"status"`
	RiskLevel       string `json:"risk_level"`
	Cwd             string `json:"cwd,omitempty"`
	ExitCode        *int   `json:"exit_code,omitempty"`
	ErrorMessage    string `json:"error_message,omitempty"`
	Stdout          string `json:"stdout,omitempty"`
	Stderr          string `json:"stderr,omitempty"`
	StdoutNextOff   int    `json:"stdout_next_offset,omitempty"`
	StderrNextOff   int    `json:"stderr_next_offset,omitempty"`
	StdoutTruncated bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated bool   `json:"stderr_truncated,omitempty"`
	StdoutTail      string `json:"stdout_tail,omitempty"`
	StderrTail      string `json:"stderr_tail,omitempty"`
	ElapsedMs       int64  `json:"elapsed_ms,omitempty"`
	Pending         bool   `json:"pending,omitempty"`
	ApprovalID      string `json:"approval_id,omitempty"`
	Message         string `json:"message,omitempty"`
}

type TerminalPollInput struct {
	TaskID       string `json:"task_id" jsonschema:"terminal.start 返回的任务 ID"`
	StdoutOffset int    `json:"stdout_offset,omitempty" jsonschema:"增量读取 stdout 的起始字节偏移"`
	StderrOffset int    `json:"stderr_offset,omitempty" jsonschema:"增量读取 stderr 的起始字节偏移"`
	WaitSeconds  int    `json:"wait_seconds,omitempty" jsonschema:"可选长轮询等待秒数（默认 0 立即返回，上限 30 秒）：当尚无新输出且任务未结束时等待新输出或终态"`
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
	registerSystemTools(srv, deps)
	registerWorkspaceTools(srv, deps)
	registerGitTools(srv, deps)
	registerTerminalTools(srv, deps)
	registerApprovalTools(srv, deps)
}

func registerSystemTools(srv *mcp.Server, d Deps) {
	var (
		capOnce   sync.Once
		cachedCap capability.Info
	)
	getCap := func() capability.Info {
		if d.Cap != nil {
			return *d.Cap
		}
		capOnce.Do(func() {
			cachedCap = capability.Detect()
		})
		return cachedCap
	}

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "system.info",
		Description: "获取宿主机操作系统、默认 Shell、可用开发工具链、当前权限/目录模式以及当前客户端有权访问的工作区列表（推荐会话开始时优先调用）",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in SystemInfoInput) (*mcp.CallToolResult, *SystemInfoOutput, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("system.info")
		p := session.FromContext(ctx)
		capInfo := getCap()

		allowAllDirs := d.FS != nil && d.FS.AllowAllDirs()
		fullPerms := d.Policy != nil && d.Policy.FullPermissions()

		var workspaces []SystemWorkspaceInfo
		if d.FS != nil {
			rawWS := d.FS.Workspaces()
			sort.Slice(rawWS, func(i, j int) bool {
				return rawWS[i].ID < rawWS[j].ID
			})
			for _, ws := range rawWS {
				if !allowAllDirs && !p.CanAccessWorkspace(ws.ID) {
					continue
				}
				item := SystemWorkspaceInfo{
					ID:       ws.ID,
					ReadOnly: ws.ReadOnly && !fullPerms,
				}
				// 默认隔离模式下隐藏宿主机真实绝对路径，仅开启「默认全部目录」时暴露
				if allowAllDirs {
					item.Root = filepath.ToSlash(ws.RealRoot)
				}
				workspaces = append(workspaces, item)
			}
		}
		if workspaces == nil {
			workspaces = []SystemWorkspaceInfo{}
		}

		cwd := ""
		if allowAllDirs {
			if cur, err := os.Getwd(); err == nil {
				cwd = filepath.ToSlash(cur)
			}
		}

		toolsMap := make(map[string]capability.ToolInfo, len(capInfo.Tools))
		for k, v := range capInfo.Tools {
			toolsMap[k] = v
		}

		out := &SystemInfoOutput{
			Source:           "local_system_info",
			OS:               capInfo.OS,
			Arch:             capInfo.Arch,
			DefaultShell:     capInfo.DefaultShell,
			GitAvailable:     capInfo.GitAvailable,
			GitVersion:       capInfo.GitVersion,
			RipgrepAvailable: capInfo.RipgrepPath != "" || toolsMap["rg"].Available,
			Tools:            toolsMap,
			FullPermissions:  fullPerms,
			AllowAllDirs:     allowAllDirs,
			ClientReadOnly:   !p.HasWritePermission(),
			Cwd:              cwd,
			Workspaces:       workspaces,
		}
		recordAudit(ctx, d.Audit, "system.info", "", string(ev.RiskLevel), in, "AUTO_ALLOW", "", start, nil)
		return nil, out, nil
	})
}

func registerWorkspaceTools(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "workspace.list",
		Description: "列出工作区或指定目录的目录结构和文件（开启全部目录模式时支持任意宿主机路径）",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in WorkspaceListInput) (*mcp.CallToolResult, *filesystem.ListResult, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("workspace.list")
		if err := authorizePrincipal(ctx, d, "workspace.list", in.WorkspaceID, string(ev.RiskLevel), false, in, start); err != nil {
			return nil, nil, err
		}
		res, err := d.FS.List(in.WorkspaceID, in.Path, in.MaxDepth, in.Limit)
		recordAudit(ctx, d.Audit, "workspace.list", in.WorkspaceID, string(ev.RiskLevel), in, "AUTO_ALLOW", "", start, err)
		return nil, res, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "workspace.glob",
		Description: "按文件名或通配符模式快速查找工作区或指定目录下的文件（默认遵循 .gitignore 并跳过构建目录与敏感路径）",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in WorkspaceGlobInput) (*mcp.CallToolResult, *filesystem.GlobResult, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("workspace.glob")
		if err := authorizePrincipal(ctx, d, "workspace.glob", in.WorkspaceID, string(ev.RiskLevel), false, in, start); err != nil {
			return nil, nil, err
		}
		res, err := d.FS.Glob(filesystem.GlobOptions{
			WorkspaceID:      in.WorkspaceID,
			Path:             in.Path,
			Pattern:          in.Pattern,
			RespectGitignore: in.RespectGitignore,
			IncludeDirs:      in.IncludeDirs,
			Limit:            in.Limit,
		})
		recordAudit(ctx, d.Audit, "workspace.glob", in.WorkspaceID, string(ev.RiskLevel), in, "AUTO_ALLOW", "", start, err)
		return nil, res, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "workspace.read",
		Description: "读取工作区或指定路径的文本文件内容，同时返回整文件 sha256 供 workspace.patch / workspace.write 乐观锁校验",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in WorkspaceReadInput) (*mcp.CallToolResult, *filesystem.ReadResult, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("workspace.read")
		if err := authorizePrincipal(ctx, d, "workspace.read", in.WorkspaceID, string(ev.RiskLevel), false, in, start); err != nil {
			return nil, nil, err
		}
		res, err := d.FS.Read(in.WorkspaceID, in.Path, in.StartLine, in.EndLine)
		recordAudit(ctx, d.Audit, "workspace.read", in.WorkspaceID, string(ev.RiskLevel), in, "AUTO_ALLOW", "", start, err)
		return nil, res, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "workspace.search",
		Description: "在工作区或指定目录内按文本或正则表达式搜索代码（优先使用本机 ripgrep，支持 .gitignore、忽略大小写与上下文行）",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in WorkspaceSearchInput) (*mcp.CallToolResult, *filesystem.SearchResult, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("workspace.search")
		if err := authorizePrincipal(ctx, d, "workspace.search", in.WorkspaceID, string(ev.RiskLevel), false, in, start); err != nil {
			return nil, nil, err
		}
		res, err := d.FS.SearchWithOptions(filesystem.SearchOptions{
			WorkspaceID:      in.WorkspaceID,
			Path:             in.Path,
			Query:            in.Query,
			IsRegex:          in.IsRegex,
			Glob:             in.Glob,
			IgnoreCase:       in.IgnoreCase,
			ContextLines:     in.ContextLines,
			RespectGitignore: in.RespectGitignore,
			MaxResults:       in.MaxResults,
		})
		recordAudit(ctx, d.Audit, "workspace.search", in.WorkspaceID, string(ev.RiskLevel), in, "AUTO_ALLOW", "", start, err)
		return nil, res, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "workspace.patch",
		Description: "使用 Search/Replace 结构化编辑块安全修改或新建文件（支持 SHA256 乐观锁、人工 Diff 审批/全权限免审批与远程异步续接）",
	}, func(ctx context.Context, callReq *mcp.CallToolRequest, in WorkspacePatchInput) (*mcp.CallToolResult, *filesystem.PatchResult, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("workspace.patch")
		if err := authorizePrincipal(ctx, d, "workspace.patch", in.WorkspaceID, string(ev.RiskLevel), true, map[string]any{"path": in.Path}, start); err != nil {
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

		p := session.FromContext(ctx)
		fp := approval.ComputeFingerprint(p.ClientID, "workspace.patch", in.WorkspaceID, in)
		var outcome approval.ExecutionOutcome
		path := in.Path
		preview, err := d.FS.PreviewPatch(patchReq)
		if err != nil {
			outcome, err = replayAfterPrecheck(d.Broker, p.IsRemote, fp, err)
		} else {
			path = preview.Resolved.RelPath
			// 锁定预检时的版本，防止审批期间的人工编辑被覆盖。
			if patchReq.ExpectedSHA256 == "" && !preview.IsNewFile {
				patchReq.ExpectedSHA256 = preview.OldSHA256
			}
			outcome, err = d.Broker.ExecuteWithApproval(ctx, approval.Request{
				SessionID:     p.SessionID,
				ClientID:      p.ClientID,
				IsRemote:      p.IsRemote,
				Fingerprint:   fp,
				Tool:          "workspace.patch",
				WorkspaceID:   in.WorkspaceID,
				RiskLevel:     ev.RiskLevel,
				AllowBatchTTL: ev.AllowBatchTTL,
				TargetPath:    path,
				DiffPreview:   preview.UnifiedDiff,
				Summary:       fmt.Sprintf("修改工作区 %s 中的文件 %s", in.WorkspaceID, path),
				Reason:        ev.Reason,
			}, func() (any, error) {
				return d.FS.ApplyPatch(patchReq)
			}, makeProgressNotifier(callReq, "正在等待文件补丁处理结果..."))
		}

		if err != nil {
			recordAudit(ctx, d.Audit, "workspace.patch", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"path": path}, outcome.Decision.DecisionTag, outcome.Decision.Approver, start, err)
			return nil, nil, err
		}
		if outcome.Pending {
			status, message := pendingResponse(outcome)
			recordAudit(ctx, d.Audit, "workspace.patch", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"path": path, "approval_id": outcome.ApprovalID}, status, outcome.Decision.Approver, start, nil)
			return nil, &filesystem.PatchResult{
				Source:      "local_workspace_file",
				WorkspaceID: in.WorkspaceID,
				Path:        path,
				Pending:     true,
				ApprovalID:  outcome.ApprovalID,
				Message:     message,
			}, nil
		}

		res, _ := outcome.Result.(*filesystem.PatchResult)
		recordAudit(ctx, d.Audit, "workspace.patch", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"path": path, "created": res != nil && res.Created}, outcome.Decision.DecisionTag, outcome.Decision.Approver, start, nil)
		return nil, res, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "workspace.write",
		Description: "整文件新建或覆写文本文件（支持 SHA256 乐观锁、Diff 审批预览、全权限免审批与远程异步续接）",
	}, func(ctx context.Context, callReq *mcp.CallToolRequest, in WorkspaceWriteInput) (*mcp.CallToolResult, *filesystem.WriteResult, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("workspace.write")
		if err := authorizePrincipal(ctx, d, "workspace.write", in.WorkspaceID, string(ev.RiskLevel), true, map[string]any{"path": in.Path, "bytes": len(in.Content)}, start); err != nil {
			return nil, nil, err
		}

		overwrite := true
		if in.Overwrite != nil {
			overwrite = *in.Overwrite
		}
		writeReq := filesystem.WriteRequest{
			WorkspaceID:    in.WorkspaceID,
			Path:           in.Path,
			Content:        in.Content,
			ExpectedSHA256: in.ExpectedSHA256,
			Overwrite:      overwrite,
		}

		p := session.FromContext(ctx)
		fp := approval.ComputeFingerprint(p.ClientID, "workspace.write", in.WorkspaceID, in)
		var outcome approval.ExecutionOutcome
		path := in.Path
		preview, err := d.FS.PreviewWrite(writeReq)
		if err != nil {
			outcome, err = replayAfterPrecheck(d.Broker, p.IsRemote, fp, err)
		} else {
			path = preview.Resolved.RelPath
			if writeReq.ExpectedSHA256 == "" && !preview.IsNewFile {
				writeReq.ExpectedSHA256 = preview.OldSHA256
			}
			writeReq.ApprovedPath = preview.Resolved.AbsPath
			actionWord := "覆写"
			if preview.IsNewFile {
				writeReq.Overwrite = false
				actionWord = "新建"
			}
			outcome, err = d.Broker.ExecuteWithApproval(ctx, approval.Request{
				SessionID:     p.SessionID,
				ClientID:      p.ClientID,
				IsRemote:      p.IsRemote,
				Fingerprint:   fp,
				Tool:          "workspace.write",
				WorkspaceID:   in.WorkspaceID,
				RiskLevel:     ev.RiskLevel,
				AllowBatchTTL: ev.AllowBatchTTL,
				TargetPath:    path,
				DiffPreview:   preview.UnifiedDiff,
				Summary:       fmt.Sprintf("%s工作区 %s 中的文件 %s (%d bytes)", actionWord, in.WorkspaceID, path, len(in.Content)),
				Reason:        ev.Reason,
			}, func() (any, error) {
				return d.FS.WriteFile(writeReq)
			}, makeProgressNotifier(callReq, "正在等待文件写入处理结果..."))
		}

		if err != nil {
			recordAudit(ctx, d.Audit, "workspace.write", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"path": path}, outcome.Decision.DecisionTag, outcome.Decision.Approver, start, err)
			return nil, nil, err
		}
		if outcome.Pending {
			status, message := pendingResponse(outcome)
			recordAudit(ctx, d.Audit, "workspace.write", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"path": path, "approval_id": outcome.ApprovalID}, status, outcome.Decision.Approver, start, nil)
			return nil, &filesystem.WriteResult{
				Source:      "local_workspace_write",
				WorkspaceID: in.WorkspaceID,
				Path:        path,
				Pending:     true,
				ApprovalID:  outcome.ApprovalID,
				Message:     message,
			}, nil
		}

		res, _ := outcome.Result.(*filesystem.WriteResult)
		recordAudit(ctx, d.Audit, "workspace.write", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"path": path, "created": res != nil && res.Created}, outcome.Decision.DecisionTag, outcome.Decision.Approver, start, nil)
		return nil, res, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "workspace.mkdir",
		Description: "在授权工作区内安全创建目录（默认 parents=true 支持递归创建缺失父目录，受工作区边界、敏感路径与人工审批约束；配合 workspace.move 移动文件到新目录前可先调用本工具）",
	}, func(ctx context.Context, callReq *mcp.CallToolRequest, in WorkspaceMkdirInput) (*mcp.CallToolResult, *filesystem.MkdirResult, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("workspace.mkdir")
		if err := authorizePrincipal(ctx, d, "workspace.mkdir", in.WorkspaceID, string(ev.RiskLevel), true, in, start); err != nil {
			return nil, nil, err
		}

		parents := true
		if in.Parents != nil {
			parents = *in.Parents
		}
		mkdirReq := filesystem.MkdirRequest{
			WorkspaceID: in.WorkspaceID,
			Path:        in.Path,
			Parents:     parents,
		}

		p := session.FromContext(ctx)
		fp := approval.ComputeFingerprint(p.ClientID, "workspace.mkdir", in.WorkspaceID, in)
		var outcome approval.ExecutionOutcome
		targetPath := in.Path
		preview, err := d.FS.PreviewMkdir(mkdirReq)
		if err != nil {
			outcome, err = replayAfterPrecheck(d.Broker, p.IsRemote, fp, err)
		} else {
			targetPath = preview.Resolved.RelPath
			mkdirReq.ApprovedPath = preview.Resolved.AbsPath
			outcome, err = d.Broker.ExecuteWithApproval(ctx, approval.Request{
				SessionID:     p.SessionID,
				ClientID:      p.ClientID,
				IsRemote:      p.IsRemote,
				Fingerprint:   fp,
				Tool:          "workspace.mkdir",
				WorkspaceID:   in.WorkspaceID,
				RiskLevel:     ev.RiskLevel,
				AllowBatchTTL: ev.AllowBatchTTL,
				TargetPath:    targetPath,
				Summary:       fmt.Sprintf("在工作区 %s 创建目录 %s", in.WorkspaceID, targetPath),
				Reason:        ev.Reason,
			}, func() (any, error) {
				return d.FS.Mkdir(mkdirReq)
			}, makeProgressNotifier(callReq, "正在等待目录创建处理结果..."))
		}

		if err != nil {
			recordAudit(ctx, d.Audit, "workspace.mkdir", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"path": targetPath, "parents": parents}, outcome.Decision.DecisionTag, outcome.Decision.Approver, start, err)
			return nil, nil, err
		}
		if outcome.Pending {
			status, message := pendingResponse(outcome)
			recordAudit(ctx, d.Audit, "workspace.mkdir", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"path": targetPath, "parents": parents, "approval_id": outcome.ApprovalID}, status, outcome.Decision.Approver, start, nil)
			return nil, &filesystem.MkdirResult{
				Source:      "local_workspace_mkdir",
				WorkspaceID: in.WorkspaceID,
				Path:        targetPath,
				Pending:     true,
				ApprovalID:  outcome.ApprovalID,
				Message:     message,
			}, nil
		}

		res, _ := outcome.Result.(*filesystem.MkdirResult)
		recordAudit(ctx, d.Audit, "workspace.mkdir", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"path": targetPath, "created": res != nil && res.Created}, outcome.Decision.DecisionTag, outcome.Decision.Approver, start, nil)
		return nil, res, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "workspace.move",
		Description: "在同一文件系统内重命名或移动文件和目录，目标父目录须已存在（如目标父目录尚不存在请先调用 workspace.mkdir；受工作区边界、敏感路径与人工审批约束）",
	}, func(ctx context.Context, callReq *mcp.CallToolRequest, in WorkspaceMoveInput) (*mcp.CallToolResult, *filesystem.MoveResult, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("workspace.move")
		if err := authorizePrincipal(ctx, d, "workspace.move", in.WorkspaceID, string(ev.RiskLevel), true, in, start); err != nil {
			return nil, nil, err
		}

		moveReq := filesystem.MoveRequest{
			WorkspaceID:     in.WorkspaceID,
			SourcePath:      in.SourcePath,
			DestinationPath: in.DestinationPath,
			Overwrite:       in.Overwrite,
		}

		p := session.FromContext(ctx)
		fp := approval.ComputeFingerprint(p.ClientID, "workspace.move", in.WorkspaceID, in)
		var outcome approval.ExecutionOutcome
		srcRel, dstRel := in.SourcePath, in.DestinationPath
		preview, err := d.FS.PreviewMove(moveReq)
		if err != nil {
			outcome, err = replayAfterPrecheck(d.Broker, p.IsRemote, fp, err)
		} else {
			srcRel = preview.Source.RelPath
			dstRel = preview.Destination.RelPath
			moveReq.ApprovedSource = preview.Source.AbsPath
			moveReq.ApprovedDestination = preview.Destination.AbsPath
			moveReq.Overwrite = moveReq.Overwrite && preview.DestExists
			outcome, err = d.Broker.ExecuteWithApproval(ctx, approval.Request{
				SessionID:     p.SessionID,
				ClientID:      p.ClientID,
				IsRemote:      p.IsRemote,
				Fingerprint:   fp,
				Tool:          "workspace.move",
				WorkspaceID:   in.WorkspaceID,
				RiskLevel:     ev.RiskLevel,
				AllowBatchTTL: ev.AllowBatchTTL,
				TargetPath:    fmt.Sprintf("%s -> %s", srcRel, dstRel),
				Summary:       fmt.Sprintf("移动工作区 %s 中的 %s -> %s", in.WorkspaceID, srcRel, dstRel),
				Reason:        ev.Reason,
			}, func() (any, error) {
				return d.FS.Move(moveReq)
			}, makeProgressNotifier(callReq, "正在等待文件移动处理结果..."))
		}

		if err != nil {
			recordAudit(ctx, d.Audit, "workspace.move", in.WorkspaceID, string(ev.RiskLevel), in, outcome.Decision.DecisionTag, outcome.Decision.Approver, start, err)
			return nil, nil, err
		}
		if outcome.Pending {
			status, message := pendingResponse(outcome)
			recordAudit(ctx, d.Audit, "workspace.move", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"source_path": srcRel, "destination_path": dstRel, "approval_id": outcome.ApprovalID}, status, outcome.Decision.Approver, start, nil)
			return nil, &filesystem.MoveResult{
				Source:          "local_workspace_move",
				WorkspaceID:     in.WorkspaceID,
				SourcePath:      srcRel,
				DestinationPath: dstRel,
				Pending:         true,
				ApprovalID:      outcome.ApprovalID,
				Message:         message,
			}, nil
		}

		res, _ := outcome.Result.(*filesystem.MoveResult)
		recordAudit(ctx, d.Audit, "workspace.move", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"source_path": srcRel, "destination_path": dstRel}, outcome.Decision.DecisionTag, outcome.Decision.Approver, start, nil)
		return nil, res, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "workspace.delete",
		Description: "删除工作区内的文件、符号链接或目录（删单文件/空目录为 L1 支持限时批授；传 recursive=true 删非空目录自动升级为 L2 强确认；始终禁止删除根目录与敏感路径）",
	}, func(ctx context.Context, callReq *mcp.CallToolRequest, in WorkspaceDeleteInput) (*mcp.CallToolResult, *filesystem.DeleteResult, error) {
		start := time.Now()
		baseEv := d.Policy.EvaluateDelete(in.Recursive)
		if err := authorizePrincipal(ctx, d, "workspace.delete", in.WorkspaceID, string(baseEv.RiskLevel), true, in, start); err != nil {
			return nil, nil, err
		}

		delReq := filesystem.DeleteRequest{
			WorkspaceID: in.WorkspaceID,
			Path:        in.Path,
			Recursive:   in.Recursive,
		}

		p := session.FromContext(ctx)
		fp := approval.ComputeFingerprint(p.ClientID, "workspace.delete", in.WorkspaceID, in)
		var outcome approval.ExecutionOutcome
		targetPath := in.Path
		ev := baseEv

		preview, err := d.FS.PreviewDelete(delReq)
		if err != nil {
			outcome, err = replayAfterPrecheck(d.Broker, p.IsRemote, fp, err)
		} else {
			targetPath = preview.Resolved.RelPath
			delReq.Recursive = preview.RecursiveNonEmpty
			delReq.ApprovedPath = preview.Resolved.AbsPath
			ev = d.Policy.EvaluateDelete(preview.RecursiveNonEmpty)
			summary := fmt.Sprintf("删除工作区 %s 中的 %s", in.WorkspaceID, targetPath)
			if preview.RecursiveNonEmpty {
				summary = fmt.Sprintf("递归删除工作区 %s 中的非空目录 %s（含约 %d 个条目）", in.WorkspaceID, targetPath, preview.EntryCount)
			}
			outcome, err = d.Broker.ExecuteWithApproval(ctx, approval.Request{
				SessionID:     p.SessionID,
				ClientID:      p.ClientID,
				IsRemote:      p.IsRemote,
				Fingerprint:   fp,
				Tool:          "workspace.delete",
				WorkspaceID:   in.WorkspaceID,
				RiskLevel:     ev.RiskLevel,
				AllowBatchTTL: ev.AllowBatchTTL,
				TargetPath:    targetPath,
				Summary:       summary,
				Reason:        ev.Reason,
			}, func() (any, error) {
				return d.FS.Delete(delReq)
			}, makeProgressNotifier(callReq, "正在等待删除处理结果..."))
		}

		if err != nil {
			recordAudit(ctx, d.Audit, "workspace.delete", in.WorkspaceID, string(ev.RiskLevel), in, outcome.Decision.DecisionTag, outcome.Decision.Approver, start, err)
			return nil, nil, err
		}
		if outcome.Pending {
			status, message := pendingResponse(outcome)
			recordAudit(ctx, d.Audit, "workspace.delete", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"path": targetPath, "recursive": in.Recursive, "approval_id": outcome.ApprovalID}, status, outcome.Decision.Approver, start, nil)
			return nil, &filesystem.DeleteResult{
				Source:      "local_workspace_delete",
				WorkspaceID: in.WorkspaceID,
				Path:        targetPath,
				Recursive:   in.Recursive,
				Pending:     true,
				ApprovalID:  outcome.ApprovalID,
				Message:     message,
			}, nil
		}

		res, _ := outcome.Result.(*filesystem.DeleteResult)
		recordAudit(ctx, d.Audit, "workspace.delete", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"path": targetPath, "recursive": res != nil && res.Recursive}, outcome.Decision.DecisionTag, outcome.Decision.Approver, start, nil)
		return nil, res, nil
	})
}

func registerGitTools(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "git.status",
		Description: "查看工作区或指定 Git 仓库目录的分支及变更状态",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in GitStatusInput) (*mcp.CallToolResult, *git.StatusResult, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("git.status")
		if err := authorizePrincipal(ctx, d, "git.status", in.WorkspaceID, string(ev.RiskLevel), false, in, start); err != nil {
			return nil, nil, err
		}
		if d.Git == nil {
			err := errors.New("当前宿主机未检测到 Git 可执行程序")
			recordAudit(ctx, d.Audit, "git.status", in.WorkspaceID, string(ev.RiskLevel), in, "UNAVAILABLE", "", start, err)
			return nil, nil, err
		}
		res, err := d.Git.StatusAt(ctx, in.WorkspaceID, in.Path)
		recordAudit(ctx, d.Audit, "git.status", in.WorkspaceID, string(ev.RiskLevel), in, "AUTO_ALLOW", "", start, err)
		return nil, res, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "git.diff",
		Description: "查看工作区、暂存区或任意分支/提交范围（base/target）的变更差异",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in GitDiffInput) (*mcp.CallToolResult, *git.DiffResult, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("git.diff")
		if err := authorizePrincipal(ctx, d, "git.diff", in.WorkspaceID, string(ev.RiskLevel), false, in, start); err != nil {
			return nil, nil, err
		}
		if d.Git == nil {
			err := errors.New("当前宿主机未检测到 Git 可执行程序")
			recordAudit(ctx, d.Audit, "git.diff", in.WorkspaceID, string(ev.RiskLevel), in, "UNAVAILABLE", "", start, err)
			return nil, nil, err
		}
		res, err := d.Git.DiffRangeAt(ctx, in.WorkspaceID, in.Path, in.Staged, in.Base, in.Target, in.Paths, in.MaxBytes)
		recordAudit(ctx, d.Audit, "git.diff", in.WorkspaceID, string(ev.RiskLevel), in, "AUTO_ALLOW", "", start, err)
		return nil, res, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "git.log",
		Description: "查看工作区或指定 Git 仓库目录的提交历史（支持 ref 范围与单文件/目录路径过滤）",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in GitLogInput) (*mcp.CallToolResult, *git.LogResult, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("git.log")
		if err := authorizePrincipal(ctx, d, "git.log", in.WorkspaceID, string(ev.RiskLevel), false, in, start); err != nil {
			return nil, nil, err
		}
		if d.Git == nil {
			err := errors.New("当前宿主机未检测到 Git 可执行程序")
			recordAudit(ctx, d.Audit, "git.log", in.WorkspaceID, string(ev.RiskLevel), in, "UNAVAILABLE", "", start, err)
			return nil, nil, err
		}
		res, err := d.Git.LogAt(ctx, in.WorkspaceID, in.Path, in.Ref, in.FilePath, in.Limit)
		recordAudit(ctx, d.Audit, "git.log", in.WorkspaceID, string(ev.RiskLevel), in, "AUTO_ALLOW", "", start, err)
		return nil, res, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "git.show",
		Description: "查看指定提交的详情与代码差异（自动排除敏感密钥文件并执行输出脱敏）",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in GitShowInput) (*mcp.CallToolResult, *git.ShowResult, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("git.show")
		if err := authorizePrincipal(ctx, d, "git.show", in.WorkspaceID, string(ev.RiskLevel), false, in, start); err != nil {
			return nil, nil, err
		}
		if d.Git == nil {
			err := errors.New("当前宿主机未检测到 Git 可执行程序")
			recordAudit(ctx, d.Audit, "git.show", in.WorkspaceID, string(ev.RiskLevel), in, "UNAVAILABLE", "", start, err)
			return nil, nil, err
		}
		res, err := d.Git.ShowAt(ctx, in.WorkspaceID, in.Path, in.Ref, in.StatOnly, in.MaxBytes)
		recordAudit(ctx, d.Audit, "git.show", in.WorkspaceID, string(ev.RiskLevel), in, "AUTO_ALLOW", "", start, err)
		return nil, res, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "git.apply_patch",
		Description: "在安全校验与人工审批（或全权限模式免审批）后，向工作区或指定 Git 仓库应用标准 Unified Diff 补丁",
	}, func(ctx context.Context, callReq *mcp.CallToolRequest, in GitApplyPatchInput) (*mcp.CallToolResult, *git.ApplyPatchResult, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("git.apply_patch")
		if err := authorizePrincipal(ctx, d, "git.apply_patch", in.WorkspaceID, string(ev.RiskLevel), true, map[string]any{"workspace_id": in.WorkspaceID, "path": in.Path}, start); err != nil {
			return nil, nil, err
		}
		if d.Git == nil {
			err := errors.New("当前宿主机未检测到 Git 可执行程序")
			recordAudit(ctx, d.Audit, "git.apply_patch", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"workspace_id": in.WorkspaceID, "path": in.Path}, "UNAVAILABLE", "", start, err)
			return nil, nil, err
		}

		p := session.FromContext(ctx)
		fp := approval.ComputeFingerprint(p.ClientID, "git.apply_patch", in.WorkspaceID, in)
		var outcome approval.ExecutionOutcome
		affected, err := d.Git.ValidatePatchAt(ctx, in.WorkspaceID, in.Path, in.Patch)
		if err != nil {
			outcome, err = replayAfterPrecheck(d.Broker, p.IsRemote, fp, err)
		} else {
			outcome, err = d.Broker.ExecuteWithApproval(ctx, approval.Request{
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
				return d.Git.ApplyPatchAt(context.Background(), in.WorkspaceID, in.Path, in.Patch)
			}, makeProgressNotifier(callReq, "正在等待 Git 补丁处理结果..."))
		}

		if err != nil {
			recordAudit(ctx, d.Audit, "git.apply_patch", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"path": in.Path, "files": affected}, outcome.Decision.DecisionTag, outcome.Decision.Approver, start, err)
			return nil, nil, err
		}
		if outcome.Pending {
			status, message := pendingResponse(outcome)
			recordAudit(ctx, d.Audit, "git.apply_patch", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"files": affected, "approval_id": outcome.ApprovalID}, status, outcome.Decision.Approver, start, nil)
			if affected == nil {
				affected = []string{}
			}
			return nil, &git.ApplyPatchResult{
				Source:        "git_output",
				WorkspaceID:   in.WorkspaceID,
				AffectedFiles: affected,
				Pending:       true,
				ApprovalID:    outcome.ApprovalID,
				Message:       message,
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
		Description: "在授权工作区内启动受分层安全策略和人工审批约束的命令行任务。默认最多短等待 10 秒（上限 30 秒，传 wait_seconds=0 可立即异步返回 task_id），短命令可直接返回完整输出与退出码",
	}, func(ctx context.Context, callReq *mcp.CallToolRequest, in TerminalStartInput) (*mcp.CallToolResult, *TerminalStartOutput, error) {
		start := time.Now()
		// 1. 策略预估 + 客户端级工作区/只读权限校验
		ev := d.Policy.EvaluateCommand(in.Executable, in.Args, in.UseShell)
		requiresWrite := ev.RiskLevel != policy.RiskL0
		if err := authorizePrincipal(ctx, d, "terminal.start", in.WorkspaceID, string(ev.RiskLevel), requiresWrite, in, start); err != nil {
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

		waitDur := resolveStartWaitDuration(in.WaitSeconds)
		p := session.FromContext(ctx)

		buildStartOutput := func(waitCtx context.Context) (*TerminalStartOutput, error) {
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

			out := &TerminalStartOutput{
				Source:      "terminal_task",
				TaskID:      rec.ID,
				WorkspaceID: rec.WorkspaceID,
				Status:      rec.Status,
				RiskLevel:   string(ev.RiskLevel),
				Cwd:         resolvedCwd.RelPath,
			}

			if waitDur > 0 {
				if pollRes, pollErr := d.Tasks.WaitUntilTerminal(waitCtx, rec.ID, waitDur); pollErr == nil && pollRes != nil {
					out.Status = string(pollRes.Status)
					out.ExitCode = pollRes.ExitCode
					out.ErrorMessage = pollRes.ErrorMessage
					out.Stdout = pollRes.StdoutChunk
					out.Stderr = pollRes.StderrChunk
					out.StdoutNextOff = pollRes.StdoutNextOff
					out.StderrNextOff = pollRes.StderrNextOff
					out.StdoutTruncated = pollRes.StdoutTruncated
					out.StderrTruncated = pollRes.StderrTruncated
					out.StdoutTail = pollRes.StdoutTail
					out.StderrTail = pollRes.StderrTail
					out.ElapsedMs = pollRes.ElapsedMs
				}
			}
			return out, nil
		}

		// 3. 急停检查与按需混合人工审批（远程客户端在全权限模式下同样经 Broker 复用指纹幂等去重与急停校验）
		if ev.Action == policy.ActionRequireApproval || (p.IsRemote && ev.BypassedByFullPerms) {
			cmdPreview := formatCommandPreview(in)
			execArgs := in
			execArgs.WaitSeconds = nil // Waiting changes the response, not the command.
			fp := approval.ComputeFingerprint(p.ClientID, "terminal.start", in.WorkspaceID, execArgs)
			execCtx := ctx
			if p.IsRemote {
				// 远程审批回调可能在原 HTTP 短窗口到期后由用户异步批准触发，使用独立上下文保证短等待收集完整输出供 approval.status 取回
				execCtx = context.Background()
			}
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
			}, func() (any, error) {
				return buildStartOutput(execCtx)
			}, makeProgressNotifier(callReq, "正在等待命令启动与输出..."))

			if err != nil {
				recordAudit(ctx, d.Audit, "terminal.start", in.WorkspaceID, string(ev.RiskLevel), in, outcome.Decision.DecisionTag, outcome.Decision.Approver, start, err)
				return nil, nil, err
			}
			if outcome.Pending {
				status, message := pendingResponse(outcome)
				recordAudit(ctx, d.Audit, "terminal.start", in.WorkspaceID, string(ev.RiskLevel), map[string]any{"executable": in.Executable, "approval_id": outcome.ApprovalID}, status, outcome.Decision.Approver, start, nil)
				return nil, &TerminalStartOutput{
					Source:      "terminal_task",
					WorkspaceID: in.WorkspaceID,
					Status:      status,
					RiskLevel:   string(ev.RiskLevel),
					Cwd:         resolvedCwd.RelPath,
					Pending:     true,
					ApprovalID:  outcome.ApprovalID,
					Message:     message,
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

		out, err := buildStartOutput(ctx)
		decisionTag := "AUTO_ALLOW"
		approver := ""
		if ev.BypassedByFullPerms {
			decisionTag = "AUTO_ALLOW_FULL_PERMISSIONS"
			approver = "full-permissions-mode"
		}
		recordAudit(ctx, d.Audit, "terminal.start", in.WorkspaceID, string(ev.RiskLevel), in, decisionTag, approver, start, err)
		if err != nil {
			return nil, nil, err
		}
		return nil, out, nil
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "terminal.poll",
		Description: "查询异步终端任务的运行状态、退出码、增量 stdout/stderr 输出及截断尾部日志（支持可选 wait_seconds 长轮询，上限 30 秒）",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in TerminalPollInput) (*mcp.CallToolResult, *task.PollResult, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("terminal.poll")

		// 先按当前状态执行一次权限校验，避免越权客户端进入长轮询等待
		wsID, err := d.Tasks.WorkspaceID(in.TaskID)
		if err != nil {
			recordAudit(ctx, d.Audit, "terminal.poll", wsID, string(ev.RiskLevel), in, "AUTO_ALLOW", "", start, err)
			return nil, nil, err
		}
		if err := authorizePrincipal(ctx, d, "terminal.poll", wsID, string(ev.RiskLevel), false, in, start); err != nil {
			return nil, nil, err
		}

		waitDur := resolvePollWaitDuration(in.WaitSeconds)
		res, err := d.Tasks.PollWait(ctx, in.TaskID, in.StdoutOffset, in.StderrOffset, waitDur)
		recordAudit(ctx, d.Audit, "terminal.poll", wsID, string(ev.RiskLevel), in, "AUTO_ALLOW", "", start, err)
		return nil, res, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "terminal.cancel",
		Description: "立即取消正在排队或运行中的终端任务并终止其完整子进程树",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in TerminalCancelInput) (*mcp.CallToolResult, *TerminalCancelOutput, error) {
		start := time.Now()
		ev := d.Policy.EvaluateTool("terminal.cancel")
		// 先校验只读权限，防止只读客户端借取消操作探测 task_id 存在性
		if authErr := authorizePrincipal(ctx, d, "terminal.cancel", "", string(ev.RiskLevel), true, in, start); authErr != nil {
			return nil, nil, authErr
		}
		if existing, pollErr := d.Tasks.Poll(in.TaskID, 0, 0); pollErr == nil && existing != nil {
			if authErr := authorizePrincipal(ctx, d, "terminal.cancel", existing.WorkspaceID, string(ev.RiskLevel), true, in, start); authErr != nil {
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
		if err := authorizePrincipal(ctx, d, "approval.status", rec.WorkspaceID, string(ev.RiskLevel), false, in, start); err != nil {
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

func resolveStartWaitDuration(waitSeconds *int) time.Duration {
	sec := defaultTerminalStartWaitSec
	if waitSeconds != nil {
		sec = *waitSeconds
	}
	if sec <= 0 {
		return 0
	}
	if sec > maxTerminalWaitSec {
		sec = maxTerminalWaitSec
	}
	return time.Duration(sec) * time.Second
}

func resolvePollWaitDuration(waitSeconds int) time.Duration {
	if waitSeconds <= 0 {
		return 0
	}
	if waitSeconds > maxTerminalWaitSec {
		waitSeconds = maxTerminalWaitSec
	}
	return time.Duration(waitSeconds) * time.Second
}

// authorizePrincipal 执行阶段二客户端级工作区子集与只读权限护栏校验。
// 遵循最小权限原则：单个 OAuth 客户端显式绑定的只读模式始终生效，不会被全局「全部权限」静默突破；
// 当开启「默认全部目录模式」时放开工作区白名单限制，允许可读写或只读客户端按自身读写级别访问任意普通目录。
func authorizePrincipal(
	ctx context.Context,
	d Deps,
	toolName, workspaceID, risk string,
	requiresWrite bool,
	args any,
	start time.Time,
) error {
	p := session.FromContext(ctx)
	allowAllDirs := d.FS != nil && d.FS.AllowAllDirs()

	if !allowAllDirs && workspaceID != "" && !p.CanAccessWorkspace(workspaceID) {
		err := fmt.Errorf("当前远程客户端（%s）未被授权访问工作区 %q", p.ClientName, workspaceID)
		recordAudit(ctx, d.Audit, toolName, workspaceID, risk, args, "CLIENT_WORKSPACE_DENIED", "", start, err)
		return err
	}
	if requiresWrite && !p.HasWritePermission() {
		err := fmt.Errorf("当前远程客户端（%s）处于只读授权模式，禁止执行写入或变更类操作 %q", p.ClientName, toolName)
		recordAudit(ctx, d.Audit, toolName, workspaceID, risk, args, "CLIENT_READONLY_DENIED", "", start, err)
		return err
	}
	return nil
}

// replayAfterPrecheck 只复用当前远程客户端的已有工单，保留预检中的权限拒绝。
func replayAfterPrecheck(broker *approval.Broker, remote bool, fingerprint string, precheckErr error) (approval.ExecutionOutcome, error) {
	if remote && !errors.Is(precheckErr, filesystem.ErrAccessDenied) {
		if outcome, found, err := broker.LookupIdempotent(fingerprint); found {
			return outcome, err
		}
	}
	return approval.ExecutionOutcome{Decision: approval.Decision{DecisionTag: "DENIED_PRECHECK"}}, precheckErr
}

func pendingResponse(outcome approval.ExecutionOutcome) (status, message string) {
	if outcome.Decision.Approved {
		return "EXECUTION_PENDING", fmt.Sprintf("审批单 %s 已获批准，操作正在后台执行。请调用 approval.status 查询执行结果。", outcome.ApprovalID)
	}
	return "APPROVAL_PENDING", fmt.Sprintf("审批单 %s 正在等待用户在本地控制台确认。批准后请调用 approval.status 查询执行结果。", outcome.ApprovalID)
}

// makeProgressNotifier 在同步等待期间向 MCP 客户端推送进度。
func makeProgressNotifier(callReq *mcp.CallToolRequest, msg string) func(context.Context, time.Duration) {
	if callReq == nil || callReq.Session == nil || callReq.Params == nil {
		return nil
	}
	tok := callReq.Params.GetProgressToken()
	if tok == nil {
		return nil
	}
	return func(ctx context.Context, elapsed time.Duration) {
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
