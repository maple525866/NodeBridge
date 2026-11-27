// Package git 封装受控 Git CLI 能力（status / diff / apply_patch），所有路径均经过工作区安全校验。
package git

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"nodebridge/internal/platform/filesystem"
)

const (
	defaultGitTimeout = 30 * time.Second
	defaultMaxDiff    = 256 * 1024 // 默认最大返回 256KB Diff
)

// Adapter 提供面向授权工作区的受控 Git 操作。
type Adapter struct {
	fsMgr   *filesystem.Manager
	gitPath string
}

// StatusResult 表示 git.status 的结构化输出。
type StatusResult struct {
	Source      string   `json:"source"`
	WorkspaceID string   `json:"workspace_id"`
	Branch      string   `json:"branch"`
	Clean       bool     `json:"clean"`
	Changed     []string `json:"changed"`
	Untracked   []string `json:"untracked"`
	Raw         string   `json:"raw"`
}

// DiffResult 表示 git.diff 的返回结果。
type DiffResult struct {
	Source      string `json:"source"`
	WorkspaceID string `json:"workspace_id"`
	Staged      bool   `json:"staged"`
	Truncated   bool   `json:"truncated"`
	Diff        string `json:"diff"`
}

// ApplyPatchResult 表示 git.apply_patch 的执行结果（或远程异步等待审批时的挂起提示）。
type ApplyPatchResult struct {
	Source        string   `json:"source"`
	WorkspaceID   string   `json:"workspace_id"`
	AffectedFiles []string `json:"affected_files"`
	Message       string   `json:"message"`
	Pending       bool     `json:"pending,omitempty"`
	ApprovalID    string   `json:"approval_id,omitempty"`
}

// NewAdapter 创建受控 Git 适配器。
func NewAdapter(fsMgr *filesystem.Manager) (*Adapter, error) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return nil, fmt.Errorf("未检测到系统 Git 可执行文件: %w", err)
	}
	return &Adapter{
		fsMgr:   fsMgr,
		gitPath: gitPath,
	}, nil
}

// Status 查看授权工作区的 Git 分支与变更状态。
func (a *Adapter) Status(ctx context.Context, workspaceID string) (*StatusResult, error) {
	return a.StatusAt(ctx, workspaceID, "")
}

// StatusAt 查看指定目录（默认工作区根目录；开启全部目录模式时可为宿主机任意目录）的 Git 状态。
func (a *Adapter) StatusAt(ctx context.Context, workspaceID, repoPath string) (*StatusResult, error) {
	resolved, err := a.fsMgr.Resolve(workspaceID, repoPath, false)
	if err != nil {
		return nil, err
	}
	ws := resolved.Workspace
	stdout, stderr, err := a.runGit(ctx, resolved.AbsPath, nil, "status", "--porcelain=v2", "--branch")
	if err != nil {
		return nil, fmt.Errorf("git status 失败: %v (%s)", err, strings.TrimSpace(stderr))
	}

	res := &StatusResult{
		Source:      "git_output",
		WorkspaceID: workspaceID,
		Raw:         stdout,
	}
	for _, line := range strings.Split(strings.ReplaceAll(stdout, "\r\n", "\n"), "\n") {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "# branch.head ") {
			res.Branch = strings.TrimPrefix(line, "# branch.head ")
			continue
		}
		if strings.HasPrefix(line, "? ") {
			p := strings.TrimPrefix(line, "? ")
			if !a.fsMgr.IsSensitive(ws, p) {
				res.Untracked = append(res.Untracked, p)
			}
			continue
		}
		if strings.HasPrefix(line, "1 ") || strings.HasPrefix(line, "2 ") || strings.HasPrefix(line, "u ") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				p := fields[len(fields)-1]
				if !a.fsMgr.IsSensitive(ws, p) {
					res.Changed = append(res.Changed, p)
				}
			}
		}
	}
	res.Clean = len(res.Changed) == 0 && len(res.Untracked) == 0
	return res, nil
}

// Diff 查看工作区或暂存区变更差异，严格校验指定路径并按上限截断。
func (a *Adapter) Diff(ctx context.Context, workspaceID string, staged bool, paths []string, maxBytes int) (*DiffResult, error) {
	return a.DiffAt(ctx, workspaceID, "", staged, paths, maxBytes)
}

// DiffAt 查看指定 Git 仓库目录（默认工作区根目录）的变更差异。
func (a *Adapter) DiffAt(ctx context.Context, workspaceID, repoPath string, staged bool, paths []string, maxBytes int) (*DiffResult, error) {
	resolvedRepo, err := a.fsMgr.Resolve(workspaceID, repoPath, false)
	if err != nil {
		return nil, err
	}
	if maxBytes <= 0 || maxBytes > 2*1024*1024 {
		maxBytes = defaultMaxDiff
	}

	args := []string{"diff", "--no-ext-diff"}
	if staged {
		args = append(args, "--cached")
	}
	if len(paths) > 0 {
		args = append(args, "--")
		for _, p := range paths {
			target := p
			if strings.TrimSpace(repoPath) != "" && !filepath.IsAbs(p) {
				target = filepath.Join(resolvedRepo.AbsPath, filepath.FromSlash(p))
			}
			resolved, err := a.fsMgr.Resolve(workspaceID, target, false)
			if err != nil {
				return nil, err
			}
			gitRel := resolved.RelPath
			if rel, relErr := filepath.Rel(resolvedRepo.AbsPath, resolved.AbsPath); relErr == nil {
				gitRel = filepath.ToSlash(rel)
			}
			args = append(args, gitRel)
		}
	}

	stdout, stderr, err := a.runGit(ctx, resolvedRepo.AbsPath, nil, args...)
	if err != nil {
		return nil, fmt.Errorf("git diff 失败: %v (%s)", err, strings.TrimSpace(stderr))
	}

	truncated := false
	if len(stdout) > maxBytes {
		stdout = stdout[:maxBytes] + "\n...(diff truncated)"
		truncated = true
	}

	return &DiffResult{
		Source:      "git_output",
		WorkspaceID: workspaceID,
		Staged:      staged,
		Truncated:   truncated,
		Diff:        stdout,
	}, nil
}

// ValidatePatch 在人工审批前解析补丁涉及的全部文件路径并进行目录/敏感文件安全校验与 `git apply --check` 预检。
func (a *Adapter) ValidatePatch(ctx context.Context, workspaceID, patchText string) ([]string, error) {
	return a.ValidatePatchAt(ctx, workspaceID, "", patchText)
}

// ValidatePatchAt 针对指定仓库目录预检标准 Unified Diff 补丁。
func (a *Adapter) ValidatePatchAt(ctx context.Context, workspaceID, repoPath, patchText string) ([]string, error) {
	if strings.TrimSpace(patchText) == "" {
		return nil, errors.New("补丁内容 patch 不能为空")
	}
	resolvedRepo, err := a.fsMgr.Resolve(workspaceID, repoPath, false)
	if err != nil {
		return nil, err
	}
	ws := resolvedRepo.Workspace
	if ws.ReadOnly && !a.fsMgr.FullPermissions() {
		return nil, fmt.Errorf("%w: 工作区 %q 为只读模式，禁止应用补丁", filesystem.ErrAccessDenied, workspaceID)
	}

	files, err := ExtractPatchPaths(patchText)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, errors.New("补丁中未解析到任何有效目标文件路径")
	}

	// 逐个文件做路径穿越、符号链接逃逸和敏感文件校验
	validated := make([]string, 0, len(files))
	for _, f := range files {
		target := f
		if strings.TrimSpace(repoPath) != "" && !filepath.IsAbs(f) {
			target = filepath.Join(resolvedRepo.AbsPath, filepath.FromSlash(f))
		}
		resolved, err := a.fsMgr.Resolve(workspaceID, target, true)
		if err != nil {
			return nil, fmt.Errorf("补丁目标路径校验失败 (%s): %w", f, err)
		}
		validated = append(validated, resolved.RelPath)
	}

	// 调用 git apply --check 预检补丁能否干净应用
	_, stderr, err := a.runGit(ctx, resolvedRepo.AbsPath, []byte(patchText), "apply", "--check", "-")
	if err != nil {
		return nil, fmt.Errorf("git apply --check 预检失败: %v (%s)", err, strings.TrimSpace(stderr))
	}
	return validated, nil
}

// ApplyPatch 校验后将标准 Unified Diff 补丁应用到授权工作区。
func (a *Adapter) ApplyPatch(ctx context.Context, workspaceID, patchText string) (*ApplyPatchResult, error) {
	return a.ApplyPatchAt(ctx, workspaceID, "", patchText)
}

// ApplyPatchAt 校验后将标准 Unified Diff 补丁应用到指定仓库目录。
func (a *Adapter) ApplyPatchAt(ctx context.Context, workspaceID, repoPath, patchText string) (*ApplyPatchResult, error) {
	files, err := a.ValidatePatchAt(ctx, workspaceID, repoPath, patchText)
	if err != nil {
		return nil, err
	}
	resolvedRepo, err := a.fsMgr.Resolve(workspaceID, repoPath, false)
	if err != nil {
		return nil, err
	}
	_, stderr, err := a.runGit(ctx, resolvedRepo.AbsPath, []byte(patchText), "apply", "-")
	if err != nil {
		return nil, fmt.Errorf("git apply 执行失败: %v (%s)", err, strings.TrimSpace(stderr))
	}
	return &ApplyPatchResult{
		Source:        "git_apply_patch",
		WorkspaceID:   workspaceID,
		AffectedFiles: files,
		Message:       fmt.Sprintf("已成功应用补丁，涉及 %d 个文件", len(files)),
	}, nil
}

// ExtractPatchPaths 从标准 Unified Diff / Git Diff 中提取所有待修改或新建的文件路径。
func ExtractPatchPaths(patchText string) ([]string, error) {
	seen := make(map[string]struct{})
	var files []string
	addPath := func(raw string) {
		p := strings.TrimSpace(raw)
		if idx := strings.IndexByte(p, '\t'); idx >= 0 {
			p = p[:idx]
		}
		p = strings.Trim(p, `"`)
		if p == "" || p == "/dev/null" {
			return
		}
		if strings.HasPrefix(p, "a/") || strings.HasPrefix(p, "b/") {
			p = p[2:]
		}
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			files = append(files, p)
		}
	}

	for _, line := range strings.Split(strings.ReplaceAll(patchText, "\r\n", "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "diff --git "):
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				addPath(parts[2])
				addPath(parts[3])
			}
		case strings.HasPrefix(line, "--- "):
			addPath(strings.TrimPrefix(line, "--- "))
		case strings.HasPrefix(line, "+++ "):
			addPath(strings.TrimPrefix(line, "+++ "))
		case strings.HasPrefix(line, "rename from "):
			addPath(strings.TrimPrefix(line, "rename from "))
		case strings.HasPrefix(line, "rename to "):
			addPath(strings.TrimPrefix(line, "rename to "))
		}
	}
	return files, nil
}

func (a *Adapter) runGit(ctx context.Context, cwd string, stdin []byte, args ...string) (string, string, error) {
	runCtx, cancel := context.WithTimeout(ctx, defaultGitTimeout)
	defer cancel()

	// 禁用外部 hooks 与终端交互提示，降低恶意仓库通过 .git/config 或钩子执行任意代码的风险
	fullArgs := append([]string{"-c", "core.hooksPath=", "-c", "protocol.ext.allow=never"}, args...)
	cmd := exec.CommandContext(runCtx, a.gitPath, fullArgs...)
	cmd.Dir = cwd
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}
