// Package git 封装受控 Git CLI 能力（status / diff / apply_patch），所有路径均经过工作区安全校验。
package git

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"nodebridge/internal/core/audit"
	"nodebridge/internal/platform/filesystem"
)

const (
	defaultGitTimeout = 30 * time.Second
	defaultMaxDiff    = 256 * 1024 // 默认最大返回 256KB Diff
	defaultLogLimit   = 20
	maxLogLimit       = 100
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
	Base        string `json:"base,omitempty"`
	Target      string `json:"target,omitempty"`
	Truncated   bool   `json:"truncated"`
	Diff        string `json:"diff"`
}

// LogCommit 表示 git.log 中的单条提交记录。
type LogCommit struct {
	Hash      string `json:"hash"`
	ShortHash string `json:"short_hash"`
	Author    string `json:"author"`
	Date      string `json:"date"`
	Subject   string `json:"subject"`
}

// LogResult 表示 git.log 的返回结果。
type LogResult struct {
	Source      string      `json:"source"`
	WorkspaceID string      `json:"workspace_id"`
	Ref         string      `json:"ref,omitempty"`
	Commits     []LogCommit `json:"commits"`
	Truncated   bool        `json:"truncated,omitempty"`
}

// ShowResult 表示 git.show 的返回结果。
type ShowResult struct {
	Source      string `json:"source"`
	WorkspaceID string `json:"workspace_id"`
	Ref         string `json:"ref"`
	Hash        string `json:"hash"`
	ShortHash   string `json:"short_hash"`
	Author      string `json:"author"`
	Date        string `json:"date"`
	Subject     string `json:"subject"`
	Body        string `json:"body,omitempty"`
	StatOnly    bool   `json:"stat_only,omitempty"`
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
	}
	var filteredRaw []string
	for _, line := range strings.Split(strings.ReplaceAll(stdout, "\r\n", "\n"), "\n") {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "# branch.head ") {
			res.Branch = strings.TrimPrefix(line, "# branch.head ")
			filteredRaw = append(filteredRaw, line)
			continue
		}
		if strings.HasPrefix(line, "# ") {
			filteredRaw = append(filteredRaw, line)
			continue
		}
		if strings.HasPrefix(line, "? ") {
			p := strings.TrimPrefix(line, "? ")
			if !a.fsMgr.IsSensitive(ws, p) {
				res.Untracked = append(res.Untracked, p)
				filteredRaw = append(filteredRaw, line)
			}
			continue
		}
		if strings.HasPrefix(line, "1 ") || strings.HasPrefix(line, "2 ") || strings.HasPrefix(line, "u ") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				p := fields[len(fields)-1]
				if !a.fsMgr.IsSensitive(ws, p) {
					res.Changed = append(res.Changed, p)
					filteredRaw = append(filteredRaw, line)
				}
			}
		}
	}
	res.Raw = strings.Join(filteredRaw, "\n")
	res.Clean = len(res.Changed) == 0 && len(res.Untracked) == 0
	return res, nil
}

// Diff 查看工作区或暂存区变更差异，严格校验指定路径并按上限截断。
func (a *Adapter) Diff(ctx context.Context, workspaceID string, staged bool, paths []string, maxBytes int) (*DiffResult, error) {
	return a.DiffAt(ctx, workspaceID, "", staged, paths, maxBytes)
}

// DiffAt 查看指定 Git 仓库目录（默认工作区根目录）的变更差异。
func (a *Adapter) DiffAt(ctx context.Context, workspaceID, repoPath string, staged bool, paths []string, maxBytes int) (*DiffResult, error) {
	return a.DiffRangeAt(ctx, workspaceID, repoPath, staged, "", "", paths, maxBytes)
}

// DiffRangeAt 查看指定 Git 仓库目录的变更差异，支持可选 base / target ref 对比（如 main...HEAD、HEAD~1）。
func (a *Adapter) DiffRangeAt(ctx context.Context, workspaceID, repoPath string, staged bool, baseRef, targetRef string, paths []string, maxBytes int) (*DiffResult, error) {
	resolvedRepo, err := a.fsMgr.Resolve(workspaceID, repoPath, false)
	if err != nil {
		return nil, err
	}
	if maxBytes <= 0 || maxBytes > 2*1024*1024 {
		maxBytes = defaultMaxDiff
	}

	baseRef = strings.TrimSpace(baseRef)
	targetRef = strings.TrimSpace(targetRef)
	if targetRef != "" && (staged || baseRef == "") {
		return nil, errors.New("target 必须与 base 搭配使用，且不能与 staged 同时使用")
	}
	args := []string{"diff", "--no-ext-diff", "--no-textconv"}
	if staged {
		args = append(args, "--cached")
	}
	if baseRef != "" {
		base, err := a.resolveRevision(ctx, resolvedRepo.AbsPath, baseRef, targetRef == "" && !staged)
		if err != nil {
			return nil, err
		}
		args = append(args, base)
	}
	if targetRef != "" {
		target, err := a.resolveCommit(ctx, resolvedRepo.AbsPath, targetRef)
		if err != nil {
			return nil, err
		}
		args = append(args, target)
	}
	specs, err := a.visiblePathspecs(resolvedRepo, workspaceID, paths)
	if err != nil {
		return nil, err
	}
	stdout, truncated, err := a.readDiff(ctx, resolvedRepo.AbsPath, maxBytes, append(args, specs...))
	if err != nil {
		return nil, err
	}

	return &DiffResult{
		Source:      "git_output",
		WorkspaceID: workspaceID,
		Staged:      staged,
		Base:        baseRef,
		Target:      targetRef,
		Truncated:   truncated,
		Diff:        stdout,
	}, nil
}

// LogAt 查看指定 Git 仓库目录的提交历史（支持 ref 与安全校验后的单文件/目录路径过滤）。
func (a *Adapter) LogAt(ctx context.Context, workspaceID, repoPath, ref, filePath string, limit int) (*LogResult, error) {
	resolvedRepo, err := a.fsMgr.Resolve(workspaceID, repoPath, false)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = defaultLogLimit
	}
	if limit > maxLogLimit {
		limit = maxLogLimit
	}
	ref = strings.TrimSpace(ref)
	args := []string{
		"log", "--no-notes", "--no-show-signature", fmt.Sprintf("-n%d", limit),
		"--format=%H%x00%h%x00%an%x00%aI%x00%s", "-z",
	}
	if ref != "" {
		resolved, err := a.resolveRevision(ctx, resolvedRepo.AbsPath, ref, true)
		if err != nil {
			return nil, err
		}
		args = append(args, resolved)
	}
	var paths []string
	if strings.TrimSpace(filePath) != "" {
		paths = []string{filePath}
	}
	specs, err := a.visiblePathspecs(resolvedRepo, workspaceID, paths)
	if err != nil {
		return nil, err
	}
	stdout, truncated, err := a.readGit(ctx, resolvedRepo.AbsPath, defaultMaxDiff, append(args, specs...)...)
	if err != nil {
		return nil, err
	}

	commits := make([]LogCommit, 0)
	fields := strings.Split(stdout, "\x00")
	for len(fields) > 5 { // the fifth field must have a terminating NUL
		commits = append(commits, LogCommit{
			Hash:      fields[0],
			ShortHash: fields[1],
			Author:    audit.RedactPrivateSecrets(fields[2]),
			Date:      fields[3],
			Subject:   audit.RedactPrivateSecrets(fields[4]),
		})
		fields = fields[5:]
	}

	return &LogResult{
		Source:      "git_output",
		WorkspaceID: workspaceID,
		Ref:         ref,
		Commits:     commits,
		Truncated:   truncated,
	}, nil
}

// ShowAt 查看指定提交的元数据与差异（强制排除敏感密钥路径并执行输出脱敏）。
func (a *Adapter) ShowAt(ctx context.Context, workspaceID, repoPath, ref string, statOnly bool, maxBytes int) (*ShowResult, error) {
	resolvedRepo, err := a.fsMgr.Resolve(workspaceID, repoPath, false)
	if err != nil {
		return nil, err
	}
	if maxBytes <= 0 || maxBytes > 2*1024*1024 {
		maxBytes = defaultMaxDiff
	}
	ref = strings.TrimSpace(ref)
	if ref == "" {
		ref = "HEAD"
	}
	oid, err := a.resolveCommit(ctx, resolvedRepo.AbsPath, ref)
	if err != nil {
		return nil, err
	}
	specs, err := a.visiblePathspecs(resolvedRepo, workspaceID, nil)
	if err != nil {
		return nil, err
	}
	metaArgs := []string{"show", "--no-patch", "--no-notes", "--no-show-signature", "--format=%H%x00%h%x00%an%x00%aI%x00%s%x00%b", oid}
	metaOut, metaTruncated, err := a.readGit(ctx, resolvedRepo.AbsPath, defaultMaxDiff, append(metaArgs, specs...)...)
	if err != nil {
		return nil, err
	}
	if metaTruncated {
		metaOut = metaOut[:strings.LastIndexByte(metaOut, '\n')+1]
	}
	fields := strings.SplitN(metaOut, "\x00", 6)
	if len(fields) < 6 {
		return nil, errors.New("该提交没有可见的变更或提交元数据超出限制")
	}
	res := &ShowResult{
		Source: "git_output", WorkspaceID: workspaceID, Ref: ref, StatOnly: statOnly,
		Hash: fields[0], ShortHash: fields[1], Author: audit.RedactPrivateSecrets(fields[2]),
		Date: fields[3], Subject: audit.RedactPrivateSecrets(fields[4]),
		Body: audit.RedactPrivateSecrets(strings.TrimSpace(fields[5])),
	}
	diffArgs := []string{"show", "--no-notes", "--no-show-signature", "--no-ext-diff", "--no-textconv", "--format="}
	if statOnly {
		diffArgs = append(diffArgs, "--stat")
	}
	diffArgs = append(diffArgs, oid)
	res.Diff, res.Truncated, err = a.readDiff(ctx, resolvedRepo.AbsPath, maxBytes, append(diffArgs, specs...))
	if err != nil {
		return nil, err
	}
	res.Truncated = res.Truncated || metaTruncated
	return res, nil
}

// Only immutable commits are passed to history commands. Git also accepts tree and
// blob objects for "show", whose output has different path filtering semantics.
func (a *Adapter) resolveCommit(ctx context.Context, dir, ref string) (string, error) {
	if err := validateGitRef(ref); err != nil {
		return "", err
	}
	out, _, err := a.readGit(ctx, dir, 128, "rev-parse", "--verify", "--end-of-options", ref)
	if err != nil {
		return "", fmt.Errorf("无效的提交引用: %w", err)
	}
	id := strings.TrimSpace(out)
	if _, err := hex.DecodeString(id); err != nil || (len(id) != 40 && len(id) != 64) {
		return "", errors.New("引用必须解析为单个 Git 对象")
	}
	out, _, err = a.readGit(ctx, dir, 128, "rev-parse", "--verify", id+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("无效的提交引用: %w", err)
	}
	return strings.TrimSpace(out), nil
}

func (a *Adapter) resolveRevision(ctx context.Context, dir, ref string, allowRange bool) (string, error) {
	if allowRange {
		left, right, found := strings.Cut(ref, "..")
		if found {
			separator := ".."
			if strings.HasPrefix(right, ".") {
				separator, right = "...", right[1:]
			}
			if left == "" {
				left = "HEAD"
			}
			if right == "" {
				right = "HEAD"
			}
			start, err := a.resolveCommit(ctx, dir, left)
			if err != nil {
				return "", err
			}
			end, err := a.resolveCommit(ctx, dir, right)
			if err != nil {
				return "", err
			}
			return start + separator + end, nil
		}
	}
	return a.resolveCommit(ctx, dir, ref)
}

func (a *Adapter) visiblePathspecs(dir *filesystem.ResolvedPath, workspaceID string, paths []string) ([]string, error) {
	specs := []string{"--"}
	if len(paths) == 0 {
		specs = append(specs, ".")
	}
	for _, p := range paths {
		target := p
		if !filepath.IsAbs(target) {
			target = filepath.Join(dir.AbsPath, filepath.FromSlash(target))
		}
		resolved, err := a.fsMgr.Resolve(workspaceID, target, false)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(dir.AbsPath, resolved.AbsPath)
		if err != nil || (rel != "." && !filepath.IsLocal(rel)) {
			return nil, fmt.Errorf("%w: 指定路径在仓库目录以外", filesystem.ErrAccessDenied)
		}
		if rel == "." {
			specs = append(specs, ".")
		} else {
			specs = append(specs, ":(literal)"+filepath.ToSlash(rel))
		}
	}
	for _, pattern := range a.fsMgr.DenyGlobsBelow(dir) {
		specs = append(specs, ":(exclude,glob,icase)"+pattern)
	}
	return specs, nil
}

func (a *Adapter) readDiff(ctx context.Context, dir string, maxBytes int, args []string) (string, bool, error) {
	// Keep enough lookahead to recognize redaction markers at the displayed boundary.
	out, truncated, err := a.readGit(ctx, dir, maxBytes+4096, args...)
	if err != nil {
		return "", false, err
	}
	if truncated {
		// Discard the unfinished line before redaction: it may contain half a token.
		out = out[:strings.LastIndexByte(out, '\n')+1]
	}
	out = audit.RedactPrivateSecrets(out)
	if len(out) > maxBytes {
		out = out[:maxBytes]
		truncated = true
	}
	if truncated {
		out += "\n...(diff truncated)"
	}
	return out, truncated, nil
}

// validateGitRef 拦截以 '-' 开头或含空白/控制字符的非法 Git 引用，防止参数注入。
func validateGitRef(ref string) error {
	if ref == "" {
		return errors.New("ref 不能为空")
	}
	if strings.HasPrefix(ref, "-") {
		return fmt.Errorf("ref 不能以 '-' 开头: %q", ref)
	}
	for _, r := range ref {
		if r <= 0x20 || r == 0x7f {
			return fmt.Errorf("ref 包含非法空白或控制字符: %q", ref)
		}
	}
	return nil
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

	// 1. 禁止通过 Git 补丁创建/修改符号链接（mode 120000）或二进制补丁，防止借助符号链接逃逸读取私钥
	if err := rejectDangerousPatchDirectives(patchText); err != nil {
		return nil, err
	}

	// 2. 结合静态解析与 Git 自身解析（`git apply --numstat -z -`），彻底消除 C-style 八进制转义路径绕过
	staticFiles, err := ExtractPatchPaths(patchText)
	if err != nil {
		return nil, err
	}
	numstatOut, numstatErrStr, numstatErr := a.runGit(ctx, resolvedRepo.AbsPath, []byte(patchText), "apply", "--numstat", "-z", "-")
	if numstatErr != nil {
		return nil, fmt.Errorf("git apply --numstat 解析补丁失败: %v (%s)", numstatErr, strings.TrimSpace(numstatErrStr))
	}
	gitFiles := parseNumstatZPaths(numstatOut)

	seen := make(map[string]struct{}, len(staticFiles)+len(gitFiles))
	var files []string
	for _, list := range [][]string{gitFiles, staticFiles} {
		for _, f := range list {
			if _, ok := seen[f]; !ok {
				seen[f] = struct{}{}
				files = append(files, f)
			}
		}
	}
	if len(files) == 0 {
		return nil, errors.New("补丁中未解析到任何有效目标文件路径")
	}

	// 3. 逐个文件做路径穿越、符号链接逃逸和敏感密钥红线校验
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

	// 4. 调用 git apply --check 预检补丁能否干净应用
	_, stderr, err := a.runGit(ctx, resolvedRepo.AbsPath, []byte(patchText), "apply", "--check", "-")
	if err != nil {
		return validated, fmt.Errorf("git apply --check 预检失败: %v (%s)", err, strings.TrimSpace(stderr))
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
		case strings.HasPrefix(line, "copy from "):
			addPath(strings.TrimPrefix(line, "copy from "))
		case strings.HasPrefix(line, "copy to "):
			addPath(strings.TrimPrefix(line, "copy to "))
		}
	}
	return files, nil
}

// rejectDangerousPatchDirectives 拦截创建/修改符号链接（mode 120000）、二进制补丁与 C-style 引号转义路径头。
func rejectDangerousPatchDirectives(patchText string) error {
	for _, line := range strings.Split(strings.ReplaceAll(patchText, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "new file mode 120000"),
			strings.HasPrefix(trimmed, "old mode 120000"),
			strings.HasPrefix(trimmed, "new mode 120000"):
			return fmt.Errorf("%w: 禁止通过 Git 补丁创建或修改符号链接 (%s)", filesystem.ErrAccessDenied, trimmed)
		case trimmed == "GIT binary patch":
			return fmt.Errorf("%w: 禁止通过 git.apply_patch 应用二进制补丁", filesystem.ErrAccessDenied)
		case (strings.HasPrefix(line, "diff --git ") ||
			strings.HasPrefix(line, "--- ") ||
			strings.HasPrefix(line, "+++ ") ||
			strings.HasPrefix(line, "rename from ") ||
			strings.HasPrefix(line, "rename to ") ||
			strings.HasPrefix(line, "copy from ") ||
			strings.HasPrefix(line, "copy to ")) &&
			strings.Contains(line, `"`):
			if strings.Contains(line, `\`) {
				return fmt.Errorf("%w: 补丁头包含 C-style 引号转义路径，已拦截 (%s)", filesystem.ErrAccessDenied, trimmed)
			}
		}
	}
	return nil
}

// parseNumstatZPaths 解析 `git apply --numstat -z -` 的 NUL 分隔输出，提取 Git 解码后的所有受影响文件路径。
func parseNumstatZPaths(out string) []string {
	if out == "" {
		return nil
	}
	var files []string
	seen := make(map[string]struct{})
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || p == "/dev/null" {
			return
		}
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			files = append(files, p)
		}
	}

	parts := strings.Split(out, "\x00")
	for i := 0; i < len(parts); i++ {
		seg := parts[i]
		if seg == "" {
			continue
		}
		fields := strings.SplitN(seg, "\t", 3)
		if len(fields) != 3 {
			continue
		}
		if fields[2] != "" {
			add(fields[2])
		} else {
			// 重命名/复制格式：<add>\t<del>\t\0<old_path>\0<new_path>\0
			if i+1 < len(parts) {
				i++
				add(parts[i])
			}
			if i+1 < len(parts) {
				i++
				add(parts[i])
			}
		}
	}
	return files
}

func (a *Adapter) runGit(ctx context.Context, cwd string, stdin []byte, args ...string) (string, string, error) {
	var stdout, stderr bytes.Buffer
	err := a.execGit(ctx, cwd, stdin, &stdout, &stderr, args...)
	return stdout.String(), stderr.String(), err
}

type limitedOutput struct {
	data      bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedOutput) Write(p []byte) (int, error) {
	n := min(len(p), b.limit-b.data.Len())
	b.data.Write(p[:n])
	b.truncated = b.truncated || n < len(p)
	return len(p), nil
}

func (a *Adapter) readGit(ctx context.Context, cwd string, limit int, args ...string) (string, bool, error) {
	stdout, stderr := limitedOutput{limit: limit}, limitedOutput{limit: 4096}
	if err := a.execGit(ctx, cwd, nil, &stdout, &stderr, args...); err != nil {
		return "", false, fmt.Errorf("git %s 失败: %w (%s)", args[0], err, audit.RedactPrivateSecrets(strings.TrimSpace(stderr.data.String())))
	}
	return stdout.data.String(), stdout.truncated, nil
}

func (a *Adapter) execGit(ctx context.Context, cwd string, stdin []byte, stdout, stderr io.Writer, args ...string) error {
	runCtx, cancel := context.WithTimeout(ctx, defaultGitTimeout)
	defer cancel()

	// 禁用外部 hooks、quotePath 转义与 ext 协议，防止恶意仓库通过配置或转义路径绕过安全检查
	fullArgs := append([]string{"-c", "core.hooksPath=", "-c", "core.quotePath=false", "-c", "protocol.ext.allow=never"}, args...)
	cmd := exec.CommandContext(runCtx, a.gitPath, fullArgs...)
	cmd.Dir = cwd
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	return cmd.Run()
}
