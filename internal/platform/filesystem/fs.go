package filesystem

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	defaultListLimit    = 200
	maxListLimit        = 2000
	defaultReadMaxBytes = 2 * 1024 * 1024 // 单文件最大 2MB
	defaultReadLines    = 400
	defaultSearchLimit  = 100
	maxSearchLimit      = 500
	maxSearchLineLen    = 400
)

// ErrConflict 表示文件 SHA256 乐观锁校验失败或 Search/Replace 无法唯一匹配。
var ErrConflict = errors.New("patch conflict")

// ListEntry 表示目录列表中的单个文件或目录条目。
type ListEntry struct {
	Path      string `json:"path"`
	IsDir     bool   `json:"is_dir"`
	Size      int64  `json:"size"`
	ModTime   string `json:"mod_time"`
}

// ListResult 表示 workspace.list 的返回结果。
type ListResult struct {
	Source      string      `json:"source"`
	WorkspaceID string      `json:"workspace_id"`
	BasePath    string      `json:"base_path"`
	Entries     []ListEntry `json:"entries"`
	Truncated   bool        `json:"truncated"`
}

// ReadResult 表示 workspace.read 的返回结果（含整文件 SHA256 用于乐观锁）。
type ReadResult struct {
	Source      string `json:"source"`
	WorkspaceID string `json:"workspace_id"`
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	TotalLines  int    `json:"total_lines"`
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
	Truncated   bool   `json:"truncated"`
	Content     string `json:"content"`
}

// SearchMatch 表示单条代码搜索命中结果。
type SearchMatch struct {
	Path       string `json:"path"`
	LineNumber int    `json:"line_number"`
	Line       string `json:"line"`
}

// SearchResult 表示 workspace.search 的返回结果。
type SearchResult struct {
	Source      string        `json:"source"`
	WorkspaceID string        `json:"workspace_id"`
	Query       string        `json:"query"`
	Matches     []SearchMatch `json:"matches"`
	Truncated   bool          `json:"truncated"`
}

// PatchEdit 表示 workspace.patch 的单个 Search/Replace 替换块。
type PatchEdit struct {
	OldText    string `json:"old_text"`
	NewText    string `json:"new_text"`
	ReplaceAll bool   `json:"replace_all,omitempty"`
}

// PatchRequest 表示一次文件补丁请求。
type PatchRequest struct {
	WorkspaceID     string      `json:"workspace_id"`
	Path            string      `json:"path"`
	ExpectedSHA256  string      `json:"expected_sha256,omitempty"`
	CreateIfMissing bool        `json:"create_if_missing,omitempty"`
	Edits           []PatchEdit `json:"edits"`
}

// PatchPreview 表示审批前生成的补丁预检结果与 Unified Diff。
type PatchPreview struct {
	Resolved    *ResolvedPath
	IsNewFile   bool
	OldSHA256   string
	NewSHA256   string
	NewContent  string
	UnifiedDiff string
}

// PatchResult 表示补丁应用成功后的结果（或远程异步等待审批时的挂起提示）。
type PatchResult struct {
	Source      string `json:"source"`
	WorkspaceID string `json:"workspace_id"`
	Path        string `json:"path"`
	Created     bool   `json:"created"`
	OldSHA256   string `json:"old_sha256,omitempty"`
	NewSHA256   string `json:"new_sha256,omitempty"`
	UnifiedDiff string `json:"unified_diff,omitempty"`
	Pending     bool   `json:"pending,omitempty"`
	ApprovalID  string `json:"approval_id,omitempty"`
	Message     string `json:"message,omitempty"`
}

var defaultSkipDirs = map[string]struct{}{
	".git":         {},
	"node_modules": {},
	".venv":        {},
	"__pycache__":  {},
	".idea":        {},
}

// List 列出授权工作区内的目录与文件，自动跳过隐藏忽略目录与敏感文件。
func (m *Manager) List(workspaceID, relPath string, maxDepth, limit int) (*ListResult, error) {
	resolved, err := m.Resolve(workspaceID, relPath, false)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(resolved.AbsPath)
	if err != nil {
		return nil, fmt.Errorf("访问目录失败: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("路径 %q 不是目录", resolved.RelPath)
	}

	if maxDepth <= 0 {
		maxDepth = 3
	}
	if limit <= 0 {
		limit = defaultListLimit
	}
	if limit > maxListLimit {
		limit = maxListLimit
	}

	var entries []ListEntry
	truncated := false
	errStop := errors.New("limit reached")
	allowAllDirs := m.AllowAllDirs()
	inWorkspace := isWithinRoot(resolved.Workspace.RealRoot, resolved.AbsPath)

	walkErr := filepath.WalkDir(resolved.AbsPath, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // 跳过无权读取的单个子条目
		}
		if p == resolved.AbsPath {
			return nil
		}
		relToBase, err := filepath.Rel(resolved.AbsPath, p)
		if err != nil {
			return nil
		}
		depth := strings.Count(filepath.ToSlash(relToBase), "/") + 1
		if d.IsDir() {
			if _, skip := defaultSkipDirs[d.Name()]; skip {
				return filepath.SkipDir
			}
			if depth > maxDepth {
				return filepath.SkipDir
			}
		} else if depth > maxDepth {
			return nil
		}

		var entryPOSIX string
		if inWorkspace {
			relToWS, relErr := filepath.Rel(resolved.Workspace.RealRoot, p)
			if relErr != nil {
				return nil
			}
			entryPOSIX = filepath.ToSlash(relToWS)
		} else {
			entryPOSIX = filepath.ToSlash(p)
		}
		if m.IsSensitive(resolved.Workspace, entryPOSIX) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// 对符号链接必须解析真实目标并执行边界与敏感路径双重检查，防止通过工作区内符号链接泄露敏感目录/私钥
		if d.Type()&os.ModeSymlink != 0 {
			realP, symErr := filepath.EvalSymlinks(p)
			if symErr != nil {
				return nil
			}
			if !allowAllDirs && !isWithinRoot(resolved.Workspace.RealRoot, realP) {
				return nil
			}
			realCheckPath := filepath.ToSlash(realP)
			if isWithinRoot(resolved.Workspace.RealRoot, realP) {
				if relReal, relErr := filepath.Rel(resolved.Workspace.RealRoot, realP); relErr == nil {
					realCheckPath = filepath.ToSlash(relReal)
				}
			}
			if m.checkHardSecretPath(filepath.ToSlash(realP)) != nil || m.IsSensitive(resolved.Workspace, realCheckPath) {
				return nil
			}
		}

		if len(entries) >= limit {
			truncated = true
			return errStop
		}

		var size int64
		var modTime string
		if fi, statErr := d.Info(); statErr == nil {
			size = fi.Size()
			modTime = fi.ModTime().UTC().Format(time.RFC3339)
		}
		entries = append(entries, ListEntry{
			Path:    entryPOSIX,
			IsDir:   d.IsDir(),
			Size:    size,
			ModTime: modTime,
		})
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, errStop) {
		return nil, walkErr
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})

	return &ListResult{
		Source:      "local_workspace_listing",
		WorkspaceID: workspaceID,
		BasePath:    resolved.RelPath,
		Entries:     entries,
		Truncated:   truncated,
	}, nil
}

// Read 安全读取工作区内文本文件，返回指定行范围内容及整文件 SHA256。
func (m *Manager) Read(workspaceID, relPath string, startLine, endLine int) (*ReadResult, error) {
	resolved, err := m.Resolve(workspaceID, relPath, false)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(resolved.AbsPath)
	if err != nil {
		return nil, fmt.Errorf("读取文件状态失败: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("路径 %q 是目录，请使用 workspace.list", resolved.RelPath)
	}
	if info.Size() > defaultReadMaxBytes {
		return nil, fmt.Errorf("文件 %q 体积过大 (%d bytes)，超过单次安全读取上限 %d bytes", resolved.RelPath, info.Size(), defaultReadMaxBytes)
	}

	raw, err := os.ReadFile(resolved.AbsPath)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %w", err)
	}
	if isBinaryContent(raw) {
		return nil, fmt.Errorf("文件 %q 为二进制文件，拒绝按文本读取", resolved.RelPath)
	}

	sum := sha256Hex(raw)
	norm := strings.ReplaceAll(string(raw), "\r\n", "\n")
	lines := strings.Split(norm, "\n")
	totalLines := len(lines)
	if len(raw) == 0 {
		totalLines = 0
		lines = nil
	}

	if startLine <= 0 {
		startLine = 1
	}
	if endLine <= 0 {
		endLine = startLine + defaultReadLines - 1
	}
	if endLine < startLine {
		return nil, fmt.Errorf("无效行范围: start_line(%d) > end_line(%d)", startLine, endLine)
	}

	truncated := false
	actualEnd := endLine
	if totalLines == 0 {
		return &ReadResult{
			Source:      "local_workspace_file",
			WorkspaceID: workspaceID,
			Path:        resolved.RelPath,
			SHA256:      sum,
			TotalLines:  0,
			StartLine:   0,
			EndLine:     0,
			Truncated:   false,
			Content:     "",
		}, nil
	}

	if startLine > totalLines {
		startLine = totalLines
	}
	if actualEnd >= totalLines {
		actualEnd = totalLines
	} else {
		truncated = true
	}

	var b strings.Builder
	for i := startLine; i <= actualEnd; i++ {
		fmt.Fprintf(&b, "%d: %s\n", i, lines[i-1])
	}

	return &ReadResult{
		Source:      "local_workspace_file",
		WorkspaceID: workspaceID,
		Path:        resolved.RelPath,
		SHA256:      sum,
		TotalLines:  totalLines,
		StartLine:   startLine,
		EndLine:     actualEnd,
		Truncated:   truncated,
		Content:     b.String(),
	}, nil
}

// Search 在授权工作区内按子串或正则搜索文本文件，自动跳过敏感文件和二进制文件。
func (m *Manager) Search(workspaceID, query string, isRegex bool, globPattern string, maxResults int) (*SearchResult, error) {
	return m.SearchInPath(workspaceID, "", query, isRegex, globPattern, maxResults)
}

// SearchInPath 在指定目录或文件（默认工作区根目录，开启全部目录模式时可为宿主机任意路径）内搜索文本。
func (m *Manager) SearchInPath(workspaceID, targetPath, query string, isRegex bool, globPattern string, maxResults int) (*SearchResult, error) {
	if strings.TrimSpace(query) == "" {
		return nil, errors.New("搜索关键词 query 不能为空")
	}
	resolved, err := m.Resolve(workspaceID, targetPath, false)
	if err != nil {
		return nil, err
	}
	ws := resolved.Workspace
	if maxResults <= 0 {
		maxResults = defaultSearchLimit
	}
	if maxResults > maxSearchLimit {
		maxResults = maxSearchLimit
	}

	var re *regexp.Regexp
	if isRegex {
		re, err = regexp.Compile(query)
		if err != nil {
			return nil, fmt.Errorf("无效正则表达式: %w", err)
		}
	}

	var matches []SearchMatch
	truncated := false
	errStop := errors.New("search limit reached")
	allowAllDirs := m.AllowAllDirs()
	inWorkspace := isWithinRoot(ws.RealRoot, resolved.AbsPath)

	walkErr := filepath.WalkDir(resolved.AbsPath, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p == resolved.AbsPath {
				return nil
			}
			if _, skip := defaultSkipDirs[d.Name()]; skip {
				return filepath.SkipDir
			}
			dirPOSIX := filepath.ToSlash(p)
			if inWorkspace {
				if relToWS, relErr := filepath.Rel(ws.RealRoot, p); relErr == nil {
					dirPOSIX = filepath.ToSlash(relToWS)
				}
			}
			if m.IsSensitive(ws, dirPOSIX) {
				return filepath.SkipDir
			}
			return nil
		}

		readTarget := p
		// 无论是否开启全部目录模式，符号链接必须先解析真实目标并执行工作区边界与敏感密钥硬红线检查
		if d.Type()&os.ModeSymlink != 0 {
			realP, symErr := filepath.EvalSymlinks(p)
			if symErr != nil {
				return nil
			}
			if !allowAllDirs && !isWithinRoot(ws.RealRoot, realP) {
				return nil
			}
			realCheckPath := filepath.ToSlash(realP)
			if isWithinRoot(ws.RealRoot, realP) {
				if relReal, relErr := filepath.Rel(ws.RealRoot, realP); relErr == nil {
					realCheckPath = filepath.ToSlash(relReal)
				}
			}
			if m.checkHardSecretPath(filepath.ToSlash(realP)) != nil || m.IsSensitive(ws, realCheckPath) {
				return nil
			}
			readTarget = realP
		}

		var entryPOSIX string
		if inWorkspace {
			relToWS, relErr := filepath.Rel(ws.RealRoot, p)
			if relErr != nil {
				return nil
			}
			entryPOSIX = filepath.ToSlash(relToWS)
		} else {
			entryPOSIX = filepath.ToSlash(p)
		}
		if m.IsSensitive(ws, entryPOSIX) {
			return nil
		}
		if globPattern != "" && !matchGlob(globPattern, entryPOSIX) {
			return nil
		}

		// 对真实目标执行 Stat，避免符号链接 Lstat 大小绕过单文件读取上限或误读目录
		fi, err := os.Stat(readTarget)
		if err != nil || fi.IsDir() || fi.Size() > defaultReadMaxBytes {
			return nil
		}

		raw, err := os.ReadFile(readTarget)
		if err != nil || isBinaryContent(raw) {
			return nil
		}

		scanner := bufio.NewScanner(bytes.NewReader(raw))
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			text := scanner.Text()
			hit := false
			if isRegex {
				hit = re.MatchString(text)
			} else {
				hit = strings.Contains(text, query)
			}
			if !hit {
				continue
			}
			if len(text) > maxSearchLineLen {
				text = text[:maxSearchLineLen] + "...(truncated)"
			}
			matches = append(matches, SearchMatch{
				Path:       entryPOSIX,
				LineNumber: lineNo,
				Line:       text,
			})
			if len(matches) >= maxResults {
				truncated = true
				return errStop
			}
		}
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, errStop) {
		return nil, walkErr
	}

	return &SearchResult{
		Source:      "local_workspace_search",
		WorkspaceID: workspaceID,
		Query:       query,
		Matches:     matches,
		Truncated:   truncated,
	}, nil
}

// PreviewPatch 在不修改磁盘的前提下校验路径、SHA256 乐观锁与 Search/Replace 匹配，并生成 Unified Diff。
func (m *Manager) PreviewPatch(req PatchRequest) (*PatchPreview, error) {
	resolved, err := m.Resolve(req.WorkspaceID, req.Path, true)
	if err != nil {
		return nil, err
	}
	return m.computePatchLocked(resolved, req)
}

// ApplyPatch 在路径互斥锁下重新校验乐观锁并原子写入修改，防止审批期间并发覆盖。
func (m *Manager) ApplyPatch(req PatchRequest) (*PatchResult, error) {
	resolved, err := m.Resolve(req.WorkspaceID, req.Path, true)
	if err != nil {
		return nil, err
	}

	unlock := m.LockPath(resolved.AbsPath)
	defer unlock()

	preview, err := m.computePatchLocked(resolved, req)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(resolved.AbsPath), 0o755); err != nil {
		return nil, fmt.Errorf("创建父目录失败: %w", err)
	}

	perm := os.FileMode(0o644)
	if fi, err := os.Stat(resolved.AbsPath); err == nil {
		perm = fi.Mode().Perm()
	}

	// 同目录临时文件原子写入后重命名
	tmpFile, err := os.CreateTemp(filepath.Dir(resolved.AbsPath), ".nodebridge-patch-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpPath := tmpFile.Name()
	if _, err := tmpFile.WriteString(preview.NewContent); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("写入补丁临时文件失败: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("关闭补丁临时文件失败: %w", err)
	}
	_ = os.Chmod(tmpPath, perm)

	if err := os.Rename(tmpPath, resolved.AbsPath); err != nil {
		// Windows 目标文件被杀软/索引短占时的安全回退
		if wErr := os.WriteFile(resolved.AbsPath, []byte(preview.NewContent), perm); wErr != nil {
			_ = os.Remove(tmpPath)
			return nil, fmt.Errorf("提交文件更新失败: %w", wErr)
		}
		_ = os.Remove(tmpPath)
	}

	return &PatchResult{
		Source:      "local_workspace_patch",
		WorkspaceID: req.WorkspaceID,
		Path:        resolved.RelPath,
		Created:     preview.IsNewFile,
		OldSHA256:   preview.OldSHA256,
		NewSHA256:   preview.NewSHA256,
		UnifiedDiff: preview.UnifiedDiff,
	}, nil
}

func (m *Manager) computePatchLocked(resolved *ResolvedPath, req PatchRequest) (*PatchPreview, error) {
	if len(req.Edits) == 0 {
		return nil, errors.New("edits 不能为空")
	}

	raw, err := os.ReadFile(resolved.AbsPath)
	isNew := false
	if err != nil {
		if os.IsNotExist(err) {
			if !req.CreateIfMissing {
				return nil, fmt.Errorf("目标文件 %q 不存在（如需新建请设置 create_if_missing=true）", resolved.RelPath)
			}
			isNew = true
			raw = nil
		} else {
			return nil, fmt.Errorf("读取目标文件失败: %w", err)
		}
	}

	var oldSHA string
	if !isNew {
		if isBinaryContent(raw) {
			return nil, fmt.Errorf("目标文件 %q 为二进制文件，禁止使用文本补丁修改", resolved.RelPath)
		}
		oldSHA = sha256Hex(raw)
		if req.ExpectedSHA256 != "" && !strings.EqualFold(req.ExpectedSHA256, oldSHA) {
			return nil, fmt.Errorf("%w: 文件 %q 已被修改（期望 sha256=%s，实际=%s），请重新读取后再提交补丁",
				ErrConflict, resolved.RelPath, req.ExpectedSHA256, oldSHA)
		}
	} else if req.ExpectedSHA256 != "" {
		return nil, fmt.Errorf("%w: 目标文件不存在，但传入了 expected_sha256", ErrConflict)
	}

	oldContent := string(raw)
	// 若原文件使用 CRLF，统一按 LF 匹配编辑并在写回时保留原行尾风格
	useCRLF := strings.Contains(oldContent, "\r\n")
	working := strings.ReplaceAll(oldContent, "\r\n", "\n")

	for idx, edit := range req.Edits {
		oldNorm := strings.ReplaceAll(edit.OldText, "\r\n", "\n")
		newNorm := strings.ReplaceAll(edit.NewText, "\r\n", "\n")

		if oldNorm == "" {
			if !isNew && working != "" {
				return nil, fmt.Errorf("%w: 第 %d 个编辑块的 old_text 不能为空（仅新建空文件允许空 old_text）", ErrConflict, idx+1)
			}
			working = newNorm
			continue
		}

		count := strings.Count(working, oldNorm)
		if count == 0 {
			return nil, fmt.Errorf("%w: 第 %d 个编辑块的 old_text 在文件 %q 中未找到匹配", ErrConflict, idx+1, resolved.RelPath)
		}
		if count > 1 && !edit.ReplaceAll {
			return nil, fmt.Errorf("%w: 第 %d 个编辑块的 old_text 命中了 %d 处（请提供更多上下文或显式设置 replace_all=true）", ErrConflict, idx+1, count)
		}
		if edit.ReplaceAll {
			working = strings.ReplaceAll(working, oldNorm, newNorm)
		} else {
			working = strings.Replace(working, oldNorm, newNorm, 1)
		}
	}

	finalContent := working
	if useCRLF {
		finalContent = strings.ReplaceAll(working, "\n", "\r\n")
	}

	newSHA := sha256Hex([]byte(finalContent))
	diff := GenerateUnifiedDiff(resolved.RelPath, oldContent, finalContent)
	if diff == "" && !isNew {
		return nil, fmt.Errorf("%w: 补丁未产生任何内容变化", ErrConflict)
	}

	return &PatchPreview{
		Resolved:    resolved,
		IsNewFile:   isNew,
		OldSHA256:   oldSHA,
		NewSHA256:   newSHA,
		NewContent:  finalContent,
		UnifiedDiff: diff,
	}, nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func isBinaryContent(data []byte) bool {
	sample := data
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	return bytes.IndexByte(sample, 0) >= 0
}
