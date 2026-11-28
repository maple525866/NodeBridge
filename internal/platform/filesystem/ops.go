package filesystem

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

// WriteRequest 表示整文件新建或覆写请求。
type WriteRequest struct {
	ApprovedPath   string `json:"-"`
	WorkspaceID    string `json:"workspace_id"`
	Path           string `json:"path"`
	Content        string `json:"content"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
	Overwrite      bool   `json:"overwrite"`
}

// WritePreview 表示整文件写入的审批前预检结果与 Unified Diff。
type WritePreview struct {
	Resolved    *ResolvedPath
	IsNewFile   bool
	OldSHA256   string
	NewSHA256   string
	NewContent  string
	UnifiedDiff string
}

// WriteResult 表示 workspace.write 的执行结果。
type WriteResult struct {
	Source      string `json:"source"`
	WorkspaceID string `json:"workspace_id"`
	Path        string `json:"path"`
	Created     bool   `json:"created"`
	Bytes       int    `json:"bytes,omitempty"`
	OldSHA256   string `json:"old_sha256,omitempty"`
	NewSHA256   string `json:"new_sha256,omitempty"`
	UnifiedDiff string `json:"unified_diff,omitempty"`
	Pending     bool   `json:"pending,omitempty"`
	ApprovalID  string `json:"approval_id,omitempty"`
	Message     string `json:"message,omitempty"`
}

// MoveRequest 表示重命名或移动文件/目录的请求。
type MoveRequest struct {
	ApprovedSource      string `json:"-"`
	ApprovedDestination string `json:"-"`
	WorkspaceID         string `json:"workspace_id"`
	SourcePath          string `json:"source_path"`
	DestinationPath     string `json:"destination_path"`
	Overwrite           bool   `json:"overwrite,omitempty"`
}

// MkdirRequest 表示创建目录的请求。
type MkdirRequest struct {
	ApprovedPath string `json:"-"`
	WorkspaceID  string `json:"workspace_id"`
	Path         string `json:"path"`
	Parents      bool   `json:"parents"`
}

// MkdirPreview 表示创建目录的预检结果。
type MkdirPreview struct {
	Resolved         *ResolvedPath
	AlreadyExists    bool
	MissingAncestors []string // 按从外到内顺序排列的待新建目录绝对路径（含目标目录本身）
}

// MkdirResult 表示 workspace.mkdir 的执行结果。
type MkdirResult struct {
	Source      string `json:"source"`
	WorkspaceID string `json:"workspace_id"`
	Path        string `json:"path"`
	Created     bool   `json:"created"`
	Pending     bool   `json:"pending,omitempty"`
	ApprovalID  string `json:"approval_id,omitempty"`
	Message     string `json:"message,omitempty"`
}

// MovePreview 表示移动操作预检结果。
type MovePreview struct {
	Source      *ResolvedPath
	Destination *ResolvedPath
	IsDir       bool
	DestExists  bool
}

// MoveResult 表示 workspace.move 的执行结果。
type MoveResult struct {
	Source          string `json:"source"`
	WorkspaceID     string `json:"workspace_id"`
	SourcePath      string `json:"source_path"`
	DestinationPath string `json:"destination_path"`
	IsDir           bool   `json:"is_dir,omitempty"`
	Pending         bool   `json:"pending,omitempty"`
	ApprovalID      string `json:"approval_id,omitempty"`
	Message         string `json:"message,omitempty"`
}

// DeleteRequest 表示删除文件或目录的请求。
type DeleteRequest struct {
	ApprovedPath string `json:"-"`
	WorkspaceID  string `json:"workspace_id"`
	Path         string `json:"path"`
	Recursive    bool   `json:"recursive,omitempty"`
}

// DeletePreview 表示删除操作预检结果，供工具层区分 L1（单文件/空目录）与 L2（递归删非空目录）。
type DeletePreview struct {
	Resolved          *ResolvedPath
	IsDir             bool
	IsSymlink         bool
	IsNonEmptyDir     bool
	RecursiveNonEmpty bool
	EntryCount        int
}

// DeleteResult 表示 workspace.delete 的执行结果。
type DeleteResult struct {
	Source      string `json:"source"`
	WorkspaceID string `json:"workspace_id"`
	Path        string `json:"path"`
	IsDir       bool   `json:"is_dir,omitempty"`
	Recursive   bool   `json:"recursive,omitempty"`
	Pending     bool   `json:"pending,omitempty"`
	ApprovalID  string `json:"approval_id,omitempty"`
	Message     string `json:"message,omitempty"`
}

// PreviewWrite 预检整文件写入（含路径、敏感红线、大小、二进制与 SHA256 乐观锁），并生成 Unified Diff。
func (m *Manager) PreviewWrite(req WriteRequest) (*WritePreview, error) {
	resolved, err := m.Resolve(req.WorkspaceID, req.Path, true)
	if err != nil {
		return nil, err
	}
	return m.computeWriteLocked(resolved, req)
}

// WriteFile 在路径互斥锁下重新校验并原子写入整文件内容。
func (m *Manager) WriteFile(req WriteRequest) (*WriteResult, error) {
	resolved, err := m.Resolve(req.WorkspaceID, req.Path, true)
	if err != nil {
		return nil, err
	}

	unlock := m.LockPath(resolved.AbsPath)
	defer unlock()

	if err := checkApprovedPath(req.ApprovedPath, resolved.AbsPath); err != nil {
		return nil, err
	}
	preview, err := m.computeWriteLocked(resolved, req)
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

	tmpFile, err := os.CreateTemp(filepath.Dir(resolved.AbsPath), ".nodebridge-write-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)
	if _, err := tmpFile.WriteString(preview.NewContent); err != nil {
		_ = tmpFile.Close()
		return nil, fmt.Errorf("写入临时文件失败: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return nil, fmt.Errorf("关闭临时文件失败: %w", err)
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return nil, err
	}
	if err := publishEntry(tmpPath, resolved.AbsPath, !preview.IsNewFile); err != nil {
		return nil, fmt.Errorf("提交文件写入失败: %w", err)
	}

	return &WriteResult{
		Source:      "local_workspace_write",
		WorkspaceID: req.WorkspaceID,
		Path:        resolved.RelPath,
		Created:     preview.IsNewFile,
		Bytes:       len(preview.NewContent),
		OldSHA256:   preview.OldSHA256,
		NewSHA256:   preview.NewSHA256,
		UnifiedDiff: preview.UnifiedDiff,
	}, nil
}

func (m *Manager) computeWriteLocked(resolved *ResolvedPath, req WriteRequest) (*WritePreview, error) {
	if len(req.Content) > defaultReadMaxBytes {
		return nil, fmt.Errorf("写入内容体积过大 (%d bytes)，超过单次文本写入上限 %d bytes", len(req.Content), defaultReadMaxBytes)
	}
	if strings.IndexByte(req.Content, 0) >= 0 {
		return nil, fmt.Errorf("%w: workspace.write 仅支持文本内容，禁止写入二进制 NUL 字节", ErrAccessDenied)
	}

	_, err := os.Lstat(resolved.AbsPath)
	isNew := os.IsNotExist(err)
	if err != nil && !isNew {
		return nil, fmt.Errorf("读取目标文件失败: %w", err)
	}

	var oldSHA string
	var raw []byte
	if !isNew {
		if !req.Overwrite {
			return nil, fmt.Errorf("%w: 目标文件 %q 已存在（overwrite=false）", ErrConflict, resolved.RelPath)
		}
		raw, err = readBoundedRegularFile(resolved.AbsPath)
		if err != nil {
			return nil, err
		}
		if bytes.IndexByte(raw, 0) >= 0 {
			return nil, fmt.Errorf("目标文件 %q 为二进制文件，禁止使用文本写入覆盖", resolved.RelPath)
		}
		oldSHA = sha256Hex(raw)
		if req.ExpectedSHA256 != "" && !strings.EqualFold(req.ExpectedSHA256, oldSHA) {
			return nil, fmt.Errorf("%w: 文件 %q 已被修改（期望 sha256=%s，实际=%s），请重新读取后再写入",
				ErrConflict, resolved.RelPath, req.ExpectedSHA256, oldSHA)
		}
	} else if req.ExpectedSHA256 != "" {
		return nil, fmt.Errorf("%w: 目标文件不存在，但传入了 expected_sha256", ErrConflict)
	}

	oldContent := string(raw)
	finalContent := req.Content
	// 若原文件使用 CRLF 且新内容纯 LF，保留原文件行尾风格
	if !isNew && strings.Contains(oldContent, "\r\n") && !strings.Contains(finalContent, "\r\n") {
		finalContent = strings.ReplaceAll(finalContent, "\n", "\r\n")
	}
	if len(finalContent) > defaultReadMaxBytes {
		return nil, fmt.Errorf("转换行尾后的文件超过 %d bytes", defaultReadMaxBytes)
	}

	newSHA := sha256Hex([]byte(finalContent))
	diff := GenerateUnifiedDiff(resolved.RelPath, oldContent, finalContent)
	return &WritePreview{
		Resolved:    resolved,
		IsNewFile:   isNew,
		OldSHA256:   oldSHA,
		NewSHA256:   newSHA,
		NewContent:  finalContent,
		UnifiedDiff: diff,
	}, nil
}

// PreviewMkdir 预检目录创建请求（校验工作区边界、审批路径、敏感祖先规则与目标类型冲突）。
func (m *Manager) PreviewMkdir(req MkdirRequest) (*MkdirPreview, error) {
	if strings.TrimSpace(req.Path) == "" {
		return nil, errors.New("path 不能为空")
	}
	resolved, err := m.resolveEntryNoFollow(req.WorkspaceID, req.Path, true)
	if err != nil {
		if errors.Is(err, syscall.ENOTDIR) && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: 祖先路径不是目录", ErrConflict)
		}
		return nil, err
	}
	if err := checkApprovedPath(req.ApprovedPath, resolved.AbsPath); err != nil {
		return nil, err
	}
	if m.containsWorkspaceRoot(resolved) {
		return nil, fmt.Errorf("%w: 目标路径不能为工作区根目录或磁盘根目录", ErrAccessDenied)
	}

	// 收集所有尚不存在的祖先目录并逐层校验边界与敏感路径规则
	var missing []string
	cur := resolved.AbsPath
	allowAllDirs := m.AllowAllDirs()
	for {
		fi, err := os.Lstat(cur)
		if err == nil {
			if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
				return nil, fmt.Errorf("%w: 路径 %q 的目标或祖先不是目录", ErrConflict, resolved.RelPath)
			}
			if cur == resolved.AbsPath {
				if !req.Parents {
					return nil, fmt.Errorf("%w: 目标目录 %q 已存在（parents=false）", ErrConflict, resolved.RelPath)
				}
				return &MkdirPreview{Resolved: resolved, AlreadyExists: true}, nil
			}
			break
		}
		// Windows also reports ENOTDIR for missing parents. Walk up to
		// distinguish a missing directory from an existing ordinary file.
		if !errors.Is(err, os.ErrNotExist) {
			if errors.Is(err, syscall.ENOTDIR) {
				return nil, fmt.Errorf("%w: 祖先路径不是目录", ErrConflict)
			}
			return nil, fmt.Errorf("检查祖先路径失败: %w", err)
		}
		if !allowAllDirs && !isWithinRoot(resolved.Workspace.RealRoot, cur) {
			return nil, fmt.Errorf("%w: 待创建的祖先目录超出授权工作区边界", ErrAccessDenied)
		}
		if isRootOrDrivePath(cur) {
			return nil, fmt.Errorf("%w: 无法创建磁盘根目录", ErrAccessDenied)
		}
		if err := m.checkHardSecretPath(filepath.ToSlash(cur)); err != nil {
			return nil, err
		}
		checkRel := filepath.ToSlash(cur)
		if isWithinRoot(resolved.Workspace.RealRoot, cur) {
			if rel, rErr := filepath.Rel(resolved.Workspace.RealRoot, cur); rErr == nil {
				checkRel = filepath.ToSlash(rel)
			}
		}
		if checkRel != "." {
			if err := m.checkSensitivePath(resolved.Workspace, checkRel); err != nil {
				return nil, err
			}
		}
		missing = append(missing, cur)
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	if !req.Parents && len(missing) > 1 {
		return nil, fmt.Errorf("父目录不存在（如需递归创建请设置 parents=true）: %w", os.ErrNotExist)
	}
	// 反转为自顶向下顺序（先建父目录，再建子目录）
	for i, j := 0, len(missing)-1; i < j; i, j = i+1, j-1 {
		missing[i], missing[j] = missing[j], missing[i]
	}

	return &MkdirPreview{
		Resolved:         resolved,
		MissingAncestors: missing,
	}, nil
}

// Mkdir 在路径互斥锁下重新校验并创建目标目录（不跟随符号链接）。
func (m *Manager) Mkdir(req MkdirRequest) (*MkdirResult, error) {
	preview, err := m.PreviewMkdir(req)
	if err != nil {
		return nil, err
	}

	unlock := m.LockPath(preview.Resolved.AbsPath)
	defer unlock()

	// 持锁二次预检防竞态
	preview, err = m.PreviewMkdir(req)
	if err != nil {
		return nil, err
	}
	if preview.AlreadyExists {
		return &MkdirResult{
			Source:      "local_workspace_mkdir",
			WorkspaceID: req.WorkspaceID,
			Path:        preview.Resolved.RelPath,
			Created:     false,
			Message:     fmt.Sprintf("目录 %s 已存在", preview.Resolved.RelPath),
		}, nil
	}

	createdAny := false
	for _, dir := range preview.MissingAncestors {
		if err := os.Mkdir(dir, 0o755); err != nil {
			if os.IsExist(err) {
				// 允许并发创建同名真实目录，但严禁符号链接或普通文件冒充目录
				fi, lErr := os.Lstat(dir)
				if lErr != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
					return nil, fmt.Errorf("%w: 路径 %q 已被非目录条目占用", ErrConflict, filepath.ToSlash(dir))
				}
				if !req.Parents && dir == preview.Resolved.AbsPath {
					return nil, fmt.Errorf("%w: 目标目录 %q 已存在（parents=false）", ErrConflict, preview.Resolved.RelPath)
				}
				continue
			}
			return nil, fmt.Errorf("创建目录失败: %w", err)
		}
		createdAny = true
	}

	msg := fmt.Sprintf("目录 %s 已存在", preview.Resolved.RelPath)
	if createdAny {
		msg = fmt.Sprintf("已创建目录 %s", preview.Resolved.RelPath)
	}
	return &MkdirResult{
		Source:      "local_workspace_mkdir",
		WorkspaceID: req.WorkspaceID,
		Path:        preview.Resolved.RelPath,
		Created:     createdAny,
		Message:     msg,
	}, nil
}

// PreviewMove 预检重命名/移动文件或目录的合法性与安全边界。
func (m *Manager) PreviewMove(req MoveRequest) (*MovePreview, error) {
	if strings.TrimSpace(req.SourcePath) == "" || strings.TrimSpace(req.DestinationPath) == "" {
		return nil, errors.New("source_path 和 destination_path 均不能为空")
	}
	src, err := m.resolveEntryNoFollow(req.WorkspaceID, req.SourcePath, true)
	if err != nil {
		return nil, fmt.Errorf("源路径校验失败: %w", err)
	}
	dst, err := m.resolveEntryNoFollow(req.WorkspaceID, req.DestinationPath, true)
	if err != nil {
		return nil, fmt.Errorf("目标路径校验失败: %w", err)
	}
	if err := checkApprovedPath(req.ApprovedSource, src.AbsPath); err != nil {
		return nil, err
	}
	if err := checkApprovedPath(req.ApprovedDestination, dst.AbsPath); err != nil {
		return nil, err
	}

	if sameFSPath(src.AbsPath, dst.AbsPath) {
		return nil, fmt.Errorf("%w: 源路径与目标路径相同", ErrConflict)
	}
	if m.containsWorkspaceRoot(src) {
		return nil, fmt.Errorf("%w: 禁止移动工作区根目录或磁盘根目录", ErrAccessDenied)
	}

	srcInfo, err := os.Lstat(src.AbsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("源路径 %q 不存在", src.RelPath)
		}
		return nil, fmt.Errorf("读取源路径状态失败: %w", err)
	}
	isDir := srcInfo.IsDir()
	if isDir && isWithinRoot(src.AbsPath, dst.AbsPath) {
		return nil, fmt.Errorf("%w: 不能将目录 %q 移动到其自身子目录 %q 中", ErrConflict, src.RelPath, dst.RelPath)
	}
	if isDir {
		if _, err := m.checkTreePaths(src.Workspace, src.AbsPath, dst.AbsPath); err != nil {
			return nil, err
		}
	}

	// A move publishes one rename. Creating or rolling back ancestors would
	// expose additional changes outside the approved source and destination.
	parent, err := os.Lstat(filepath.Dir(dst.AbsPath))
	if err != nil {
		return nil, fmt.Errorf("移动的目标父目录必须已存在: %w", err)
	}
	if !parent.IsDir() {
		return nil, errors.New("移动的目标父路径不是目录")
	}

	destExists := false
	if dstInfo, statErr := os.Lstat(dst.AbsPath); statErr == nil {
		destExists = true
		if !req.Overwrite {
			return nil, fmt.Errorf("%w: 目标路径 %q 已存在（如需覆盖请设置 overwrite=true）", ErrConflict, dst.RelPath)
		}
		if dstInfo.IsDir() {
			return nil, fmt.Errorf("%w: 禁止使用 overwrite 覆盖已存在的目录 %q", ErrConflict, dst.RelPath)
		}
		if isDir {
			return nil, fmt.Errorf("%w: 不能用目录替换文件 %q", ErrConflict, dst.RelPath)
		}
	} else if !os.IsNotExist(statErr) {
		return nil, fmt.Errorf("检查目标路径失败: %w", statErr)
	}

	return &MovePreview{
		Source:      src,
		Destination: dst,
		IsDir:       isDir,
		DestExists:  destExists,
	}, nil
}

// Move 在按顺序获取双路径锁下安全执行文件或目录移动/重命名。
func (m *Manager) Move(req MoveRequest) (*MoveResult, error) {
	preview, err := m.PreviewMove(req)
	if err != nil {
		return nil, err
	}

	unlock := m.lockTwoPaths(preview.Source.AbsPath, preview.Destination.AbsPath)
	defer unlock()

	// 持锁二次校验防竞态
	preview, err = m.PreviewMove(req)
	if err != nil {
		return nil, err
	}

	src, dst := preview.Source.AbsPath, preview.Destination.AbsPath
	if err := publishEntry(src, dst, preview.DestExists && req.Overwrite); err != nil {
		// Windows returns ERROR_NOT_SAME_DEVICE (17) directly from MoveFileEx.
		if errors.Is(err, syscall.EXDEV) || (runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(17))) {
			return nil, fmt.Errorf("workspace.move 仅支持同一文件系统内的重命名或移动: %w", err)
		}
		return nil, fmt.Errorf("移动失败: %w", err)
	}

	return &MoveResult{
		Source:          "local_workspace_move",
		WorkspaceID:     req.WorkspaceID,
		SourcePath:      preview.Source.RelPath,
		DestinationPath: preview.Destination.RelPath,
		IsDir:           preview.IsDir,
		Message:         fmt.Sprintf("已将 %s 移动至 %s", preview.Source.RelPath, preview.Destination.RelPath),
	}, nil
}

// PreviewDelete 预检删除目标（不跟随符号链接），返回目录是否非空供策略层区分 L1/L2。
func (m *Manager) PreviewDelete(req DeleteRequest) (*DeletePreview, error) {
	if strings.TrimSpace(req.Path) == "" {
		return nil, errors.New("path 不能为空")
	}
	resolved, err := m.resolveEntryNoFollow(req.WorkspaceID, req.Path, true)
	if err != nil {
		return nil, err
	}
	if err := checkApprovedPath(req.ApprovedPath, resolved.AbsPath); err != nil {
		return nil, err
	}
	if m.containsWorkspaceRoot(resolved) {
		return nil, fmt.Errorf("%w: 禁止删除工作区根目录或磁盘根目录", ErrAccessDenied)
	}

	info, err := os.Lstat(resolved.AbsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("目标路径 %q 不存在", resolved.RelPath)
		}
		return nil, fmt.Errorf("检查目标路径失败: %w", err)
	}

	isSymlink := info.Mode()&os.ModeSymlink != 0
	isDir := !isSymlink && info.IsDir()
	isNonEmpty := false
	entryCount := 1

	if isDir {
		entries, readErr := os.ReadDir(resolved.AbsPath)
		if readErr != nil {
			return nil, fmt.Errorf("读取目录内容失败: %w", readErr)
		}
		if len(entries) > 0 {
			isNonEmpty = true
			if !req.Recursive {
				return nil, fmt.Errorf("%w: 目录 %q 非空（包含 %d 个直接条目），如需递归删除请显式设置 recursive=true（将触发 L2 人工审批）",
					ErrConflict, resolved.RelPath, len(entries))
			}
			// 递归删除前必须确认目录树内不含任何受硬保护的敏感密钥目录或文件
			count, secErr := m.checkTreePaths(resolved.Workspace, resolved.AbsPath, "")
			if secErr != nil {
				return nil, secErr
			}
			entryCount = count
		}
	}

	return &DeletePreview{
		Resolved:          resolved,
		IsDir:             isDir,
		IsSymlink:         isSymlink,
		IsNonEmptyDir:     isNonEmpty,
		RecursiveNonEmpty: isDir && isNonEmpty && req.Recursive,
		EntryCount:        entryCount,
	}, nil
}

// Delete 在路径锁下安全删除文件、符号链接（仅删链接本身）、空目录或经审批的递归非空目录。
func (m *Manager) Delete(req DeleteRequest) (*DeleteResult, error) {
	preview, err := m.PreviewDelete(req)
	if err != nil {
		return nil, err
	}

	unlock := m.LockPath(preview.Resolved.AbsPath)
	defer unlock()

	// 持锁二次校验防竞态
	preview, err = m.PreviewDelete(req)
	if err != nil {
		return nil, err
	}

	if preview.IsDir && preview.RecursiveNonEmpty {
		if err := os.RemoveAll(preview.Resolved.AbsPath); err != nil {
			return nil, fmt.Errorf("递归删除目录失败: %w", err)
		}
	} else {
		if err := os.Remove(preview.Resolved.AbsPath); err != nil {
			return nil, fmt.Errorf("删除路径失败: %w", err)
		}
	}

	return &DeleteResult{
		Source:      "local_workspace_delete",
		WorkspaceID: req.WorkspaceID,
		Path:        preview.Resolved.RelPath,
		IsDir:       preview.IsDir,
		Recursive:   preview.RecursiveNonEmpty,
		Message:     fmt.Sprintf("已删除 %s", preview.Resolved.RelPath),
	}, nil
}

// resolveEntryNoFollow 解析文件或目录条目本身（对父目录解析符号链接防逃逸，但对叶节点保留符号链接本身以便移动/删除链接而非目标）。
func (m *Manager) resolveEntryNoFollow(workspaceID, targetPath string, forWrite bool) (*ResolvedPath, error) {
	allowAllDirs := m.AllowAllDirs()
	fullPerms := m.FullPermissions()

	ws, err := m.GetWorkspace(workspaceID)
	if err != nil {
		return nil, err
	}
	if forWrite && ws.ReadOnly && !fullPerms {
		return nil, fmt.Errorf("%w: 工作区 %q 为只读模式，禁止写入或变更", ErrAccessDenied, workspaceID)
	}

	raw := strings.TrimSpace(targetPath)
	if raw == "" || raw == "." {
		return nil, fmt.Errorf("%w: 目标路径不能为工作区根目录", ErrAccessDenied)
	}
	if allowAllDirs {
		raw = normalizeAllDirsDrivePath(raw)
	}
	if err := checkDangerousPathSyntax(raw); err != nil {
		return nil, err
	}

	var candidate string
	if filepath.IsAbs(raw) {
		candidate = filepath.Clean(raw)
	} else {
		candidate = filepath.Clean(filepath.Join(ws.RealRoot, filepath.FromSlash(raw)))
	}
	if !allowAllDirs && !isWithinRoot(ws.RealRoot, candidate) {
		return nil, fmt.Errorf("%w: 路径 %q 超出授权工作区边界", ErrAccessDenied, targetPath)
	}
	if isRootOrDrivePath(candidate) {
		return nil, fmt.Errorf("%w: 禁止操作磁盘根目录 %q", ErrAccessDenied, targetPath)
	}

	parentReal, err := resolveRealPath(filepath.Dir(candidate))
	if err != nil {
		return nil, fmt.Errorf("%w: 解析父目录失败: %w", ErrAccessDenied, err)
	}
	entryAbs := filepath.Clean(filepath.Join(parentReal, filepath.Base(candidate)))
	if !allowAllDirs && !isWithinRoot(ws.RealRoot, entryAbs) {
		return nil, fmt.Errorf("%w: 路径 %q 经父目录符号链接解析后逃逸出授权工作区", ErrAccessDenied, targetPath)
	}

	// 若目标存在且不是符号链接，同时检查其真实路径；若是符号链接，只校验链接路径本身与真实目标的硬红线
	if fi, lErr := os.Lstat(entryAbs); lErr == nil && fi.Mode()&os.ModeSymlink == 0 {
		if realTarget, rErr := filepath.EvalSymlinks(entryAbs); rErr == nil {
			entryAbs = filepath.Clean(realTarget)
			if !allowAllDirs && !isWithinRoot(ws.RealRoot, entryAbs) {
				return nil, fmt.Errorf("%w: 路径 %q 经符号链接解析后逃逸出授权工作区", ErrAccessDenied, targetPath)
			}
		}
	}

	var relPOSIX string
	if isWithinRoot(ws.RealRoot, entryAbs) {
		relOS, relErr := filepath.Rel(ws.RealRoot, entryAbs)
		if relErr != nil {
			return nil, fmt.Errorf("%w: 计算相对路径失败: %v", ErrAccessDenied, relErr)
		}
		relPOSIX = filepath.ToSlash(relOS)
	} else {
		relPOSIX = filepath.ToSlash(entryAbs)
	}
	if relPOSIX == "." {
		return nil, fmt.Errorf("%w: 目标路径不能为工作区根目录", ErrAccessDenied)
	}

	if err := m.checkHardSecretPath(filepath.ToSlash(entryAbs)); err != nil {
		return nil, err
	}
	if err := m.checkSensitivePath(ws, relPOSIX); err != nil {
		return nil, err
	}

	return &ResolvedPath{
		Workspace: ws,
		AbsPath:   entryAbs,
		RelPath:   relPOSIX,
	}, nil
}

func (m *Manager) checkTreePaths(ws *Workspace, dirAbs, destination string) (int, error) {
	count := 0
	checkPath := func(p string) error {
		if err := m.checkHardSecretPath(filepath.ToSlash(p)); err != nil {
			return err
		}
		if isWithinRoot(ws.RealRoot, p) {
			rel, err := filepath.Rel(ws.RealRoot, p)
			if err != nil {
				return err
			}
			p = rel
		}
		return m.checkSensitivePath(ws, filepath.ToSlash(p))
	}
	err := filepath.WalkDir(dirAbs, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		count++
		if p == dirAbs {
			return nil
		}
		if err := checkPath(p); err != nil {
			return err
		}
		if destination != "" {
			rel, err := filepath.Rel(dirAbs, p)
			if err != nil {
				return err
			}
			return checkPath(filepath.Join(destination, rel))
		}
		return nil
	})
	return count, err
}

func (m *Manager) lockTwoPaths(a, b string) func() {
	ka := filepath.Clean(a)
	kb := filepath.Clean(b)
	if runtime.GOOS == "windows" {
		ka = strings.ToLower(ka)
		kb = strings.ToLower(kb)
	}
	if ka == kb {
		return m.LockPath(a)
	}
	if ka < kb {
		u1 := m.LockPath(a)
		u2 := m.LockPath(b)
		return func() {
			u2()
			u1()
		}
	}
	u1 := m.LockPath(b)
	u2 := m.LockPath(a)
	return func() {
		u2()
		u1()
	}
}

func sameFSPath(a, b string) bool {
	ca := filepath.Clean(a)
	cb := filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(ca, cb)
	}
	return ca == cb
}

func checkApprovedPath(approved, current string) error {
	if approved != "" && approved != current {
		return fmt.Errorf("%w: 目标路径在审批后发生变化，请重新预览", ErrConflict)
	}
	return nil
}

func isRootOrDrivePath(absPath string) bool {
	clean := filepath.Clean(absPath)
	return filepath.Dir(clean) == clean
}

// The chosen workspace may itself be a synthetic all-directories workspace.
func (m *Manager) containsWorkspaceRoot(target *ResolvedPath) bool {
	if isRootOrDrivePath(target.AbsPath) || isWithinRoot(target.AbsPath, target.Workspace.RealRoot) {
		return true
	}
	for _, ws := range m.workspaces {
		if isWithinRoot(target.AbsPath, ws.RealRoot) {
			return true
		}
	}
	return false
}

func publishEntry(src, dst string, overwrite bool) error {
	if overwrite {
		return os.Rename(src, dst)
	}
	err := renameNoReplace(src, dst)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%w: 目标已存在", ErrConflict)
	}
	return err
}
