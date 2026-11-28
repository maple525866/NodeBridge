package filesystem

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"nodebridge/internal/core/audit"
)

const (
	defaultGlobLimit = 200
	maxGlobLimit     = 2000
	maxContextLines  = 5
	defaultRGTimeout = 15 * time.Second
)

// searchSkipDirs 在纯 Go 搜索与 Glob 中默认跳过的常见依赖与构建产物目录。
var searchSkipDirs = map[string]struct{}{
	".git":         {},
	"node_modules": {},
	".venv":        {},
	"__pycache__":  {},
	".idea":        {},
	"dist":         {},
	"build":        {},
	"target":       {},
	".next":        {},
	".nuxt":        {},
	"vendor":       {},
	".gradle":      {},
	".cache":       {},
}

// GlobOptions 定义 workspace.glob 的查询参数。
type GlobOptions struct {
	WorkspaceID      string
	Path             string
	Pattern          string
	RespectGitignore *bool
	IncludeDirs      bool
	Limit            int
}

// GlobResult 表示 workspace.glob 的返回结果。
type GlobResult struct {
	Source      string      `json:"source"`
	WorkspaceID string      `json:"workspace_id"`
	BasePath    string      `json:"base_path"`
	Pattern     string      `json:"pattern"`
	Entries     []ListEntry `json:"entries"`
	Truncated   bool        `json:"truncated"`
}

// SearchOptions 定义增强版 workspace.search 的查询参数。
type SearchOptions struct {
	WorkspaceID      string
	Path             string
	Query            string
	IsRegex          bool
	Glob             string
	IgnoreCase       bool
	ContextLines     int
	RespectGitignore *bool
	MaxResults       int
	ForceGoEngine    bool // 主要用于单元测试对比双引擎一致性
}

// Glob 按文件名或通配符模式查找匹配的文件或目录，支持 .gitignore 与敏感路径过滤。
func (m *Manager) Glob(opts GlobOptions) (*GlobResult, error) {
	pattern := strings.TrimSpace(opts.Pattern)
	if pattern == "" {
		return nil, errors.New("glob 模式 pattern 不能为空")
	}
	resolved, err := m.Resolve(opts.WorkspaceID, opts.Path, false)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(resolved.AbsPath)
	if err != nil {
		return nil, fmt.Errorf("访问搜索目录失败: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("路径 %q 不是目录", resolved.RelPath)
	}

	limit := opts.Limit
	if limit <= 0 {
		limit = defaultGlobLimit
	}
	if limit > maxGlobLimit {
		limit = maxGlobLimit
	}
	respectGI := true
	if opts.RespectGitignore != nil {
		respectGI = *opts.RespectGitignore
	}

	var gi *gitignoreTree
	if respectGI {
		gi = newGitignoreTree(ignoreRoot(resolved))
	}

	ws := resolved.Workspace
	allowAllDirs := m.AllowAllDirs()
	inWorkspace := isWithinRoot(ws.RealRoot, resolved.AbsPath)
	var entries []ListEntry
	truncated := false
	errStop := errors.New("glob limit reached")

	walkErr := filepath.WalkDir(resolved.AbsPath, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if p == resolved.AbsPath {
			if gi != nil && gi.ancestorIgnored(p, true) {
				return filepath.SkipDir
			}
			return nil
		}
		isDir := d.IsDir()
		relToBase, relErr := filepath.Rel(resolved.AbsPath, p)
		if relErr != nil {
			return nil
		}
		relBasePOSIX := filepath.ToSlash(relToBase)

		if isDir {
			if _, skip := searchSkipDirs[d.Name()]; skip {
				return filepath.SkipDir
			}
			if gi != nil && gi.IsIgnored(p, true) {
				return filepath.SkipDir
			}
		} else if gi != nil && gi.IsIgnored(p, false) {
			return nil
		}

		entryPOSIX := filepath.ToSlash(p)
		if inWorkspace {
			if relToWS, rErr := filepath.Rel(ws.RealRoot, p); rErr == nil {
				entryPOSIX = filepath.ToSlash(relToWS)
			}
		}
		if m.checkHardSecretPath(filepath.ToSlash(p)) != nil || m.IsSensitive(ws, entryPOSIX) {
			if isDir {
				return filepath.SkipDir
			}
			return nil
		}

		if d.Type()&os.ModeSymlink != 0 {
			realP, symErr := filepath.EvalSymlinks(p)
			if symErr != nil {
				return nil
			}
			if !allowAllDirs && !isWithinRoot(ws.RealRoot, realP) {
				return nil
			}
			realCheck := filepath.ToSlash(realP)
			if isWithinRoot(ws.RealRoot, realP) {
				if relReal, rErr := filepath.Rel(ws.RealRoot, realP); rErr == nil {
					realCheck = filepath.ToSlash(relReal)
				}
			}
			if m.checkHardSecretPath(filepath.ToSlash(realP)) != nil || m.IsSensitive(ws, realCheck) {
				return nil
			}
		}

		if isDir && !opts.IncludeDirs {
			return nil
		}

		if !matchFilePattern(pattern, relBasePOSIX, entryPOSIX, d.Name()) {
			return nil
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
			IsDir:   isDir,
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
	if entries == nil {
		entries = []ListEntry{}
	}

	return &GlobResult{
		Source:      "local_workspace_glob",
		WorkspaceID: opts.WorkspaceID,
		BasePath:    resolved.RelPath,
		Pattern:     pattern,
		Entries:     entries,
		Truncated:   truncated,
	}, nil
}

// SearchWithOptions 在指定目录或文件内搜索代码。优先调用本机 ripgrep (rg)，未安装时回退增强版纯 Go 引擎。
func (m *Manager) SearchWithOptions(opts SearchOptions) (*SearchResult, error) {
	if strings.TrimSpace(opts.Query) == "" {
		return nil, errors.New("搜索关键词 query 不能为空")
	}
	resolved, err := m.Resolve(opts.WorkspaceID, opts.Path, false)
	if err != nil {
		return nil, err
	}
	maxResults := opts.MaxResults
	if maxResults <= 0 {
		maxResults = defaultSearchLimit
	}
	if maxResults > maxSearchLimit {
		maxResults = maxSearchLimit
	}
	ctxLines := opts.ContextLines
	if ctxLines < 0 {
		ctxLines = 0
	}
	if ctxLines > maxContextLines {
		ctxLines = maxContextLines
	}
	respectGI := true
	if opts.RespectGitignore != nil {
		respectGI = *opts.RespectGitignore
	}

	// Compile once so both engines use the same match and line-number semantics.
	var re *regexp.Regexp
	prefilter := opts.Query
	if opts.IsRegex || opts.IgnoreCase {
		pattern := opts.Query
		if !opts.IsRegex {
			pattern = regexp.QuoteMeta(pattern)
		}
		if opts.IgnoreCase {
			pattern = "(?i)" + pattern
		}
		re, err = regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("无效正则表达式: %w", err)
		}
		if opts.IsRegex {
			// Rust and Go differ on Unicode character classes and word boundaries.
			// A mandatory literal prefix can safely narrow the files examined by Go.
			prefilter, _ = re.LiteralPrefix()
		}
	}
	search := fileSearch{
		manager:      m,
		resolved:     resolved,
		opts:         opts,
		pattern:      re,
		prefilter:    prefilter,
		limit:        maxResults,
		contextLines: ctxLines,
		result: SearchResult{
			Source:      "local_workspace_search",
			WorkspaceID: opts.WorkspaceID,
			Query:       opts.Query,
			Engine:      "go",
			Matches:     []SearchMatch{},
		},
	}
	if respectGI {
		search.ignore = newGitignoreTree(ignoreRoot(resolved))
	}
	if !opts.ForceGoEngine && prefilter != "" {
		search.rg, _ = exec.LookPath("rg")
		if search.rg != "" {
			search.result.Engine = "ripgrep"
		}
	}
	return search.run()
}

// Gitignore rules above a subdirectory query still apply inside that directory.
func ignoreRoot(resolved *ResolvedPath) string {
	if isWithinRoot(resolved.Workspace.RealRoot, resolved.AbsPath) {
		return resolved.Workspace.RealRoot
	}
	return resolved.AbsPath
}

type searchFile struct {
	abs  string
	name string
}

type fileSearch struct {
	manager      *Manager
	resolved     *ResolvedPath
	opts         SearchOptions
	pattern      *regexp.Regexp
	prefilter    string
	limit        int
	contextLines int
	result       SearchResult
	ignore       *gitignoreTree
	rg           string
	batch        []searchFile
	batchSize    int
}

func (s *fileSearch) run() (*SearchResult, error) {
	if _, err := os.Stat(s.resolved.AbsPath); err != nil {
		return nil, err
	}
	err := filepath.WalkDir(s.resolved.AbsPath, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if s.ignore != nil {
			ignored := s.ignore.IsIgnored(p, d.IsDir())
			if p == s.resolved.AbsPath {
				ignored = s.ignore.ancestorIgnored(p, d.IsDir())
			}
			if ignored {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		name := filepath.ToSlash(p)
		if isWithinRoot(s.resolved.Workspace.RealRoot, p) {
			rel, err := filepath.Rel(s.resolved.Workspace.RealRoot, p)
			if err != nil {
				return err
			}
			name = filepath.ToSlash(rel)
		}
		if s.manager.checkHardSecretPath(filepath.ToSlash(p)) != nil || s.manager.IsSensitive(s.resolved.Workspace, name) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if _, skip := searchSkipDirs[d.Name()]; skip && p != s.resolved.AbsPath {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(s.resolved.AbsPath, p)
		if err != nil || !matchFilePattern(s.opts.Glob, filepath.ToSlash(rel), name, d.Name()) {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			resolved, err := s.manager.Resolve(s.opts.WorkspaceID, p, false)
			if err != nil {
				return nil
			}
			p = resolved.AbsPath
		}
		info, err := os.Stat(p)
		if err != nil || !info.Mode().IsRegular() || info.Size() > defaultReadMaxBytes {
			return nil
		}
		if s.rg == "" {
			s.collect(searchFile{p, name})
		} else {
			// Keep each invocation below Windows' process command-line limit.
			s.batch = append(s.batch, searchFile{p, name})
			s.batchSize += len(p) + 3
			if len(s.batch) >= 128 || s.batchSize >= 16000 {
				s.flush()
			}
		}
		if s.result.Truncated {
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.flush()
	return &s.result, nil
}

// ripgrep only receives previously selected regular files and emits at most one
// NUL-terminated path per argument. File content and JSON events never accumulate.
func (s *fileSearch) flush() {
	files := s.batch
	s.batch = nil
	s.batchSize = 0
	if len(files) == 0 {
		return
	}
	args := []string{"--no-config", "--files-with-matches", "--null", "--no-follow", "--no-ignore", "--encoding", "none", "--fixed-strings"}
	if s.opts.IgnoreCase {
		args = append(args, "--ignore-case")
	}
	args = append(args, "-e", s.prefilter, "--")
	for _, f := range files {
		args = append(args, f.abs)
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultRGTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, s.rg, args...).Output()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return
	}
	var matched map[string]bool
	if err == nil {
		matched = make(map[string]bool, len(files))
		for _, p := range bytes.Split(output, []byte{0}) {
			matched[filepath.Clean(string(p))] = true
		}
	} else {
		// Unsupported rg syntax or a transient subprocess error: inspect this
		// batch in Go and avoid retrying the same failing program for every batch.
		s.rg = ""
		s.result.Engine = "go"
	}
	for _, f := range files {
		if matched == nil || matched[f.abs] {
			s.collect(f)
			if s.result.Truncated {
				return
			}
		}
	}
}

func (s *fileSearch) collect(f searchFile) {
	raw, err := readBoundedRegularFile(f.abs)
	if err != nil || len(raw) == 0 || isBinaryContent(raw) {
		return
	}
	content := strings.TrimSuffix(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
	lines := strings.Split(content, "\n")
	var display []string
	for i, line := range lines {
		if !s.matches(line) {
			continue
		}
		if len(s.result.Matches) >= s.limit {
			s.result.Truncated = true
			return
		}
		if display == nil {
			display = strings.Split(audit.RedactPrivateSecretsPreservingLines(content), "\n")
		}
		// A retained substring would keep the entire file alive for each hit.
		hit := SearchMatch{Path: f.name, LineNumber: i + 1, Line: strings.Clone(truncateSearchLine(display[i]))}
		for j := max(0, i-s.contextLines); j < i; j++ {
			hit.ContextBefore = append(hit.ContextBefore, fmt.Sprintf("%d: %s", j+1, truncateSearchLine(display[j])))
		}
		for j := i + 1; j < min(len(lines), i+s.contextLines+1); j++ {
			hit.ContextAfter = append(hit.ContextAfter, fmt.Sprintf("%d: %s", j+1, truncateSearchLine(display[j])))
		}
		s.result.Matches = append(s.result.Matches, hit)
	}
}

func (s *fileSearch) matches(line string) bool {
	if s.pattern != nil {
		return s.pattern.MatchString(line)
	}
	return strings.Contains(line, s.opts.Query)
}
func truncateSearchLine(s string) string {
	if len(s) > maxSearchLineLen {
		return s[:maxSearchLineLen] + "...(truncated)"
	}
	return s
}

// matchFilePattern 支持完整路径通配符（如 **/*.go、src/*.ts）以及裸文件名通配符（如 *_test.go、*auth*）。
func matchFilePattern(pattern, relToBase, entryPOSIX, baseName string) bool {
	p := strings.TrimSpace(filepath.ToSlash(pattern))
	if p == "" {
		return true
	}
	if matchGlob(p, relToBase) || matchGlob(p, entryPOSIX) {
		return true
	}
	if !strings.Contains(p, "/") {
		if ok, _ := path.Match(strings.ToLower(p), strings.ToLower(baseName)); ok {
			return true
		}
		if matchGlob("**/"+p, relToBase) {
			return true
		}
	}
	return false
}

// --- 轻量级层级 .gitignore 匹配器 ---

type gitignoreRule struct {
	baseDir  string // .gitignore 所在目录的规范绝对路径
	pattern  string
	negate   bool
	dirOnly  bool
	anchored bool // 包含斜杠，需相对于 baseDir 匹配
}

type gitignoreTree struct {
	rootAbs string
	loaded  map[string][]gitignoreRule
}

func newGitignoreTree(rootAbs string) *gitignoreTree {
	t := &gitignoreTree{
		rootAbs: filepath.Clean(rootAbs),
		loaded:  make(map[string][]gitignoreRule),
	}
	t.loadDir(t.rootAbs)
	return t
}

func (t *gitignoreTree) loadDir(dirAbs string) []gitignoreRule {
	dirAbs = filepath.Clean(dirAbs)
	if rules, ok := t.loaded[dirAbs]; ok {
		return rules
	}
	var rules []gitignoreRule
	raw, err := readBoundedRegularFile(filepath.Join(dirAbs, ".gitignore"))
	if err == nil {
		norm := strings.TrimPrefix(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\uFEFF")
		for _, line := range strings.Split(norm, "\n") {
			// Git treats leading spaces and escaped trailing spaces as literal.
			for strings.HasSuffix(line, " ") {
				run := strings.TrimRight(line[:len(line)-1], "\\")
				if (len(line)-1-len(run))%2 == 1 {
					break
				}
				line = line[:len(line)-1]
			}
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			rule := gitignoreRule{baseDir: dirAbs}
			if strings.HasPrefix(line, "!") {
				rule.negate = true
				line = strings.TrimPrefix(line, "!")
			}
			if strings.HasSuffix(line, "/") {
				rule.dirOnly = true
				line = strings.TrimSuffix(line, "/")
			}
			if strings.HasPrefix(line, "/") {
				rule.anchored = true
				line = strings.TrimPrefix(line, "/")
			} else if strings.Contains(line, "/") {
				rule.anchored = true
			}
			if line == "" {
				continue
			}
			rule.pattern = line
			rules = append(rules, rule)
		}
	}
	t.loaded[dirAbs] = rules
	return rules
}

func (t *gitignoreTree) IsIgnored(absPath string, isDir bool) bool {
	absPath = filepath.Clean(absPath)
	// 从 rootAbs 向下收集每一层目录的 .gitignore 规则
	var dirs []string
	cur := filepath.Dir(absPath)
	for {
		if !isWithinRoot(t.rootAbs, cur) {
			break
		}
		dirs = append(dirs, cur)
		if sameFSPath(cur, t.rootAbs) {
			break
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	// 反转，保证父目录规则先执行、子目录规则覆盖父目录
	for i, j := 0, len(dirs)-1; i < j; i, j = i+1, j-1 {
		dirs[i], dirs[j] = dirs[j], dirs[i]
	}

	ignored := false
	for _, dir := range dirs {
		rules := t.loadDir(dir)
		if len(rules) == 0 {
			continue
		}
		rel, err := filepath.Rel(dir, absPath)
		if err != nil {
			continue
		}
		relPOSIX := filepath.ToSlash(rel)
		baseName := filepath.Base(absPath)
		for _, rule := range rules {
			if rule.dirOnly && !isDir {
				continue
			}
			matched := false
			if rule.anchored {
				matched = matchIgnorePattern(rule.pattern, relPOSIX)
			} else {
				matched = matchIgnorePattern(rule.pattern, baseName)
			}
			if matched {
				ignored = !rule.negate
			}
		}
	}
	return ignored
}

func (t *gitignoreTree) ancestorIgnored(p string, isDir bool) bool {
	for isWithinRoot(t.rootAbs, p) && !sameFSPath(p, t.rootAbs) {
		if t.IsIgnored(p, isDir) {
			return true
		}
		p = filepath.Dir(p)
		isDir = true
	}
	return false
}

func matchIgnorePattern(pattern, name string) bool {
	if runtime.GOOS == "windows" {
		pattern = strings.ToLower(pattern)
		name = strings.ToLower(name)
	}
	if prefix, ok := strings.CutSuffix(pattern, "/**"); ok {
		// A trailing /** matches entries inside the directory, not the directory
		// itself. A later negation can therefore re-include its direct children.
		pattern = prefix + "/*/**"
	}
	return matchSegments(strings.Split(pattern, "/"), strings.Split(name, "/"))
}
