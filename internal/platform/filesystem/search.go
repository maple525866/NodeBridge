package filesystem

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"nodebridge/internal/core/audit"
)

const (
	defaultGlobLimit   = 200
	maxGlobLimit       = 2000
	maxContextLines    = 5
	defaultRGTimeout   = 15 * time.Second
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
		gi = newGitignoreTree(resolved.AbsPath)
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

	// 先校验正则合法性，确保双引擎对非法正则的行为一致
	if opts.IsRegex {
		pat := opts.Query
		if opts.IgnoreCase {
			pat = "(?i)" + pat
		}
		if _, err := regexp.Compile(pat); err != nil {
			return nil, fmt.Errorf("无效正则表达式: %w", err)
		}
	}

	if !opts.ForceGoEngine {
		if rgPath, lookErr := exec.LookPath("rg"); lookErr == nil {
			res, rgErr := m.searchWithRipgrep(rgPath, resolved, opts, maxResults, ctxLines, respectGI)
			if rgErr == nil {
				return res, nil
			}
			// 若 ripgrep 因正则不支持等非系统原因失败，自动回退纯 Go 引擎以保证可用性
		}
	}

	return m.searchWithGo(resolved, opts, maxResults, ctxLines, respectGI)
}

func (m *Manager) searchWithRipgrep(
	rgPath string,
	resolved *ResolvedPath,
	opts SearchOptions,
	maxResults int,
	ctxLines int,
	respectGI bool,
) (*SearchResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultRGTimeout)
	defer cancel()

	args := []string{
		"--json",
		"--no-follow", // 严禁跟随符号链接逃逸到敏感目录或工作区外
		"--color", "never",
		"--max-filesize", "2M",
	}
	if !opts.IsRegex {
		args = append(args, "--fixed-strings")
	}
	if opts.IgnoreCase {
		args = append(args, "--ignore-case")
	}
	if ctxLines > 0 {
		args = append(args, "--context", strconv.Itoa(ctxLines))
	}
	if !respectGI {
		args = append(args, "--no-ignore")
	}
	if strings.TrimSpace(opts.Glob) != "" {
		args = append(args, "--glob", strings.TrimSpace(opts.Glob))
	}

	// 注入默认忽略目录与全部敏感密钥硬保护排除规则，同时后续输出仍做二次 Go 校验
	for dir := range searchSkipDirs {
		args = append(args, "--glob", "!**/"+dir+"/**")
	}
	seenExclude := make(map[string]struct{})
	addExclude := func(g string) {
		g = strings.TrimSpace(g)
		if g == "" {
			return
		}
		if _, ok := seenExclude[g]; ok {
			return
		}
		seenExclude[g] = struct{}{}
		args = append(args, "--glob", "!"+g)
	}
	for _, g := range m.hardSecretDenyGlobs {
		addExclude(g)
	}
	for _, g := range m.globalDenyGlobs {
		addExclude(g)
	}
	if resolved.Workspace != nil {
		for _, g := range resolved.Workspace.DenyGlobs {
			addExclude(g)
		}
	}

	// 使用 -e 传递搜索词，防止以 '-' 开头的搜索词被误解析为命令行参数
	args = append(args, "-e", opts.Query, "--", resolved.AbsPath)

	cmd := exec.CommandContext(ctx, rgPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) && exitErr.ExitCode() == 1 {
			// ripgrep 退出码 1 表示正常执行但无匹配结果
		} else {
			return nil, fmt.Errorf("ripgrep 执行失败: %v (%s)", runErr, strings.TrimSpace(stderr.String()))
		}
	}

	matches, truncated := m.parseRipgrepJSON(&stdout, resolved, maxResults, ctxLines)
	if matches == nil {
		matches = []SearchMatch{}
	}
	return &SearchResult{
		Source:      "local_workspace_search",
		WorkspaceID: opts.WorkspaceID,
		Query:       opts.Query,
		Engine:      "ripgrep",
		Matches:     matches,
		Truncated:   truncated,
	}, nil
}

type rgJSONEvent struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

type rgTextField struct {
	Text string `json:"text"`
}

type rgLineData struct {
	Path       rgTextField `json:"path"`
	Lines      rgTextField `json:"lines"`
	LineNumber int         `json:"line_number"`
}

func (m *Manager) parseRipgrepJSON(r *bytes.Buffer, resolved *ResolvedPath, maxResults, ctxLines int) ([]SearchMatch, bool) {
	ws := resolved.Workspace
	inWorkspace := isWithinRoot(ws.RealRoot, resolved.AbsPath)
	allowAllDirs := m.AllowAllDirs()

	type fileRecord struct {
		path      string
		lineTexts map[int]string
		matchNums []int
	}

	var fileOrder []*fileRecord
	byFile := make(map[string]*fileRecord)
	totalHits := 0
	truncated := false

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var ev rgJSONEvent
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue
		}
		if ev.Type != "match" && ev.Type != "context" {
			continue
		}
		var data rgLineData
		if err := json.Unmarshal(ev.Data, &data); err != nil {
			continue
		}
		rawPath := data.Path.Text
		if rawPath == "" {
			continue
		}
		absP := rawPath
		if !filepath.IsAbs(absP) {
			absP = filepath.Join(resolved.AbsPath, absP)
		}
		absP = filepath.Clean(absP)

		// 二次强制边界与敏感密钥红线校验，绝不单靠外部 rg 参数
		if !allowAllDirs && !isWithinRoot(ws.RealRoot, absP) {
			continue
		}
		if m.checkHardSecretPath(filepath.ToSlash(absP)) != nil {
			continue
		}
		entryPOSIX := filepath.ToSlash(absP)
		if inWorkspace {
			if relToWS, relErr := filepath.Rel(ws.RealRoot, absP); relErr == nil {
				entryPOSIX = filepath.ToSlash(relToWS)
			}
		}
		if m.IsSensitive(ws, entryPOSIX) {
			continue
		}

		rec, ok := byFile[entryPOSIX]
		if !ok {
			rec = &fileRecord{
				path:      entryPOSIX,
				lineTexts: make(map[int]string),
			}
			byFile[entryPOSIX] = rec
			fileOrder = append(fileOrder, rec)
		}

		lineText := strings.TrimRight(strings.ReplaceAll(data.Lines.Text, "\r\n", "\n"), "\n")
		lineText = audit.RedactPrivateSecrets(lineText)
		if len(lineText) > maxSearchLineLen {
			lineText = lineText[:maxSearchLineLen] + "...(truncated)"
		}
		rec.lineTexts[data.LineNumber] = lineText

		if ev.Type == "match" {
			if totalHits >= maxResults {
				truncated = true
				continue
			}
			rec.matchNums = append(rec.matchNums, data.LineNumber)
			totalHits++
		}
	}

	matches := make([]SearchMatch, 0, totalHits)
	for _, rec := range fileOrder {
		for _, ln := range rec.matchNums {
			sm := SearchMatch{
				Path:       rec.path,
				LineNumber: ln,
				Line:       rec.lineTexts[ln],
			}
			if ctxLines > 0 {
				for i := ln - ctxLines; i < ln; i++ {
					if txt, ok := rec.lineTexts[i]; ok {
						sm.ContextBefore = append(sm.ContextBefore, fmt.Sprintf("%d: %s", i, txt))
					}
				}
				for i := ln + 1; i <= ln+ctxLines; i++ {
					if txt, ok := rec.lineTexts[i]; ok {
						sm.ContextAfter = append(sm.ContextAfter, fmt.Sprintf("%d: %s", i, txt))
					}
				}
			}
			matches = append(matches, sm)
		}
	}
	return matches, truncated
}

func (m *Manager) searchWithGo(
	resolved *ResolvedPath,
	opts SearchOptions,
	maxResults int,
	ctxLines int,
	respectGI bool,
) (*SearchResult, error) {
	ws := resolved.Workspace
	var re *regexp.Regexp
	if opts.IsRegex {
		pat := opts.Query
		if opts.IgnoreCase {
			pat = "(?i)" + pat
		}
		var err error
		re, err = regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("无效正则表达式: %w", err)
		}
	}
	lowerQuery := strings.ToLower(opts.Query)

	var gi *gitignoreTree
	if respectGI {
		if fi, statErr := os.Stat(resolved.AbsPath); statErr == nil && fi.IsDir() {
			gi = newGitignoreTree(resolved.AbsPath)
		}
	}

	var matches []SearchMatch
	truncated := false
	errStop := errors.New("search limit reached")
	allowAllDirs := m.AllowAllDirs()
	inWorkspace := isWithinRoot(ws.RealRoot, resolved.AbsPath)

	walkErr := filepath.WalkDir(resolved.AbsPath, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			if p == resolved.AbsPath {
				return nil
			}
			if _, skip := searchSkipDirs[d.Name()]; skip {
				return filepath.SkipDir
			}
			if gi != nil && gi.IsIgnored(p, true) {
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

		if gi != nil && gi.IsIgnored(p, false) {
			return nil
		}

		readTarget := p
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

		entryPOSIX := filepath.ToSlash(p)
		if inWorkspace {
			if relToWS, relErr := filepath.Rel(ws.RealRoot, p); relErr == nil {
				entryPOSIX = filepath.ToSlash(relToWS)
			}
		}
		if m.IsSensitive(ws, entryPOSIX) {
			return nil
		}
		if opts.Glob != "" {
			relToBase := entryPOSIX
			if r, rErr := filepath.Rel(resolved.AbsPath, p); rErr == nil {
				relToBase = filepath.ToSlash(r)
			}
			if !matchFilePattern(opts.Glob, relToBase, entryPOSIX, d.Name()) {
				return nil
			}
		}

		fi, err := os.Stat(readTarget)
		if err != nil || fi.IsDir() || fi.Size() > defaultReadMaxBytes {
			return nil
		}

		raw, err := os.ReadFile(readTarget)
		if err != nil || isBinaryContent(raw) {
			return nil
		}

		norm := strings.ReplaceAll(string(raw), "\r\n", "\n")
		lines := strings.Split(norm, "\n")
		for idx, rawLine := range lines {
			hit := false
			if opts.IsRegex {
				hit = re.MatchString(rawLine)
			} else if opts.IgnoreCase {
				hit = strings.Contains(strings.ToLower(rawLine), lowerQuery)
			} else {
				hit = strings.Contains(rawLine, opts.Query)
			}
			if !hit {
				continue
			}

			lineText := truncateSearchLine(audit.RedactPrivateSecrets(rawLine))
			sm := SearchMatch{
				Path:       entryPOSIX,
				LineNumber: idx + 1,
				Line:       lineText,
			}
			if ctxLines > 0 {
				startCtx := max(0, idx-ctxLines)
				for i := startCtx; i < idx; i++ {
					sm.ContextBefore = append(sm.ContextBefore, fmt.Sprintf("%d: %s", i+1, truncateSearchLine(audit.RedactPrivateSecrets(lines[i]))))
				}
				endCtx := min(len(lines)-1, idx+ctxLines)
				for i := idx + 1; i <= endCtx; i++ {
					sm.ContextAfter = append(sm.ContextAfter, fmt.Sprintf("%d: %s", i+1, truncateSearchLine(audit.RedactPrivateSecrets(lines[i]))))
				}
			}
			matches = append(matches, sm)
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
	if matches == nil {
		matches = []SearchMatch{}
	}

	return &SearchResult{
		Source:      "local_workspace_search",
		WorkspaceID: opts.WorkspaceID,
		Query:       opts.Query,
		Engine:      "go",
		Matches:     matches,
		Truncated:   truncated,
	}, nil
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
	raw, err := os.ReadFile(filepath.Join(dirAbs, ".gitignore"))
	if err == nil {
		norm := strings.ReplaceAll(string(raw), "\r\n", "\n")
		for _, line := range strings.Split(norm, "\n") {
			line = strings.TrimSpace(line)
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
				matched = matchGlob(rule.pattern, relPOSIX)
			} else {
				matched = matchGlob(rule.pattern, baseName) || matchGlob("**/"+rule.pattern, relPOSIX)
			}
			if matched {
				ignored = !rule.negate
			}
		}
	}
	return ignored
}
