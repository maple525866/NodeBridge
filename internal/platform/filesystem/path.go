// Package filesystem 提供跨平台安全路径解析、目录隔离、敏感文件拦截、文件锁和 Search/Replace 补丁能力。
package filesystem

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"nodebridge/internal/config"
)

// ErrAccessDenied 表示路径越权、命中敏感文件规则或只读工作区写入被拦截。
var ErrAccessDenied = errors.New("access denied")

// Workspace 表示运行时已解析并锁定的授权工作区。
type Workspace struct {
	ID        string
	Root      string
	RealRoot  string
	ReadOnly  bool
	DenyGlobs []string
}

// ResolvedPath 表示经过完整安全校验后的路径结果。
type ResolvedPath struct {
	Workspace *Workspace
	AbsPath   string // 规范化后的真实绝对路径
	RelPath   string // 相对于工作区根目录的 POSIX 风格路径（使用 /）
}

// Manager 负责管理所有授权工作区的路径安全解析、运行时权限模式与路径级互斥锁。
type Manager struct {
	workspaces          map[string]*Workspace
	defaultWSID         string
	hardSecretDenyGlobs []string
	globalDenyGlobs     []string

	modeMu          sync.RWMutex
	allowAllDirs    bool
	fullPermissions bool

	lockMu sync.Mutex
	locks  map[string]*sync.Mutex
}

// NewManager 根据配置初始化文件系统安全管理器，解析并校验各工作区真实根目录。
func NewManager(workspaces []config.WorkspaceConfig, globalDenyGlobs []string) (*Manager, error) {
	if len(globalDenyGlobs) == 0 {
		globalDenyGlobs = config.DefaultGlobalDenyGlobs()
	}
	m := &Manager{
		workspaces:          make(map[string]*Workspace, len(workspaces)),
		hardSecretDenyGlobs: config.HardSecretDenyGlobs(),
		globalDenyGlobs:     append([]string(nil), globalDenyGlobs...),
		locks:               make(map[string]*sync.Mutex),
	}

	for _, ws := range workspaces {
		absRoot, err := filepath.Abs(ws.Root)
		if err != nil {
			return nil, fmt.Errorf("解析工作区 %s 路径失败: %w", ws.ID, err)
		}
		realRoot, err := filepath.EvalSymlinks(absRoot)
		if err != nil {
			return nil, fmt.Errorf("工作区 %s 根目录不可用 (%s): %w", ws.ID, absRoot, err)
		}
		info, err := os.Stat(realRoot)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("工作区 %s 根目录不是有效目录: %s", ws.ID, realRoot)
		}
		m.workspaces[ws.ID] = &Workspace{
			ID:        ws.ID,
			Root:      absRoot,
			RealRoot:  filepath.Clean(realRoot),
			ReadOnly:  ws.ReadOnly,
			DenyGlobs: append([]string(nil), ws.DenyGlobs...),
		}
		if m.defaultWSID == "" || ws.ID == "default" {
			m.defaultWSID = ws.ID
		}
	}
	return m, nil
}

// SetAllowAllDirs 动态开启或关闭“默认全部目录模式”（开启后允许访问宿主机任意目录）。
func (m *Manager) SetAllowAllDirs(enabled bool) {
	m.modeMu.Lock()
	m.allowAllDirs = enabled
	m.modeMu.Unlock()
}

// AllowAllDirs 返回当前是否开启了“默认全部目录模式”。
func (m *Manager) AllowAllDirs() bool {
	m.modeMu.RLock()
	v := m.allowAllDirs
	m.modeMu.RUnlock()
	return v
}

// SetFullPermissions 动态开启或关闭“全部权限模式”（开启后放开工作区只读限制，但敏感密钥/私钥目录仍受硬红线保护）。
func (m *Manager) SetFullPermissions(enabled bool) {
	m.modeMu.Lock()
	m.fullPermissions = enabled
	m.modeMu.Unlock()
}

// FullPermissions 返回当前是否开启了“全部权限模式”。
func (m *Manager) FullPermissions() bool {
	m.modeMu.RLock()
	v := m.fullPermissions
	m.modeMu.RUnlock()
	return v
}

// Workspaces 返回当前已注册的全部工作区副本。
func (m *Manager) Workspaces() []Workspace {
	out := make([]Workspace, 0, len(m.workspaces))
	for _, ws := range m.workspaces {
		out = append(out, *ws)
	}
	return out
}

// GetWorkspace 按 ID 获取工作区定义。当开启“默认全部目录模式”时，支持空值/通配符回退默认工作区或直接传入绝对目录路径。
func (m *Manager) GetWorkspace(id string) (*Workspace, error) {
	trimmed := strings.TrimSpace(id)
	if ws, ok := m.workspaces[trimmed]; ok {
		return ws, nil
	}
	if !m.AllowAllDirs() {
		return nil, fmt.Errorf("%w: 未授权的工作区 %q", ErrAccessDenied, id)
	}

	// 全部目录模式：空值、default、*、all 回退到默认工作区（或当前工作目录）
	if trimmed == "" || trimmed == "." || trimmed == "*" || strings.EqualFold(trimmed, "all") || strings.EqualFold(trimmed, "default") {
		if ws, ok := m.workspaces[m.defaultWSID]; ok {
			return ws, nil
		}
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("获取当前工作目录失败: %w", err)
		}
		realCwd, err := resolveRealPath(cwd)
		if err != nil {
			realCwd = filepath.Clean(cwd)
		}
		return &Workspace{
			ID:       "all",
			Root:     filepath.Clean(cwd),
			RealRoot: realCwd,
			ReadOnly: false,
		}, nil
	}

	// 全部目录模式：支持调用方直接将宿主机绝对目录路径作为 workspace_id 传入
	candidate := normalizeAllDirsDrivePath(trimmed)
	if filepath.IsAbs(candidate) {
		if err := checkDangerousPathSyntax(candidate); err != nil {
			return nil, err
		}
		realDir, err := resolveRealPath(filepath.Clean(candidate))
		if err != nil {
			return nil, fmt.Errorf("%w: 无法解析目录工作区 %q: %v", ErrAccessDenied, id, err)
		}
		info, err := os.Stat(realDir)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("%w: 目录工作区 %q 不存在或不是有效目录", ErrAccessDenied, id)
		}
		if err := m.checkSensitivePath(nil, filepath.ToSlash(realDir)); err != nil {
			return nil, err
		}
		return &Workspace{
			ID:       trimmed,
			Root:     filepath.Clean(candidate),
			RealRoot: realDir,
			ReadOnly: false,
		}, nil
	}

	return nil, fmt.Errorf("%w: 未授权的工作区 %q（全部目录模式下请留空/填 default，或直接传入有效绝对目录路径）", ErrAccessDenied, id)
}

// LockPath 对指定规范化绝对路径加锁，防止同一文件并发修改冲突。
func (m *Manager) LockPath(absPath string) func() {
	key := filepath.Clean(absPath)
	if runtime.GOOS == "windows" {
		key = strings.ToLower(key)
	}
	m.lockMu.Lock()
	mu, ok := m.locks[key]
	if !ok {
		mu = &sync.Mutex{}
		m.locks[key] = mu
	}
	m.lockMu.Unlock()

	mu.Lock()
	return mu.Unlock
}

// Resolve 将用户/模型传入的路径解析并验证安全边界。
// 在默认模式下严格限制在授权工作区内并拦截敏感文件；
// 开启“全部目录模式”后放开普通目录边界限制，开启“全部权限模式”后放开工作区只读限制；
// 敏感密钥目录与私钥文件硬保护红线在任何模式下均始终强制生效。
func (m *Manager) Resolve(workspaceID, targetPath string, forWrite bool) (*ResolvedPath, error) {
	allowAllDirs := m.AllowAllDirs()
	fullPerms := m.FullPermissions()

	ws, err := m.GetWorkspace(workspaceID)
	if err != nil {
		return nil, err
	}
	if forWrite && ws.ReadOnly && !fullPerms {
		return nil, fmt.Errorf("%w: 工作区 %q 为只读模式，禁止写入", ErrAccessDenied, workspaceID)
	}

	raw := strings.TrimSpace(targetPath)
	if raw == "" || raw == "." {
		if forWrite {
			return nil, fmt.Errorf("%w: 写入目标不能为工作区根目录", ErrAccessDenied)
		}
		// 即使访问工作区根本身，若该目录命中密钥硬保护红线（例如 .ssh/.gnupg/.aws），依然强制拦截
		if err := m.checkHardSecretPath(filepath.ToSlash(ws.RealRoot)); err != nil {
			return nil, err
		}
		return &ResolvedPath{
			Workspace: ws,
			AbsPath:   ws.RealRoot,
			RelPath:   ".",
		}, nil
	}

	if allowAllDirs {
		raw = normalizeAllDirsDrivePath(raw)
	}

	if err := checkDangerousPathSyntax(raw); err != nil {
		return nil, err
	}

	// 组合候选绝对路径：允许相对路径，也允许绝对路径
	var candidate string
	if filepath.IsAbs(raw) {
		candidate = filepath.Clean(raw)
	} else {
		candidate = filepath.Clean(filepath.Join(ws.RealRoot, filepath.FromSlash(raw)))
	}

	// 非全部目录模式下，先做一次词法边界检查，避免在工作区外触发不必要的系统 stat
	if !allowAllDirs && !isWithinRoot(ws.RealRoot, candidate) {
		return nil, fmt.Errorf("%w: 路径 %q 超出授权工作区边界", ErrAccessDenied, targetPath)
	}

	// 解析真实路径（防止默认模式下的符号链接/Junction 逃逸）
	realTarget, err := resolveRealPath(candidate)
	if err != nil {
		return nil, fmt.Errorf("%w: 解析真实路径失败: %v", ErrAccessDenied, err)
	}

	if !allowAllDirs && !isWithinRoot(ws.RealRoot, realTarget) {
		return nil, fmt.Errorf("%w: 路径 %q 经符号链接解析后逃逸出授权工作区", ErrAccessDenied, targetPath)
	}

	if forWrite {
		if fi, statErr := os.Stat(realTarget); statErr == nil && fi.IsDir() {
			return nil, fmt.Errorf("%w: 写入目标 %q 是目录而非文件", ErrAccessDenied, targetPath)
		}
	}

	var relPOSIX string
	if isWithinRoot(ws.RealRoot, realTarget) {
		relOS, relErr := filepath.Rel(ws.RealRoot, realTarget)
		if relErr != nil {
			return nil, fmt.Errorf("%w: 计算相对路径失败: %v", ErrAccessDenied, relErr)
		}
		relPOSIX = filepath.ToSlash(relOS)
	} else {
		// 全部目录模式下，工作区外路径（含跨盘符）直接返回规范化 POSIX 风格绝对路径，便于后续工具直接回传
		relPOSIX = filepath.ToSlash(realTarget)
	}

	// 无论是否开启「全部权限」或「默认全部目录」，均强制对真实绝对路径与工作区相对路径执行敏感密钥/凭证硬拦截
	if err := m.checkHardSecretPath(filepath.ToSlash(realTarget)); err != nil {
		return nil, err
	}
	if relPOSIX == "." {
		if forWrite {
			return nil, fmt.Errorf("%w: 写入目标不能为工作区根目录", ErrAccessDenied)
		}
	} else {
		if err := m.checkSensitivePath(ws, relPOSIX); err != nil {
			return nil, err
		}
	}

	return &ResolvedPath{
		Workspace: ws,
		AbsPath:   realTarget,
		RelPath:   relPOSIX,
	}, nil
}

// normalizeAllDirsDrivePath 在全部目录模式下将形如 "C:" 的盘符简写补全为根目录 "C:\"。
func normalizeAllDirsDrivePath(raw string) string {
	if len(raw) == 2 && isASCIIAlpha(raw[0]) && raw[1] == ':' {
		return raw + string(filepath.Separator)
	}
	return raw
}

// IsSensitive 检查相对或绝对 POSIX 路径是否命中敏感密钥/凭证拒绝规则。
// 该安全边界始终生效，不可被「全部权限」或「默认全部目录」绕过。
func (m *Manager) IsSensitive(ws *Workspace, relPOSIX string) bool {
	return m.checkSensitivePath(ws, relPOSIX) != nil
}

// DenyGlobsBelow returns the active exclusions relative to a resolved directory.
// A directory can match several prefixes of a pattern containing **.
func (m *Manager) DenyGlobsBelow(dir *ResolvedPath) []string {
	var prefix []string
	if dir.RelPath != "." {
		prefix = strings.Split(strings.ToLower(strings.Trim(filepath.ToSlash(dir.RelPath), "/")), "/")
	}
	seen := make(map[string]bool)
	var globs []string
	for _, rules := range [][]string{m.hardSecretDenyGlobs, m.globalDenyGlobs, dir.Workspace.DenyGlobs} {
		for _, rule := range rules {
			parts := strings.Split(strings.TrimPrefix(filepath.ToSlash(rule), "/"), "/")
			// Each position is the next pattern component after consuming the directory prefix.
			positions := map[int]bool{0: true}
			for _, name := range prefix {
				next := make(map[int]bool)
				for i := range positions {
					for i < len(parts) && parts[i] == "**" {
						next[i] = true
						i++
					}
					if i == len(parts) {
						return []string{"**"} // a denied directory excludes all its descendants
					}
					if ok, _ := path.Match(strings.ToLower(parts[i]), name); ok {
						next[i+1] = true
					}
				}
				positions = next
			}
			for i := 0; i <= len(parts); i++ {
				if !positions[i] {
					continue
				}
				if i == len(parts) {
					return []string{"**"}
				}
				suffix := strings.Join(parts[i:], "/")
				if !seen[suffix] {
					seen[suffix] = true
					globs = append(globs, suffix)
				}
			}
		}
	}
	return globs
}

func (m *Manager) checkHardSecretPath(pathPOSIX string) error {
	cleanPath := strings.TrimPrefix(path.Clean("/"+filepath.ToSlash(pathPOSIX)), "/")
	if cleanPath == "" || cleanPath == "." {
		return nil
	}
	for _, g := range m.hardSecretDenyGlobs {
		if matchGlob(g, cleanPath) {
			return fmt.Errorf("%w: 路径 %q 命中敏感密钥/凭证硬保护红线 (%s)，禁止查看或修改", ErrAccessDenied, cleanPath, g)
		}
	}
	return nil
}

func (m *Manager) checkSensitivePath(ws *Workspace, relPOSIX string) error {
	cleanRel := strings.TrimPrefix(path.Clean("/"+filepath.ToSlash(relPOSIX)), "/")
	if cleanRel == "" || cleanRel == "." {
		return nil
	}
	if err := m.checkHardSecretPath(cleanRel); err != nil {
		return err
	}
	for _, g := range m.globalDenyGlobs {
		if matchGlob(g, cleanRel) {
			return fmt.Errorf("%w: 路径 %q 命中全局敏感文件保护规则 (%s)", ErrAccessDenied, cleanRel, g)
		}
	}
	if ws != nil {
		for _, g := range ws.DenyGlobs {
			if matchGlob(g, cleanRel) {
				return fmt.Errorf("%w: 路径 %q 命中工作区拒绝规则 (%s)", ErrAccessDenied, cleanRel, g)
			}
		}
	}
	return nil
}

// checkDangerousPathSyntax 拦截 NUL 字节、UNC 网络路径、Windows 设备路径、ADS 和保留设备名。
func checkDangerousPathSyntax(raw string) error {
	if strings.ContainsRune(raw, 0) {
		return fmt.Errorf("%w: 路径包含非法空字符", ErrAccessDenied)
	}
	// 拦截 UNC 路径（\\server\share 或 //server/share）及 Windows 设备路径（\\.\, \\?\）
	if strings.HasPrefix(raw, `\\`) || strings.HasPrefix(raw, `//`) {
		return fmt.Errorf("%w: 禁止访问 UNC 网络路径或设备路径 %q", ErrAccessDenied, raw)
	}

	// 检查 Windows Alternate Data Streams（除盘符 C: 外任何位置不允许出现冒号）
	colonCheck := raw
	if len(colonCheck) >= 2 && isASCIIAlpha(colonCheck[0]) && colonCheck[1] == ':' {
		// 仅 Windows 允许绝对盘符，且盘符后必须紧跟路径分隔符（禁止 C:relative 隐式当前目录绕过）
		if len(colonCheck) == 2 || (colonCheck[2] != '\\' && colonCheck[2] != '/') {
			return fmt.Errorf("%w: 禁止使用非标准盘符相对路径 %q", ErrAccessDenied, raw)
		}
		colonCheck = colonCheck[2:]
	}
	if strings.ContainsRune(colonCheck, ':') {
		return fmt.Errorf("%w: 路径包含非法冒号或 Alternate Data Stream %q", ErrAccessDenied, raw)
	}

	// 拦截 Windows 保留设备名及尾随点号/空格（防御 Windows NTFS 自动剥离末尾 . / 空格绕过敏感文件扩展名检查）
	norm := strings.ReplaceAll(raw, `\`, `/`)
	for _, seg := range strings.Split(norm, "/") {
		if seg == "" || seg == "." || seg == ".." {
			continue
		}
		if strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
			return fmt.Errorf("%w: 路径段 %q 包含非法尾随点号或空格", ErrAccessDenied, seg)
		}
		if isWindowsReservedName(seg) {
			return fmt.Errorf("%w: 路径包含系统保留设备名 %q", ErrAccessDenied, seg)
		}
	}
	return nil
}

func isASCIIAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

var windowsReservedNames = map[string]struct{}{
	"CON": {}, "PRN": {}, "AUX": {}, "NUL": {},
	"COM1": {}, "COM2": {}, "COM3": {}, "COM4": {}, "COM5": {}, "COM6": {}, "COM7": {}, "COM8": {}, "COM9": {},
	"LPT1": {}, "LPT2": {}, "LPT3": {}, "LPT4": {}, "LPT5": {}, "LPT6": {}, "LPT7": {}, "LPT8": {}, "LPT9": {},
}

func isWindowsReservedName(seg string) bool {
	base := strings.TrimRight(seg, ". ")
	if dot := strings.IndexByte(base, '.'); dot >= 0 {
		base = base[:dot]
	}
	_, reserved := windowsReservedNames[strings.ToUpper(base)]
	return reserved
}

// resolveRealPath 解析已存在路径的真实路径；若目标尚不存在则解析最近存在的祖先目录并拼回剩余子段。
func resolveRealPath(absPath string) (string, error) {
	if resolved, err := filepath.EvalSymlinks(absPath); err == nil {
		return filepath.Clean(resolved), nil
	} else if !os.IsNotExist(err) {
		return "", err
	}

	// 向上查找最近存在的祖先目录
	cur := absPath
	var tail []string
	for {
		parent := filepath.Dir(cur)
		base := filepath.Base(cur)
		if parent == cur {
			return "", os.ErrNotExist
		}
		tail = append([]string{base}, tail...)
		cur = parent
		resolvedParent, err := filepath.EvalSymlinks(cur)
		if err == nil {
			parts := append([]string{resolvedParent}, tail...)
			return filepath.Clean(filepath.Join(parts...)), nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
	}
}

// isWithinRoot 判定 target 是否等于 root 或位于 root 之下（在 Windows 上做大小写不敏感校验）。
func isWithinRoot(root, target string) bool {
	cleanRoot := filepath.Clean(root)
	cleanTarget := filepath.Clean(target)
	if runtime.GOOS == "windows" {
		cleanRoot = strings.ToLower(cleanRoot)
		cleanTarget = strings.ToLower(cleanTarget)
	}
	rel, err := filepath.Rel(cleanRoot, cleanTarget)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

// matchGlob 支持 POSIX 风格 `**` 递归通配符匹配（大小写不敏感以防御 Windows 大小写绕过）。
func matchGlob(pattern, relPOSIX string) bool {
	p := strings.ToLower(strings.TrimPrefix(filepath.ToSlash(pattern), "/"))
	s := strings.ToLower(strings.TrimPrefix(filepath.ToSlash(relPOSIX), "/"))

	pSegs := strings.Split(p, "/")
	sSegs := strings.Split(s, "/")
	return matchSegments(pSegs, sSegs)
}

func matchSegments(pSegs, sSegs []string) bool {
	if len(pSegs) == 0 {
		return len(sSegs) == 0
	}
	if pSegs[0] == "**" {
		// `**` 匹配 0 段或多段目录
		if matchSegments(pSegs[1:], sSegs) {
			return true
		}
		if len(sSegs) > 0 {
			return matchSegments(pSegs, sSegs[1:])
		}
		return false
	}
	if len(sSegs) == 0 {
		return false
	}
	ok, err := path.Match(pSegs[0], sSegs[0])
	if err != nil || !ok {
		return false
	}
	return matchSegments(pSegs[1:], sSegs[1:])
}
