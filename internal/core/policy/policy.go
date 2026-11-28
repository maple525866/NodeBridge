// Package policy 实现工具与终端命令的四级风险评估（L0-L3）及危险模式拦截。
package policy

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"

	"nodebridge/internal/config"
)

// RiskLevel 表示操作风险等级。
type RiskLevel string

const (
	RiskL0 RiskLevel = "L0" // 只读操作
	RiskL1 RiskLevel = "L1" // 普通写入 / 白名单开发测试（支持限时工作区批授）
	RiskL2 RiskLevel = "L2" // 高风险（未知程序、显式 Shell、依赖安装、删除等，必须逐次确认）
	RiskL3 RiskLevel = "L3" // 关键或危险操作（提权、远程脚本执行、破坏性命令、git push 等）
)

// Action 表示策略引擎的裁决动作。
type Action string

const (
	ActionAllow           Action = "ALLOW"
	ActionRequireApproval Action = "REQUIRE_APPROVAL"
	ActionDeny            Action = "DENY"
)

// Evaluation 表示策略评估的详细结果。
type Evaluation struct {
	RiskLevel           RiskLevel `json:"risk_level"`
	Action              Action    `json:"action"`
	AllowBatchTTL       bool      `json:"allow_batch_ttl"`                  // 是否允许享受工作区限时批量授权（仅 L1 为 true）
	BypassedByFullPerms bool      `json:"bypassed_by_full_perms,omitempty"` // 本次放行是否由「全部权限模式」触发（供审计精确记录）
	Reason              string    `json:"reason"`
}

// Engine 封装基于配置的风险评估引擎，并支持运行时动态切换“全部权限模式”。
type Engine struct {
	cmdCfg          config.CommandPolicyConfig
	hardDenySet     map[string]struct{}
	l2ExecSet       map[string]struct{}
	l0Rules         map[string][]string
	l1Rules         map[string][]string
	fullPermissions atomic.Bool
}

var dangerousPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(curl|wget)\b[^|]*\|\s*(sh|bash|zsh|dash|pwsh|powershell)`),
	regexp.MustCompile(`(?i)\b(iwr|invoke-webrequest|irm|invoke-restmethod)\b[^|]*\|\s*(iex|invoke-expression)`),
	regexp.MustCompile(`(?i)\b(powershell|pwsh)\b[^\n]*\s-(e|ec|enc|encodedcommand)\b`),
	regexp.MustCompile(`(?i)\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+(/|~|\$home|\*)\b`),
	regexp.MustCompile(`(?i)\bremove-item\b[^\n]*-recurse[^\n]*-force[^\n]*([a-z]:\\|/)`),
}

var encodedShellPattern = regexp.MustCompile(`(?i)\b(powershell|pwsh)\b[^\n]*\s-(e|ec|enc|encodedcommand)\b`)

// secretAccessPatterns 定义不可被「全部权限模式」绕过的密钥目录与私钥/凭证访问硬红线。
// 注意：结尾边界包含括号/花括号/反引号等 Shell 语法符，且对易冲突后缀（如 .key）做更精确的路径/文件名限定以减少对 jq '.key'、go test -run 等正常命令的误杀。
var secretAccessPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:^|[\s"'=:\\/;,&|<>~%(\[\{` + "`" + `])\.ssh(?:$|[\\/\s"';,&|<>)\]\}` + "`" + `])`),
	regexp.MustCompile(`(?i)(?:^|[\s"'=:\\/;,&|<>~%(\[\{` + "`" + `])\.gnupg(?:$|[\\/\s"';,&|<>)\]\}` + "`" + `])`),
	regexp.MustCompile(`(?i)(?:^|[\s"'=:\\/;,&|<>~%(\[\{` + "`" + `])\.aws(?:$|[\\/\s"';,&|<>)\]\}` + "`" + `])`),
	regexp.MustCompile(`(?i)(?:^|[\s"'=:\\/;,&|<>~%(\[\{` + "`" + `])\.kube(?:$|[\\/\s"';,&|<>)\]\}` + "`" + `])`),
	regexp.MustCompile(`(?i)(?:^|[\s"'=:\\/;,&|<>~%(\[\{` + "`" + `])\.docker[\\/]config\.json(?:$|[\s"';,&|<>)\]\}` + "`" + `])`),
	regexp.MustCompile(`(?i)(?:^|[\s"'=:\\/;,&|<>~%(\[\{` + "`" + `])\.env(?:\.[a-z0-9_.-]+)?(?:$|[\s"';,&|<>)\]\}` + "`" + `])`),
	regexp.MustCompile(`(?i)(?:^|[\s"'=:\\/;,&|<>~%(\[\{` + "`" + `])(?:\.npmrc|\.pypirc|\.git-credentials|\.netrc|_netrc|credentials\.json)(?:$|[\s"';,&|<>)\]\}` + "`" + `])`),
	regexp.MustCompile(`(?i)(?:^|[\s"'=:\\/;,&|<>~%(\[\{` + "`" + `])(id_rsa|id_ed25519|id_ecdsa|id_dsa)(?:\.[a-z0-9_-]+)?(?:$|[\s"';,&|<>)\]\}` + "`" + `])`),
	regexp.MustCompile(`(?i)(?:^|[\s"'=:\\/;,&|<>~%(\[\{` + "`" + `])authorized_keys(?:$|[\s"';,&|<>)\]\}` + "`" + `])`),
	regexp.MustCompile(`(?i)(?:^|[\s"'=:\\/;,&|<>~%(\[\{` + "`" + `])[a-z0-9._\\/-]+\.(?:pem|ppk|p12|pfx|jks|keystore|kdbx)(?:$|[\s"';,&|<>)\]\}` + "`" + `])`),
	regexp.MustCompile(`(?i)(?:^|[\s"'=:\\/;,&|<>~%(\[\{` + "`" + `])(?:[a-z0-9_-]+[\\/])*[a-z0-9_-]+\.key(?:$|[\s"';,&|<>)\]\}` + "`" + `])`),
	regexp.MustCompile(`(?i)(?:^|[\s"'=:\\/;,&|<>~%(\[\{` + "`" + `])nodebridge\.yaml(?:$|[\s"';,&|<>)\]\}` + "`" + `])`),
	regexp.MustCompile(`(?i)(?:^|[\s"'=:\\/;,&|<>~%(\[\{` + "`" + `])service\.env(?:$|[\s"';,&|<>)\]\}` + "`" + `])`),
}

// NewEngine 根据安全配置构建策略引擎。
func NewEngine(sec config.SecurityConfig) *Engine {
	e := &Engine{
		cmdCfg:      sec.CommandPolicy,
		hardDenySet: make(map[string]struct{}),
		l2ExecSet:   make(map[string]struct{}),
		l0Rules:     make(map[string][]string),
		l1Rules:     make(map[string][]string),
	}
	e.fullPermissions.Store(sec.FullPermissions)
	for _, exe := range sec.CommandPolicy.HardDenyExecutables {
		e.hardDenySet[normalizeExecName(exe)] = struct{}{}
	}
	for _, exe := range sec.CommandPolicy.L2Executables {
		e.l2ExecSet[normalizeExecName(exe)] = struct{}{}
	}
	for _, r := range sec.CommandPolicy.L0Rules {
		name := normalizeExecName(r.Executable)
		e.l0Rules[name] = append(e.l0Rules[name], lowerSlice(r.AllowedSubcommands)...)
	}
	for _, r := range sec.CommandPolicy.L1Rules {
		name := normalizeExecName(r.Executable)
		e.l1Rules[name] = append(e.l1Rules[name], lowerSlice(r.AllowedSubcommands)...)
	}
	return e
}

// SetFullPermissions 动态开启或关闭“全部权限模式”。
func (e *Engine) SetFullPermissions(enabled bool) {
	e.fullPermissions.Store(enabled)
}

// FullPermissions 返回当前是否处于“全部权限模式”。
func (e *Engine) FullPermissions() bool {
	return e.fullPermissions.Load()
}

// EvaluateTool 对非终端类内置 MCP 工具给出风险评估结果。
func (e *Engine) EvaluateTool(toolName string) Evaluation {
	ev := e.evaluateToolBase(toolName)
	if e.fullPermissions.Load() && ev.Action != ActionAllow {
		ev.Action = ActionAllow
		ev.AllowBatchTTL = false
		ev.BypassedByFullPerms = true
		ev.Reason = "已开启全部权限模式，免审批直接放行"
	}
	return ev
}

// EvaluateDelete 针对 workspace.delete 根据是否为非空目录递归删除给出差异化风险评估。
// 删除单文件或空目录按 L1（支持限时批授）；递归删除非空目录自动升级为 L2（强制每次人工审批）。
func (e *Engine) EvaluateDelete(recursiveNonEmpty bool) Evaluation {
	var ev Evaluation
	if recursiveNonEmpty {
		ev = Evaluation{
			RiskLevel:     RiskL2,
			Action:        ActionRequireApproval,
			AllowBatchTTL: false,
			Reason:        "将在工作区内递归删除非空目录，属于 L2 高风险操作，必须每次人工审批",
		}
	} else {
		ev = Evaluation{
			RiskLevel:     RiskL1,
			Action:        ActionRequireApproval,
			AllowBatchTTL: true,
			Reason:        "将在授权工作区内删除单个文件或空目录，需要人工确认（支持限时批量授权）",
		}
	}
	if e.fullPermissions.Load() && ev.Action != ActionAllow {
		ev.Action = ActionAllow
		ev.AllowBatchTTL = false
		ev.BypassedByFullPerms = true
		ev.Reason = "已开启全部权限模式，免审批直接放行"
	}
	return ev
}

func (e *Engine) evaluateToolBase(toolName string) Evaluation {
	switch toolName {
	case "system.info", "workspace.list", "workspace.read", "workspace.search", "workspace.glob",
		"git.status", "git.diff", "git.log", "git.show", "terminal.poll", "approval.status":
		return Evaluation{
			RiskLevel:     RiskL0,
			Action:        ActionAllow,
			AllowBatchTTL: false,
			Reason:        "授权工作区内的只读查询操作，自动放行",
		}
	case "workspace.patch", "workspace.write", "workspace.mkdir", "workspace.move", "workspace.delete", "git.apply_patch":
		return Evaluation{
			RiskLevel:     RiskL1,
			Action:        ActionRequireApproval,
			AllowBatchTTL: true,
			Reason:        "将在授权工作区内修改、新建、移动或删除代码文件及目录，需要人工确认（支持限时批量授权）",
		}
	case "terminal.cancel":
		return Evaluation{
			RiskLevel:     RiskL0,
			Action:        ActionAllow,
			AllowBatchTTL: false,
			Reason:        "取消已启动任务属于安全控制操作，自动放行",
		}
	default:
		return Evaluation{
			RiskLevel:     RiskL2,
			Action:        ActionRequireApproval,
			AllowBatchTTL: false,
			Reason:        fmt.Sprintf("未分类工具 %q，默认按 L2 高风险需人工确认", toolName),
		}
	}
}

// EvaluateCommand 对 terminal.start 请求执行四层命令策略评估。
func (e *Engine) EvaluateCommand(executable string, args []string, useShell bool) Evaluation {
	fullLine := strings.TrimSpace(executable + " " + strings.Join(args, " "))
	if fullLine == "" {
		return Evaluation{
			RiskLevel: RiskL3,
			Action:    ActionDeny,
			Reason:    "命令不能为空",
		}
	}
	// 硬红线 1：禁止编码 PowerShell 命令（防 Base64 编码绕过密钥保护与输出脱敏）
	if encodedShellPattern.MatchString(fullLine) {
		return Evaluation{
			RiskLevel: RiskL3,
			Action:    ActionDeny,
			Reason:    "命中编码命令硬保护红线（禁止使用 PowerShell -EncodedCommand 规避安全检查）",
		}
	}
	// 硬红线 2：任何模式（含全部权限模式）下都禁止通过命令直接查看、读取、修改或删除 SSH 私钥、密钥目录与凭证文件
	if matchesSecretAccess(executable, args, useShell, fullLine) {
		return Evaluation{
			RiskLevel: RiskL3,
			Action:    ActionDeny,
			Reason:    "命中敏感密钥/凭证硬保护红线（禁止通过命令查看、读取或修改 SSH 私钥、密钥目录等敏感凭证）",
		}
	}
	ev := e.evaluateCommandBase(executable, args, useShell, fullLine)
	if e.fullPermissions.Load() && ev.Action != ActionAllow {
		ev.Action = ActionAllow
		ev.AllowBatchTTL = false
		ev.BypassedByFullPerms = true
		ev.Reason = "已开启全部权限模式，跳过策略拦截与人工审批直接放行"
	}
	return ev
}

// matchesSecretAccess 精确检查命令是否访问敏感密钥/凭证路径，同时在参数数组模式下避免误杀 git commit 消息或 go test 过滤正则。
func matchesSecretAccess(executable string, args []string, useShell bool, fullLine string) bool {
	if useShell {
		for _, re := range secretAccessPatterns {
			if re.MatchString(fullLine) {
				return true
			}
		}
		return false
	}

	execName := normalizeExecName(executable)
	// 参数数组模式逐参检查，跳过明显非文件路径的文本参数（如 git commit -m <msg>、go test -run <regex>、jq 过滤表达式）
	for i, arg := range args {
		if isNonFileTextArg(execName, args, i) {
			continue
		}
		for _, re := range secretAccessPatterns {
			if re.MatchString(arg) {
				return true
			}
		}
	}
	for _, re := range secretAccessPatterns {
		if re.MatchString(executable) {
			return true
		}
	}
	return false
}

func isNonFileTextArg(execName string, args []string, idx int) bool {
	if idx <= 0 {
		// jq 第一个非 flag 参数是过滤表达式（如 jq '.key' data.json）
		if execName == "jq" && idx == 0 && !strings.HasPrefix(args[0], "-") {
			return true
		}
		return false
	}
	prev := strings.ToLower(strings.TrimSpace(args[idx-1]))
	switch execName {
	case "git":
		sub := strings.ToLower(strings.TrimSpace(args[0]))
		if sub == "commit" && (prev == "-m" || prev == "--message") {
			return true
		}
	case "go":
		sub := strings.ToLower(strings.TrimSpace(args[0]))
		if sub == "test" && (prev == "-run" || prev == "-bench" || prev == "-skip") {
			return true
		}
	case "rg", "grep":
		if prev == "-e" || prev == "--regexp" {
			return true
		}
	}
	return false
}

func (e *Engine) evaluateCommandBase(executable string, args []string, useShell bool, fullLine string) Evaluation {

	// 1. 检测下载并执行脚本、编码提权、根目录递归强制删除等高危模式
	for _, re := range dangerousPatterns {
		if re.MatchString(fullLine) {
			return Evaluation{
				RiskLevel: RiskL3,
				Action:    ActionDeny,
				Reason:    "命中高危命令安全规则（禁止下载执行脚本、编码命令或破坏性删除）",
			}
		}
	}

	// 2. 显式 Shell 模式检查
	if useShell {
		if !e.cmdCfg.AllowExplicitShell {
			return Evaluation{
				RiskLevel: RiskL3,
				Action:    ActionDeny,
				Reason:    "配置已禁用显式 Shell（use_shell=true）执行模式",
			}
		}
		// 检查 Shell 字符串首词是否命中硬拒绝程序
		fields := strings.Fields(fullLine)
		if len(fields) > 0 {
			if _, denied := e.hardDenySet[normalizeExecName(fields[0])]; denied {
				return Evaluation{
					RiskLevel: RiskL3,
					Action:    ActionDeny,
					Reason:    fmt.Sprintf("命令 %q 命中 L3 硬拒绝黑名单（提权或系统级破坏风险）", fields[0]),
				}
			}
		}
		return Evaluation{
			RiskLevel:     RiskL2,
			Action:        ActionRequireApproval,
			AllowBatchTTL: false,
			Reason:        "显式 Shell 解释执行模式存在命令注入与副作用风险，必须每次人工审批",
		}
	}

	// 3. 参数数组模式：规范化可执行文件名
	execName := normalizeExecName(executable)
	if _, denied := e.hardDenySet[execName]; denied {
		return Evaluation{
			RiskLevel: RiskL3,
			Action:    ActionDeny,
			Reason:    fmt.Sprintf("可执行程序 %q 位于 L3 硬拒绝清单中", executable),
		}
	}

	// 4. 针对 Git 危险子命令提升至 L3 每次强确认
	if execName == "git" && len(args) > 0 {
		sub := strings.ToLower(strings.TrimSpace(args[0]))
		if sub == "push" || sub == "clean" || (sub == "reset" && containsArg(args[1:], "--hard")) {
			return Evaluation{
				RiskLevel:     RiskL3,
				Action:        ActionRequireApproval,
				AllowBatchTTL: false,
				Reason:        fmt.Sprintf("git %s 属于 L3 关键操作（影响远端或不可逆丢弃变更），必须每次单独确认", sub),
			}
		}
	}

	// An interpreter module used for package installation requires its own approval.
	if (execName == "python" || execName == "python3") && len(args) >= 2 && args[0] == "-m" {
		module := strings.ToLower(args[1])
		if module == "pip" || strings.HasPrefix(module, "pip.") || module == "ensurepip" {
			return Evaluation{RiskLevel: RiskL2, Action: ActionRequireApproval,
				Reason: "Python 包管理模块需要每次人工审批"}
		}
	}

	// 5. L0 白名单匹配
	bareName := filepath.Base(executable) == executable
	versionQuery := execName == "node" || execName == "rustc"
	if subs, ok := e.l0Rules[execName]; ok && bareName && (!versionQuery || len(args) == 1) && matchSubcommand(subs, args) {
		return Evaluation{
			RiskLevel:     RiskL0,
			Action:        ActionAllow,
			AllowBatchTTL: false,
			Reason:        fmt.Sprintf("命中 L0 只读白名单命令 (%s)", execName),
		}
	}

	// 6. L1 白名单匹配（支持工作区限时批量授权）
	if subs, ok := e.l1Rules[execName]; ok && matchSubcommand(subs, args) {
		return Evaluation{
			RiskLevel:     RiskL1,
			Action:        ActionRequireApproval,
			AllowBatchTTL: true,
			Reason:        fmt.Sprintf("命中 L1 开发测试命令 (%s)，需人工审批或工作区限时授权", execName),
		}
	}

	// 7. L2 已知高风险程序或不在白名单中的未知程序 -> 强制每次人工审批
	if _, isL2 := e.l2ExecSet[execName]; isL2 {
		return Evaluation{
			RiskLevel:     RiskL2,
			Action:        ActionRequireApproval,
			AllowBatchTTL: false,
			Reason:        fmt.Sprintf("程序 %q 属于 L2 高风险类别（依赖安装/网络/删除），必须每次明确审批", executable),
		}
	}

	return Evaluation{
		RiskLevel:     RiskL2,
		Action:        ActionRequireApproval,
		AllowBatchTTL: false,
		Reason:        fmt.Sprintf("程序 %q 不在低风险白名单中，自动升级为 L2 强制人工审批", executable),
	}
}

func normalizeExecName(raw string) string {
	base := filepath.Base(strings.TrimSpace(raw))
	lower := strings.ToLower(base)
	for _, ext := range []string{".exe", ".cmd", ".bat", ".com", ".ps1"} {
		lower = strings.TrimSuffix(lower, ext)
	}
	return lower
}

func lowerSlice(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.ToLower(strings.TrimSpace(s)))
	}
	return out
}

func matchSubcommand(allowed []string, args []string) bool {
	// 允许子命令列表为空表示该可执行程序任意参数均匹配该规则
	if len(allowed) == 0 {
		return true
	}
	if len(args) == 0 {
		return false
	}
	first := strings.ToLower(strings.TrimSpace(args[0]))
	for _, a := range allowed {
		if first == a {
			return true
		}
	}
	return false
}

func containsArg(args []string, target string) bool {
	for _, a := range args {
		if strings.EqualFold(strings.TrimSpace(a), target) {
			return true
		}
	}
	return false
}
