// Package audit 提供结构化 JSONL 审计日志、敏感信息脱敏与文件轮转能力。
package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Event 表示一次 MCP 工具调用或安全控制事件的审计记录。
type Event struct {
	EventID     string    `json:"event_id"`
	Timestamp   time.Time `json:"timestamp"`
	SessionID   string    `json:"session_id,omitempty"`
	ClientInfo  string    `json:"client_info,omitempty"`
	Tool        string    `json:"tool"`
	WorkspaceID string    `json:"workspace_id,omitempty"`
	RiskLevel   string    `json:"risk_level,omitempty"`
	ArgsSummary string    `json:"args_summary,omitempty"`
	Decision    string    `json:"decision"`
	Approver    string    `json:"approver,omitempty"`
	Status      string    `json:"status"`
	DurationMs  int64     `json:"duration_ms"`
	Error       string    `json:"error,omitempty"`
}

// Logger 负责脱敏、写入 JSONL 轮转文件并维护内存环形缓存供控制台实时查询。
type Logger struct {
	mu          sync.Mutex
	filePath    string
	maxSize     int64
	maxBackups  int
	recentLimit int
	recent      []Event
	listeners   map[chan Event]struct{}
}

var (
	// 匹配常见敏感凭据模式（Bearer Token、OpenAI/Anthropic/Google/GitHub Key、私钥块等）
	secretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(bearer\s+)[a-z0-9._\-]{8,}`),
		regexp.MustCompile(`(?i)((?:api[_-]?key|token|secret|password|passwd|cookie|authorization)["']?\s*[:=]\s*["']?)[^\s"',;]{4,}`),
		regexp.MustCompile(`sk-[A-Za-z0-9_\-]{12,}`),
		regexp.MustCompile(`AIza[0-9A-Za-z\-_]{20,}`),
		regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`),
		regexp.MustCompile(`nb_(?:at|rt|code|pair)_[A-Za-z0-9_\-]{8,}`),
		regexp.MustCompile(`-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----`),
	}
)

// NewLogger 创建带自动轮转和敏感脱敏功能的 JSONL 审计日志记录器。
func NewLogger(dataDir string, maxSizeMB, maxBackups int) (*Logger, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建审计日志目录失败: %w", err)
	}
	if maxSizeMB <= 0 {
		maxSizeMB = 10
	}
	if maxBackups <= 0 {
		maxBackups = 10
	}
	return &Logger{
		filePath:    filepath.Join(dataDir, "audit.jsonl"),
		maxSize:     int64(maxSizeMB) * 1024 * 1024,
		maxBackups:  maxBackups,
		recentLimit: 200,
		recent:      make([]Event, 0, 64),
		listeners:   make(map[chan Event]struct{}),
	}, nil
}

// Redact 对文本中的常见密钥、Token、密码和私钥块执行脱敏替换。
func Redact(input string) string {
	out := input
	for i, re := range secretPatterns {
		switch i {
		case 0, 1:
			out = re.ReplaceAllString(out, "${1}[REDACTED]")
		default:
			out = re.ReplaceAllString(out, "[REDACTED]")
		}
	}
	return out
}

// RedactSummary 生成定长且脱敏后的参数摘要字符串。
func RedactSummary(v any, maxLen int) string {
	if maxLen <= 0 {
		maxLen = 512
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return Redact(fmt.Sprintf("%v", v))
	}
	s := Redact(string(raw))
	if len(s) > maxLen {
		return s[:maxLen] + "...(truncated)"
	}
	return s
}

// Record 写入一条审计记录并向实时订阅者广播。
func (l *Logger) Record(ev Event) error {
	if ev.EventID == "" {
		ev.EventID = newEventID()
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	ev.ArgsSummary = Redact(ev.ArgsSummary)
	ev.Error = Redact(ev.Error)

	line, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("序列化审计日志失败: %w", err)
	}
	line = append(line, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.rotateIfNeededLocked(int64(len(line))); err != nil {
		return err
	}

	f, err := os.OpenFile(l.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("打开审计日志文件失败: %w", err)
	}
	_, writeErr := f.Write(line)
	closeErr := f.Close()
	if writeErr != nil {
		return fmt.Errorf("写入审计日志失败: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("关闭审计日志文件失败: %w", closeErr)
	}

	l.recent = append(l.recent, ev)
	if len(l.recent) > l.recentLimit {
		l.recent = l.recent[len(l.recent)-l.recentLimit:]
	}
	for ch := range l.listeners {
		select {
		case ch <- ev:
		default:
		}
	}
	return nil
}

// Recent 返回最近写入的审计事件（按时间倒序）。
func (l *Logger) Recent(limit int) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()

	n := len(l.recent)
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]Event, 0, limit)
	for i := n - 1; i >= n-limit; i-- {
		out = append(out, l.recent[i])
	}
	return out
}

// Subscribe 订阅实时审计事件流（供本地 Web 控制台 SSE 使用）。
func (l *Logger) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 32)
	l.mu.Lock()
	l.listeners[ch] = struct{}{}
	l.mu.Unlock()
	cancel := func() {
		l.mu.Lock()
		if _, ok := l.listeners[ch]; ok {
			delete(l.listeners, ch)
			close(ch)
		}
		l.mu.Unlock()
	}
	return ch, cancel
}

// FilePath 返回当前活跃审计日志文件路径。
func (l *Logger) FilePath() string {
	return l.filePath
}

func (l *Logger) rotateIfNeededLocked(incoming int64) error {
	info, err := os.Stat(l.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Size()+incoming <= l.maxSize {
		return nil
	}
	// 轮转现有备份：audit.jsonl.N-1 -> audit.jsonl.N
	for i := l.maxBackups - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", l.filePath, i)
		dst := fmt.Sprintf("%s.%d", l.filePath, i+1)
		if _, err := os.Stat(src); err == nil {
			_ = os.Remove(dst)
			_ = os.Rename(src, dst)
		}
	}
	firstBackup := fmt.Sprintf("%s.1", l.filePath)
	_ = os.Remove(firstBackup)
	if err := os.Rename(l.filePath, firstBackup); err != nil {
		return fmt.Errorf("轮转审计日志文件失败: %w", err)
	}
	return nil
}

func newEventID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "evt_" + strings.ToLower(hex.EncodeToString(b))
}
