// Package store 定义本地状态持久化接口与基于文件的原子 JSON 实现。
// 通过 Store 接口隔离底层介质，便于阶段三平滑切换到 SQLite。
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DeviceIdentity 描述持久化在本地的独立设备身份信息。
type DeviceIdentity struct {
	DeviceID  string    `json:"device_id"`
	Hostname  string    `json:"hostname,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// LoadOrCreateDeviceIdentity 读取或首次生成高熵持久化设备 ID（落盘 0600 权限）。
func LoadOrCreateDeviceIdentity(dataDir, preferredID string) (DeviceIdentity, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return DeviceIdentity{}, fmt.Errorf("创建数据目录失败: %w", err)
	}
	path := filepath.Join(dataDir, "device.json")
	preferredID = strings.TrimSpace(preferredID)
	hostname, _ := os.Hostname()

	if raw, err := os.ReadFile(path); err == nil && len(raw) > 0 {
		var existing DeviceIdentity
		if err := json.Unmarshal(raw, &existing); err == nil && strings.TrimSpace(existing.DeviceID) != "" {
			if preferredID != "" && existing.DeviceID != preferredID {
				existing.DeviceID = preferredID
				_ = writeAtomicJSON(path, existing)
			}
			return existing, nil
		}
	}

	devID := preferredID
	if devID == "" {
		buf := make([]byte, 8)
		if _, err := rand.Read(buf); err != nil {
			return DeviceIdentity{}, fmt.Errorf("生成设备 ID 失败: %w", err)
		}
		devID = "dev_" + strings.ToLower(hex.EncodeToString(buf))
	}
	ident := DeviceIdentity{
		DeviceID:  devID,
		Hostname:  hostname,
		CreatedAt: time.Now().UTC(),
	}
	if err := writeAtomicJSON(path, ident); err != nil {
		return DeviceIdentity{}, fmt.Errorf("保存设备身份失败: %w", err)
	}
	return ident, nil
}

func writeAtomicJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		if wErr := os.WriteFile(path, data, 0o600); wErr != nil {
			return wErr
		}
		_ = os.Remove(tmpPath)
	}
	return nil
}

// TaskRecord 表示可持久化的异步任务快照记录。
type TaskRecord struct {
	ID              string    `json:"id"`
	SessionID       string    `json:"session_id"`
	WorkspaceID     string    `json:"workspace_id"`
	ToolName        string    `json:"tool_name"`
	Executable      string    `json:"executable"`
	Args            []string  `json:"args"`
	Cwd             string    `json:"cwd"`
	Status          string    `json:"status"`
	ExitCode        *int      `json:"exit_code,omitempty"`
	ErrorMessage    string    `json:"error_message,omitempty"`
	OutputSummary   string    `json:"output_summary,omitempty"`
	StdoutTruncated bool      `json:"stdout_truncated,omitempty"`
	StderrTruncated bool      `json:"stderr_truncated,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	StartedAt       time.Time `json:"started_at,omitempty"`
	FinishedAt      time.Time `json:"finished_at,omitempty"`
}

// TaskStore 定义任务记录的持久化存储契约。
type TaskStore interface {
	LoadAll() ([]TaskRecord, error)
	SaveAll(records []TaskRecord) error
}

// JSONFileTaskStore 基于单个 JSON 文件实现原子快照存储（零 CGo、零外部依赖）。
type JSONFileTaskStore struct {
	mu   sync.Mutex
	path string
}

// NewJSONFileTaskStore 创建基于本地 JSON 文件的任务存储实例。
func NewJSONFileTaskStore(dataDir string) (*JSONFileTaskStore, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %w", err)
	}
	return &JSONFileTaskStore{
		path: filepath.Join(dataDir, "tasks.json"),
	}, nil
}

// LoadAll 从快照文件加载历史任务记录；若文件尚不存在则返回空切片。
func (s *JSONFileTaskStore) LoadAll() ([]TaskRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	raw, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("读取任务快照失败: %w", err)
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var records []TaskRecord
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, fmt.Errorf("解析任务快照失败: %w", err)
	}
	return records, nil
}

// SaveAll 将全部任务记录以“写临时文件 + 重命名”的方式原子写入磁盘。
func (s *JSONFileTaskStore) SaveAll(records []TaskRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化任务快照失败: %w", err)
	}
	tmpPath := s.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("写入任务临时快照失败: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		// Windows 上目标文件已存在时 Rename 可能受并发读取影响，做一次回退覆盖
		if wErr := os.WriteFile(s.path, data, 0o600); wErr != nil {
			return fmt.Errorf("提交任务快照失败: %w", err)
		}
		_ = os.Remove(tmpPath)
	}
	return nil
}
