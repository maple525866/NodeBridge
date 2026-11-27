package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SecurityMode 表示可通过 Web 控制台实时切换并持久化的安全运行模式。
type SecurityMode struct {
	FullPermissions bool      `json:"full_permissions"`
	AllowAllDirs    bool      `json:"allow_all_dirs"`
	UpdatedAt       time.Time `json:"updated_at,omitempty"`
}

const securityModeFileName = "security_mode.json"

// SecurityModeExists 检查 dataDir 下是否已存在持久化的安全运行模式文件。
func SecurityModeExists(dataDir string) bool {
	if dataDir == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(dataDir, securityModeFileName))
	return err == nil
}

// LoadSecurityMode 从 dataDir 加载上次保存的安全模式；若尚未保存过则回退到配置文件默认值。
func LoadSecurityMode(dataDir string, defaultFullPerms, defaultAllowAllDirs bool) (SecurityMode, error) {
	mode := SecurityMode{
		FullPermissions: defaultFullPerms,
		AllowAllDirs:    defaultAllowAllDirs,
	}
	if dataDir == "" {
		return mode, nil
	}
	p := filepath.Join(dataDir, securityModeFileName)
	raw, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return mode, nil
		}
		return mode, fmt.Errorf("读取安全模式配置失败: %w", err)
	}
	if err := json.Unmarshal(raw, &mode); err != nil {
		return SecurityMode{
			FullPermissions: defaultFullPerms,
			AllowAllDirs:    defaultAllowAllDirs,
		}, fmt.Errorf("解析安全模式配置失败: %w", err)
	}
	return mode, nil
}

// SaveSecurityMode 将当前安全运行模式原子写入 dataDir/security_mode.json。
func SaveSecurityMode(dataDir string, mode SecurityMode) error {
	if dataDir == "" {
		return nil
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("创建数据目录失败: %w", err)
	}
	if mode.UpdatedAt.IsZero() {
		mode.UpdatedAt = time.Now().UTC()
	}
	raw, err := json.MarshalIndent(mode, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化安全模式失败: %w", err)
	}
	target := filepath.Join(dataDir, securityModeFileName)
	tmpFile, err := os.CreateTemp(dataDir, "security_mode.*.tmp")
	if err != nil {
		return fmt.Errorf("创建安全模式临时文件失败: %w", err)
	}
	tmpPath := tmpFile.Name()
	if _, err := tmpFile.Write(raw); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("写入安全模式临时文件失败: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("刷盘安全模式临时文件失败: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("关闭安全模式临时文件失败: %w", err)
	}
	_ = os.Chmod(tmpPath, 0o600)
	if err := os.Rename(tmpPath, target); err != nil {
		// Windows 目标文件偶发被短占时回退直接写入
		if wErr := os.WriteFile(target, raw, 0o600); wErr != nil {
			_ = os.Remove(tmpPath)
			return fmt.Errorf("保存安全模式失败: %w", wErr)
		}
		_ = os.Remove(tmpPath)
	}
	return nil
}
