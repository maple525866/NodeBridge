//go:build !windows && !linux && !darwin

package service

import (
	"fmt"
	"runtime"
)

// IsAdmin 返回当前进程是否具备管理员权限。
func IsAdmin() bool {
	return false
}

// Install 在未适配操作系统上返回明确错误提示。
func Install(InstallOptions) (Status, error) {
	return Status{}, fmt.Errorf("当前操作系统 (%s) 暂不支持自动安装开机自启动守护进程", runtime.GOOS)
}

// Uninstall 在未适配操作系统上返回明确错误提示。
func Uninstall(ControlOptions) error {
	return fmt.Errorf("当前操作系统 (%s) 暂不支持自动卸载开机自启动守护进程", runtime.GOOS)
}

// Start 在未适配操作系统上返回明确错误提示。
func Start(ControlOptions) (Status, error) {
	return Status{}, fmt.Errorf("当前操作系统 (%s) 暂不支持启动开机自启动守护进程", runtime.GOOS)
}

// Stop 在未适配操作系统上返回明确错误提示。
func Stop(ControlOptions) (Status, error) {
	return Status{}, fmt.Errorf("当前操作系统 (%s) 暂不支持停止开机自启动守护进程", runtime.GOOS)
}

// Restart 在未适配操作系统上返回明确错误提示。
func Restart(ControlOptions) (Status, error) {
	return Status{}, fmt.Errorf("当前操作系统 (%s) 暂不支持重启开机自启动守护进程", runtime.GOOS)
}

// QueryStatus 在未适配操作系统上返回基础未安装状态。
func QueryStatus(opts ControlOptions) (Status, error) {
	name, _ := ValidateServiceName(opts.ServiceName)
	return Status{
		ServiceName: name,
		Platform:    runtime.GOOS,
		Scope:       opts.Scope,
		Backend:     "unsupported",
		Installed:   false,
		State:       "unsupported",
	}, nil
}
