//go:build !windows

package service

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
)

func atomicReplaceFile(src, dst string) error {
	return os.Rename(src, dst)
}

func restrictPrivatePathACL(targetPath string) error {
	fi, err := os.Stat(targetPath)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return os.Chmod(targetPath, 0o700)
	}
	return os.Chmod(targetPath, 0o600)
}

// fixOwnershipForUser 在 Linux / macOS 的 sudo 系统级安装场景下，将由 root 创建的
// data/service、service.env、metadata.json、data/logs 等目录与文件归属权修正给目标运行用户，
// 避免 systemd(User=) 或 launchd(UserName) 切换账号后出现 EACCES 崩溃死循环。
func fixOwnershipForUser(runAsUser string, paths ...string) error {
	uName := strings.TrimSpace(runAsUser)
	if uName == "" || uName == "root" || os.Geteuid() != 0 {
		return nil
	}
	u, err := user.Lookup(uName)
	if err != nil {
		return fmt.Errorf("查找运行用户 %q 失败: %w", uName, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("解析用户 %q 的 UID 失败: %w", uName, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("解析用户 %q 的 GID 失败: %w", uName, err)
	}
	for _, p := range paths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if _, statErr := os.Stat(p); statErr != nil {
			continue
		}
		if err := os.Chown(p, uid, gid); err != nil {
			return fmt.Errorf("修正路径 %s 归属给用户 %s 失败: %w", p, uName, err)
		}
	}
	return nil
}
