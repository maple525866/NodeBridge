//go:build windows

package service

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// atomicReplaceFile 在 Windows 上使用 MoveFileEx(MOVEFILE_REPLACE_EXISTING) 原子替换目标文件。
func atomicReplaceFile(src, dst string) error {
	srcPtr, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	dstPtr, err := windows.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(srcPtr, dstPtr, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// restrictPrivatePathACL 在 Windows 上为受限目录或敏感文件（如 service.env）设置受保护 NTFS DACL，
// 移除父目录继承权限，仅允许 NT AUTHORITY\SYSTEM、BUILTIN\Administrators 与当前用户访问，防止同机普通用户读取或篡改。
func restrictPrivatePathACL(targetPath string) error {
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("创建 SYSTEM SID 失败: %w", err)
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("创建 Administrators SID 失败: %w", err)
	}

	entries := []windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(systemSID),
			},
		},
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(adminSID),
			},
		},
	}

	if tokUser, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil && tokUser != nil && tokUser.User.Sid != nil {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(tokUser.User.Sid),
			},
		})
	}

	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("构造受限 NTFS ACL 失败: %w", err)
	}
	err = windows.SetNamedSecurityInfo(
		targetPath,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	)
	if err != nil {
		return fmt.Errorf("应用受限 NTFS ACL 失败 (%s): %w", targetPath, err)
	}
	return nil
}

// fixOwnershipForUser 在 Windows 上为空实现（权限已通过 NTFS DACL 控制）。
func fixOwnershipForUser(_ string, _ ...string) error {
	return nil
}

func isRegularOrMissing(path string) bool {
	_, err := os.Stat(path)
	return err == nil || os.IsNotExist(err)
}
