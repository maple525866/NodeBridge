package service

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
)

// RenderSystemdUnit 生成 Linux systemd 守护进程单元文件内容（支持 user 与 system 两种作用域）。
func RenderSystemdUnit(opts InstallOptions, scope Scope) string {
	execParts := append([]string{opts.ExecutablePath}, BuildDaemonArgs(opts)...)
	quotedExec := make([]string, 0, len(execParts))
	for _, p := range execParts {
		quotedExec = append(quotedExec, quoteSystemdArg(p))
	}

	wantedBy := "default.target"
	if scope == ScopeSystem {
		wantedBy = "multi-user.target"
	}

	var sb strings.Builder
	sb.WriteString("[Unit]\n")
	sb.WriteString(fmt.Sprintf("Description=NodeBridge Local Agent Gateway (%s)\n", sanitizeUnitValue(opts.ServiceName)))
	if scope == ScopeSystem {
		sb.WriteString("After=network-online.target\n")
		sb.WriteString("Wants=network-online.target\n")
	} else {
		sb.WriteString("After=network.target\n")
	}
	sb.WriteString("StartLimitIntervalSec=0\n")
	sb.WriteString("\n[Service]\n")
	sb.WriteString("Type=simple\n")
	if scope == ScopeSystem && strings.TrimSpace(opts.RunAsUser) != "" {
		sb.WriteString(fmt.Sprintf("User=%s\n", sanitizeUnitValue(opts.RunAsUser)))
	}
	if strings.TrimSpace(opts.WorkingDir) != "" {
		sb.WriteString(fmt.Sprintf("WorkingDirectory=%s\n", quoteSystemdArg(opts.WorkingDir)))
	}
	sb.WriteString(fmt.Sprintf("ExecStart=%s\n", strings.Join(quotedExec, " ")))
	sb.WriteString("Restart=always\n")
	sb.WriteString("RestartSec=5s\n")
	sb.WriteString("KillMode=mixed\n")
	sb.WriteString("TimeoutStopSec=15s\n")
	if strings.TrimSpace(opts.LogFilePath) != "" {
		sb.WriteString(fmt.Sprintf("StandardOutput=append:%s\n", sanitizeUnitValue(opts.LogFilePath)))
		sb.WriteString(fmt.Sprintf("StandardError=append:%s\n", sanitizeUnitValue(opts.LogFilePath)))
	}
	sb.WriteString("\n[Install]\n")
	sb.WriteString(fmt.Sprintf("WantedBy=%s\n", wantedBy))
	return sb.String()
}

// LaunchdLabel 返回 macOS launchd 服务标签。
func LaunchdLabel(serviceName string) string {
	return "io.nodebridge." + serviceName
}

// RenderLaunchdPlist 生成 macOS launchd LaunchAgent / LaunchDaemon plist 文件内容。
func RenderLaunchdPlist(opts InstallOptions, scope Scope) string {
	args := append([]string{opts.ExecutablePath}, BuildDaemonArgs(opts)...)

	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	sb.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	sb.WriteString(`<plist version="1.0">` + "\n")
	sb.WriteString("<dict>\n")
	sb.WriteString("  <key>Label</key>\n")
	sb.WriteString("  <string>" + xmlEscape(LaunchdLabel(opts.ServiceName)) + "</string>\n")

	if scope == ScopeSystem && strings.TrimSpace(opts.RunAsUser) != "" {
		sb.WriteString("  <key>UserName</key>\n")
		sb.WriteString("  <string>" + xmlEscape(opts.RunAsUser) + "</string>\n")
	}

	sb.WriteString("  <key>ProgramArguments</key>\n")
	sb.WriteString("  <array>\n")
	for _, a := range args {
		sb.WriteString("    <string>" + xmlEscape(a) + "</string>\n")
	}
	sb.WriteString("  </array>\n")

	if strings.TrimSpace(opts.WorkingDir) != "" {
		sb.WriteString("  <key>WorkingDirectory</key>\n")
		sb.WriteString("  <string>" + xmlEscape(opts.WorkingDir) + "</string>\n")
	}

	sb.WriteString("  <key>RunAtLoad</key>\n")
	sb.WriteString("  <true/>\n")
	sb.WriteString("  <key>KeepAlive</key>\n")
	sb.WriteString("  <true/>\n")
	sb.WriteString("  <key>ThrottleInterval</key>\n")
	sb.WriteString("  <integer>5</integer>\n")

	if strings.TrimSpace(opts.LogFilePath) != "" {
		sb.WriteString("  <key>StandardOutPath</key>\n")
		sb.WriteString("  <string>" + xmlEscape(opts.LogFilePath) + "</string>\n")
		sb.WriteString("  <key>StandardErrorPath</key>\n")
		sb.WriteString("  <string>" + xmlEscape(opts.LogFilePath) + "</string>\n")
	}

	sb.WriteString("</dict>\n")
	sb.WriteString("</plist>\n")
	return sb.String()
}

// WindowsTaskName 生成规范化的 Windows 任务计划程序任务名称。
func WindowsTaskName(serviceName string) string {
	if serviceName == "" || strings.EqualFold(serviceName, DefaultServiceName) {
		return "NodeBridge"
	}
	return "NodeBridge-" + serviceName
}

// RenderWindowsTaskXML 生成 Windows 任务计划程序 1.2 XML 定义（支持无黑框运行、电池不中断、永不超时与崩溃自动重启）。
func RenderWindowsTaskXML(opts InstallOptions, userID string, conhostPath string) string {
	daemonArgs := BuildDaemonArgs(opts)
	command := opts.ExecutablePath
	argList := daemonArgs
	if strings.TrimSpace(conhostPath) != "" {
		command = conhostPath
		argList = append([]string{"--headless", opts.ExecutablePath}, daemonArgs...)
	}
	argsStr := joinWindowsArgs(argList)

	var triggerBlock strings.Builder
	triggerBlock.WriteString("    <LogonTrigger>\n")
	triggerBlock.WriteString("      <Enabled>true</Enabled>\n")
	if strings.TrimSpace(userID) != "" {
		triggerBlock.WriteString("      <UserId>" + xmlEscape(userID) + "</UserId>\n")
	}
	triggerBlock.WriteString("    </LogonTrigger>\n")

	var principalBlock strings.Builder
	principalBlock.WriteString("    <Principal id=\"Author\">\n")
	if strings.TrimSpace(userID) != "" {
		principalBlock.WriteString("      <UserId>" + xmlEscape(userID) + "</UserId>\n")
	}
	principalBlock.WriteString("      <LogonType>InteractiveToken</LogonType>\n")
	principalBlock.WriteString("      <RunLevel>LeastPrivilege</RunLevel>\n")
	principalBlock.WriteString("    </Principal>\n")

	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-16"?>` + "\n")
	sb.WriteString(`<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">` + "\n")
	sb.WriteString("  <RegistrationInfo>\n")
	sb.WriteString("    <Description>" + xmlEscape("NodeBridge Local Agent Gateway 开机自启动守护进程 ("+opts.ServiceName+")") + "</Description>\n")
	sb.WriteString("  </RegistrationInfo>\n")
	sb.WriteString("  <Triggers>\n")
	sb.WriteString(triggerBlock.String())
	sb.WriteString("  </Triggers>\n")
	sb.WriteString("  <Principals>\n")
	sb.WriteString(principalBlock.String())
	sb.WriteString("  </Principals>\n")
	sb.WriteString("  <Settings>\n")
	sb.WriteString("    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n")
	sb.WriteString("    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n")
	sb.WriteString("    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n")
	sb.WriteString("    <AllowHardTerminate>true</AllowHardTerminate>\n")
	sb.WriteString("    <StartWhenAvailable>true</StartWhenAvailable>\n")
	sb.WriteString("    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n")
	sb.WriteString("    <IdleSettings>\n")
	sb.WriteString("      <StopOnIdleEnd>false</StopOnIdleEnd>\n")
	sb.WriteString("      <RestartOnIdle>false</RestartOnIdle>\n")
	sb.WriteString("    </IdleSettings>\n")
	sb.WriteString("    <AllowStartOnDemand>true</AllowStartOnDemand>\n")
	sb.WriteString("    <Enabled>true</Enabled>\n")
	sb.WriteString("    <Hidden>true</Hidden>\n")
	sb.WriteString("    <RunOnlyIfIdle>false</RunOnlyIfIdle>\n")
	sb.WriteString("    <WakeToRun>false</WakeToRun>\n")
	sb.WriteString("    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n")
	sb.WriteString("    <Priority>7</Priority>\n")
	sb.WriteString("    <RestartOnFailure>\n")
	sb.WriteString("      <Interval>PT1M</Interval>\n")
	sb.WriteString("      <Count>999</Count>\n")
	sb.WriteString("    </RestartOnFailure>\n")
	sb.WriteString("  </Settings>\n")
	sb.WriteString("  <Actions Context=\"Author\">\n")
	sb.WriteString("    <Exec>\n")
	sb.WriteString("      <Command>" + xmlEscape(command) + "</Command>\n")
	sb.WriteString("      <Arguments>" + xmlEscape(argsStr) + "</Arguments>\n")
	if strings.TrimSpace(opts.WorkingDir) != "" {
		sb.WriteString("      <WorkingDirectory>" + xmlEscape(opts.WorkingDir) + "</WorkingDirectory>\n")
	}
	sb.WriteString("    </Exec>\n")
	sb.WriteString("  </Actions>\n")
	sb.WriteString("</Task>\n")
	return sb.String()
}

func quoteSystemdArg(arg string) string {
	cleaned := sanitizeUnitValue(arg)
	// systemd ExecStart 对包含空格、引号、反斜杠或 % 的参数使用双引号与转义
	escaped := strings.ReplaceAll(cleaned, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	escaped = strings.ReplaceAll(escaped, `%`, `%%`)
	if strings.ContainsAny(escaped, " \t\"'\\$") {
		return `"` + escaped + `"`
	}
	return escaped
}

func sanitizeUnitValue(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	return s
}

func xmlEscape(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

func joinWindowsArgs(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, a := range args {
		quoted = append(quoted, quoteWindowsArg(a))
	}
	return strings.Join(quoted, " ")
}

// quoteWindowsArg 按 Windows CommandLineToArgvW 规则转义单个参数。
func quoteWindowsArg(s string) string {
	if s == "" {
		return `""`
	}
	if !strings.ContainsAny(s, " \t\"") {
		return s
	}
	var sb strings.Builder
	sb.WriteByte('"')
	slashes := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			slashes++
		case '"':
			sb.WriteString(strings.Repeat(`\`, slashes*2+1))
			sb.WriteByte('"')
			slashes = 0
		default:
			if slashes > 0 {
				sb.WriteString(strings.Repeat(`\`, slashes))
				slashes = 0
			}
			sb.WriteByte(s[i])
		}
	}
	if slashes > 0 {
		sb.WriteString(strings.Repeat(`\`, slashes*2))
	}
	sb.WriteByte('"')
	return sb.String()
}
