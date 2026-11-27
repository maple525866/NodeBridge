package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nodebridge/internal/config"
	"nodebridge/internal/platform/filesystem"
)

func TestValidateServiceNameAndScope(t *testing.T) {
	if name, err := ValidateServiceName(""); err != nil || name != DefaultServiceName {
		t.Fatalf("空服务名应回退默认值，实际 name=%q err=%v", name, err)
	}
	if name, err := ValidateServiceName("nodebridge-home_01"); err != nil || name != "nodebridge-home_01" {
		t.Fatalf("合法服务名校验失败: name=%q err=%v", name, err)
	}
	for _, bad := range []string{"../evil", "bad name", "-leading-dash", "a;rm -rf /", "a<b"} {
		if _, err := ValidateServiceName(bad); err == nil {
			t.Fatalf("应拒绝非法服务名 %q", bad)
		}
	}

	for _, okScope := range []string{"", "auto", "user", "system", "SYSTEM"} {
		if _, err := ParseScope(okScope); err != nil {
			t.Fatalf("应接受合法 scope %q: %v", okScope, err)
		}
	}
	if _, err := ParseScope("global"); err == nil {
		t.Fatalf("应拒绝非法 scope")
	}

	if u, err := ValidateRunAsUser("alice_01"); err != nil || u != "alice_01" {
		t.Fatalf("合法 RunAsUser 校验失败: u=%q err=%v", u, err)
	}
	for _, badUser := range []string{"alice\nExecStart=/bin/sh", "bad user", "root;id"} {
		if _, err := ValidateRunAsUser(badUser); err == nil {
			t.Fatalf("应拒绝非法 RunAsUser %q", badUser)
		}
	}
}

func TestValidateRelayModeForAutostart(t *testing.T) {
	if warns, err := ValidateRelayModeForAutostart(config.RelayModeCloudflaredNamed, false); err != nil || len(warns) != 0 {
		t.Fatalf("固定域名 named 模式应直接放行且无警告: warns=%v err=%v", warns, err)
	}
	if warns, err := ValidateRelayModeForAutostart(config.RelayModeExternal, false); err != nil || len(warns) != 0 {
		t.Fatalf("固定域名 external 模式应直接放行且无警告: warns=%v err=%v", warns, err)
	}
	if _, err := ValidateRelayModeForAutostart(config.RelayModeCloudflaredQuick, false); err == nil {
		t.Fatalf("未加 --allow-quick-tunnel 时应阻止临时域名模式安装开机自启")
	}
	if warns, err := ValidateRelayModeForAutostart(config.RelayModeCloudflaredQuick, true); err != nil || len(warns) == 0 {
		t.Fatalf("显式允许 quick tunnel 时应放行并返回警告: warns=%v err=%v", warns, err)
	}
	if warns, err := ValidateRelayModeForAutostart(config.RelayModeDisabled, false); err != nil || len(warns) == 0 {
		t.Fatalf("disabled 本地模式应允许安装并给出本地提示: warns=%v err=%v", warns, err)
	}
}

func TestValidateExecutablePathRejectsGoRunTemp(t *testing.T) {
	tmp := t.TempDir()
	fakeGoBuild := filepath.Join(tmp, "go-build123456", "b001", "exe", "nodebridge.exe")
	if err := os.MkdirAll(filepath.Dir(fakeGoBuild), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fakeGoBuild, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateExecutablePath(fakeGoBuild); err == nil {
		t.Fatalf("应拦截 go run 临时构建目录可执行文件")
	}

	stableBin := filepath.Join(tmp, "nodebridge.exe")
	if err := os.WriteFile(stableBin, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := ValidateExecutablePath(stableBin)
	if err != nil {
		t.Fatalf("合法二进制路径不应报错: %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("应返回绝对路径，实际: %s", got)
	}
}

func TestEnvFileWriteParseBuildAndLoad(t *testing.T) {
	tmp := t.TempDir()
	envPath := filepath.Join(tmp, "service", "service.env")

	t.Setenv("NB_TEST_TUNNEL_TOK", "eyJhIjoi123456==\"quoted\"")
	cfg, err := config.DefaultConfig(tmp)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Relay.Mode = config.RelayModeCloudflaredNamed
	cfg.Relay.PublicURL = "https://mcp.example.com"
	cfg.Relay.TunnelToken = "env:NB_TEST_TUNNEL_TOK"

	envMap, err := BuildServiceEnv(cfg, envPath, map[string]string{"CUSTOM_FLAG": "hello world"})
	if err != nil {
		t.Fatalf("BuildServiceEnv 失败: %v", err)
	}
	if envMap["NB_TEST_TUNNEL_TOK"] != "eyJhIjoi123456==\"quoted\"" {
		t.Fatalf("未正确捕获 env: 隧道令牌: %q", envMap["NB_TEST_TUNNEL_TOK"])
	}
	if envMap["CUSTOM_FLAG"] != "hello world" {
		t.Fatalf("未正确合并 extraEnv: %q", envMap["CUSTOM_FLAG"])
	}
	if err := WriteEnvFile(envPath, envMap); err != nil {
		t.Fatalf("WriteEnvFile 失败: %v", err)
	}

	parsed, err := ParseEnvFile(envPath)
	if err != nil {
		t.Fatalf("ParseEnvFile 失败: %v", err)
	}
	if parsed["NB_TEST_TUNNEL_TOK"] != envMap["NB_TEST_TUNNEL_TOK"] || parsed["CUSTOM_FLAG"] != "hello world" {
		t.Fatalf("解析结果与写入不一致: %+v", parsed)
	}

	// 验证 LoadIntoProcessEnv 返回新注入的键名列表，且不覆盖当前进程已有变量
	t.Setenv("NB_TEST_TUNNEL_TOK", "explicit-override")
	t.Setenv("CUSTOM_FLAG", "")
	injected, err := LoadIntoProcessEnv(envPath)
	if err != nil {
		t.Fatalf("LoadIntoProcessEnv 失败: %v", err)
	}
	if os.Getenv("NB_TEST_TUNNEL_TOK") != "explicit-override" {
		t.Fatalf("不应覆盖显式环境变量，实际: %q", os.Getenv("NB_TEST_TUNNEL_TOK"))
	}
	if os.Getenv("CUSTOM_FLAG") != "hello world" {
		t.Fatalf("应填充未设置的环境变量，实际: %q", os.Getenv("CUSTOM_FLAG"))
	}
	if len(injected) != 1 || injected[0] != "CUSTOM_FLAG" {
		t.Fatalf("期望返回新注入的非 PATH 键名 [CUSTOM_FLAG]，实际: %v", injected)
	}

	// 回归测试（P1-3）：终端轮换新 Token 后重装，必须优先采纳当前终端环境变量而非旧 service.env 中的失效值
	t.Setenv("NB_TEST_TUNNEL_TOK", "rotated-new-token-999")
	rotatedMap, err := BuildServiceEnv(cfg, envPath, nil)
	if err != nil {
		t.Fatalf("轮换后 BuildServiceEnv 失败: %v", err)
	}
	if rotatedMap["NB_TEST_TUNNEL_TOK"] != "rotated-new-token-999" {
		t.Fatalf("当前终端新 Token 必须覆盖旧 service.env 值，实际: %q", rotatedMap["NB_TEST_TUNNEL_TOK"])
	}
	// extraEnv 优先级高于当前终端环境变量
	overrideMap, err := BuildServiceEnv(cfg, envPath, map[string]string{"NB_TEST_TUNNEL_TOK": "extra-override-token"})
	if err != nil {
		t.Fatalf("extraEnv 覆盖 BuildServiceEnv 失败: %v", err)
	}
	if overrideMap["NB_TEST_TUNNEL_TOK"] != "extra-override-token" {
		t.Fatalf("extraEnv 必须拥有最高优先级，实际: %q", overrideMap["NB_TEST_TUNNEL_TOK"])
	}

	// 验证缺失 env: 变量时明确报错
	cfgMissing, _ := config.DefaultConfig(tmp)
	cfgMissing.Relay.Mode = config.RelayModeCloudflaredNamed
	cfgMissing.Relay.PublicURL = "https://mcp.example.com"
	cfgMissing.Relay.TunnelToken = "env:NB_MISSING_TOKEN_XYZ"
	if _, err := BuildServiceEnv(cfgMissing, filepath.Join(tmp, "none.env"), nil); err == nil {
		t.Fatalf("缺少 env: 变量值时应明确报错")
	}
}

func TestPeekServiceEnvPathWithCustomDataDir(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "nodebridge.yaml")
	if err := os.WriteFile(cfgPath, []byte("storage:\n  data_dir: \"./custom-state\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := PeekServiceEnvPath(cfgPath)
	want := filepath.Join(tmp, "custom-state", "service", "service.env")
	if filepath.Clean(got) != filepath.Clean(want) {
		t.Fatalf("PeekServiceEnvPath 不匹配: got=%s want=%s", got, want)
	}
}

func TestServiceEnvProtectedByHardSecretRedline(t *testing.T) {
	tmp := t.TempDir()
	envPath := filepath.Join(tmp, "data", "service", "service.env")
	if err := os.MkdirAll(filepath.Dir(envPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envPath, []byte("CLOUDFLARE_TUNNEL_TOKEN=\"secret\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, _ := config.DefaultConfig(tmp)
	fsMgr, err := filesystem.NewManager(cfg.Workspaces, cfg.Security.GlobalDenyGlobs)
	if err != nil {
		t.Fatal(err)
	}
	// 即便同时开启全部权限与默认全部目录，service.env 也必须处于不可绕过的硬保护红线内
	fsMgr.SetFullPermissions(true)
	fsMgr.SetAllowAllDirs(true)

	if _, err := fsMgr.Resolve("default", "data/service/service.env", false); err == nil {
		t.Fatalf("service.env 必须被内核密钥红线拦截，禁止读取")
	}
	if _, err := fsMgr.Resolve("default", envPath, true); err == nil {
		t.Fatalf("service.env 必须被内核密钥红线拦截，禁止写入")
	}
}

func TestRotatingLogWriterAndTailFile(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "logs", "daemon.log")

	w, err := NewRotatingLogWriter(logPath, 1, 2)
	if err != nil {
		t.Fatalf("NewRotatingLogWriter 失败: %v", err)
	}
	// 手动调小单文件阈值测试轮转
	w.maxBytes = 128
	for i := 1; i <= 20; i++ {
		if _, err := fmt.Fprintf(w, "line-%02d: nodebridge daemon heartbeat payload\n", i); err != nil {
			t.Fatalf("写入日志失败: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(logPath + ".1"); err != nil {
		t.Fatalf("期望生成轮转备份文件 %s.1: %v", logPath, err)
	}
	tail, err := TailFile(logPath, 3)
	if err != nil {
		t.Fatalf("TailFile 失败: %v", err)
	}
	if len(tail) == 0 || !strings.Contains(tail[len(tail)-1], "line-20") {
		t.Fatalf("尾部日志内容异常: %v", tail)
	}
}

func TestRenderTemplatesCrossPlatform(t *testing.T) {
	opts := InstallOptions{
		ServiceName:    "nodebridge",
		ExecutablePath: `/opt/my apps/nodebridge`,
		ConfigPath:     `/home/alice/my config/nodebridge.yaml`,
		WorkingDir:     `/home/alice/my config`,
		EnvFilePath:    `/home/alice/my config/data/service/service.env`,
		LogFilePath:    `/home/alice/my config/data/logs/daemon.log`,
		RunAsUser:      "alice",
	}

	// 1. Linux systemd system unit（验证 $ -> $$ 与 % -> %% 转义，且不与 RotatingLogWriter 共享 StandardOutput）
	optsWithSpecial := opts
	optsWithSpecial.ConfigPath = `/home/alice/$100%dir/nodebridge.yaml`
	unit := RenderSystemdUnit(optsWithSpecial, ScopeSystem)
	for _, must := range []string{
		"After=network-online.target",
		"User=alice",
		"Restart=always",
		"RestartSec=5s",
		"--managed",
		`"/opt/my apps/nodebridge"`,
		`$$100%%dir`,
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(unit, must) {
			t.Fatalf("systemd unit 缺少关键字段 %q:\n%s", must, unit)
		}
	}
	if strings.Contains(unit, "StandardOutput=append:") {
		t.Fatalf("systemd unit 不应将 StandardOutput=append 指向 daemon.log 导致双写与 fd 泄漏:\n%s", unit)
	}

	// 2. macOS launchd plist（验证独立崩溃兜底日志 .launchd.log）
	plist := RenderLaunchdPlist(opts, ScopeSystem)
	for _, must := range []string{
		"<string>io.nodebridge.nodebridge</string>",
		"<key>UserName</key>",
		"<string>alice</string>",
		"<string>--managed</string>",
		"<key>RunAtLoad</key>",
		"<key>KeepAlive</key>",
		"daemon.launchd.log",
		"<true/>",
	} {
		if !strings.Contains(plist, must) {
			t.Fatalf("launchd plist 缺少关键字段 %q:\n%s", must, plist)
		}
	}

	// 3. Windows Task Scheduler XML（含特殊字符 & 空格路径转义与无黑框 conhost --headless）
	winOpts := InstallOptions{
		ServiceName:    "nodebridge",
		ExecutablePath: `C:\Program Files\Node & Bridge\nodebridge.exe`,
		ConfigPath:     `C:\Users\Alice\nodebridge.yaml`,
		WorkingDir:     `C:\Users\Alice`,
		EnvFilePath:    `C:\Users\Alice\data\service\service.env`,
		LogFilePath:    `C:\Users\Alice\data\logs\daemon.log`,
	}
	taskXML := RenderWindowsTaskXML(winOpts, `DESKTOP\Alice`, `C:\Windows\System32\conhost.exe`)
	for _, must := range []string{
		"<LogonTrigger>",
		"<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
		"<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>",
		"<RestartOnFailure>",
		"<Command>C:\\Windows\\System32\\conhost.exe</Command>",
		"--headless",
		"--managed",
		"Node &amp; Bridge",
	} {
		if !strings.Contains(taskXML, must) {
			t.Fatalf("Windows Task XML 缺少关键字段 %q:\n%s", must, taskXML)
		}
	}
}
