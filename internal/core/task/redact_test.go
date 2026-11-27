package task

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCappedBufferStreamingPrivateKeyAndTokenRedaction(t *testing.T) {
	buf := newCappedBuffer(64 * 1024)

	// 1. 跨分片写入高敏 Token 与中文，中间 ReadFrom 不得泄露明文前缀且偏移单调递增
	_, _ = buf.Write([]byte("你好前缀 token=sk-1234567890"))
	c1, off1, _ := buf.ReadFrom(0)
	if strings.Contains(c1, "sk-1234567890") {
		t.Fatalf("未换行分片不应提前泄露 Token 明文前缀: %q", c1)
	}
	_, _ = buf.Write([]byte("abcdefghijklmno 结束\n"))
	c2, off2, _ := buf.ReadFrom(off1)
	if strings.Contains(c2, "sk-1234567890") || !strings.Contains(c2, "[REDACTED_SECRET]") || !strings.Contains(c2, "你好前缀") || !strings.Contains(c2, "结束") {
		t.Fatalf("Token 脱敏或中文完整性异常: %q", c2)
	}
	if !utf8.ValidString(c2) {
		t.Fatalf("输出出现非法 UTF-8 截断: %q", c2)
	}

	// 2. 跨分片写入完整 OpenSSH 私钥块，中间多次 ReadFrom 均不得泄露正文
	_, _ = buf.Write([]byte("-----BEGIN OPENSSH PRIV"))
	c3, off3, _ := buf.ReadFrom(off2)
	if c3 != "" {
		t.Fatalf("未完整私钥头不应提前吐出: %q", c3)
	}
	_, _ = buf.Write([]byte("ATE KEY-----\nAAAA_SECRET_LINE_1\n"))
	c4, off4, _ := buf.ReadFrom(off3)
	if strings.Contains(c4, "AAAA_SECRET_LINE_1") || !strings.Contains(c4, "[REDACTED_PRIVATE_KEY]") {
		t.Fatalf("私钥块首段未正确脱敏: %q", c4)
	}
	_, _ = buf.Write([]byte("BBBB_SECRET_LINE_2\n-----END OPENSSH PRIVATE KEY-----\n后续正常日志\n"))
	c5, off5, _ := buf.ReadFrom(off4)
	if strings.Contains(c5, "BBBB_SECRET_LINE_2") || !strings.Contains(c5, "后续正常日志") {
		t.Fatalf("私钥块结束后的正常输出异常: %q", c5)
	}
	if off5 <= off4 {
		t.Fatalf("偏移量必须单调递增: off4=%d off5=%d", off4, off5)
	}

	// 3. 未闭合私钥头遇到非 Base64 正常中文日志时应自动恢复，不吞噬后续全部日志
	_, _ = buf.Write([]byte("-----BEGIN RSA PRIVATE KEY-----\nMIIE_TRUNCATED_BODY\n[INFO] 编译完成：全部测试通过！\n"))
	buf.Flush()
	c6, _, _ := buf.ReadFrom(off5)
	if strings.Contains(c6, "MIIE_TRUNCATED_BODY") {
		t.Fatalf("未闭合私钥正文被泄露: %q", c6)
	}
	if !strings.Contains(c6, "[REDACTED_PRIVATE_KEY]") || !strings.Contains(c6, "编译完成：全部测试通过！") {
		t.Fatalf("未闭合私钥头不应吞噬后续正常日志: %q", c6)
	}
}
