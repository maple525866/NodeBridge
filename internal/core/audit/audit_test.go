package audit

import (
	"os"
	"strings"
	"testing"
)

func TestRedactSensitiveTokens(t *testing.T) {
	raw := `Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abcdef12345 api_key="mysecretvalue" key=sk-1234567890abcdef1234`
	out := Redact(raw)
	if strings.Contains(out, "eyJhbGciOiJIUzI1NiJ9") || strings.Contains(out, "mysecretvalue") || strings.Contains(out, "sk-1234567890") {
		t.Fatalf("敏感凭据未被脱敏: %s", out)
	}
}

func TestAuditLoggerRecordAndRotate(t *testing.T) {
	tmp := t.TempDir()
	logger, err := NewLogger(tmp, 1, 2)
	if err != nil {
		t.Fatalf("NewLogger 失败: %v", err)
	}
	// 缩小轮转阈值以快速测试轮转
	logger.maxSize = 200

	for i := 0; i < 6; i++ {
		err := logger.Record(Event{
			Tool:        "workspace.read",
			WorkspaceID: "default",
			RiskLevel:   "L0",
			ArgsSummary: `{"token":"super_secret_token_999999","path":"main.go"}`,
			Decision:    "AUTO_ALLOW",
			Status:      "SUCCEEDED",
		})
		if err != nil {
			t.Fatalf("Record 失败: %v", err)
		}
	}

	recent := logger.Recent(10)
	if len(recent) != 6 {
		t.Fatalf("期望 6 条最近记录，实际 %d", len(recent))
	}
	if strings.Contains(recent[0].ArgsSummary, "super_secret_token_999999") {
		t.Fatalf("审计摘要未脱敏: %s", recent[0].ArgsSummary)
	}
	if _, err := os.Stat(logger.FilePath() + ".1"); err != nil {
		t.Fatalf("期望触发日志轮转产生 .1 备份文件: %v", err)
	}
}
