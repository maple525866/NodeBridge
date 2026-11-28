package capability

import (
	"testing"

	"nodebridge/internal/platform/process"
)

func TestVersionBannerOmitsHostDiagnostics(t *testing.T) {
	for _, tc := range []struct{ output, want string }{
		{"Picked up JAVA_TOOL_OPTIONS: -Dexample=local\nopenjdk version \"21.0.4\" 2024-07-16\n", "21.0.4"},
		{"Unrecognized VM option: example", ""},
		{"git version 2.51.0.windows.1", "2.51.0.windows.1"},
		{"go version go1.24.1 windows/amd64", "1.24.1"},
		{"v20.1.2", "20.1.2"},
	} {
		if got := versionFromOutput(tc.output); got != tc.want {
			t.Errorf("versionFromOutput(%q)=%q, want %q", tc.output, got, tc.want)
		}
	}
}

func TestDetectedShellMatchesTerminal(t *testing.T) {
	info := Detect()
	cmd, err := process.BuildCommand(process.Spec{UseShell: true, Executable: "echo test"})
	if err != nil {
		t.Fatal(err)
	}
	if info.DefaultShellBin != cmd.Path {
		t.Errorf("advertised shell %q differs from actual interpreter %q", info.DefaultShellBin, cmd.Path)
	}
}
