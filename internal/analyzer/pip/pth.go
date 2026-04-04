package pip

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

// checkPthFiles detects .pth files that can auto-execute code when Python starts.
// This was the attack vector used by TeamPCP in the LiteLLM compromise.
func checkPthFiles(dir string) []types.Finding {
	var findings []types.Finding

	// Look for .pth files in the project directory
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "__pycache__" || name == ".tox" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}

		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}

		if !strings.HasSuffix(d.Name(), ".pth") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		relPath, _ := filepath.Rel(dir, path)
		if relPath == "" {
			relPath = path
		}

		// .pth files with "import" lines execute code on Python startup
		lines := strings.Split(string(content), "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "import ") || strings.HasPrefix(trimmed, "import\t") {
				findings = append(findings, types.Finding{
					CheckID:  types.CheckInstallScripts,
					Severity: types.SeverityCritical,
					Ecosystem: "pip",
					File:     relPath,
					Line:     i + 1,
					Title:    "Auto-executing .pth file detected",
					Description: "File '" + relPath + "' contains an import statement that executes code automatically " +
						"when Python starts. This was the exact technique used by TeamPCP to backdoor LiteLLM in March 2026.",
					Remediation: "Review the .pth file content. If not intentional, delete it and investigate how it was created.",
				})
			}
		}

		return nil
	})

	if err != nil {
		return findings
	}

	return findings
}
