package npm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

func checkPhantomDeps(dir string) []types.Finding {
	var findings []types.Finding

	pkgPath := filepath.Join(dir, "package.json")
	pkgData, err := os.ReadFile(pkgPath)
	if err != nil {
		return findings
	}

	var pkg packageJSON
	if err := json.Unmarshal(pkgData, &pkg); err != nil {
		return findings
	}

	sourceImports := collectImports(dir)

	for name := range pkg.Dependencies {
		if isKnownNonImport(name) {
			continue
		}

		importName := normalizeImportName(name)
		if !sourceImports[importName] && !sourceImports[name] {
			findings = append(findings, types.Finding{
				CheckID:     types.CheckPhantomDependency,
				Severity:    types.SeverityLow,
				Ecosystem:   "npm",
				Package:     name,
				File:        "package.json",
				Title:       "Phantom dependency detected",
				Description: "Package '" + name + "' is declared in dependencies but never imported in source code. Phantom dependencies increase attack surface without providing value.",
				Remediation: "If the package is unused, remove it with 'npm uninstall " + name + "'. If it's used indirectly (e.g., a CLI tool), move it to devDependencies.",
			})
		}
	}

	return findings
}

func collectImports(dir string) map[string]bool {
	imports := make(map[string]bool)

	extensions := []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			base := d.Name()
			if base == "node_modules" || base == ".git" || base == "dist" || base == "build" || base == ".next" {
				return filepath.SkipDir
			}
			return nil
		}

		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}

		ext := filepath.Ext(path)
		isSource := false
		for _, e := range extensions {
			if ext == e {
				isSource = true
				break
			}
		}
		if !isSource {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		content := string(data)
		extractImportNames(content, imports)
		return nil
	})

	if err != nil {
		return imports
	}

	return imports
}

func extractImportNames(content string, imports map[string]bool) {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// require('package') or require("package")
		if idx := strings.Index(trimmed, "require("); idx != -1 {
			name := extractStringArg(trimmed[idx+8:])
			if name != "" && !strings.HasPrefix(name, ".") && !strings.HasPrefix(name, "/") {
				imports[extractPackageName(name)] = true
			}
		}

		// import ... from 'package' or import ... from "package"
		if strings.Contains(trimmed, " from ") {
			parts := strings.SplitN(trimmed, " from ", 2)
			if len(parts) == 2 {
				name := extractQuotedString(parts[1])
				if name != "" && !strings.HasPrefix(name, ".") && !strings.HasPrefix(name, "/") {
					imports[extractPackageName(name)] = true
				}
			}
		}

		// import 'package' (side-effect imports)
		if strings.HasPrefix(trimmed, "import ") && !strings.Contains(trimmed, " from ") {
			name := extractQuotedString(trimmed[7:])
			if name != "" && !strings.HasPrefix(name, ".") && !strings.HasPrefix(name, "/") {
				imports[extractPackageName(name)] = true
			}
		}
	}
}

func extractStringArg(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 3 {
		return ""
	}
	quote := s[0]
	if quote != '\'' && quote != '"' && quote != '`' {
		return ""
	}
	end := strings.IndexByte(s[1:], quote)
	if end == -1 {
		return ""
	}
	return s[1 : end+1]
}

func extractQuotedString(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, ";")
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return ""
	}
	quote := s[0]
	if quote != '\'' && quote != '"' {
		return ""
	}
	end := strings.IndexByte(s[1:], quote)
	if end == -1 {
		return ""
	}
	return s[1 : end+1]
}

// extractPackageName gets the package name from an import path.
// "@scope/pkg/sub" -> "@scope/pkg", "pkg/sub" -> "pkg"
func extractPackageName(importPath string) string {
	if strings.HasPrefix(importPath, "@") {
		parts := strings.SplitN(importPath, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return importPath
	}
	parts := strings.SplitN(importPath, "/", 2)
	return parts[0]
}

func normalizeImportName(pkgName string) string {
	return strings.ToLower(pkgName)
}

// Packages that are commonly used without being imported (build tools, type defs, etc.)
func isKnownNonImport(name string) bool {
	nonImport := map[string]bool{
		"typescript":     true,
		"@types/node":    true,
		"eslint":         true,
		"prettier":       true,
		"nodemon":        true,
		"ts-node":        true,
		"tsx":            true,
		"concurrently":   true,
		"husky":          true,
		"lint-staged":    true,
		"tailwindcss":    true,
		"autoprefixer":   true,
		"postcss":        true,
	}

	if nonImport[name] {
		return true
	}
	if strings.HasPrefix(name, "@types/") {
		return true
	}
	return false
}
