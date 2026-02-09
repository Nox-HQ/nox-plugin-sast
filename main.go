package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

// sastRule defines a single static analysis rule with compiled regex patterns
// keyed by file extension.
type sastRule struct {
	ID          string
	Description string
	Severity    pluginv1.Severity
	CWE         string
	Patterns    map[string]*regexp.Regexp // extension -> compiled regex
}

// Compiled regex patterns for each rule, grouped by language extension.
var rules = []sastRule{
	{
		ID:          "SAST-001",
		Description: "SQL Injection: unsanitized input in SQL query construction",
		Severity:    sdk.SeverityHigh,
		CWE:         "CWE-89",
		Patterns: map[string]*regexp.Regexp{
			".go": regexp.MustCompile(`fmt\.Sprintf.*SELECT|query.*\+.*|Exec\(.*\+`),
			".py": regexp.MustCompile(`execute\(.*%|execute\(.*\.format|f".*SELECT`),
			".js": regexp.MustCompile(`query\(.*\+|query\(` + "`" + `.*\$\{`),
			".ts": regexp.MustCompile(`query\(.*\+|query\(` + "`" + `.*\$\{`),
		},
	},
	{
		ID:          "SAST-002",
		Description: "Cross-Site Scripting (XSS): unsafe DOM manipulation or template rendering",
		Severity:    sdk.SeverityHigh,
		CWE:         "CWE-79",
		Patterns: map[string]*regexp.Regexp{
			".go": regexp.MustCompile(`template\.HTML\(`),
			".js": regexp.MustCompile(`\.innerHTML\s*=|document\.write\(`),
			".ts": regexp.MustCompile(`\.innerHTML\s*=|document\.write\(`),
			".py": regexp.MustCompile(`\|safe|mark_safe\(`),
		},
	},
	{
		ID:          "SAST-003",
		Description: "Path Traversal: user-controlled input in file path operations",
		Severity:    sdk.SeverityHigh,
		CWE:         "CWE-22",
		Patterns: map[string]*regexp.Regexp{
			".go":   regexp.MustCompile(`filepath\.Join\(.*\+|os\.Open\(.*\+`),
			".py":   regexp.MustCompile(`open\(.*\+.*\.\.\/|os\.path\.join\(.*\+`),
			".js":   regexp.MustCompile(`path\.join\(.*\+.*\.\.|fs\.\w+\(.*\+`),
			".ts":   regexp.MustCompile(`path\.join\(.*\+.*\.\.|fs\.\w+\(.*\+`),
			".java": regexp.MustCompile(`new File\(.*\+|Paths\.get\(.*\+`),
		},
	},
	{
		ID:          "SAST-004",
		Description: "Command Injection: unsanitized input passed to system command execution",
		Severity:    sdk.SeverityCritical,
		CWE:         "CWE-78",
		Patterns: map[string]*regexp.Regexp{
			".go":   regexp.MustCompile(`exec\.Command\(.*\+`),
			".py":   regexp.MustCompile(`os\.system\(|subprocess\.call\(.*shell=True`),
			".js":   regexp.MustCompile(`child_process\.\w+\(.*\+`),
			".ts":   regexp.MustCompile(`child_process\.\w+\(.*\+`),
			".java": regexp.MustCompile(`Runtime\.getRuntime\(\)\.exec\(.*\+`),
		},
	},
	{
		ID:          "SAST-005",
		Description: "Insecure Deserialization: untrusted data passed to deserialization functions",
		Severity:    sdk.SeverityHigh,
		CWE:         "CWE-502",
		Patterns: map[string]*regexp.Regexp{
			".py":   regexp.MustCompile(`pickle\.loads?\(|yaml\.load\(`),
			".java": regexp.MustCompile(`ObjectInputStream|readObject\(`),
			".js":   regexp.MustCompile(`JSON\.parse\(.*req\.\w+`),
			".ts":   regexp.MustCompile(`JSON\.parse\(.*req\.\w+`),
		},
	},
}

// supportedExtensions lists file extensions that the SAST scanner processes.
var supportedExtensions = map[string]bool{
	".go":   true,
	".py":   true,
	".js":   true,
	".ts":   true,
	".java": true,
}

// skippedDirs contains directory names to skip during recursive walks.
var skippedDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
	"__pycache__":  true,
	".venv":        true,
}

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/sast", version).
		Capability("sast", "Static Application Security Testing for multiple languages").
		Tool("scan", "Scan source files for common security vulnerabilities", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive)).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("scan", handleScan)
}

func handleScan(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	workspaceRoot, _ := req.Input["workspace_root"].(string)
	if workspaceRoot == "" {
		workspaceRoot = req.WorkspaceRoot
	}

	resp := sdk.NewResponse()

	if workspaceRoot == "" {
		return resp.Build(), nil
	}

	err := filepath.WalkDir(workspaceRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible files
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := filepath.Ext(path)
		if !supportedExtensions[ext] {
			return nil
		}

		return scanFile(resp, path, ext)
	})
	if err != nil && err != context.Canceled {
		return nil, fmt.Errorf("walking workspace: %w", err)
	}

	return resp.Build(), nil
}

func scanFile(resp *sdk.ResponseBuilder, filePath, ext string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return nil // skip unreadable files
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for i := range rules {
			rule := &rules[i]
			pattern, ok := rule.Patterns[ext]
			if !ok {
				continue
			}
			if pattern.MatchString(line) {
				resp.Finding(
					rule.ID,
					rule.Severity,
					sdk.ConfidenceMedium,
					fmt.Sprintf("%s: %s", rule.Description, strings.TrimSpace(line)),
				).
					At(filePath, lineNum, lineNum).
					WithMetadata("cwe", rule.CWE).
					WithMetadata("language", extToLanguage(ext)).
					Done()
			}
		}
	}

	return scanner.Err()
}

func extToLanguage(ext string) string {
	switch ext {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js":
		return "javascript"
	case ".ts":
		return "typescript"
	case ".java":
		return "java"
	default:
		return "unknown"
	}
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-sast: %v\n", err)
		os.Exit(1)
	}
}
