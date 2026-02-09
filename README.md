# nox-plugin-sast

**Multi-language static application security testing for common vulnerability classes.**

## Overview

`nox-plugin-sast` is a Nox security scanner plugin that performs static application security testing (SAST) across multiple programming languages. It detects the vulnerability classes that account for the majority of real-world exploits: SQL injection, cross-site scripting, path traversal, command injection, and insecure deserialization.

Unlike heavyweight commercial SAST tools that require build integration and produce thousands of noisy findings, this plugin operates on raw source files with zero build dependencies. It uses targeted regex patterns tuned for each language to detect high-signal vulnerability patterns with minimal false positives. The result is a fast, deterministic scanner that runs anywhere -- locally, in CI, or as part of an MCP-driven agent workflow.

The plugin supports Go, Python, JavaScript, TypeScript, and Java. All findings include CWE identifiers for compliance mapping and the matched source line for developer context. It operates in passive read-only mode with no external dependencies.

## Use Cases

### CI/CD Security Gate for Every Commit

Your team needs a fast security check that runs on every pull request without slowing down the pipeline. The SAST plugin scans only changed files in seconds, catching SQL injection and command injection patterns before they reach code review. Its deterministic output means no flaky test failures -- the same code always produces the same findings.

### Baseline Security Scanning for New Projects

Your organization is spinning up a new microservice and wants to establish a security baseline from day one. The SAST plugin runs alongside unit tests to catch common vulnerability patterns as code is written, preventing security debt from accumulating before the first release.

### Polyglot Codebase Coverage

Your platform includes Go backend services, Python data pipelines, and TypeScript frontends. Rather than configuring separate SAST tools for each language, the plugin provides unified coverage with consistent rule IDs and CWE mappings across all five supported languages, simplifying both developer workflows and compliance reporting.

### Agent-Driven Security Analysis

Your AI agents use Nox via MCP to analyze code repositories autonomously. The SAST plugin provides structured findings with CWE metadata that agents can interpret, correlate with other findings, and use to generate security reports or remediation plans.

## 5-Minute Demo

### Prerequisites

- Go 1.25+
- [Nox](https://github.com/Nox-HQ/nox) installed

### Quick Start

1. **Install the plugin**

   ```bash
   nox plugin install Nox-HQ/nox-plugin-sast
   ```

2. **Create test files with vulnerable patterns**

   ```bash
   mkdir -p demo-sast && cd demo-sast

   cat > handler.py <<'EOF'
   import subprocess
   import pickle
   from flask import Flask, request

   app = Flask(__name__)

   @app.route("/search")
   def search():
       term = request.args["q"]
       cursor = app.db.cursor()
       cursor.execute("SELECT * FROM products WHERE name = '%s'" % term)
       return cursor.fetchall()

   @app.route("/run")
   def run_command():
       cmd = request.args["cmd"]
       os.system(cmd)

   @app.route("/load")
   def load_data():
       data = request.get_data()
       return pickle.loads(data)
   EOF

   cat > server.js <<'EOF'
   const express = require("express");
   const { exec } = require("child_process");
   const fs = require("fs");
   const path = require("path");

   const app = express();

   app.get("/page", (req, res) => {
       document.write(req.query.content);
   });

   app.get("/file", (req, res) => {
       const filePath = path.join("/data", req.query.path + "../../etc/passwd");
       fs.readFileSync(filePath);
   });

   app.get("/exec", (req, res) => {
       child_process.exec("ls " + req.query.dir);
   });
   EOF
   ```

3. **Run the scan**

   ```bash
   nox scan --plugin nox/sast demo-sast/
   ```

4. **Review findings**

   ```
   nox/sast scan completed: 6 findings

   SAST-001 [HIGH] SQL Injection: unsanitized input in SQL query construction:
       cursor.execute("SELECT * FROM products WHERE name = '%s'" % term)
     Location: demo-sast/handler.py:11
     CWE: CWE-89
     Language: python

   SAST-004 [CRITICAL] Command Injection: unsanitized input passed to system command execution:
       os.system(cmd)
     Location: demo-sast/handler.py:16
     CWE: CWE-78
     Language: python

   SAST-005 [HIGH] Insecure Deserialization: untrusted data passed to deserialization functions:
       return pickle.loads(data)
     Location: demo-sast/handler.py:21
     CWE: CWE-502
     Language: python

   SAST-002 [HIGH] Cross-Site Scripting (XSS): unsafe DOM manipulation or template rendering:
       document.write(req.query.content);
     Location: demo-sast/server.js:10
     CWE: CWE-79
     Language: javascript

   SAST-003 [HIGH] Path Traversal: user-controlled input in file path operations:
       const filePath = path.join("/data", req.query.path + "../../etc/passwd");
     Location: demo-sast/server.js:14
     CWE: CWE-22
     Language: javascript

   SAST-004 [CRITICAL] Command Injection: unsanitized input passed to system command execution:
       child_process.exec("ls " + req.query.dir);
     Location: demo-sast/server.js:18
     CWE: CWE-78
     Language: javascript
   ```

## Rules

| Rule ID  | Description | Severity | Confidence | CWE |
|----------|-------------|----------|------------|-----|
| SAST-001 | SQL Injection: unsanitized input in SQL query construction via string concatenation or formatting | High | Medium | CWE-89 |
| SAST-002 | Cross-Site Scripting (XSS): unsafe DOM manipulation (`innerHTML`, `document.write`) or template rendering (`template.HTML`, `mark_safe`) | High | Medium | CWE-79 |
| SAST-003 | Path Traversal: user-controlled input in file path operations (`filepath.Join`, `os.Open`, `path.join`, `fs.*`, `new File`, `Paths.get`) | High | Medium | CWE-22 |
| SAST-004 | Command Injection: unsanitized input passed to system command execution (`exec.Command`, `os.system`, `subprocess.call`, `child_process.*`, `Runtime.exec`) | Critical | Medium | CWE-78 |
| SAST-005 | Insecure Deserialization: untrusted data passed to deserialization functions (`pickle.loads`, `yaml.load`, `ObjectInputStream`, `JSON.parse` with request data) | High | Medium | CWE-502 |

## Supported Languages / File Types

| Language | Extensions | Coverage |
|----------|-----------|----------|
| Go | `.go` | SAST-001 through SAST-004 |
| Python | `.py` | SAST-001 through SAST-005 |
| JavaScript | `.js` | SAST-001 through SAST-005 |
| TypeScript | `.ts` | SAST-001 through SAST-005 |
| Java | `.java` | SAST-003 through SAST-005 |

## Configuration

The plugin operates with sensible defaults and requires no configuration. It scans the entire workspace recursively, skipping `.git`, `vendor`, `node_modules`, `__pycache__`, and `.venv` directories.

Pass `workspace_root` as input to override the default scan directory:

```bash
nox scan --plugin nox/sast --input workspace_root=/path/to/project
```

## Installation

### Via Nox (recommended)

```bash
nox plugin install Nox-HQ/nox-plugin-sast
```

### Standalone

```bash
git clone https://github.com/Nox-HQ/nox-plugin-sast.git
cd nox-plugin-sast
make build
```

## Development

```bash
# Build the plugin binary
make build

# Run tests with race detection
make test

# Run linter
make lint

# Clean build artifacts
make clean

# Build Docker image
docker build -t nox-plugin-sast .
```

## Architecture

The plugin follows the standard Nox plugin architecture, communicating via the Nox Plugin SDK over stdio.

1. **File Discovery**: Recursively walks the workspace, filtering for supported source file extensions (`.go`, `.py`, `.js`, `.ts`, `.java`). Skips common non-source directories.

2. **Language-Aware Pattern Matching**: Each source file is scanned line by line. For each line, all rules are checked, but only patterns matching the file's extension are evaluated. This ensures Go-specific regex patterns never run against Python files, eliminating cross-language false positives.

3. **Finding Emission**: Each match produces a finding with the rule ID, severity, CWE identifier, language, and the matched source line. Findings include precise file location (path and line number) for IDE integration.

4. **Deterministic Execution**: The scanner uses pre-compiled regex patterns with no runtime state, external services, or randomness. The same source files always produce identical findings.

## Contributing

Contributions are welcome. Please open an issue or submit a pull request on the [GitHub repository](https://github.com/Nox-HQ/nox-plugin-sast).

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for your changes
4. Ensure `make test` and `make lint` pass
5. Submit a pull request

## License

Apache-2.0
