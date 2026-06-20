# Changelog

All notable changes to this project will be documented in this file.

## [0.3.0] - Unreleased

### Added
- SAST-006 SSRF (CWE-918), SAST-007 weak cryptography (CWE-327), SAST-008 open redirect (CWE-601), SAST-009 server-side template injection (CWE-1336).
- Negative test fixtures (testdata/safe/) + TestSafeCodeHasNoFindings false-positive guard.

### Fixed
- SAST-001 (SQL injection, Python) no longer flags parameterized `%s` placeholders (safe DB-API form) as injection; now matches only the `%` format operator, f-strings, and .format().


- chore: add CI/CD, lint config, pre-commit hooks, and fix lint issues
- chore: add LICENSE, .gitignore, and tidy go.mod

