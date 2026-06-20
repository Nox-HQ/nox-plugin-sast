package main

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestConformance(t *testing.T) {
	srv := buildServer()
	sdk.RunConformance(t, srv)
}

func TestTrackConformance(t *testing.T) {
	srv := buildServer()
	sdk.RunForTrack(t, srv, registry.TrackCoreAnalysis)
}

func TestScanFindsGoSQLInjection(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "SAST-001")
	if len(found) == 0 {
		t.Fatal("expected at least one SAST-001 (SQL Injection) finding in vuln_app.go")
	}

	for _, f := range found {
		if f.GetLocation() == nil {
			t.Error("finding must include a location")
			continue
		}
		if f.GetLocation().GetStartLine() == 0 {
			t.Error("finding location must have a non-zero start line")
		}
		if f.GetMetadata()["cwe"] != "CWE-89" {
			t.Errorf("expected CWE-89 metadata, got %q", f.GetMetadata()["cwe"])
		}
	}
}

func TestScanFindsPythonCommandInjection(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "SAST-004")
	if len(found) == 0 {
		t.Fatal("expected at least one SAST-004 (Command Injection) finding in vuln_app.py")
	}

	for _, f := range found {
		if f.GetSeverity() != sdk.SeverityCritical {
			t.Errorf("SAST-004 severity should be CRITICAL, got %v", f.GetSeverity())
		}
		if f.GetMetadata()["language"] != "python" {
			t.Errorf("expected language=python, got %q", f.GetMetadata()["language"])
		}
	}
}

func TestScanFindsJSXSS(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "SAST-002")
	if len(found) == 0 {
		t.Fatal("expected at least one SAST-002 (XSS) finding in vuln_app.js")
	}

	for _, f := range found {
		if f.GetMetadata()["cwe"] != "CWE-79" {
			t.Errorf("expected CWE-79 metadata, got %q", f.GetMetadata()["cwe"])
		}
	}
}

func TestScanEmptyWorkspace(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, t.TempDir())

	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings for empty workspace, got %d", len(resp.GetFindings()))
	}
}

func TestScanNoWorkspace(t *testing.T) {
	client := testClient(t)

	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}
	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings when no workspace provided, got %d", len(resp.GetFindings()))
	}
}

// --- helpers ---

func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file path")
	}
	return filepath.Join(filepath.Dir(filename), "testdata")
}

func testClient(t *testing.T) pluginv1.PluginServiceClient {
	t.Helper()
	const bufSize = 1024 * 1024

	lis := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(grpcServer, buildServer())

	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(func() { grpcServer.Stop() })

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return pluginv1.NewPluginServiceClient(conn)
}

func invokeScan(t *testing.T, client pluginv1.PluginServiceClient, workspaceRoot string) *pluginv1.InvokeToolResponse {
	t.Helper()
	input, err := structpb.NewStruct(map[string]any{
		"workspace_root": workspaceRoot,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool(scan): %v", err)
	}
	return resp
}

func findByRule(findings []*pluginv1.Finding, ruleID string) []*pluginv1.Finding {
	var result []*pluginv1.Finding
	for _, f := range findings {
		if f.GetRuleId() == ruleID {
			result = append(result, f)
		}
	}
	return result
}

func safeDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file path")
	}
	return filepath.Join(filepath.Dir(filename), "testdata", "safe")
}

// TestPythonSQLiStillDetected confirms the SAST-001 fix detects the `%` format
// operator (unsafe) while the safe-code test confirms it ignores `%s` params.
func TestPythonSQLiStillDetected(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))
	if len(findByRule(resp.GetFindings(), "SAST-001")) == 0 {
		t.Fatal("expected SAST-001 (SQLi) to still fire on the `%` format operator")
	}
}

// TestNewRulesDetected exercises the SAST-006..009 rules against the vulnerable
// fixtures; each must produce at least one finding with its CWE.
func TestNewRulesDetected(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	want := map[string]string{
		"SAST-006": "CWE-918",  // SSRF
		"SAST-007": "CWE-327",  // weak crypto
		"SAST-008": "CWE-601",  // open redirect
		"SAST-009": "CWE-1336", // SSTI
	}
	for rule, cwe := range want {
		found := findByRule(resp.GetFindings(), rule)
		if len(found) == 0 {
			t.Errorf("expected at least one %s finding", rule)
			continue
		}
		if got := found[0].GetMetadata()["cwe"]; got != cwe {
			t.Errorf("%s: expected %s, got %q", rule, cwe, got)
		}
	}
}

// TestSafeCodeHasNoFindings is the false-positive guard: equivalent SAFE code
// (parameterized queries, sha256, allow-listed/constant URLs, constant
// redirects) must produce ZERO findings. Without this, adding regex rules
// silently inflates false positives.
func TestSafeCodeHasNoFindings(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, safeDir(t))

	if n := len(resp.GetFindings()); n != 0 {
		for _, f := range resp.GetFindings() {
			t.Logf("unexpected finding: %s at line %d", f.GetRuleId(), f.GetLocation().GetStartLine())
		}
		t.Fatalf("expected 0 findings on safe code, got %d", n)
	}
}
