package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestExitCodeOnFindings(t *testing.T) {
	code, out, _ := runCLI(t, "../../examples/wildcard-clusterrole.yaml")
	if code != 1 {
		t.Fatalf("exit = %d, want 1\n%s", code, out)
	}
	if !strings.Contains(out, "CRITICAL") {
		t.Errorf("want a critical finding:\n%s", out)
	}
}

// Acceptance: --min-severity critical exits 0 on a manifest whose worst
// finding is high.
func TestExitZeroWhenBelowGate(t *testing.T) {
	code, out, _ := runCLI(t, "--min-severity", "critical", "../../examples/secret-reader.yaml")
	if code != 0 {
		t.Fatalf("exit = %d, want 0\n%s", code, out)
	}
	code, out, _ = runCLI(t, "../../examples/secret-reader.yaml")
	if code != 1 {
		t.Fatalf("default gate: exit = %d, want 1\n%s", code, out)
	}
	if !strings.Contains(out, "HIGH") || !strings.Contains(out, "secrets-read") {
		t.Errorf("want a high secrets-read finding:\n%s", out)
	}
}

func TestExitZeroOnCleanManifest(t *testing.T) {
	code, out, errb := runCLI(t, "../../examples/least-privilege.yaml")
	if code != 0 {
		t.Fatalf("exit = %d, want 0\nstdout: %s\nstderr: %s", code, out, errb)
	}
	if !strings.Contains(out, "clean: no findings") {
		t.Errorf("want the clean summary:\n%s", out)
	}
}

func TestJSONOutputParses(t *testing.T) {
	code, out, _ := runCLI(t, "--format", "json", "../../examples")
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	var rep struct {
		Findings []map[string]any `json:"findings"`
		Summary  map[string]any   `json:"summary"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out)
	}
	if len(rep.Findings) == 0 {
		t.Error("examples/ should produce findings")
	}
}

func TestBadFlagsExitTwo(t *testing.T) {
	if code, _, _ := runCLI(t, "--format", "yaml", "../../examples"); code != 2 {
		t.Errorf("unknown --format: exit = %d, want 2", code)
	}
	if code, _, _ := runCLI(t, "--min-severity", "urgent", "../../examples"); code != 2 {
		t.Errorf("unknown --min-severity: exit = %d, want 2", code)
	}
	if code, _, errb := runCLI(t); code != 2 || !strings.Contains(errb, "usage:") {
		t.Errorf("no paths: exit = %d, stderr = %q", code, errb)
	}
	if code, _, _ := runCLI(t, "./does-not-exist"); code != 2 {
		t.Errorf("missing path: exit = %d, want 2", code)
	}
}

func TestVersionFlag(t *testing.T) {
	code, out, _ := runCLI(t, "--version")
	if code != 0 || strings.TrimSpace(out) != version {
		t.Errorf("--version: exit = %d, out = %q, want %q", code, out, version)
	}
}
