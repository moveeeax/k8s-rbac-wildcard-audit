package audit

import (
	"strings"
	"testing"
)

func decodeString(t *testing.T, name, body string) []Object {
	t.Helper()
	objs, err := Decode(strings.NewReader(body), name)
	if err != nil {
		t.Fatalf("Decode(%s): unexpected error: %v", name, err)
	}
	return objs
}

// findingIDs lists the rule ids in report order.
func findingIDs(rep Report) []string {
	out := make([]string, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		out = append(out, f.RuleID)
	}
	return out
}

func find(rep Report, id string) (Finding, bool) {
	for _, f := range rep.Findings {
		if f.RuleID == id {
			return f, true
		}
	}
	return Finding{}, false
}

// Acceptance: a ClusterRole with apiGroups/resources/verbs all ["*"] is
// reported critical.
func TestFullWildcardIsCritical(t *testing.T) {
	objs := decodeString(t, "wild.yaml", `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-everything
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
`)
	rep := Auditor{}.Objects(objs)

	if got := findingIDs(rep); len(got) != 1 || got[0] != "wildcard-all" {
		t.Fatalf("want exactly [wildcard-all], got %v", got)
	}
	f := rep.Findings[0]
	if f.Severity != Critical {
		t.Errorf("severity = %s, want critical", f.Severity)
	}
	if f.Kind != "ClusterRole" || f.Name != "cluster-everything" {
		t.Errorf("object = %s/%s, want ClusterRole/cluster-everything", f.Kind, f.Name)
	}
	if f.RuleIndex != 0 || f.DocIndex != 0 || f.File != "wild.yaml" {
		t.Errorf("location = %s#%d rule %d, want wild.yaml#0 rule 0", f.File, f.DocIndex, f.RuleIndex)
	}
}

// Acceptance: a Role granting get on secrets is reported high even with no
// wildcard present.
func TestSecretsGetIsHighWithoutWildcard(t *testing.T) {
	objs := decodeString(t, "secrets.yaml", `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: apps
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]
`)
	rep := Auditor{}.Objects(objs)

	f, ok := find(rep, "secrets-read")
	if !ok {
		t.Fatalf("no secrets-read finding; got %v", findingIDs(rep))
	}
	if f.Severity != High {
		t.Errorf("severity = %s, want high", f.Severity)
	}
	if f.Namespace != "apps" {
		t.Errorf("namespace = %q, want apps", f.Namespace)
	}
	for _, id := range findingIDs(rep) {
		if strings.HasPrefix(id, "wildcard-") {
			t.Errorf("unexpected wildcard finding %s on a manifest with no wildcard", id)
		}
	}
}

// Acceptance: --min-severity critical exits 0 on a manifest whose worst
// finding is high. Here: the filter empties the report, so the CLI's
// "len(findings) > 0" gate returns 0.
func TestMinSeverityGate(t *testing.T) {
	objs := decodeString(t, "secrets.yaml", `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: apps
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
`)
	if rep := (Auditor{MinSeverity: High}).Objects(objs); rep.Worst() != High {
		t.Fatalf("at min-severity high: worst = %s, want high", rep.Worst())
	}
	rep := Auditor{MinSeverity: Critical}.Objects(objs)
	if len(rep.Findings) != 0 {
		t.Fatalf("at min-severity critical: want no findings, got %v", findingIDs(rep))
	}
	if rep.Summary.Total != 0 || rep.Summary.High != 0 {
		t.Errorf("summary = %+v, want zeroed counts", rep.Summary)
	}
	if rep.Summary.ObjectsScanned != 1 {
		t.Errorf("objects scanned = %d, want 1 (filtering must not hide the scan)", rep.Summary.ObjectsScanned)
	}
}

// Acceptance: multi-document files report each offending object with its file
// path and document index.
func TestMultiDocumentLocations(t *testing.T) {
	objs, err := DecodeFile("testdata/multidoc.yaml")
	if err != nil {
		t.Fatalf("DecodeFile: %v", err)
	}
	if len(objs) != 2 {
		t.Fatalf("decoded %d RBAC objects, want 2 (the ServiceAccount and ConfigMap must be skipped)", len(objs))
	}
	rep := Auditor{}.Objects(objs)

	want := map[string]int{"secret-reader": 1, "binder": 2}
	seen := map[string]bool{}
	for _, f := range rep.Findings {
		idx, ok := want[f.Name]
		if !ok {
			t.Fatalf("finding on unexpected object %q", f.Name)
		}
		if f.DocIndex != idx {
			t.Errorf("%s: doc index = %d, want %d", f.Name, f.DocIndex, idx)
		}
		if f.File != "testdata/multidoc.yaml" {
			t.Errorf("%s: file = %q, want testdata/multidoc.yaml", f.Name, f.File)
		}
		seen[f.Name] = true
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("no finding reported for %s", name)
		}
	}
	if f, ok := find(rep, "rbac-bind"); !ok || f.Severity != Critical {
		t.Errorf("rbac-bind finding = %+v, want present and critical", f)
	}
}

func TestCleanManifestHasNoFindings(t *testing.T) {
	objs, err := DecodeFile("testdata/clean.yaml")
	if err != nil {
		t.Fatalf("DecodeFile: %v", err)
	}
	rep := Auditor{}.Objects(objs)
	if len(rep.Findings) != 0 {
		t.Fatalf("want clean, got %v", findingIDs(rep))
	}
	if rep.Summary.ObjectsScanned != 2 {
		t.Errorf("objects scanned = %d, want 2", rep.Summary.ObjectsScanned)
	}
	if rep.Worst() != 0 {
		t.Errorf("worst = %s, want none", rep.Worst())
	}
}

// A wildcard on resources alone still has to reach the escalation rules:
// resources ["*"] with verbs ["get"] is a secrets read.
func TestWildcardResourcesImpliesSecretsRead(t *testing.T) {
	objs := decodeString(t, "w.yaml", `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: reader
rules:
  - apiGroups: [""]
    resources: ["*"]
    verbs: ["get"]
`)
	rep := Auditor{}.Objects(objs)
	if _, ok := find(rep, "wildcard-resources"); !ok {
		t.Errorf("no wildcard-resources finding; got %v", findingIDs(rep))
	}
	if _, ok := find(rep, "secrets-read"); !ok {
		t.Errorf("resources:[*] + get must imply secrets-read; got %v", findingIDs(rep))
	}
}

// verbs: ["*"] on a narrow resource is not the full triple, so it must not be
// collapsed into wildcard-all.
func TestWildcardVerbsOnNarrowResource(t *testing.T) {
	objs := decodeString(t, "w.yaml", `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cm-owner
  namespace: apps
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["*"]
`)
	rep := Auditor{}.Objects(objs)
	ids := findingIDs(rep)
	if _, ok := find(rep, "wildcard-all"); ok {
		t.Errorf("must not collapse to wildcard-all; got %v", ids)
	}
	if f, ok := find(rep, "wildcard-verbs"); !ok || f.Severity != High {
		t.Errorf("wildcard-verbs = %+v, want present and high", f)
	}
}

func TestEscalateVerbIsCritical(t *testing.T) {
	objs := decodeString(t, "e.yaml", `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: role-editor
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles"]
    verbs: ["get", "escalate"]
`)
	rep := Auditor{}.Objects(objs)
	f, ok := find(rep, "rbac-escalate")
	if !ok {
		t.Fatalf("no rbac-escalate finding; got %v", findingIDs(rep))
	}
	if f.Severity != Critical {
		t.Errorf("severity = %s, want critical", f.Severity)
	}
	if !strings.Contains(f.Message, "escalate") {
		t.Errorf("message does not name the verb: %q", f.Message)
	}
}

func TestPodsExecSubresource(t *testing.T) {
	objs := decodeString(t, "x.yaml", `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: debugger
  namespace: apps
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: ["create"]
`)
	rep := Auditor{}.Objects(objs)
	f, ok := find(rep, "pods-exec")
	if !ok {
		t.Fatalf("no pods-exec finding; got %v", findingIDs(rep))
	}
	if f.RuleIndex != 1 {
		t.Errorf("rule index = %d, want 1", f.RuleIndex)
	}
	// Granting get/list on pods alone is not a finding; only the exec
	// subresource rule is.
	if _, ok := find(rep, "pods-create"); ok {
		t.Errorf("pods get/list must not be reported as pods-create: %v", findingIDs(rep))
	}
}

func TestFindingsSortedWorstFirst(t *testing.T) {
	objs := decodeString(t, "mix.yaml", `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: mixed
  namespace: apps
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["create"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles"]
    verbs: ["bind"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["list"]
`)
	rep := Auditor{}.Objects(objs)
	if len(rep.Findings) < 3 {
		t.Fatalf("want at least 3 findings, got %v", findingIDs(rep))
	}
	for i := 1; i < len(rep.Findings); i++ {
		if rep.Findings[i-1].Severity < rep.Findings[i].Severity {
			t.Fatalf("not sorted worst-first: %v", findingIDs(rep))
		}
	}
	if rep.Summary.Critical != 1 {
		t.Errorf("critical count = %d, want 1", rep.Summary.Critical)
	}
	if rep.Summary.Total != len(rep.Findings) {
		t.Errorf("summary total = %d, want %d", rep.Summary.Total, len(rep.Findings))
	}
}

func TestParseSeverity(t *testing.T) {
	for in, want := range map[string]Severity{
		"medium":   Medium,
		"HIGH":     High,
		" crit  ":  Critical,
		"critical": Critical,
	} {
		got, err := ParseSeverity(in)
		if err != nil {
			t.Fatalf("ParseSeverity(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("ParseSeverity(%q) = %s, want %s", in, got, want)
		}
	}
	if _, err := ParseSeverity("urgent"); err == nil {
		t.Error("ParseSeverity(\"urgent\") should fail")
	}
}

func TestRuleString(t *testing.T) {
	r := Rule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}}
	want := `apiGroups=[""] resources=[secrets] verbs=[get,list]`
	if got := r.String(); got != want {
		t.Errorf("Rule.String() = %q, want %q", got, want)
	}
	if got := (Rule{}).String(); got != "<empty rule>" {
		t.Errorf("empty Rule.String() = %q", got)
	}
}
