package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func day(t *testing.T, s string) time.Time {
	t.Helper()
	d, err := time.Parse(expiresLayout, s)
	if err != nil {
		t.Fatal(err)
	}
	return d.Add(15 * time.Hour) // mid-afternoon, to catch off-by-one-day bugs
}

func loadIgnores(t *testing.T) []IgnoreEntry {
	t.Helper()
	ignores, err := LoadIgnoreFile("testdata/ignore.yaml")
	if err != nil {
		t.Fatalf("LoadIgnoreFile: %v", err)
	}
	return ignores
}

func TestAnnotationSuppressesListedRules(t *testing.T) {
	objs, err := DecodeFile("testdata/suppressed.yaml")
	if err != nil {
		t.Fatalf("DecodeFile: %v", err)
	}
	rep := Auditor{}.Objects(objs[:1])

	if len(rep.Findings) != 0 {
		t.Fatalf("want every finding on operator suppressed, got %v", findingIDs(rep))
	}
	if rep.Summary.Suppressed != 2 || rep.Summary.Total != 0 || rep.Summary.High != 0 {
		t.Errorf("summary = %+v, want 2 suppressed and zero reported", rep.Summary)
	}
	for _, f := range rep.Suppressed {
		s := f.Suppression
		if s == nil || s.Source != SourceAnnotation {
			t.Fatalf("%s: suppression = %+v, want source annotation", f.RuleID, s)
		}
		if !strings.Contains(s.Reason, "TLS secrets") {
			t.Errorf("%s: reason = %q, want the annotation text", f.RuleID, s.Reason)
		}
	}
	if len(rep.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", rep.Warnings)
	}
}

// The annotation names rule ids, not "everything": a rule it does not list is
// still reported.
func TestAnnotationOnlyCoversNamedRules(t *testing.T) {
	objs := decodeString(t, "partial.yaml", `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: operator
  annotations:
    rbac-audit.moveeeax.io/ignore: secrets-read,secrets-wirte
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "update"]
`)
	rep := Auditor{}.Objects(objs)
	if got := findingIDs(rep); len(got) != 1 || got[0] != "secrets-write" {
		t.Fatalf("want only secrets-write reported, got %v", got)
	}
	if rep.Summary.Suppressed != 1 {
		t.Errorf("suppressed = %d, want 1", rep.Summary.Suppressed)
	}
	if len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0], `"secrets-wirte"`) {
		t.Errorf("want one warning about the misspelt id, got %v", rep.Warnings)
	}
}

func TestIgnoreFileSuppressesUntilExpiry(t *testing.T) {
	objs, err := DecodeFile("testdata/suppressed.yaml")
	if err != nil {
		t.Fatalf("DecodeFile: %v", err)
	}
	ignores := loadIgnores(t)

	// The expiry day itself is still covered.
	for _, now := range []string{"2026-11-12", "2027-03-01"} {
		rep := Auditor{Ignores: ignores, Now: day(t, now)}.Objects(objs)
		if len(rep.Findings) != 0 {
			t.Fatalf("%s: want nothing reported, got %v", now, findingIDs(rep))
		}
		if rep.Summary.Suppressed != 3 {
			t.Errorf("%s: suppressed = %d, want 3", now, rep.Summary.Suppressed)
		}
		f := rep.Suppressed[len(rep.Suppressed)-1]
		if f.Name != "config-sync" || f.Suppression.Source != SourceIgnoreFile || f.Suppression.Expires != "2027-03-01" {
			t.Errorf("%s: last suppressed = %s %+v, want config-sync from the ignore file", now, f.Name, f.Suppression)
		}
	}

	rep := Auditor{Ignores: ignores, Now: day(t, "2027-03-02")}.Objects(objs)
	f, ok := find(rep, "secrets-read")
	if !ok || f.Name != "config-sync" || f.Suppression != nil {
		t.Fatalf("expired entry: want config-sync secrets-read reported again, got %v", rep.Findings)
	}
	if rep.Summary.Suppressed != 2 || rep.Summary.High != 1 {
		t.Errorf("expired entry: summary = %+v, want 2 suppressed, 1 high", rep.Summary)
	}
	if len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0], "expired on 2027-03-01") {
		t.Errorf("want one expiry warning, got %v", rep.Warnings)
	}
}

func TestIgnoreEntryMatching(t *testing.T) {
	f := Finding{RuleID: "secrets-read", Kind: "Role", Name: "config-sync", Namespace: "apps"}
	cases := []struct {
		entry IgnoreEntry
		want  bool
	}{
		{IgnoreEntry{RuleID: "secrets-read", Name: "config-sync"}, true},
		{IgnoreEntry{RuleID: "secrets-read", Kind: "Role", Name: "config-sync", Namespace: "apps"}, true},
		{IgnoreEntry{RuleID: "secrets-read", Kind: "ClusterRole", Name: "config-sync"}, false},
		{IgnoreEntry{RuleID: "secrets-read", Name: "config-sync", Namespace: "other"}, false},
		{IgnoreEntry{RuleID: "pods-exec", Name: "config-sync"}, false},
		{IgnoreEntry{RuleID: "secrets-read", Name: "config"}, false},
	}
	for _, c := range cases {
		if got := c.entry.matches(f); got != c.want {
			t.Errorf("%+v matches = %v, want %v", c.entry, got, c.want)
		}
	}
}

// Below-gate findings are not counted as suppressed: summary.suppressed is
// what would have failed this run.
func TestSuppressedRespectsGate(t *testing.T) {
	objs, err := DecodeFile("testdata/suppressed.yaml")
	if err != nil {
		t.Fatalf("DecodeFile: %v", err)
	}
	if rep := (Auditor{MinSeverity: High}).Objects(objs[:1]); rep.Summary.Suppressed != 2 {
		t.Errorf("at high: suppressed = %d, want 2", rep.Summary.Suppressed)
	}
	rep := Auditor{MinSeverity: Critical}.Objects(objs[:1])
	if rep.Summary.Suppressed != 0 || len(rep.Suppressed) != 0 {
		t.Errorf("at critical: suppressed = %d, want 0 (both operator findings are high)", rep.Summary.Suppressed)
	}
}

func TestParseIgnoreFileRejectsBadEntries(t *testing.T) {
	cases := map[string]string{
		"missing rule_id": "ignores:\n  - name: a\n    reason: r\n",
		"unknown rule_id": "ignores:\n  - rule_id: secret-read\n    name: a\n    reason: r\n",
		"missing name":    "ignores:\n  - rule_id: secrets-read\n    reason: r\n",
		"missing reason":  "ignores:\n  - rule_id: secrets-read\n    name: a\n",
		"bad kind":        "ignores:\n  - rule_id: secrets-read\n    kind: RoleBinding\n    name: a\n    reason: r\n",
		"bad date":        "ignores:\n  - rule_id: secrets-read\n    name: a\n    reason: r\n    expires: 01/03/2027\n",
		"unknown key":     "ignores:\n  - rule_id: secrets-read\n    name: a\n    reason: r\n    expiry: 2027-03-01\n",
		"not yaml":        "ignores: [\n",
	}
	for name, body := range cases {
		if _, err := ParseIgnoreFile(strings.NewReader(body), "ignore.yaml"); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	got, err := ParseIgnoreFile(strings.NewReader(""), "empty.yaml")
	if err != nil || len(got) != 0 {
		t.Errorf("empty file: got %v, %v; want no entries and no error", got, err)
	}
}

func TestKnownRuleIDsCoverEveryCheck(t *testing.T) {
	ids := KnownRuleIDs()
	if len(ids) != len(wildcardRuleIDs)+len(escalationRules) {
		t.Fatalf("KnownRuleIDs has %d ids, want %d", len(ids), len(wildcardRuleIDs)+len(escalationRules))
	}
	// Every id the wildcard checks emit must be suppressible.
	objs := decodeString(t, "wild.yaml", `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: wide
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
  - apiGroups: ["*"]
    resources: ["configmaps"]
    verbs: ["get"]
  - apiGroups: [""]
    resources: ["*"]
    nonResourceURLs: ["*"]
    verbs: ["*"]
`)
	for _, f := range (Auditor{}).Objects(objs).Findings {
		if !isKnownRuleID(f.RuleID) {
			t.Errorf("rule id %q is emitted but not in KnownRuleIDs", f.RuleID)
		}
	}
}

func TestReportsShowSuppressed(t *testing.T) {
	objs, err := DecodeFile("testdata/suppressed.yaml")
	if err != nil {
		t.Fatalf("DecodeFile: %v", err)
	}
	rep := Auditor{}.Objects(objs)

	var buf bytes.Buffer
	if err := WriteText(&buf, rep); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"ACCEPTED", "high, suppressed by annotation: reconciles TLS secrets",
		"1 finding (0 critical, 1 high, 0 medium) in 2 RBAC objects across 1 file, 2 suppressed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text report missing %q:\n%s", want, out)
		}
	}

	buf.Reset()
	if err := WriteJSON(&buf, rep); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var back struct {
		Suppressed []Finding `json:"suppressed"`
		Summary    Summary   `json:"summary"`
	}
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("JSON does not parse: %v", err)
	}
	if len(back.Suppressed) != 2 || back.Summary.Suppressed != 2 {
		t.Errorf("JSON: %d suppressed listed, summary %d; want 2 and 2", len(back.Suppressed), back.Summary.Suppressed)
	}
	if back.Suppressed[0].Suppression == nil || back.Suppressed[0].Suppression.Source != SourceAnnotation {
		t.Errorf("JSON: suppression = %+v, want source annotation", back.Suppressed[0].Suppression)
	}

	// A clean run that suppressed something must say so.
	buf.Reset()
	if err := WriteText(&buf, Auditor{}.Objects(objs[:1])); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	if !strings.Contains(buf.String(), "clean: no findings in 1 RBAC object across 1 file, 2 suppressed") {
		t.Errorf("clean summary should count suppressions: %q", buf.String())
	}
}
