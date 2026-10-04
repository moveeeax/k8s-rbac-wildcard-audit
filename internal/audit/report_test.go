package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestWriteTextIncludesLocationAndRule(t *testing.T) {
	objs, err := DecodeFile("testdata/wildcard.yaml")
	if err != nil {
		t.Fatalf("DecodeFile: %v", err)
	}
	var buf bytes.Buffer
	if err := WriteText(&buf, Auditor{}.Objects(objs)); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"CRITICAL", "wildcard-all", "ClusterRole/cluster-everything",
		"testdata/wildcard.yaml#0 rule 0", "verbs=[*]", "1 finding (1 critical",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text report missing %q:\n%s", want, out)
		}
	}
}

func TestWriteTextCleanRun(t *testing.T) {
	objs, err := DecodeFile("testdata/clean.yaml")
	if err != nil {
		t.Fatalf("DecodeFile: %v", err)
	}
	var buf bytes.Buffer
	if err := WriteText(&buf, Auditor{}.Objects(objs)); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	if !strings.Contains(buf.String(), "clean: no findings in 2 RBAC objects") {
		t.Errorf("unexpected clean report: %q", buf.String())
	}
}

// A gated run that filters everything out must say so rather than claim a
// clean audit.
func TestWriteTextNamesTheGate(t *testing.T) {
	objs, err := DecodeFile("testdata/multidoc.yaml")
	if err != nil {
		t.Fatalf("DecodeFile: %v", err)
	}
	var buf bytes.Buffer
	if err := WriteText(&buf, Auditor{MinSeverity: Critical}.Objects(objs)); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	if !strings.Contains(buf.String(), "rbac-bind") {
		t.Fatalf("multidoc has a critical finding, report was: %q", buf.String())
	}

	buf.Reset()
	clean, err := DecodeFile("testdata/clean.yaml")
	if err != nil {
		t.Fatalf("DecodeFile: %v", err)
	}
	if err := WriteText(&buf, Auditor{MinSeverity: Critical}.Objects(clean)); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	if !strings.Contains(buf.String(), "at or above critical") {
		t.Errorf("gated clean line must name the gate: %q", buf.String())
	}
}

func TestWriteJSONShape(t *testing.T) {
	objs, err := DecodeFile("testdata/wildcard.yaml")
	if err != nil {
		t.Fatalf("DecodeFile: %v", err)
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, Auditor{}.Objects(objs)); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var got struct {
		Findings []struct {
			RuleID    string `json:"rule_id"`
			Severity  string `json:"severity"`
			File      string `json:"file"`
			DocIndex  int    `json:"doc_index"`
			RuleIndex int    `json:"rule_index"`
			Rule      string `json:"rule"`
		} `json:"findings"`
		Summary Summary `json:"summary"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if len(got.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got.Findings))
	}
	f := got.Findings[0]
	if f.Severity != "critical" {
		t.Errorf("severity = %q, want the word \"critical\"", f.Severity)
	}
	if f.RuleID != "wildcard-all" || f.File != "testdata/wildcard.yaml" {
		t.Errorf("finding = %+v", f)
	}
	if got.Summary.Total != 1 || got.Summary.Critical != 1 {
		t.Errorf("summary = %+v", got.Summary)
	}
}

// findings must be [] and not null on a clean run, so jq pipelines do not
// blow up on the happy path.
func TestWriteJSONCleanIsEmptyArray(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, Report{}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if !strings.Contains(buf.String(), `"findings": []`) {
		t.Errorf("clean JSON should carry an empty array:\n%s", buf.String())
	}
}

func TestSeverityJSONRoundTrip(t *testing.T) {
	for _, sev := range []Severity{Medium, High, Critical} {
		b, err := json.Marshal(sev)
		if err != nil {
			t.Fatalf("Marshal(%s): %v", sev, err)
		}
		if string(b) != `"`+sev.String()+`"` {
			t.Errorf("Marshal(%s) = %s, want the bare word", sev, b)
		}
		var back Severity
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatalf("Unmarshal(%s): %v", b, err)
		}
		if back != sev {
			t.Errorf("round trip of %s gave %s", sev, back)
		}
	}
	var back Severity
	if err := json.Unmarshal([]byte(`"urgent"`), &back); err == nil {
		t.Error("unmarshalling a bogus severity should fail")
	}
}
