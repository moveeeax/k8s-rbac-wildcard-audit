// Package audit statically inspects Kubernetes RBAC manifests for rules that
// grant more than they appear to. It never talks to an API server.
package audit

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity ranks a finding. The zero value is intentionally invalid so that a
// forgotten severity in a rule definition fails the unit tests instead of
// silently sorting below everything else.
type Severity int

const (
	Medium Severity = iota + 1
	High
	Critical
)

// ParseSeverity maps a CLI word onto a Severity.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "medium", "m":
		return Medium, nil
	case "high", "h":
		return High, nil
	case "critical", "crit", "c":
		return Critical, nil
	}
	return 0, fmt.Errorf("unknown severity %q (want medium, high or critical)", s)
}

func (s Severity) String() string {
	switch s {
	case Medium:
		return "medium"
	case High:
		return "high"
	case Critical:
		return "critical"
	}
	return "unknown"
}

// MarshalJSON renders the severity as its lowercase word rather than an int,
// so `jq 'select(.severity=="critical")'` works on the JSON output.
func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// UnmarshalJSON accepts the same words MarshalJSON emits, so a report can be
// read back into Go without a second set of structs.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var word string
	if err := json.Unmarshal(b, &word); err != nil {
		return err
	}
	if word == "unknown" {
		*s = 0
		return nil
	}
	parsed, err := ParseSeverity(word)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// Rule is a single PolicyRule out of a Role or ClusterRole.
type Rule struct {
	APIGroups       []string `yaml:"apiGroups"`
	Resources       []string `yaml:"resources"`
	Verbs           []string `yaml:"verbs"`
	ResourceNames   []string `yaml:"resourceNames"`
	NonResourceURLs []string `yaml:"nonResourceURLs"`
}

// String renders a rule compactly for the text report.
func (r Rule) String() string {
	parts := make([]string, 0, 4)
	if len(r.APIGroups) > 0 {
		parts = append(parts, "apiGroups="+brackets(r.APIGroups))
	}
	if len(r.Resources) > 0 {
		parts = append(parts, "resources="+brackets(r.Resources))
	}
	if len(r.NonResourceURLs) > 0 {
		parts = append(parts, "nonResourceURLs="+brackets(r.NonResourceURLs))
	}
	if len(r.Verbs) > 0 {
		parts = append(parts, "verbs="+brackets(r.Verbs))
	}
	if len(parts) == 0 {
		return "<empty rule>"
	}
	return strings.Join(parts, " ")
}

func brackets(in []string) string {
	shown := make([]string, len(in))
	for i, s := range in {
		if s == "" {
			shown[i] = `""` // the core API group reads as nothing otherwise
			continue
		}
		shown[i] = s
	}
	return "[" + strings.Join(shown, ",") + "]"
}

// Object is the slice of a Role/ClusterRole document this tool cares about.
type Object struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Rules []Rule `yaml:"rules"`

	// File and DocIndex record where the object came from, so a finding can
	// point at one document inside a `helm template` stream.
	File     string `yaml:"-"`
	DocIndex int    `yaml:"-"`
}

// Ref names the object the way kubectl would, for log lines.
func (o Object) Ref() string {
	if o.Metadata.Namespace != "" {
		return fmt.Sprintf("%s/%s.%s", o.Kind, o.Metadata.Name, o.Metadata.Namespace)
	}
	return fmt.Sprintf("%s/%s", o.Kind, o.Metadata.Name)
}

// Finding is one offending rule inside one object.
type Finding struct {
	RuleID    string   `json:"rule_id"`
	Severity  Severity `json:"severity"`
	Message   string   `json:"message"`
	File      string   `json:"file"`
	DocIndex  int      `json:"doc_index"`
	Kind      string   `json:"kind"`
	Name      string   `json:"name"`
	Namespace string   `json:"namespace,omitempty"`
	RuleIndex int      `json:"rule_index"`
	RuleText  string   `json:"rule"`
}

// Report is the whole result of a run.
type Report struct {
	Findings []Finding `json:"findings"`
	Summary  Summary   `json:"summary"`
}

// Summary carries the counts a CI log wants on one line.
type Summary struct {
	FilesScanned   int `json:"files_scanned"`
	ObjectsScanned int `json:"objects_scanned"`
	Critical       int `json:"critical"`
	High           int `json:"high"`
	Medium         int `json:"medium"`
	Total          int `json:"total"`
	// MinSeverity echoes the gate the report was filtered at, so a "no
	// findings" line can never be mistaken for a full audit.
	MinSeverity Severity `json:"min_severity"`
}

// Worst returns the highest severity present, or 0 when the report is clean.
func (r Report) Worst() Severity {
	var worst Severity
	for _, f := range r.Findings {
		if f.Severity > worst {
			worst = f.Severity
		}
	}
	return worst
}
