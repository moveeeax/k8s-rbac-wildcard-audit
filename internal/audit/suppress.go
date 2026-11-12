package audit

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Annotation keys a Role or ClusterRole can carry to accept specific findings
// on itself. The value of IgnoreAnnotation is a comma-separated list of rule
// ids; IgnoreReasonAnnotation is free text and optional.
const (
	IgnoreAnnotation       = "rbac-audit.moveeeax.io/ignore"
	IgnoreReasonAnnotation = "rbac-audit.moveeeax.io/reason"
)

// Suppression sources, as they appear in Suppression.Source.
const (
	SourceAnnotation = "annotation"
	SourceIgnoreFile = "ignore-file"
)

// expiresLayout is the date format of IgnoreEntry.Expires.
const expiresLayout = "2006-01-02"

// wildcardRuleIDs are the ids emitted by the wildcard checks in inspect.
var wildcardRuleIDs = []string{
	"wildcard-all", "wildcard-verbs", "wildcard-resources",
	"wildcard-apigroups", "wildcard-nonresource",
}

// KnownRuleIDs lists every rule id this build can emit, sorted.
func KnownRuleIDs() []string {
	ids := append([]string{}, wildcardRuleIDs...)
	for _, er := range escalationRules {
		ids = append(ids, er.ID)
	}
	sort.Strings(ids)
	return ids
}

func isKnownRuleID(id string) bool {
	for _, known := range KnownRuleIDs() {
		if id == known {
			return true
		}
	}
	return false
}

// Suppression records why a finding was accepted instead of reported.
type Suppression struct {
	Source string `json:"source"`
	Reason string `json:"reason,omitempty"`
	// Expires is copied from the ignore-file entry, empty for annotations.
	Expires string `json:"expires,omitempty"`
}

// IgnoreEntry is one accepted finding in an ignore file. RuleID and Name are
// required so that an entry can never silence a rule repo-wide; an empty Kind
// or Namespace matches any.
type IgnoreEntry struct {
	RuleID    string `yaml:"rule_id"`
	Kind      string `yaml:"kind"`
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
	Reason    string `yaml:"reason"`
	// Expires is a YYYY-MM-DD date. The entry still applies on that day and
	// stops applying the day after, so the finding comes back on its own.
	Expires string `yaml:"expires"`

	expires time.Time // parsed Expires, zero when unset
}

// IgnoreFile is the on-disk shape of --ignore-file.
type IgnoreFile struct {
	Ignores []IgnoreEntry `yaml:"ignores"`
}

// ParseIgnoreFile decodes and validates an ignore file. Unknown keys, unknown
// rule ids, a missing name or reason, and a malformed date are all errors: a
// typo in an ignore file must not quietly turn into "nothing suppressed" or,
// worse, into a broader match than intended.
func ParseIgnoreFile(r io.Reader, file string) ([]IgnoreEntry, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	var doc IgnoreFile
	if err := dec.Decode(&doc); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	for i := range doc.Ignores {
		e := &doc.Ignores[i]
		where := fmt.Sprintf("%s: ignores[%d]", file, i)
		switch {
		case e.RuleID == "":
			return nil, fmt.Errorf("%s: rule_id is required", where)
		case !isKnownRuleID(e.RuleID):
			return nil, fmt.Errorf("%s: unknown rule_id %q", where, e.RuleID)
		case e.Name == "":
			return nil, fmt.Errorf("%s: name is required", where)
		case strings.TrimSpace(e.Reason) == "":
			return nil, fmt.Errorf("%s: reason is required", where)
		}
		if e.Kind != "" && !rbacKinds[e.Kind] {
			return nil, fmt.Errorf("%s: kind %q is not Role or ClusterRole", where, e.Kind)
		}
		if e.Expires != "" {
			t, err := time.Parse(expiresLayout, e.Expires)
			if err != nil {
				return nil, fmt.Errorf("%s: expires %q is not a YYYY-MM-DD date", where, e.Expires)
			}
			e.expires = t
		}
	}
	return doc.Ignores, nil
}

// LoadIgnoreFile reads and validates an ignore file from disk.
func LoadIgnoreFile(path string) ([]IgnoreEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseIgnoreFile(f, path)
}

// String names the entry for warnings.
func (e IgnoreEntry) String() string {
	kind := e.Kind
	if kind == "" {
		kind = "*"
	}
	ref := kind + "/" + e.Name
	if e.Namespace != "" {
		ref += "." + e.Namespace
	}
	return e.RuleID + " " + ref
}

func (e IgnoreEntry) matches(f Finding) bool {
	return e.RuleID == f.RuleID &&
		e.Name == f.Name &&
		(e.Kind == "" || e.Kind == f.Kind) &&
		(e.Namespace == "" || e.Namespace == f.Namespace)
}

// expired reports whether the entry no longer applies on the date of now.
func (e IgnoreEntry) expired(now time.Time) bool {
	if e.expires.IsZero() {
		return false
	}
	y, m, d := now.Date()
	today := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	return today.After(e.expires)
}

// annotationIgnores returns the rule ids an object accepts on itself.
func annotationIgnores(obj Object) map[string]bool {
	raw, ok := obj.Metadata.Annotations[IgnoreAnnotation]
	if !ok {
		return nil
	}
	ids := map[string]bool{}
	for _, id := range strings.Split(raw, ",") {
		if id = strings.TrimSpace(id); id != "" {
			ids[id] = true
		}
	}
	return ids
}

// annotationWarnings flags ignore annotations naming rule ids this build does
// not know. Those entries suppress nothing, which is the safe outcome, but a
// typo there should not go unnoticed.
func annotationWarnings(objs []Object) []string {
	var out []string
	for _, obj := range objs {
		ids := annotationIgnores(obj)
		unknown := make([]string, 0, len(ids))
		for id := range ids {
			if !isKnownRuleID(id) {
				unknown = append(unknown, id)
			}
		}
		sort.Strings(unknown)
		for _, id := range unknown {
			out = append(out, fmt.Sprintf("%s#%d %s: %s names unknown rule id %q, nothing suppressed",
				obj.File, obj.DocIndex, obj.Ref(), IgnoreAnnotation, id))
		}
	}
	return out
}

// suppress decides whether a finding is accepted. Annotations are checked
// first; an ignore-file entry only applies while it has not expired.
func (a Auditor) suppress(obj Object, f Finding, now time.Time) *Suppression {
	if annotationIgnores(obj)[f.RuleID] {
		return &Suppression{
			Source: SourceAnnotation,
			Reason: obj.Metadata.Annotations[IgnoreReasonAnnotation],
		}
	}
	for _, e := range a.Ignores {
		if e.matches(f) && !e.expired(now) {
			return &Suppression{Source: SourceIgnoreFile, Reason: e.Reason, Expires: e.Expires}
		}
	}
	return nil
}

// expiredWarnings lists ignore-file entries past their date that would have
// matched a finding, so the log says why a finding came back.
func (a Auditor) expiredWarnings(findings []Finding, now time.Time) []string {
	var out []string
	for _, e := range a.Ignores {
		if !e.expired(now) {
			continue
		}
		for _, f := range findings {
			if e.matches(f) {
				out = append(out, fmt.Sprintf("ignore entry %s expired on %s, reporting the finding again", e, e.Expires))
				break
			}
		}
	}
	return out
}
