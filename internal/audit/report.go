package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// WriteJSON renders the report as a single JSON object with a stable shape:
// {"findings": [...], "summary": {...}}. findings is always an array, never
// null, so `jq '.findings | length'` works on a clean run too.
func WriteJSON(w io.Writer, rep Report) error {
	if rep.Findings == nil {
		rep.Findings = []Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// WriteText renders the human/CI-log report.
func WriteText(w io.Writer, rep Report) error {
	for _, f := range rep.Findings {
		label := strings.ToUpper(f.Severity.String())
		if _, err := fmt.Fprintf(w, "%-8s %-20s %s  %s#%d rule %d\n",
			label, f.RuleID, f.ref(), f.File, f.DocIndex, f.RuleIndex); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "         %s\n", f.RuleText); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "         %s\n\n", f.Message); err != nil {
			return err
		}
	}
	s := rep.Summary
	if s.Total == 0 {
		gate := ""
		if s.MinSeverity > Medium {
			// Saying "clean" after filtering out every high finding would be
			// a lie by omission in a CI log.
			gate = fmt.Sprintf(" at or above %s", s.MinSeverity)
		}
		_, err := fmt.Fprintf(w, "clean: no findings%s in %s across %s\n",
			gate, plural(s.ObjectsScanned, "RBAC object"), plural(s.FilesScanned, "file"))
		return err
	}
	_, err := fmt.Fprintf(w, "%s (%d critical, %d high, %d medium) in %s across %s\n",
		plural(s.Total, "finding"), s.Critical, s.High, s.Medium,
		plural(s.ObjectsScanned, "RBAC object"), plural(s.FilesScanned, "file"))
	return err
}

func (f Finding) ref() string {
	if f.Namespace != "" {
		return fmt.Sprintf("%s/%s.%s", f.Kind, f.Name, f.Namespace)
	}
	return fmt.Sprintf("%s/%s", f.Kind, f.Name)
}

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}
