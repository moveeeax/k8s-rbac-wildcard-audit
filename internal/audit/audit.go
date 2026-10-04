package audit

import (
	"fmt"
	"sort"
)

// Auditor applies the built-in rule set to parsed objects.
type Auditor struct {
	// MinSeverity drops findings below this level from the report. The zero
	// value means Medium, i.e. report everything.
	MinSeverity Severity
}

// Objects runs the audit over already-parsed objects and returns a sorted,
// severity-filtered report.
func (a Auditor) Objects(objs []Object) Report {
	var rep Report
	files := map[string]bool{}
	for _, obj := range objs {
		files[obj.File] = true
		rep.Summary.ObjectsScanned++
		for i, rule := range obj.Rules {
			rep.Findings = append(rep.Findings, a.inspect(obj, rule, i)...)
		}
	}
	rep.Summary.FilesScanned = len(files)

	min := a.MinSeverity
	if min == 0 {
		min = Medium
	}
	kept := make([]Finding, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		if f.Severity < min {
			continue
		}
		kept = append(kept, f)
	}
	rep.Findings = kept
	rep.Summary.MinSeverity = min
	sortFindings(rep.Findings)

	for _, f := range rep.Findings {
		switch f.Severity {
		case Critical:
			rep.Summary.Critical++
		case High:
			rep.Summary.High++
		case Medium:
			rep.Summary.Medium++
		}
	}
	rep.Summary.Total = len(rep.Findings)
	return rep
}

// inspect applies every check to a single PolicyRule.
func (a Auditor) inspect(obj Object, rule Rule, idx int) []Finding {
	mk := func(id string, sev Severity, msg string) Finding {
		return Finding{
			RuleID:    id,
			Severity:  sev,
			Message:   msg,
			File:      obj.File,
			DocIndex:  obj.DocIndex,
			Kind:      obj.Kind,
			Name:      obj.Metadata.Name,
			Namespace: obj.Metadata.Namespace,
			RuleIndex: idx,
			RuleText:  rule.String(),
		}
	}

	wildGroups := hasWildcard(rule.APIGroups)
	wildResources := hasWildcard(rule.Resources)
	wildVerbs := hasWildcard(rule.Verbs)

	// The full wildcard triple is cluster-admin by another name. Report it
	// once and stop: expanding it into every escalation path underneath adds
	// a dozen findings that all have the same single fix.
	if wildGroups && wildResources && wildVerbs {
		return []Finding{mk("wildcard-all", Critical,
			"every verb on every resource in every API group — this rule is cluster-admin, whatever the role is called")}
	}

	var out []Finding
	if wildVerbs {
		out = append(out, mk("wildcard-verbs", High,
			"verbs: [\"*\"] includes escalate, bind and impersonate, not just the CRUD verbs people picture"))
	}
	if wildResources {
		out = append(out, mk("wildcard-resources", High,
			"resources: [\"*\"] covers secrets and the exec/attach subresources, and silently absorbs every CRD added later"))
	}
	if wildGroups && !wildResources {
		out = append(out, mk("wildcard-apigroups", Medium,
			"apiGroups: [\"*\"] applies the named resources across every group, including future CRDs that reuse the name"))
	}
	if hasWildcard(rule.NonResourceURLs) && wildVerbs {
		out = append(out, mk("wildcard-nonresource", Medium,
			"nonResourceURLs: [\"*\"] with wildcard verbs exposes every non-resource endpoint, /debug/pprof included"))
	}

	for _, er := range escalationRules {
		group, okGroup := coversAny(rule.APIGroups, er.Groups)
		resource, okResource := coversAny(rule.Resources, er.Resources)
		verb, okVerb := coversAny(rule.Verbs, er.Verbs)
		if !okGroup || !okResource || !okVerb {
			continue
		}
		out = append(out, mk(er.ID, er.Severity,
			fmt.Sprintf("%s on %s: %s", verb, qualify(group, resource), er.Message)))
	}
	return out
}

// qualify renders a group/resource pair the way RBAC docs do.
func qualify(group, resource string) string {
	if group == "" || group == Wildcard {
		return resource
	}
	return resource + "." + group
}

func sortFindings(f []Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		a, b := f[i], f[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity // worst first
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.DocIndex != b.DocIndex {
			return a.DocIndex < b.DocIndex
		}
		if a.RuleIndex != b.RuleIndex {
			return a.RuleIndex < b.RuleIndex
		}
		return a.RuleID < b.RuleID
	})
}

// Run is the whole pipeline: expand paths, decode, audit. Parse errors are
// returned alongside whatever was successfully audited, so one broken file in
// a directory does not hide the findings in the rest.
func (a Auditor) Run(paths []string) (Report, []error) {
	files, err := CollectFiles(paths)
	if err != nil {
		return Report{}, []error{err}
	}
	var (
		objs []Object
		errs []error
	)
	for _, f := range files {
		got, err := DecodeFile(f)
		if err != nil {
			errs = append(errs, err)
		}
		objs = append(objs, got...)
	}
	rep := a.Objects(objs)
	// Files that parsed but held no RBAC still count as scanned.
	rep.Summary.FilesScanned = len(files)
	return rep, errs
}
