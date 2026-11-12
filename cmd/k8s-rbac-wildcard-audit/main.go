// Command k8s-rbac-wildcard-audit statically audits Kubernetes Role and
// ClusterRole manifests for wildcard rules and known privilege-escalation
// paths. It reads YAML only — no kubeconfig, no cluster, no credentials.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/moveeeax/k8s-rbac-wildcard-audit/internal/audit"
)

// version is overridden at release time with -ldflags "-X main.version=...".
var version = "0.2.0"

const usage = `k8s-rbac-wildcard-audit — find RBAC rules that grant more than they look like they do

usage:
  k8s-rbac-wildcard-audit [flags] <path>...

Paths may be files or directories (walked for .yaml/.yml). Use "-" to read a
manifest stream from stdin.

flags:
  --format string         text or json (default "text")
  --min-severity string   report and gate on medium, high or critical (default "medium")
  --ignore-file string    YAML file of accepted findings (rule_id, kind, name,
                          namespace, reason, expires)
  --show-suppressed       also list the findings that were suppressed
  --version               print the version and exit

A Role or ClusterRole can also accept findings on itself with the annotation
rbac-audit.moveeeax.io/ignore: "secrets-read,pods-exec" and an optional
rbac-audit.moveeeax.io/reason. Suppressed findings never fail the run.

exit codes:
  0  no findings at or above --min-severity
  1  at least one finding at or above --min-severity
  2  bad usage, unreadable path, a YAML syntax error, or an invalid ignore file

examples:
  k8s-rbac-wildcard-audit ./manifests
  helm template mychart | k8s-rbac-wildcard-audit --min-severity high -
  k8s-rbac-wildcard-audit --format json ./k8s | jq .findings
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("k8s-rbac-wildcard-audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }

	format := fs.String("format", "text", "output format: text or json")
	minSev := fs.String("min-severity", "medium", "minimum severity to report and fail on")
	ignoreFile := fs.String("ignore-file", "", "YAML file of accepted findings")
	showSuppressed := fs.Bool("show-suppressed", false, "also list suppressed findings")
	showVersion := fs.Bool("version", false, "print version and exit")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "error: unknown --format %q (want text or json)\n", *format)
		return 2
	}
	sev, err := audit.ParseSeverity(*minSev)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	paths := fs.Args()
	if len(paths) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}

	var ignores []audit.IgnoreEntry
	if *ignoreFile != "" {
		// An ignore file that cannot be read is a usage error, not an empty
		// list: auditing without it would fail a gate the team already
		// accepted, or worse, pass one with a silently broken file.
		ignores, err = audit.LoadIgnoreFile(*ignoreFile)
		if err != nil {
			fmt.Fprintf(stderr, "error: --ignore-file: %v\n", err)
			return 2
		}
	}

	rep, errs := audit.Auditor{MinSeverity: sev, Ignores: ignores}.Run(paths)
	for _, e := range errs {
		fmt.Fprintf(stderr, "error: %v\n", e)
	}
	for _, w := range rep.Warnings {
		fmt.Fprintf(stderr, "warning: %s\n", w)
	}
	if !*showSuppressed {
		rep.Suppressed = nil // still counted in summary.suppressed
	}

	out := bufio.NewWriter(stdout)
	if *format == "json" {
		err = audit.WriteJSON(out, rep)
	} else {
		err = audit.WriteText(out, rep)
	}
	if err == nil {
		err = out.Flush()
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: writing report: %v\n", err)
		return 2
	}

	// A file we could not parse is a hole in the audit, so it outranks a
	// clean result: never report "clean" over a manifest nobody read.
	if len(errs) > 0 {
		return 2
	}
	if len(rep.Findings) > 0 {
		return 1
	}
	return 0
}
