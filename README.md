# k8s-rbac-wildcard-audit

[![ci](https://github.com/moveeeax/k8s-rbac-wildcard-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/k8s-rbac-wildcard-audit/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.23%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Static audit of Kubernetes `Role` and `ClusterRole` manifests. It names the rules
that grant more than they look like they do — the wildcards, and the handful of
narrow-looking rules that are really cluster admin.

Reads YAML only. No kubeconfig, no API server, no credentials, so it runs in a
pull-request job on a repo that has no cluster access at all.

## Why not `kubectl auth can-i`

`can-i` answers questions you already thought to ask, against a cluster that
already has the role installed. This reads the manifest before it merges, and it
flags paths that contain no wildcard whatsoever:

| rule | why it matters |
| --- | --- |
| `secrets` + `get`/`list` | every ServiceAccount token in scope, so transitively those identities |
| `pods/exec`, `pods/attach` | a shell in any pod, which is that pod's token and volumes |
| `escalate` on roles | skips the permission-containment check: write any rule, including cluster-admin |
| `bind` on clusterroles | bind `cluster-admin` to yourself |
| `impersonate` | act as any user, group or ServiceAccount |
| `serviceaccounts/token` + `create` | mint a token for an account you do not hold |
| `nodes/proxy` | the kubelet API directly, around API-server authorization |
| `certificatesigningrequests/approval` | issue cluster-trusted client certs naming privileged groups |

## Install

```sh
go install github.com/moveeeax/k8s-rbac-wildcard-audit/cmd/k8s-rbac-wildcard-audit@latest
```

Or build from a clone:

```sh
go build -o k8s-rbac-wildcard-audit ./cmd/k8s-rbac-wildcard-audit
```

## Usage

```sh
k8s-rbac-wildcard-audit ./manifests
helm template mychart | k8s-rbac-wildcard-audit --min-severity high -
k8s-rbac-wildcard-audit --format json ./k8s | jq .findings
```

Paths can be files or directories; directories are walked for `.yaml`/`.yml`,
skipping `.git`, `vendor` and `charts`. `-` reads a manifest stream from stdin,
which is how you point it at `helm template` or `kustomize build` output.
Non-RBAC documents in the stream are ignored without comment.

Real output:

```console
$ k8s-rbac-wildcard-audit examples/wildcard-clusterrole.yaml
CRITICAL wildcard-all         ClusterRole/platform-admin  examples/wildcard-clusterrole.yaml#0 rule 0
         apiGroups=[*] resources=[*] verbs=[*]
         every verb on every resource in every API group — this rule is cluster-admin, whatever the role is called

HIGH     wildcard-verbs       Role/configmap-owner.apps  examples/wildcard-clusterrole.yaml#1 rule 0
         apiGroups=[""] resources=[configmaps] verbs=[*]
         verbs: ["*"] includes escalate, bind and impersonate, not just the CRUD verbs people picture

2 findings (1 critical, 1 high, 0 medium) in 2 RBAC objects across 1 file
```

Every finding carries the file, the document index inside that file, the object
and the index of the offending rule — enough to find it in a 4000-line
`helm template` dump.

### Flags

| flag | default | meaning |
| --- | --- | --- |
| `--format` | `text` | `text` or `json` |
| `--min-severity` | `medium` | report and fail on `medium`, `high` or `critical` |
| `--version` | | print the version and exit |

### Exit codes

| code | meaning |
| --- | --- |
| `0` | no findings at or above `--min-severity` |
| `1` | at least one finding at or above `--min-severity` |
| `2` | bad usage, unreadable path, or a YAML syntax error |

Exit `2` outranks a clean result on purpose: a manifest nobody could parse is a
hole in the audit, not a pass.

## How it works

1. Expand the positional paths into a sorted file list.
2. Decode each file as a multi-document YAML stream and keep only `Role` and
   `ClusterRole` documents, recording the file and document index on each.
3. Run every `PolicyRule` through the wildcard checks and the built-in
   escalation rule set in [`internal/audit/rules.go`](internal/audit/rules.go).
4. Filter by `--min-severity`, sort worst-first, print, and set the exit code.

Resource matching honours the RBAC wildcard, so `resources: ["*"]` with
`verbs: ["get"]` is reported as a secrets read as well as a wildcard — the
grant is real whether or not `secrets` is spelled out.

### JSON output

```json
{
  "findings": [
    {
      "rule_id": "secrets-read",
      "severity": "high",
      "message": "get on secrets: reading Secrets exposes every ServiceAccount token in scope, so this is transitively the union of those identities",
      "file": "examples/secret-reader.yaml",
      "doc_index": 0,
      "kind": "Role",
      "name": "app-config-reader",
      "namespace": "apps",
      "rule_index": 1,
      "rule": "apiGroups=[\"\"] resources=[secrets] verbs=[get,list]"
    }
  ],
  "summary": {
    "files_scanned": 1,
    "objects_scanned": 1,
    "critical": 0,
    "high": 1,
    "medium": 0,
    "total": 1,
    "min_severity": "medium"
  }
}
```

`findings` is always an array, never `null`, so a `jq` pipeline survives a clean
run. `min_severity` echoes the gate, so a zero-finding report can't be mistaken
for a full audit.

## In CI

```yaml
- name: audit RBAC
  run: |
    go install github.com/moveeeax/k8s-rbac-wildcard-audit/cmd/k8s-rbac-wildcard-audit@latest
    k8s-rbac-wildcard-audit --min-severity high ./manifests
```

Start at `--min-severity critical` on an existing repo, fix what it finds, then
tighten to `high`. Gating a brownfield cluster at `medium` on day one just
teaches people to pass `--min-severity critical` in the pipeline.

## Examples

`examples/` is the fixture set the CI job checks itself against:

- `wildcard-clusterrole.yaml` — the full wildcard triple, plus a narrower `verbs: ["*"]`
- `secret-reader.yaml` — no wildcard anywhere, still a `high`
- `escalation-paths.yaml` — `escalate`, `bind`, `impersonate`, exec, token minting
- `least-privilege.yaml` — what a clean run looks like

## Limitations

It reads manifests, not a cluster. It does not resolve `RoleBinding`s, so it
reports that a rule is dangerous, not who currently holds it. Aggregated
ClusterRoles (`aggregationRule`) are read as written, and the rules the
controller fills in are not evaluated. Both are on the list.

## License

MIT — see [LICENSE](LICENSE).
