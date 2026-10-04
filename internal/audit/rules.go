package audit

// Wildcard is the RBAC "everything" token.
const Wildcard = "*"

// escalationRule describes one known privilege-escalation path. A rule in a
// manifest matches when it covers at least one of the listed API groups, at
// least one of the listed resources, and at least one of the listed verbs.
//
// Everything here is a path that does NOT need a wildcard to be dangerous,
// which is the half of RBAC review people usually skip.
type escalationRule struct {
	ID        string
	Severity  Severity
	Groups    []string
	Resources []string
	Verbs     []string
	Message   string
}

const (
	coreGroup = ""
	rbacGroup = "rbac.authorization.k8s.io"
)

// escalationRules is the built-in rule set. Order is stable so that reports
// are reproducible.
var escalationRules = []escalationRule{
	{
		ID:        "rbac-escalate",
		Severity:  Critical,
		Groups:    []string{rbacGroup},
		Resources: []string{"roles", "clusterroles"},
		Verbs:     []string{"escalate"},
		Message:   "the escalate verb removes the permission-containment check: the holder can write any rule into a role, including cluster-admin",
	},
	{
		ID:        "rbac-bind",
		Severity:  Critical,
		Groups:    []string{rbacGroup},
		Resources: []string{"roles", "clusterroles"},
		Verbs:     []string{"bind"},
		Message:   "the bind verb lets the holder bind an existing privileged role (cluster-admin included) to itself",
	},
	{
		ID:        "impersonate",
		Severity:  Critical,
		Groups:    []string{coreGroup, "authentication.k8s.io"},
		Resources: []string{"users", "groups", "serviceaccounts"},
		Verbs:     []string{"impersonate"},
		Message:   "impersonate lets the holder act as any user, group or ServiceAccount, inheriting their permissions",
	},
	{
		ID:        "rbac-write",
		Severity:  High,
		Groups:    []string{rbacGroup},
		Resources: []string{"roles", "clusterroles", "rolebindings", "clusterrolebindings"},
		Verbs:     []string{"create", "update", "patch"},
		Message:   "writing RBAC objects is a path to more permissions; it is only contained by the escalation check, which escalate/bind bypass",
	},
	{
		ID:        "secrets-read",
		Severity:  High,
		Groups:    []string{coreGroup},
		Resources: []string{"secrets"},
		Verbs:     []string{"get", "list", "watch"},
		Message:   "reading Secrets exposes every ServiceAccount token in scope, so this is transitively the union of those identities",
	},
	{
		ID:        "secrets-write",
		Severity:  High,
		Groups:    []string{coreGroup},
		Resources: []string{"secrets"},
		Verbs:     []string{"create", "update", "patch", "delete", "deletecollection"},
		Message:   "writing Secrets allows swapping credentials that other workloads trust",
	},
	{
		ID:        "pods-exec",
		Severity:  High,
		Groups:    []string{coreGroup},
		Resources: []string{"pods/exec"},
		Verbs:     []string{"create", "get"},
		Message:   "pods/exec is a shell in any pod in scope, which means that pod's ServiceAccount token and mounted volumes",
	},
	{
		ID:        "pods-attach",
		Severity:  High,
		Groups:    []string{coreGroup},
		Resources: []string{"pods/attach"},
		Verbs:     []string{"create", "get"},
		Message:   "pods/attach reaches the process streams of any pod in scope, much like pods/exec",
	},
	{
		ID:        "pods-portforward",
		Severity:  Medium,
		Groups:    []string{coreGroup},
		Resources: []string{"pods/portforward"},
		Verbs:     []string{"create", "get"},
		Message:   "pods/portforward tunnels to services that are otherwise only reachable inside the cluster network",
	},
	{
		ID:        "sa-token-create",
		Severity:  High,
		Groups:    []string{coreGroup},
		Resources: []string{"serviceaccounts/token"},
		Verbs:     []string{"create"},
		Message:   "minting a token for a ServiceAccount is equivalent to holding that account's permissions",
	},
	{
		ID:        "nodes-proxy",
		Severity:  High,
		Groups:    []string{coreGroup},
		Resources: []string{"nodes/proxy"},
		Verbs:     []string{"get", "create"},
		Message:   "nodes/proxy reaches the kubelet API directly, bypassing API-server authorization for pod exec and logs",
	},
	{
		ID:        "pods-create",
		Severity:  Medium,
		Groups:    []string{coreGroup},
		Resources: []string{"pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs"},
		Verbs:     []string{"create"},
		Message:   "creating workloads allows mounting any ServiceAccount in the namespace, and hostPath if no policy forbids it",
	},
	{
		ID:        "csr-approve",
		Severity:  High,
		Groups:    []string{"certificates.k8s.io"},
		Resources: []string{"certificatesigningrequests/approval", "signers"},
		Verbs:     []string{"update", "patch", "approve", "sign"},
		Message:   "approving CSRs issues cluster-trusted client certificates, including ones naming privileged groups",
	},
}

// covers reports whether a manifest's list of API groups / resources / verbs
// includes want, honouring the RBAC wildcard.
func covers(declared []string, want string) bool {
	for _, d := range declared {
		if d == Wildcard || d == want {
			return true
		}
	}
	return false
}

// coversAny reports whether declared covers at least one of the wants, and
// returns the first one it matched for the report text.
func coversAny(declared []string, wants []string) (string, bool) {
	for _, w := range wants {
		if covers(declared, w) {
			return w, true
		}
	}
	return "", false
}

// hasWildcard reports whether the list contains the "*" token itself.
func hasWildcard(declared []string) bool {
	for _, d := range declared {
		if d == Wildcard {
			return true
		}
	}
	return false
}
