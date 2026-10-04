package audit

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDecodeSkipsNonRBAC(t *testing.T) {
	objs, err := Decode(strings.NewReader(`
apiVersion: v1
kind: Service
metadata:
  name: web
spec:
  ports: [{port: 80}]
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
---
# a comment-only document
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: web
roleRef:
  kind: Role
  name: web
`), "mixed.yaml")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(objs) != 0 {
		t.Fatalf("want 0 RBAC role objects, got %d (%+v)", len(objs), objs)
	}
}

func TestDecodeKeepsDocumentIndex(t *testing.T) {
	objs, err := Decode(strings.NewReader(`
apiVersion: v1
kind: Namespace
metadata:
  name: apps
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: second
  namespace: apps
rules: []
`), "s.yaml")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(objs) != 1 {
		t.Fatalf("want 1 object, got %d", len(objs))
	}
	if objs[0].DocIndex != 1 {
		t.Errorf("doc index = %d, want 1", objs[0].DocIndex)
	}
	if objs[0].Ref() != "Role/second.apps" {
		t.Errorf("Ref() = %q, want Role/second.apps", objs[0].Ref())
	}
}

func TestDecodeSyntaxErrorIsReported(t *testing.T) {
	_, err := DecodeFile("testdata/broken.yaml")
	if err == nil {
		t.Fatal("broken.yaml should fail to parse")
	}
	if !strings.Contains(err.Error(), "testdata/broken.yaml") {
		t.Errorf("error should name the file, got %q", err)
	}
}

// A YAML syntax error must not be reported as "clean" — Run returns the
// error alongside the partial report and the CLI turns that into exit 2.
func TestRunSurfacesParseErrors(t *testing.T) {
	rep, errs := Auditor{}.Run([]string{"testdata/broken.yaml"})
	if len(errs) != 1 {
		t.Fatalf("want 1 parse error, got %v", errs)
	}
	if len(rep.Findings) != 0 {
		t.Errorf("want no findings from an unparseable file, got %d", len(rep.Findings))
	}
}

func TestCollectFilesWalksDirectories(t *testing.T) {
	files, err := CollectFiles([]string{"testdata"})
	if err != nil {
		t.Fatalf("CollectFiles: %v", err)
	}
	if len(files) < 3 {
		t.Fatalf("want at least 3 yaml files under testdata, got %v", files)
	}
	for _, f := range files {
		if ext := filepath.Ext(f); ext != ".yaml" && ext != ".yml" {
			t.Errorf("non-yaml file collected: %s", f)
		}
	}
	// Sorted output keeps reports reproducible across filesystems.
	for i := 1; i < len(files); i++ {
		if files[i-1] > files[i] {
			t.Fatalf("file list not sorted: %v", files)
		}
	}
}

func TestCollectFilesPassesStdinThrough(t *testing.T) {
	files, err := CollectFiles([]string{StdinPath})
	if err != nil {
		t.Fatalf("CollectFiles: %v", err)
	}
	if len(files) != 1 || files[0] != StdinPath {
		t.Fatalf("want [-], got %v", files)
	}
}

func TestCollectFilesMissingPath(t *testing.T) {
	if _, err := CollectFiles([]string{"testdata/does-not-exist.yaml"}); err == nil {
		t.Fatal("a missing path should error rather than scan nothing")
	}
}

func TestRunOverDirectory(t *testing.T) {
	// broken.yaml lives in testdata too, so the directory run must report
	// both the findings from the good files and the parse error.
	rep, errs := Auditor{}.Run([]string{"testdata"})
	if len(errs) != 1 {
		t.Fatalf("want exactly the broken.yaml error, got %v", errs)
	}
	if rep.Summary.Critical == 0 {
		t.Errorf("want at least one critical finding across testdata, got %+v", rep.Summary)
	}
	if rep.Summary.FilesScanned < 3 {
		t.Errorf("files scanned = %d, want >= 3", rep.Summary.FilesScanned)
	}
}
