package install

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go-rua/internal/aur"
)

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mresp(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewBufferString(body)), Header: make(http.Header)}
}

func TestBuildPlanSimpleGraph(t *testing.T) {
	// Fake pacman commands
	bin := t.TempDir()
	// -T marks libfoo missing
	write := func(name, body string) {
		p := filepath.Join(bin, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("pacman", `
if [ "$1" = "-T" ]; then
  for n in "$@"; do if [ "$n" = "libfoo" ]; then echo "$n"; fi; done; exit 0
fi
if [ "$1" = "-Si" ]; then
  if [ "$2" = "libfoo" ]; then exit 0; else exit 1; fi
fi
exit 1
`)
	t.Setenv("PATH", bin)

	// Mock AUR Info: first app, then aurbar (batched with non-AUR dep)
	t.Cleanup(aur.SetHTTPClientForTests(&http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("type") == "info" {
			q := r.URL.Query()["arg[]"]
			if len(q) == 1 && q[0] == "app" {
				body := `{"version":5,"type":"multiinfo","resultcount":1,"results":[{"Name":"app","Version":"1","PackageBase":"app","Depends":["libfoo>=1","aurbar>=2"]}]}`
				return mresp(200, body), nil
			}
			// next round may include both AUR and non-AUR names; return aurbar when present
			for _, v := range q {
				if v == "aurbar" {
					body := `{"version":5,"type":"multiinfo","resultcount":1,"results":[{"Name":"aurbar","Version":"2","PackageBase":"aurbar"}]}`
					return mresp(200, body), nil
				}
			}
		}
		return mresp(404, ""), nil
	})}))

	plan, err := BuildPlan([]string{"app"})
	if err != nil {
		t.Fatalf("BuildPlan error: %v", err)
	}
	if got := strings.Join(plan.BuildOrder, ","); got != "aurbar,app" {
		t.Fatalf("order unexpected: %v", plan.BuildOrder)
	}
	if len(plan.RepoMissing) != 1 || plan.RepoMissing[0] != "libfoo" {
		t.Fatalf("RepoMissing unexpected: %v", plan.RepoMissing)
	}
	if plan.Depths["app"] != 0 || plan.Depths["aurbar"] != 1 {
		t.Fatalf("Depths unexpected: %v", plan.Depths)
	}
}

func TestTopoSortCycle(t *testing.T) {
	nodes := []string{"a", "b"}
	edges := map[string][]string{"a": {"b"}, "b": {"a"}}
	indeg := map[string]int{"a": 1, "b": 1}
	if _, err := topoSort(nodes, edges, indeg); err == nil {
		t.Fatalf("expected cycle error")
	}
}

func TestFormatSummary(t *testing.T) {
	s := DepSummary{Targets: []string{"app"}, RepoMissing: []string{"libfoo"}, Unknown: []string{"virt"}}
	out := FormatSummary(s)
	if !strings.Contains(out, "Repo deps missing:") || !strings.Contains(out, "virt") {
		t.Fatalf("summary format missing fields: %q", out)
	}
}

func TestDedupCopy(t *testing.T) {
	got := dedupCopy([]string{"a", "b", "a", "c", "b"})
	if len(got) != 3 {
		t.Fatalf("dedupCopy unexpected: %v", got)
	}
}
