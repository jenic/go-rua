package aur

import (
	"encoding/json"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestSearchANDPatterns(t *testing.T) {
	packages := []Package{
		{Name: "python", Description: "A language"},
		{Name: "python-foo-git", Description: "Terminal tools"},
		{Name: "python-bar", Description: "Libraries"},
		{Name: "other-python-git", Description: "Terminal tools"},
		{Name: "other-git", Description: "Python tools"},
		{Name: "description-only", Description: "Python terminal -git"},
		{Name: "python-git-extra", Description: "Development tools"},
		{Name: "python-git", Description: "Python terminal"},
		{Name: "python3.14-git", Description: "A language"},
		{Name: "python3x14-git", Description: "A language"},
		{Name: "libc++-git", Description: "C++ library"},
	}
	body, err := json.Marshal(rpcResponse{Type: "search", Results: packages})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		terms []string
		seed  string
		by    string
		want  []string
	}{
		{name: "plain description and name AND", terms: []string{"python", "terminal"}, seed: "terminal", by: "name-desc", want: []string{"description-only", "other-python-git", "python-foo-git", "python-git"}},
		{name: "anchor prefix", terms: []string{"^PYTHON"}, seed: "python", by: "name", want: []string{"python", "python-foo-git", "python-bar", "python-git-extra", "python-git", "python3.14-git", "python3x14-git"}},
		{name: "wildcard prefix", terms: []string{"python*"}, seed: "python", by: "name", want: []string{"python", "python-foo-git", "python-bar", "python-git-extra", "python-git", "python3.14-git", "python3x14-git"}},
		{name: "anchor suffix", terms: []string{"-GIT$"}, seed: "-git", by: "name", want: []string{"python-foo-git", "other-python-git", "other-git", "python-git", "python3.14-git", "python3x14-git", "libc++-git"}},
		{name: "wildcard suffix", terms: []string{"*-git"}, seed: "-git", by: "name", want: []string{"python-foo-git", "other-python-git", "other-git", "python-git", "python3.14-git", "python3x14-git", "libc++-git"}},
		{name: "anchor exact", terms: []string{"^python$"}, seed: "python", by: "name", want: []string{"python"}},
		{name: "anchor prefix and suffix AND", terms: []string{"^python", "-git$"}, seed: "python", by: "name", want: []string{"python-foo-git", "python-git", "python3.14-git", "python3x14-git"}},
		{name: "wildcard prefix and suffix", terms: []string{"python*-git"}, seed: "python", by: "name", want: []string{"python-foo-git", "python-git", "python3.14-git", "python3x14-git"}},
		{name: "zero length wildcard", terms: []string{"python*-git", "^python-git$"}, seed: "python-git", by: "name", want: []string{"python-git"}},
		{name: "multiple wildcards", terms: []string{"*python*-git"}, seed: "python", by: "name", want: []string{"python-foo-git", "other-python-git", "python-git", "python3.14-git", "python3x14-git"}},
		{name: "longest literal inside pattern", terms: []string{"py*foo*-git"}, seed: "-git", by: "name", want: []string{"python-foo-git"}},
		{name: "mixed description and prefix", terms: []string{"^python", "terminal"}, seed: "terminal", by: "name-desc", want: []string{"python-foo-git", "python-git"}},
		{name: "short pattern with longer seed", terms: []string{"^p", "terminal"}, seed: "terminal", by: "name-desc", want: []string{"python-foo-git", "python-git"}},
		{name: "dot is literal", terms: []string{"^python3.14"}, seed: "python3.14", by: "name", want: []string{"python3.14-git"}},
		{name: "plus is literal", terms: []string{"libc++*"}, seed: "libc++", by: "name", want: []string{"libc++-git"}},
		{name: "no matches", terms: []string{"^missing"}, seed: "missing", by: "name", want: []string{}},
		{name: "unicode short term does not hide usable seed", terms: []string{"界", "py"}, seed: "py", by: "name-desc", want: []string{}},
		{name: "unicode short pattern does not hide usable literal", terms: []string{"*界*py"}, seed: "py", by: "name", want: []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			t.Cleanup(SetHTTPClientForTests(&http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				q := r.URL.Query()
				if q.Get("type") != "search" || q.Get("arg") != tt.seed || q.Get("by") != tt.by {
					t.Errorf("unexpected RPC query: %s; want search by %s with arg %q", r.URL.RawQuery, tt.by, tt.seed)
				}
				return mockResponse(200, string(body)), nil
			})}))
			got, err := SearchAND(tt.terms)
			if err != nil {
				t.Fatal(err)
			}
			names := make([]string, 0, len(got))
			for _, p := range got {
				names = append(names, p.Name)
			}
			sort.Strings(names)
			want := append([]string{}, tt.want...)
			sort.Strings(want)
			if !reflect.DeepEqual(names, want) {
				t.Errorf("results = %q, want %q", names, want)
			}
			if calls != 1 {
				t.Errorf("RPC calls = %d, want 1", calls)
			}
		})
	}
}

func TestSearchANDRejectsUnqueryableTerms(t *testing.T) {
	tests := [][]string{{""}, {"python", ""}, {"*"}, {"^"}, {"$"}, {"^$"}, {"***"}, {"p*"}, {"*p*y*"}, {"^p", "y$"}}
	for _, terms := range tests {
		t.Run(strings.Join(terms, ","), func(t *testing.T) {
			t.Cleanup(SetHTTPClientForTests(&http.Client{Transport: rtFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("invalid search must not issue an RPC request")
				return nil, nil
			})}))
			if _, err := SearchAND(terms); err == nil {
				t.Fatal("expected a useful error for an empty term or missing literal query")
			}
		})
	}
}

func TestSearchANDNoTerms(t *testing.T) {
	t.Cleanup(SetHTTPClientForTests(&http.Client{Transport: rtFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("empty search must not issue an RPC request")
		return nil, nil
	})}))
	got, err := SearchAND(nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty search = %v, %v", got, err)
	}
}

func TestRPCErrorResponses(t *testing.T) {
	for _, body := range []string{
		`{"version":5,"type":"error","error":"Too many package results."}`,
		`{"version":5,"type":"error"}`,
	} {
		t.Run(body, func(t *testing.T) {
			t.Cleanup(SetHTTPClientForTests(&http.Client{Transport: rtFunc(func(*http.Request) (*http.Response, error) {
				return mockResponse(200, body), nil
			})}))
			for _, query := range []struct {
				name string
				run  func([]string) ([]Package, error)
			}{
				{name: "search", run: SearchAND},
				{name: "legacy search", run: Search},
				{name: "info", run: Info},
			} {
				_, err := query.run([]string{"python"})
				if err == nil || !strings.Contains(err.Error(), "aur rpc:") {
					t.Fatalf("%s error = %v, want RPC error", query.name, err)
				}
				if strings.Contains(body, "Too many") && !strings.Contains(err.Error(), "Too many package results.") {
					t.Errorf("API error detail lost: %v", err)
				}
			}
		})
	}
}
