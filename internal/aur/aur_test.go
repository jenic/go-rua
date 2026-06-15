package aur

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mockResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}
}

func TestJoinMulti(t *testing.T) {
	got := joinMulti("arg[]", []string{"a", "b"})
	if !(got == "arg%5B%5D=a&arg%5B%5D=b" || got == "arg%5B%5D=b&arg%5B%5D=a") {
		t.Fatalf("unexpected encoding: %q", got)
	}
}

func TestSearchANDAndInfo(t *testing.T) {
	// Mock AUR RPC responses
	t.Cleanup(SetHTTPClientForTests(&http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		q := r.URL.Query()
		ttype := q.Get("type")
		if ttype == "search" {
			// Return two candidates with name/desc
			body := `{"version":5,"type":"search","resultcount":2,"results":[{"Name":"foo","Version":"1","Description":"a foo pkg"},{"Name":"bar","Version":"2","Description":"bar util"}]}`
			return mockResponse(200, body), nil
		}
		if ttype == "info" {
			// Echo back info for requested names
			// We do not parse joinMulti here; just return both
			body := `{"version":5,"type":"multiinfo","resultcount":2,"results":[{"Name":"foo","Version":"1","PackageBase":"foo-base"},{"Name":"bar","Version":"2","PackageBase":"bar"}]}`
			return mockResponse(200, body), nil
		}
		return mockResponse(404, ""), nil
	})}))

	res, err := SearchAND([]string{"foo", "pkg"})
	if err != nil {
		t.Fatalf("SearchAND error: %v", err)
	}
	if len(res) != 1 || res[0].Name != "foo" {
		t.Fatalf("SearchAND filter unexpected: %+v", res)
	}

	info, err := Info([]string{"foo", "bar"})
	if err != nil || len(info) != 2 {
		t.Fatalf("Info unexpected: %v, %v", info, err)
	}
}
