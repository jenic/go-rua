package aur

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

type rtFunc2 func(*http.Request) (*http.Response, error)

func (f rtFunc2) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mockResp2(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewBufferString(body)), Header: make(http.Header)}
}

func TestSearchLegacyOR(t *testing.T) {
	t.Cleanup(SetHTTPClientForTests(&http.Client{Transport: rtFunc2(func(r *http.Request) (*http.Response, error) {
		return mockResp2(200, `{"version":5,"type":"search","resultcount":1,"results":[{"Name":"foo","Version":"1","Description":"foo"}]}`), nil
	})}))
	got, err := Search([]string{"foo", "bar"})
	if err != nil || len(got) == 0 {
		t.Fatalf("Search error: %v %v", got, err)
	}
}

func TestSearchErrorStatus(t *testing.T) {
	t.Cleanup(SetHTTPClientForTests(&http.Client{Transport: rtFunc2(func(r *http.Request) (*http.Response, error) {
		return mockResp2(500, ""), nil
	})}))
	if _, err := SearchAND([]string{"foo"}); err == nil {
		t.Fatalf("expected error on non-200 status")
	}
}

func TestInfoBatching(t *testing.T) {
	// Make 205 names to enforce batching (200 + 5)
	names := make([]string, 205)
	for i := range names {
		names[i] = "p"
	}
	calls := 0
	t.Cleanup(SetHTTPClientForTests(&http.Client{Transport: rtFunc2(func(r *http.Request) (*http.Response, error) {
		calls++
		return mockResp2(200, `{"version":5,"type":"multiinfo","resultcount":1,"results":[{"Name":"p","Version":"1"}]}`), nil
	})}))
	_, err := Info(names)
	if err != nil || calls < 2 {
		t.Fatalf("expected multiple calls for batching: calls=%d err=%v", calls, err)
	}
}
