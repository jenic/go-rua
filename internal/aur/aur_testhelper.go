package aur

import "net/http"

// SetHTTPClientForTests allows tests in other packages to inject a custom client.
func SetHTTPClientForTests(c *http.Client) func() {
	old := httpClient
	httpClient = c
	return func() { httpClient = old }
}
