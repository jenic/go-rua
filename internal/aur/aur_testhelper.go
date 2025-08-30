package aur

import "net/http"

// SetHTTPClientForTests allows tests in other packages to inject a custom client.
func SetHTTPClientForTests(c *http.Client) { httpClient = c }
