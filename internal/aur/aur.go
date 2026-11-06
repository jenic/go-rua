package aur

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const base = "https://aur.archlinux.org/rpc/?v=5"

type Package struct {
	Name         string   `json:"Name"`
	Version      string   `json:"Version"`
	Description  string   `json:"Description"`
	URL          string   `json:"URL"`
	Maintainer   string   `json:"Maintainer"`
	NumVotes     int      `json:"NumVotes"`
	Popularity   float64  `json:"Popularity"`
	OutOfDate    int64    `json:"OutOfDate"`
	PackageBase  string   `json:"PackageBase"`
	Depends      []string `json:"Depends"`
	MakeDepends  []string `json:"MakeDepends"`
	CheckDepends []string `json:"CheckDepends"`
	OptDepends   []string `json:"OptDepends"`
	Provides     []string `json:"Provides"`
	Conflicts    []string `json:"Conflicts"`
}

type rpcResponse struct {
	Version     int       `json:"version"`
	Type        string    `json:"type"`
	ResultCount int       `json:"resultcount"`
	Results     []Package `json:"results"`
	Error       string    `json:"error"`
}

var httpClient = &http.Client{Timeout: 20 * time.Second}

func Search(terms []string) ([]Package, error) {
	// Legacy OR search across terms (kept for compatibility if needed elsewhere)
	seen := map[string]Package{}
	for _, t := range terms {
		u := fmt.Sprintf("%s&type=search&by=name-desc&arg=%s", base, url.QueryEscape(t))
		var resp rpcResponse
		if err := getJSON(u, &resp); err != nil {
			return nil, err
		}
		for _, p := range resp.Results {
			seen[p.Name] = p
		}
	}
	out := make([]Package, 0, len(seen))
	for _, p := range seen {
		out = append(out, p)
	}
	return out, nil
}

// SearchAND requires every term to match, ignoring case. Plain terms match
// substrings in names or descriptions; terms with *, a leading ^, or a trailing $
// match package names only. It queries by the longest literal substring and
// applies patterns locally, since the RPC API only supports substring searches.
func SearchAND(terms []string) ([]Package, error) {
	if len(terms) == 0 {
		return nil, nil
	}
	matchers := make([]searchTerm, 0, len(terms))
	var longest string
	by := "name-desc"
	for _, t := range terms {
		matcher, err := parseSearchTerm(t)
		if err != nil {
			return nil, err
		}
		matchers = append(matchers, matcher)
		if utf8.RuneCountInString(matcher.literal) > utf8.RuneCountInString(longest) {
			longest = matcher.literal
			by = "name-desc"
			if matcher.pattern != nil {
				by = "name"
			}
		}
	}
	if utf8.RuneCountInString(longest) < 2 {
		return nil, fmt.Errorf("search requires at least two consecutive literal characters in one term")
	}
	u := fmt.Sprintf("%s&type=search&by=%s&arg=%s", base, by, url.QueryEscape(longest))
	var resp rpcResponse
	if err := getJSON(u, &resp); err != nil {
		return nil, err
	}
	out := []Package{}
	for _, p := range resp.Results {
		name := strings.ToLower(p.Name)
		desc := strings.ToLower(p.Description)
		ok := true
		for _, matcher := range matchers {
			if !matcher.matches(name, desc) {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, p)
		}
	}
	return out, nil
}

func Info(names []string) ([]Package, error) {
	// batch if many
	out := []Package{}
	batch := 200
	for i := 0; i < len(names); i += batch {
		j := i + batch
		if j > len(names) {
			j = len(names)
		}
		u := fmt.Sprintf("%s&type=info&%s", base, joinMulti("arg[]", names[i:j]))
		var resp rpcResponse
		if err := getJSON(u, &resp); err != nil {
			return nil, err
		}
		out = append(out, resp.Results...)
	}
	return out, nil
}

func joinMulti(key string, vals []string) string {
	v := url.Values{}
	for _, s := range vals {
		v.Add(key, s)
	}
	return v.Encode()
}

func getJSON(u string, v *rpcResponse) error {
	req, _ := http.NewRequest("GET", u, nil)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("AUR RPC HTTP %d", resp.StatusCode)
	}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(v); err != nil {
		return err
	}
	if v.Type == "error" || v.Error != "" {
		message := v.Error
		if message == "" {
			message = "unspecified error"
		}
		return fmt.Errorf("aur rpc: %s", message)
	}
	return nil
}
