package aur

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
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
}

var httpClient = &http.Client{Timeout: 20 * time.Second}

func Search(terms []string) ([]Package, error) {
	// Legacy OR search across terms (kept for compatibility if needed elsewhere)
	seen := map[string]Package{}
	for _, by := range []string{"name", "desc"} {
		for _, t := range terms {
			u := fmt.Sprintf("%s&type=search&by=%s&arg=%s", base, by, url.QueryEscape(t))
			var resp rpcResponse
			if err := getJSON(u, &resp); err != nil {
				return nil, err
			}
			for _, p := range resp.Results {
				seen[p.Name] = p
			}
		}
	}
	out := make([]Package, 0, len(seen))
	for _, p := range seen {
		out = append(out, p)
	}
	return out, nil
}

// SearchAND performs AUR search that requires all keywords to match
// either in name or description. It queries by the longest keyword and
// then filters locally for the rest.
func SearchAND(terms []string) ([]Package, error) {
	if len(terms) == 0 {
		return nil, nil
	}
	// pick the longest term as the initial query
	longest := terms[0]
	for _, t := range terms[1:] {
		if len(t) > len(longest) {
			longest = t
		}
	}
	// get initial candidate set
	seen := map[string]Package{}
	for _, by := range []string{"name", "desc"} {
		u := fmt.Sprintf("%s&type=search&by=%s&arg=%s", base, by, url.QueryEscape(longest))
		var resp rpcResponse
		if err := getJSON(u, &resp); err != nil {
			return nil, err
		}
		for _, p := range resp.Results {
			seen[p.Name] = p
		}
	}
	// filter: every term must match name or description (case-insensitive)
	out := []Package{}
	for _, p := range seen {
		name := strings.ToLower(p.Name)
		desc := strings.ToLower(p.Description)
		ok := true
		for _, t := range terms {
			lt := strings.ToLower(t)
			if !strings.Contains(name, lt) && !strings.Contains(desc, lt) {
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

func getJSON(u string, v any) error {
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
	return dec.Decode(v)
}
