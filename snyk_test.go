package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeSnyk mimics the Snyk REST API. The org-level /issues endpoint filters on
// scan_item.type/scan_item.id only; any other query parameter is ignored and
// the whole organization is returned, which is how Snyk behaves.
func fakeSnyk(t *testing.T) *httptest.Server {
	t.Helper()

	issuesByProject := map[string][]string{
		"proj-a": {"iss-a1", "iss-a2"},
		"proj-b": {"iss-b1", "iss-b2"},
	}

	return httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		q := req.URL.Query()
		rw.Header().Set("Content-Type", "application/vnd.api+json")

		switch {
		case strings.HasSuffix(req.URL.Path, "/orgs"):
			//nolint:errcheck
			rw.Write([]byte(`{"data":[{"id":"org-1","attributes":{"name":"acme"}}],"links":{}}`))

		case strings.HasSuffix(req.URL.Path, "/projects"):
			//nolint:errcheck
			rw.Write([]byte(`{"data":[
				{"id":"proj-a","attributes":{"name":"a","status":"active"}},
				{"id":"proj-b","attributes":{"name":"b","status":"active"}}
			],"links":{}}`))

		case strings.HasSuffix(req.URL.Path, "/issues"):
			var ids []string
			if q.Get("scan_item.type") == "project" && q.Get("scan_item.id") != "" {
				ids = issuesByProject[q.Get("scan_item.id")]
			} else {
				ids = append(ids, issuesByProject["proj-a"]...)
				ids = append(ids, issuesByProject["proj-b"]...)
			}
			//nolint:errcheck
			json.NewEncoder(rw).Encode(map[string]any{
				"data":  issueItems(ids),
				"links": map[string]any{},
			})

		default:
			t.Errorf("unexpected request path %s", req.URL.Path)
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
}

func issueItems(ids []string) []map[string]any {
	var items []map[string]any
	for _, id := range ids {
		items = append(items, map[string]any{
			"id": id,
			"attributes": map[string]any{
				"title":                    "CVE",
				"type":                     "package_vulnerability",
				"effective_severity_level": "high",
				"ignored":                  false,
				"coordinates":              []any{},
			},
		})
	}
	return items
}

// TestIssuesAreScopedToProject guards against the issue counts scaling with the
// number of projects in an organization. Issues must be requested per project
// with scan_item.id; without that filter every project reports the whole
// organization and the totals inflate on every project scraped.
func TestIssuesAreScopedToProject(t *testing.T) {
	server := fakeSnyk(t)
	defer server.Close()

	c := &client{httpClient: server.Client(), token: "token", baseURL: server.URL}

	orgs, err := getOrganizations(c, nil)
	if err != nil {
		t.Fatalf("get organizations: %v", err)
	}

	results, err := collect(context.Background(), c, orgs[0], nil)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	total := 0
	for _, r := range results {
		for _, ar := range r.results {
			total += ar.count
		}
	}

	const want = 4 // 2 projects x 2 issues each
	if total != want {
		t.Errorf("issue count inflated: got %d, want %d", total, want)
	}
}

// TestPaginationLoopGuard ensures a self-referential next link terminates
// instead of accumulating the same page forever.
func TestPaginationLoopGuard(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		requests++
		if requests > 10 {
			t.Fatal("pagination did not terminate")
		}
		//nolint:errcheck
		json.NewEncoder(rw).Encode(map[string]any{
			"data":  issueItems([]string{"iss-1"}),
			"links": map[string]any{"next": "/orgs/org-1/issues?version=" + apiVersion + "&same=1"},
		})
	}))
	defer server.Close()

	c := &client{httpClient: server.Client(), token: "token", baseURL: server.URL}
	issues, err := c.getIssues("org-1", "proj-a")
	if err != nil {
		t.Fatalf("get issues: %v", err)
	}
	// first page + one follow of the next link, then the loop is detected
	if len(issues.Issues) > 2 {
		t.Errorf("pagination loop accumulated %d issues", len(issues.Issues))
	}
}

func TestResolveNext(t *testing.T) {
	tt := []struct {
		name string
		base string
		next string
		want string
	}{
		{
			name: "empty next",
			base: "https://api.snyk.io/rest",
			next: "",
			want: "",
		},
		{
			name: "absolute next used as-is",
			base: "https://api.snyk.io/rest",
			next: "https://api.snyk.io/rest/orgs?starting_after=x",
			want: "https://api.snyk.io/rest/orgs?starting_after=x",
		},
		{
			name: "relative next keeps the base path prefix",
			base: "https://api.snyk.io/rest",
			next: "/orgs/org-1/issues?version=2024-10-15&starting_after=x",
			want: "https://api.snyk.io/rest/orgs/org-1/issues?version=2024-10-15&starting_after=x",
		},
		{
			name: "relative next already carrying the base path is not doubled",
			base: "https://api.snyk.io/rest",
			next: "/rest/orgs/org-1/issues?starting_after=x",
			want: "https://api.snyk.io/rest/orgs/org-1/issues?starting_after=x",
		},
		{
			name: "base without a path",
			base: "https://api.snyk.io",
			next: "/orgs?starting_after=x",
			want: "https://api.snyk.io/orgs?starting_after=x",
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveNext(tc.base, tc.next); got != tc.want {
				t.Errorf("resolveNext(%q, %q) = %q, want %q", tc.base, tc.next, got, tc.want)
			}
		})
	}
}
