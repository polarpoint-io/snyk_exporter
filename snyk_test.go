package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// snykStub mimics the Snyk REST API closely enough to exercise grouping.
type snykStub struct {
	// issues maps a project ID to the issue IDs found in it. The empty key
	// holds issues returned with no scan_item reference at all.
	issues map[string][]string
	// projects is the set of projects the projects endpoint reports.
	projects []string

	mu           sync.Mutex
	issueQueries int
}

func (s *snykStub) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/vnd.api+json")

		switch {
		case strings.HasSuffix(req.URL.Path, "/orgs"):
			//nolint:errcheck
			rw.Write([]byte(`{"data":[{"id":"org-1","attributes":{"name":"acme"}}],"links":{}}`))

		case strings.HasSuffix(req.URL.Path, "/projects"):
			var items []map[string]any
			for _, p := range s.projects {
				items = append(items, map[string]any{
					"id":         p,
					"attributes": map[string]any{"name": p, "status": "active"},
				})
			}
			//nolint:errcheck
			json.NewEncoder(rw).Encode(map[string]any{"data": items, "links": map[string]any{}})

		case strings.HasSuffix(req.URL.Path, "/issues"):
			s.mu.Lock()
			s.issueQueries++
			s.mu.Unlock()

			var items []map[string]any
			for projectID, ids := range s.issues {
				for _, id := range ids {
					item := map[string]any{
						"id": id,
						"attributes": map[string]any{
							"title":                    "CVE",
							"type":                     "package_vulnerability",
							"effective_severity_level": "high",
							"ignored":                  false,
							"coordinates":              []any{},
						},
					}
					if projectID != "" {
						item["relationships"] = map[string]any{
							"scan_item": map[string]any{
								"data": map[string]any{"id": projectID, "type": "project"},
							},
						}
					}
					items = append(items, item)
				}
			}
			//nolint:errcheck
			json.NewEncoder(rw).Encode(map[string]any{"data": items, "links": map[string]any{}})

		default:
			t.Errorf("unexpected request path %s", req.URL.Path)
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
}

func countByProject(results []gaugeResult) map[string]int {
	counts := make(map[string]int)
	for _, r := range results {
		for _, ar := range r.results {
			counts[r.project] += ar.count
		}
	}
	return counts
}

func collectFrom(t *testing.T, stub *snykStub) []gaugeResult {
	t.Helper()
	server := stub.server(t)
	defer server.Close()

	c := &client{httpClient: server.Client(), token: "token", baseURL: server.URL}
	orgs, err := getOrganizations(c, nil)
	if err != nil {
		t.Fatalf("get organizations: %v", err)
	}
	results, err := collect(context.Background(), c, orgs[0])
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	return results
}

// TestIssuesGroupedByProject guards against the totals scaling with the number
// of projects. Every issue must be counted exactly once, under its own project.
func TestIssuesGroupedByProject(t *testing.T) {
	stub := &snykStub{
		projects: []string{"proj-a", "proj-b"},
		issues: map[string][]string{
			"proj-a": {"iss-a1", "iss-a2"},
			"proj-b": {"iss-b1"},
		},
	}

	counts := countByProject(collectFrom(t, stub))

	if got, want := counts["proj-a"], 2; got != want {
		t.Errorf("proj-a count = %d, want %d", got, want)
	}
	if got, want := counts["proj-b"], 1; got != want {
		t.Errorf("proj-b count = %d, want %d", got, want)
	}

	total := 0
	for _, c := range counts {
		total += c
	}
	if want := 3; total != want {
		t.Errorf("total count = %d, want %d", total, want)
	}
}

// TestIssuesFetchedOncePerOrganization pins the request pattern: one issues
// call per organization, not one per project.
func TestIssuesFetchedOncePerOrganization(t *testing.T) {
	stub := &snykStub{
		projects: []string{"proj-a", "proj-b", "proj-c"},
		issues:   map[string][]string{"proj-a": {"iss-a1"}},
	}

	collectFrom(t, stub)

	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.issueQueries != 1 {
		t.Errorf("issues endpoint called %d times, want 1", stub.issueQueries)
	}
}

// TestUnattributedIssuesAreStillCounted ensures issues Snyk returns without a
// scan_item reference are surfaced rather than silently dropped.
func TestUnattributedIssuesAreStillCounted(t *testing.T) {
	stub := &snykStub{
		projects: []string{"proj-a"},
		issues: map[string][]string{
			"proj-a": {"iss-a1"},
			"":       {"iss-orphan1", "iss-orphan2"},
		},
	}

	counts := countByProject(collectFrom(t, stub))

	if got, want := counts["proj-a"], 1; got != want {
		t.Errorf("proj-a count = %d, want %d", got, want)
	}
	if got, want := counts[unknownProject], 2; got != want {
		t.Errorf("%s count = %d, want %d", unknownProject, got, want)
	}
}

// TestIssuesForUnknownProjectAreCounted covers issues referencing a scan item
// that is missing from the project list.
func TestIssuesForUnknownProjectAreCounted(t *testing.T) {
	stub := &snykStub{
		projects: []string{"proj-a"},
		issues: map[string][]string{
			"proj-a":    {"iss-a1"},
			"proj-gone": {"iss-x1"},
		},
	}

	counts := countByProject(collectFrom(t, stub))

	if got, want := counts["proj-a"], 1; got != want {
		t.Errorf("proj-a count = %d, want %d", got, want)
	}
	if got, want := counts[unknownProject], 1; got != want {
		t.Errorf("%s count = %d, want %d", unknownProject, got, want)
	}
}

// TestPaginationLoopGuard ensures a self-referential next link terminates
// instead of accumulating the same page forever.
func TestPaginationLoopGuard(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		requests++
		if requests > 10 {
			t.Error("pagination did not terminate")
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		//nolint:errcheck
		json.NewEncoder(rw).Encode(map[string]any{
			"data": []map[string]any{{
				"id":         "iss-1",
				"attributes": map[string]any{"effective_severity_level": "high"},
			}},
			"links": map[string]any{"next": "/orgs/org-1/issues?version=" + apiVersion + "&same=1"},
		})
	}))
	defer server.Close()

	c := &client{httpClient: server.Client(), token: "token", baseURL: server.URL}
	issues, err := c.getOrgIssues("org-1")
	if err != nil {
		t.Fatalf("get issues: %v", err)
	}
	// first page plus one follow of the next link, then the loop is detected
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
