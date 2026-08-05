package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// apiVersion is the Snyk REST API version used for all requests.
const apiVersion = "2024-10-15"

type client struct {
	httpClient *http.Client
	token      string
	baseURL    string
}

// fetchPages walks a paginated REST collection from startURL, calling decode
// for each page body. decode returns the raw "next" link from that page.
//
// A page URL is never requested twice. Without that guard a self-referential
// next link would loop forever, appending the same records on every pass.
func (c *client) fetchPages(startURL string, decode func(body io.Reader) (string, error)) error {
	seen := make(map[string]struct{})
	next := startURL
	for next != "" {
		if _, visited := seen[next]; visited {
			slog.Warn("Pagination loop detected, stopping early", "url", next)
			return nil
		}
		seen[next] = struct{}{}

		req, err := http.NewRequest(http.MethodGet, next, nil)
		if err != nil {
			return err
		}
		response, err := c.do(req)
		if err != nil {
			return err
		}
		link, err := decode(response.Body)
		response.Body.Close()
		if err != nil {
			return err
		}
		next = resolveNext(c.baseURL, link)
	}
	return nil
}

// getOrganizations fetches all orgs the token has access to, following pagination.
func (c *client) getOrganizations() (orgsResponse, error) {
	var all []org
	start := fmt.Sprintf("%s/orgs?version=%s&limit=100", c.baseURL, apiVersion)
	err := c.fetchPages(start, func(body io.Reader) (string, error) {
		var page restOrgsPage
		if err := json.NewDecoder(body).Decode(&page); err != nil {
			return "", err
		}
		for _, item := range page.Data {
			all = append(all, org{
				ID:   item.ID,
				Name: item.Attributes.Name,
			})
		}
		return page.Links.Next, nil
	})
	if err != nil {
		return orgsResponse{}, err
	}
	return orgsResponse{Orgs: all}, nil
}

// getProjects fetches all projects for an org, following pagination.
func (c *client) getProjects(organizationID string) (projectsResponse, error) {
	var all []project
	start := fmt.Sprintf("%s/orgs/%s/projects?version=%s&limit=100", c.baseURL, url.PathEscape(organizationID), apiVersion)
	err := c.fetchPages(start, func(body io.Reader) (string, error) {
		var page restProjectsPage
		if err := json.NewDecoder(body).Decode(&page); err != nil {
			return "", err
		}
		for _, item := range page.Data {
			all = append(all, project{
				ID:          item.ID,
				Name:        item.Attributes.Name,
				IsMonitored: item.Attributes.Status == "active",
			})
		}
		return page.Links.Next, nil
	})
	if err != nil {
		return projectsResponse{}, err
	}
	return projectsResponse{Projects: all}, nil
}

// getIssues fetches all issues for an org+project, following pagination.
//
// The org-level issues endpoint is scoped to a single project with the
// scan_item.type/scan_item.id pair. Snyk silently ignores unrecognised query
// parameters, so getting this wrong returns every issue in the organization
// for every project, inflating the totals by a factor of the project count.
func (c *client) getIssues(organizationID, projectID string) (issuesResponse, error) {
	var all []issue
	query := url.Values{
		"version":        {apiVersion},
		"limit":          {"100"},
		"scan_item.type": {"project"},
		"scan_item.id":   {projectID},
	}
	start := fmt.Sprintf("%s/orgs/%s/issues?%s", c.baseURL, url.PathEscape(organizationID), query.Encode())
	err := c.fetchPages(start, func(body io.Reader) (string, error) {
		var page restIssuesPage
		if err := json.NewDecoder(body).Decode(&page); err != nil {
			return "", err
		}
		for _, item := range page.Data {
			all = append(all, issue{
				ID:        item.ID,
				IssueType: item.Attributes.IssueType,
				IssueData: issueData{
					Title:    item.Attributes.Title,
					Severity: item.Attributes.EffectiveSeverityLevel,
				},
				Ignored: item.Attributes.Ignored,
				FixInfo: fixInfo{
					Upgradeable: item.Attributes.Coordinates.IsUpgradeable(),
					Patchable:   item.Attributes.Coordinates.IsPatchable(),
				},
			})
		}
		return page.Links.Next, nil
	})
	if err != nil {
		return issuesResponse{}, err
	}
	return issuesResponse{Issues: all}, nil
}

// resolveNext converts a relative or absolute "next" link into a full URL.
// Returns "" when there is no next page.
//
// Snyk returns next links rooted at the API version prefix (for example
// "/orgs/{id}/issues?...") while baseURL carries that prefix ("…/rest").
// A plain ResolveReference would drop it, so the base path is reapplied when
// the link does not already carry it.
func resolveNext(base, next string) string {
	if next == "" {
		return ""
	}
	// If already absolute, use as-is.
	if u, err := url.Parse(next); err == nil && u.IsAbs() {
		return next
	}
	b, err := url.Parse(base)
	if err != nil {
		return ""
	}
	rel, err := url.Parse(next)
	if err != nil {
		return ""
	}
	basePath := strings.TrimSuffix(b.Path, "/")
	if basePath != "" && strings.HasPrefix(rel.Path, "/") && !strings.HasPrefix(rel.Path, basePath+"/") {
		rel.Path = basePath + rel.Path
	}
	return b.ResolveReference(rel).String()
}

func (c *client) do(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", fmt.Sprintf("token %s", c.token))
	req.Header.Set("Content-Type", "application/vnd.api+json")
	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		body, err := io.ReadAll(response.Body)
		if err != nil {
			slog.Error("read body failed", "error", err)
			body = []byte("failed to read body")
		}
		response.Body.Close()
		requestDump, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			slog.Debug("Failed to dump request for logging")
		} else {
			slog.Debug("Failed request dump", "dump", string(requestDump))
		}
		return nil, fmt.Errorf("request not OK: %s: body: %s", response.Status, body)
	}
	return response, nil
}

// ── REST API v2 response shapes ──────────────────────────────────────────────

type restLinks struct {
	Next string `json:"next"`
}

// orgs

type restOrgsPage struct {
	Data  []restOrgItem `json:"data"`
	Links restLinks     `json:"links"`
}

type restOrgItem struct {
	ID         string       `json:"id"`
	Attributes restOrgAttrs `json:"attributes"`
}

type restOrgAttrs struct {
	Name string `json:"name"`
}

// projects

type restProjectsPage struct {
	Data  []restProjectItem `json:"data"`
	Links restLinks         `json:"links"`
}

type restProjectItem struct {
	ID         string           `json:"id"`
	Attributes restProjectAttrs `json:"attributes"`
}

type restProjectAttrs struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "active" | "inactive"
}

// issues

type restIssuesPage struct {
	Data  []restIssueItem `json:"data"`
	Links restLinks       `json:"links"`
}

type restIssueItem struct {
	ID         string         `json:"id"`
	Attributes restIssueAttrs `json:"attributes"`
}

type restIssueAttrs struct {
	Title                  string          `json:"title"`
	IssueType              string          `json:"type"`
	EffectiveSeverityLevel string          `json:"effective_severity_level"`
	Ignored                bool            `json:"ignored"`
	Coordinates            restCoordinates `json:"coordinates"`
}

// restCoordinates is a named slice so we can attach helper methods.
type restCoordinates []restCoordinate

type restCoordinate struct {
	Remedies []restRemedy `json:"remedies"`
}

// IsUpgradeable returns true if any coordinate has an upgrade remedy.
func (coords restCoordinates) IsUpgradeable() bool {
	for _, c := range coords {
		for _, r := range c.Remedies {
			if r.Type == "indirectUpgrade" || r.Type == "directUpgrade" {
				return true
			}
		}
	}
	return false
}

// IsPatchable returns true if any coordinate has a patch remedy.
func (coords restCoordinates) IsPatchable() bool {
	for _, c := range coords {
		for _, r := range c.Remedies {
			if r.Type == "patch" {
				return true
			}
		}
	}
	return false
}

type restRemedy struct {
	Type string `json:"type"`
}

// ── Domain types (used by main.go / tests) ───────────────────────────────────

type orgsResponse struct {
	Orgs []org
}

type org struct {
	ID   string
	Name string
}

type projectsResponse struct {
	Projects []project
}

type project struct {
	Name        string
	ID          string
	IsMonitored bool
}

type issuesResponse struct {
	Issues []issue
}

type issue struct {
	ID        string
	IssueType string
	IssueData issueData
	Ignored   bool
	FixInfo   fixInfo
}

type issueData struct {
	Title    string
	Severity string
}

type fixInfo struct {
	Upgradeable bool
	Patchable   bool
}
