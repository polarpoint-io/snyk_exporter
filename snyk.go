package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// apiVersion is the Snyk REST API version used for all requests.
const apiVersion = "2024-10-15"

type client struct {
	httpClient *http.Client
	token      string
	baseURL    string
}

// getOrganizations fetches all orgs the token has access to, following pagination.
func (c *client) getOrganizations() (orgsResponse, error) {
	var all []org
	next := fmt.Sprintf("%s/orgs?version=%s&limit=100", c.baseURL, apiVersion)
	for next != "" {
		req, err := http.NewRequest(http.MethodGet, next, nil)
		if err != nil {
			return orgsResponse{}, err
		}
		response, err := c.do(req)
		if err != nil {
			return orgsResponse{}, err
		}
		var page restOrgsPage
		if err = json.NewDecoder(response.Body).Decode(&page); err != nil {
			return orgsResponse{}, err
		}
		response.Body.Close()
		for _, item := range page.Data {
			all = append(all, org{
				ID:   item.ID,
				Name: item.Attributes.Name,
			})
		}
		next = resolveNext(c.baseURL, page.Links.Next)
	}
	return orgsResponse{Orgs: all}, nil
}

// getProjects fetches all projects for an org, following pagination.
func (c *client) getProjects(organizationID string) (projectsResponse, error) {
	var all []project
	next := fmt.Sprintf("%s/orgs/%s/projects?version=%s&limit=100", c.baseURL, organizationID, apiVersion)
	for next != "" {
		req, err := http.NewRequest(http.MethodGet, next, nil)
		if err != nil {
			return projectsResponse{}, err
		}
		response, err := c.do(req)
		if err != nil {
			return projectsResponse{}, err
		}
		var page restProjectsPage
		if err = json.NewDecoder(response.Body).Decode(&page); err != nil {
			return projectsResponse{}, err
		}
		response.Body.Close()
		for _, item := range page.Data {
			all = append(all, project{
				ID:          item.ID,
				Name:        item.Attributes.Name,
				IsMonitored: item.Attributes.Status == "active",
			})
		}
		next = resolveNext(c.baseURL, page.Links.Next)
	}
	return projectsResponse{Projects: all}, nil
}

// getIssues fetches all issues for an org+project, following pagination.
func (c *client) getIssues(organizationID, projectID string) (issuesResponse, error) {
	var all []issue
	next := fmt.Sprintf("%s/orgs/%s/issues?version=%s&limit=100&project_id=%s", c.baseURL, organizationID, apiVersion, projectID)
	for next != "" {
		req, err := http.NewRequest(http.MethodGet, next, nil)
		if err != nil {
			return issuesResponse{}, err
		}
		response, err := c.do(req)
		if err != nil {
			return issuesResponse{}, err
		}
		var page restIssuesPage
		if err = json.NewDecoder(response.Body).Decode(&page); err != nil {
			return issuesResponse{}, err
		}
		response.Body.Close()
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
		next = resolveNext(c.baseURL, page.Links.Next)
	}
	return issuesResponse{Issues: all}, nil
}

// resolveNext converts a relative or absolute "next" link into a full URL.
// Returns "" when there is no next page.
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
	ID         string          `json:"id"`
	Attributes restOrgAttrs    `json:"attributes"`
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
	ID         string             `json:"id"`
	Attributes restProjectAttrs   `json:"attributes"`
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
	ID         string          `json:"id"`
	Attributes restIssueAttrs  `json:"attributes"`
}

type restIssueAttrs struct {
	Title                  string           `json:"title"`
	IssueType              string           `json:"type"`
	EffectiveSeverityLevel string           `json:"effective_severity_level"`
	Ignored                bool             `json:"ignored"`
	Coordinates            restCoordinates  `json:"coordinates"`
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
	ID    string
	Name  string
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
