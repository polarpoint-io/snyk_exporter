package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

const (
	projectLabel      = "project"
	issueTypeLabel    = "issue_type"
	severityLabel     = "severity"
	organizationLabel = "organization"
	ignoredLabel      = "ignored"
	upgradeableLabel  = "upgradeable"
	patchableLabel    = "patchable"
	monitoredLabel    = "monitored"
)

var (
	vulnerabilityGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "snyk_vulnerabilities_total",
			Help: "Gauge of Snyk vulnerabilities",
		},
		[]string{organizationLabel, projectLabel, issueTypeLabel, severityLabel, ignoredLabel, upgradeableLabel, patchableLabel, monitoredLabel},
	)

	// The metrics below describe the scrape itself. They exist so a failure
	// against the Snyk API is visible in Prometheus rather than only in
	// container logs, which are not always available to whoever is debugging.
	scrapeSuccessGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "snyk_scrape_success",
			Help: "1 if the last scrape of this organization succeeded, 0 if it failed",
		},
		[]string{organizationLabel},
	)

	scrapeErrorsCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "snyk_scrape_errors_total",
			Help: "Count of failed Snyk API calls by organization and stage",
		},
		[]string{organizationLabel, "stage"},
	)

	lastScrapeTimestampGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "snyk_last_scrape_timestamp_seconds",
			Help: "Unix timestamp of the last completed scrape cycle",
		},
	)

	scrapeDurationGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "snyk_scrape_duration_seconds",
			Help: "Duration of the last completed scrape cycle in seconds",
		},
	)

	// Issues Snyk returned without a resolvable project reference. A non-zero
	// value means grouping fell back to the "unknown" project label and the
	// per-project breakdown is incomplete.
	unattributedIssuesGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "snyk_unattributed_issues",
			Help: "Issues that could not be attributed to a project in the last scrape",
		},
		[]string{organizationLabel},
	)
)

// unknownProject labels issues Snyk returned without a usable scan_item
// reference. They are still counted, so totals stay correct even when the
// per-project split cannot be reconstructed.
const unknownProject = "unknown"

var (
	ready       = false
	readyMutex  = &sync.RWMutex{}
	scrapeMutex = &sync.RWMutex{}
)

var (
	version = ""
)

func main() {
	flags := kingpin.New("snyk_exporter", "Snyk exporter for Prometheus. Provide your Snyk API token and the organization(s) to scrape to expose Prometheus metrics.")
	snykAPIURL := flags.Flag("snyk.api-url", "Snyk REST API base URL").Default("https://api.snyk.io/rest").String()
	snykAPIToken := flags.Flag("snyk.api-token", "Snyk API token").Required().String()
	snykInterval := flags.Flag("snyk.interval", "Polling interval for requesting data from Snyk API in seconds").Short('i').Default("600").Int()
	snykOrganizations := flags.Flag("snyk.organization", "Snyk organization ID to scrape projects from (can be repeated for multiple organizations)").Strings()
	requestTimeout := flags.Flag("snyk.timeout", "Timeout for requests against Snyk API").Default("10").Int()
	listenAddress := flags.Flag("web.listen-address", "Address on which to expose metrics.").Default(":9532").String()
	flags.HelpFlag.Short('h')
	flags.Version(version)
	kingpin.MustParse(flags.Parse(os.Args[1:]))

	if len(*snykOrganizations) != 0 {
		slog.Info("Starting Snyk exporter for organization", "organizations", strings.Join(*snykOrganizations, ","))
	} else {
		slog.Info("Starting Snyk exporter for all organization for token")
	}

	prometheus.MustRegister(
		vulnerabilityGauge,
		scrapeSuccessGauge,
		scrapeErrorsCounter,
		lastScrapeTimestampGauge,
		scrapeDurationGauge,
		unattributedIssuesGauge,
	)
	http.Handle("/metrics", promhttp.InstrumentMetricHandler(
		prometheus.DefaultRegisterer, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			scrapeMutex.RLock()
			defer scrapeMutex.RUnlock()
			promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{}).ServeHTTP(rw, r)
		}),
	))

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "healthy")
	})

	http.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		readyMutex.RLock()
		defer readyMutex.RUnlock()

		if ready {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		_, err := w.Write([]byte(strconv.FormatBool(ready)))
		if err != nil {
			slog.Error("Failed to write ready response", "error", err)
		}
	})

	// context used to stop worker components from signal or component failures
	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	// used to report errors from components
	var exitCode int
	componentFailed := make(chan error, 1)
	var wg sync.WaitGroup

	go func() {
		slog.Info("Listening", "address", *listenAddress)
		err := http.ListenAndServe(*listenAddress, nil)
		if err != nil {
			componentFailed <- fmt.Errorf("http listener stopped: %v", err)
		}
	}()

	// Go routine responsible for starting shutdown sequence based of signals or
	// component failures
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case sig := <-sigs:
			slog.Info("Received os signal, terminating", "signal", sig)
		case err := <-componentFailed:
			if err != nil {
				slog.Error("Component failed", "error", err)
				exitCode = 1
			}
		}
		stop()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		slog.Info("Snyk API scraper starting")
		defer slog.Info("Snyk API scraper stopped")
		err := runAPIPolling(ctx, *snykAPIURL, *snykAPIToken, *snykOrganizations, secondDuration(*snykInterval), secondDuration(*requestTimeout))
		if err != nil {
			componentFailed <- fmt.Errorf("snyk api scraper: %w", err)
		}
	}()

	// wait for all components to stop
	wg.Wait()
	if exitCode != 0 {
		slog.Error("Snyk exporter exiting", "exitCode", exitCode)
		os.Exit(exitCode)
	} else {
		slog.Info("Snyk exporter exited with exit 0")
	}
}

func secondDuration(seconds int) time.Duration {
	return time.Duration(seconds) * time.Second
}

func runAPIPolling(ctx context.Context, url, token string, organizationIDs []string, requestInterval, requestTimeout time.Duration) error {
	client := client{
		httpClient: &http.Client{
			Timeout: requestTimeout,
		},
		token:   token,
		baseURL: url,
	}
	organizations, err := getOrganizations(&client, organizationIDs)
	if err != nil {
		return err
	}
	slog.Info("Running Snyk API scraper for organizations", "organizations", strings.Join(organizationNames(organizations), ", "))

	// kick off a poll right away to get metrics available right after startup
	pollAPI(ctx, &client, organizations)

	ticker := time.NewTicker(requestInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			pollAPI(ctx, &client, organizations)
		}
	}
}

// pollAPI collects data from provided organizations and registers them in the
// prometheus registry.
func pollAPI(ctx context.Context, client *client, organizations []org) {
	scrapeStart := time.Now()
	total := len(organizations)
	slog.Info("Scrape cycle started", "organizations", total)

	var gaugeResults []gaugeResult
	for i, organization := range organizations {
		slog.Info("Collecting organization",
			"progress", fmt.Sprintf("%d/%d", i+1, total),
			"organization", organization.Name,
			"organizationId", organization.ID)
		orgStart := time.Now()
		results, err := collect(ctx, client, organization)
		orgDuration := time.Since(orgStart)
		if err != nil {
			scrapeSuccessGauge.WithLabelValues(organization.Name).Set(0)
			scrapeErrorsCounter.WithLabelValues(organization.Name, stageOf(err)).Inc()
			slog.Error("Collection failed for organization",
				"error", err,
				"organization", organization.Name,
				"organizationId", organization.ID,
				"duration", orgDuration)
			continue
		}
		scrapeSuccessGauge.WithLabelValues(organization.Name).Set(1)
		gaugeResults = append(gaugeResults, results...)
		// count total issues across all projects for this org
		issueCount := 0
		for _, r := range results {
			for _, ar := range r.results {
				issueCount += ar.count
			}
		}
		slog.Info("Collected organization",
			"progress", fmt.Sprintf("%d/%d", i+1, total),
			"organization", organization.Name,
			"projects", len(results),
			"issues", issueCount,
			"duration", orgDuration.Round(time.Millisecond))
		// stop right away in case of the context being cancelled.
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
	scrapeDuration := time.Since(scrapeStart)
	slog.Info("Scrape cycle complete",
		"organizations", total,
		"totalGaugeResults", len(gaugeResults),
		"duration", scrapeDuration.Round(time.Millisecond))
	scrapeMutex.Lock()
	register(gaugeResults)
	scrapeMutex.Unlock()

	lastScrapeTimestampGauge.Set(float64(time.Now().Unix()))
	scrapeDurationGauge.Set(scrapeDuration.Seconds())

	// Readiness marks "this process completed a scrape cycle", not "the scrape
	// found data". Gating on results meant any Snyk-side failure took the pod
	// out of the Service, which removed the Prometheus target altogether and
	// hid the very metrics that explain the failure.
	readyMutex.Lock()
	ready = true
	readyMutex.Unlock()

	slog.Info("Published metrics snapshot", "gaugeResults", len(gaugeResults))
}

func organizationNames(orgs []org) []string {
	var names []string
	for _, org := range orgs {
		names = append(names, org.Name)
	}
	return names
}

func getOrganizations(client *client, organizationIDs []string) ([]org, error) {
	orgsResponse, err := client.getOrganizations()
	if err != nil {
		return nil, err
	}
	organizations := orgsResponse.Orgs
	if len(organizationIDs) != 0 {
		organizations = filterByIDs(orgsResponse.Orgs, organizationIDs)
		if len(organizations) == 0 {
			return nil, fmt.Errorf("no organizations match the filter: '%v'", strings.Join(organizationIDs, ","))
		}
	}
	return organizations, nil
}

func filterByIDs(organizations []org, ids []string) []org {
	var filtered []org
	for i := range organizations {
		for _, id := range ids {
			if organizations[i].ID == id {
				filtered = append(filtered, organizations[i])
			}
		}
	}
	return filtered
}

// register replaces the vulnerability gauge with a complete scrape snapshot.
// Reset is only called once the full cycle is collected so Prometheus scrapes
// see stable values between cycles instead of partial ramp-up data.
// See https://github.com/lunarway/snyk_exporter/issues/21 for details.
func register(results []gaugeResult) {
	vulnerabilityGauge.Reset()
	for _, r := range results {
		for _, result := range r.results {
			vulnerabilityGauge.WithLabelValues(r.organization, r.project, result.issueType, result.severity, strconv.FormatBool(result.ignored), strconv.FormatBool(result.upgradeable), strconv.FormatBool(result.patchable), strconv.FormatBool(r.isMonitored)).Set(float64(result.count))
		}
	}
}

type gaugeResult struct {
	organization string
	project      string
	isMonitored  bool
	results      []aggregateResult
}

// collect gathers one organization's issues and groups them by project.
//
// Both API calls are organization-scoped, so the request count no longer grows
// with the number of projects.
func collect(ctx context.Context, client *client, organization org) ([]gaugeResult, error) {
	projects, err := client.getProjects(organization.ID)
	if err != nil {
		return nil, fmt.Errorf("get projects for organization: %w", err)
	}
	slog.Info("Fetched projects for organization",
		"organization", organization.Name,
		"projects", len(projects.Projects))

	select {
	case <-ctx.Done():
		return nil, nil
	default:
	}

	start := time.Now()
	issues, err := client.getOrgIssues(organization.ID)
	if err != nil {
		return nil, fmt.Errorf("get issues for organization: %w", err)
	}
	slog.Info("Fetched issues for organization",
		"organization", organization.Name,
		"issues", len(issues.Issues),
		"duration", time.Since(start).Round(time.Millisecond))

	byProject := make(map[string][]issue, len(projects.Projects))
	var unattributed []issue
	for _, i := range issues.Issues {
		if i.ProjectID == "" {
			unattributed = append(unattributed, i)
			continue
		}
		byProject[i.ProjectID] = append(byProject[i.ProjectID], i)
	}

	unattributedIssuesGauge.WithLabelValues(organization.Name).Set(float64(len(unattributed)))
	if len(unattributed) > 0 {
		slog.Warn("Issues had no resolvable project reference, counting them under the unknown project",
			"organization", organization.Name,
			"issues", len(unattributed))
	}

	var gaugeResults []gaugeResult
	seen := make(map[string]struct{}, len(projects.Projects))
	for _, project := range projects.Projects {
		seen[project.ID] = struct{}{}
		projectIssues := byProject[project.ID]
		if len(projectIssues) == 0 {
			// Nothing to report for a clean project, and emitting an empty
			// result would only add a series with no samples.
			continue
		}
		gaugeResults = append(gaugeResults, gaugeResult{
			organization: organization.Name,
			project:      project.Name,
			results:      aggregateIssues(projectIssues),
			isMonitored:  project.IsMonitored,
		})
	}

	// Issues pointing at a scan item that is not in the project list, plus any
	// that carried no reference at all. Reported so totals stay complete.
	orphaned := unattributed
	for id, group := range byProject {
		if _, ok := seen[id]; !ok {
			orphaned = append(orphaned, group...)
		}
	}
	if len(orphaned) > 0 {
		slog.Warn("Issues did not match any known project",
			"organization", organization.Name,
			"issues", len(orphaned))
		gaugeResults = append(gaugeResults, gaugeResult{
			organization: organization.Name,
			project:      unknownProject,
			results:      aggregateIssues(orphaned),
			isMonitored:  false,
		})
	}

	return gaugeResults, nil
}

// stageOf labels a collection failure so snyk_scrape_errors_total shows which
// API call is failing without needing the log line.
func stageOf(err error) string {
	switch {
	case strings.Contains(err.Error(), "get projects"):
		return "projects"
	case strings.Contains(err.Error(), "get issues"):
		return "issues"
	default:
		return "other"
	}
}

type aggregateResult struct {
	issueType   string
	severity    string
	ignored     bool
	upgradeable bool
	patchable   bool
	count       int
}

func aggregationKey(i issue) string {
	return fmt.Sprintf("%s_%s_%t_%t_%t", i.IssueData.Severity, i.IssueType, i.Ignored, i.FixInfo.Upgradeable, i.FixInfo.Patchable)
}

func aggregateIssues(issues []issue) []aggregateResult {
	aggregateResults := make(map[string]aggregateResult)

	for _, issue := range issues {
		aggregate, ok := aggregateResults[aggregationKey(issue)]
		if !ok {
			aggregate = aggregateResult{
				issueType:   issue.IssueType,
				severity:    issue.IssueData.Severity,
				count:       0,
				ignored:     issue.Ignored,
				upgradeable: issue.FixInfo.Upgradeable,
				patchable:   issue.FixInfo.Patchable,
			}
		}
		aggregate.count++
		aggregateResults[aggregationKey(issue)] = aggregate
	}
	var output []aggregateResult
	for i := range aggregateResults {
		output = append(output, aggregateResults[i])
	}
	return output
}
