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
	issueTitleLabel   = "issue_title"
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
		[]string{organizationLabel, projectLabel, issueTypeLabel, issueTitleLabel, severityLabel, ignoredLabel, upgradeableLabel, patchableLabel, monitoredLabel},
	)
)

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

	prometheus.MustRegister(vulnerabilityGauge)
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
			slog.Error("Collection failed for organization",
				"error", err,
				"organization", organization.Name,
				"organizationId", organization.ID,
				"duration", orgDuration)
			continue
		}
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
		gaugeResults = append(gaugeResults, results...)
		// stop right away in case of the context being cancelled. This ensures that
		// we don't wait for a complete collect run for all organizations before
		// stopping.
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
	readyMutex.Lock()
	ready = true
	readyMutex.Unlock()
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

// register registers results in the vulnerability gauge. To handle changing
// flags, e.g. ignored, upgradeable the metric is cleared before setting new
// values.
// See https://github.com/lunarway/snyk_exporter/issues/21 for details.
func register(results []gaugeResult) {
	vulnerabilityGauge.Reset()
	for _, r := range results {
		for _, result := range r.results {
			vulnerabilityGauge.WithLabelValues(r.organization, r.project, result.issueType, result.title, result.severity, strconv.FormatBool(result.ignored), strconv.FormatBool(result.upgradeable), strconv.FormatBool(result.patchable), strconv.FormatBool(r.isMonitored)).Set(float64(result.count))
		}
	}
}

type gaugeResult struct {
	organization string
	project      string
	isMonitored  bool
	results      []aggregateResult
}

func collect(ctx context.Context, client *client, organization org) ([]gaugeResult, error) {
	projects, err := client.getProjects(organization.ID)
	if err != nil {
		return nil, fmt.Errorf("get projects for organization: %w", err)
	}

	total := len(projects.Projects)
	slog.Info("Fetched projects for organization",
		"organization", organization.Name,
		"projects", total)

	var gaugeResults []gaugeResult
	for i, project := range projects.Projects {
		start := time.Now()
		issues, err := client.getIssues(organization.ID, project.ID)
		duration := time.Since(start)
		if err != nil {
			slog.Error("Failed to get issues for project",
				"organization", organization.Name,
				"project", project.Name,
				"projectId", project.ID,
				"progress", fmt.Sprintf("%d/%d", i+1, total),
				"duration", duration.Round(time.Millisecond),
				"error", err)
			continue
		}
		results := aggregateIssues(issues.Issues)
		issueCount := len(issues.Issues)
		slog.Info("Collected project",
			"organization", organization.Name,
			"project", project.Name,
			"progress", fmt.Sprintf("%d/%d", i+1, total),
			"issues", issueCount,
			"monitored", project.IsMonitored,
			"duration", duration.Round(time.Millisecond))
		gaugeResults = append(gaugeResults, gaugeResult{
			organization: organization.Name,
			project:      project.Name,
			results:      results,
			isMonitored:  project.IsMonitored,
		})
		// stop right away in case of the context being cancelled. This ensures that
		// we don't wait for a complete collect run for all projects before
		// stopping.
		select {
		case <-ctx.Done():
			return nil, nil
		default:
		}
	}
	return gaugeResults, nil
}

type aggregateResult struct {
	issueType   string
	title       string
	severity    string
	ignored     bool
	upgradeable bool
	patchable   bool
	count       int
}

func aggregationKey(i issue) string {
	return fmt.Sprintf("%s_%s_%s_%t_%t_%t", i.IssueData.Severity, i.IssueType, i.IssueData.Title, i.Ignored, i.FixInfo.Upgradeable, i.FixInfo.Patchable)
}

func aggregateIssues(issues []issue) []aggregateResult {
	aggregateResults := make(map[string]aggregateResult)

	for _, issue := range issues {
		aggregate, ok := aggregateResults[aggregationKey(issue)]
		if !ok {
			aggregate = aggregateResult{
				issueType:   issue.IssueType,
				title:       issue.IssueData.Title,
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
