package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"
)

func TestAggregateIssues(t *testing.T) {
	issues := func(issues ...issue) []issue {
		return issues
	}
	ignoredIssue := func(id, severity, title string) issue {
		return issue{
			ID: id,
			IssueData: issueData{
				Severity: severity,
				Title:    title,
			},
			Ignored: true,
		}
	}
	iss := func(id, severity, title string) issue {
		return issue{
			ID: id,
			IssueData: issueData{
				Severity: severity,
				Title:    title,
			},
		}
	}
	aggregateResults := func(aggregateResults ...aggregateResult) []aggregateResult {
		return aggregateResults
	}
	result := func(severity string, count int, ignored bool) aggregateResult {
		return aggregateResult{
			severity: severity,
			count:    count,
			ignored:  ignored,
		}
	}
	tt := []struct {
		name       string
		issues     []issue
		aggregates []aggregateResult
	}{
		{
			name:       "nil issues",
			issues:     nil,
			aggregates: nil,
		},
		{
			name:       "single issue",
			issues:     issues(iss("iss-1", "high", "DDoS")),
			aggregates: aggregateResults(result("high", 1, false)),
		},
		{
			name: "multiple of different severity and same title",
			issues: issues(
				iss("iss-1", "high", "DDoS"),
				iss("iss-2", "low", "DDoS"),
			),
			aggregates: aggregateResults(
				result("high", 1, false),
				result("low", 1, false),
			),
		},
		{
			name: "multiple of same severity and title",
			issues: issues(
				iss("iss-1", "high", "DDoS"),
				iss("iss-2", "high", "DDoS"),
			),
			aggregates: aggregateResults(
				result("high", 2, false),
			),
		},
		{
			name: "multiple of same severity and title but some ignored",
			issues: issues(
				iss("iss-1", "high", "DDoS"),
				ignoredIssue("iss-2", "high", "DDoS"),
			),
			aggregates: aggregateResults(
				result("high", 1, false),
				result("high", 1, true),
			),
		},
		{
			name: "multiple of same severity different title",
			issues: issues(
				iss("iss-1", "high", "DDoS"),
				iss("iss-2", "high", "ReDoS"),
			),
			aggregates: aggregateResults(
				result("high", 2, false),
			),
		},
		{
			name: "multiple of same severity different title some ignored",
			issues: issues(
				iss("iss-1", "high", "DDoS"),
				ignoredIssue("iss-2", "high", "ReDoS"),
			),
			aggregates: aggregateResults(
				result("high", 1, false),
				result("high", 1, true),
			),
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			output := aggregateIssues(tc.issues)
			if len(output) != len(tc.aggregates) {
				t.Logf("output: %v\n", output)
				t.Errorf("Length of aggregate results not as expected: expected %d got %d", len(tc.aggregates), len(output))
				return
			}
			// sort as aggregateIssues does not provide a stable ordered slice
			sort.Slice(output, func(i, j int) bool {
				return aggregationKey(issue{
					IssueData: issueData{
						Severity: output[i].severity,
					},
					Ignored: output[i].ignored,
				}) < aggregationKey(issue{
					IssueData: issueData{
						Severity: output[j].severity,
					},
					Ignored: output[j].ignored,
				})
			})
			if !reflect.DeepEqual(output, tc.aggregates) {
				t.Errorf("Aggregates are not matching expectations: expected %v got %v", tc.aggregates, output)
			}
		})
	}
}

// TestRunAPIPolling_notReadyBeforeFirstCycle checks that readiness is withheld
// until a scrape cycle finishes.
//
// Readiness deliberately reports "this process completed a cycle", not "the
// cycle found data". Tying it to results meant a Snyk-side failure pulled the
// pod from its Service, which removed the Prometheus target and hid the
// scrape-failure metrics that explain the outage.
func TestRunAPIPolling_notReadyBeforeFirstCycle(t *testing.T) {
	readyMutex.Lock()
	ready = false
	readyMutex.Unlock()

	release := make(chan struct{})
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		calls++
		// allow organizations call to succeed
		if calls == 1 {
			//nolint:errcheck
			rw.Write([]byte(`{
				"data": [{
					"id": "id",
					"attributes": {"name": "name"}
				}],
				"links": {}
			}`))
			return
		}
		// block the first collection until the test releases it
		<-release
		rw.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := runAPIPolling(ctx, server.URL, "token", nil, 20*time.Millisecond, 5*time.Second)
		if err != nil {
			t.Errorf("unexpected error result: %v", err)
		}
	}()

	<-time.After(100 * time.Millisecond)

	readyMutex.RLock()
	readyMidCycle := ready
	readyMutex.RUnlock()
	if readyMidCycle {
		t.Error("ready should not be set before the first cycle completes")
	}

	close(release)
	cancel()
	wg.Wait()
}
