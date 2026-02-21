package tools

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

// Common GraphQL endpoint paths to probe.
var graphqlPaths = []string{
	"/graphql",
	"/api/graphql",
	"/v1/graphql",
	"/graphql/v1",
	"/graph",
	"/gql",
	"/query",
	"/api/query",
	"/graphiql",
	"/playground",
	"/graphql/console",
	"/graphql/playground",
	"/api",
	"/graphql/explorer",
}

// introspectionQuery is the standard GraphQL introspection query.
const introspectionQuery = `{"query":"{ __schema { queryType { name } mutationType { name } types { name kind } } }"}`

// fullIntrospectionQuery fetches more schema detail including field names.
const fullIntrospectionQuery = `{"query":"{ __schema { types { name kind fields { name type { name kind ofType { name kind } } } } } }"}`

// ProbeGraphQL checks all live HTTP services for exposed GraphQL endpoints.
// It tests common paths and attempts introspection.
func ProbeGraphQL(httpServices []models.HTTPService, timeoutSecs int) []models.GraphQLResult {
	client := &http.Client{
		Timeout: time.Duration(timeoutSecs) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	sem := make(chan struct{}, 15)
	var mu sync.Mutex
	var results []models.GraphQLResult
	seen := make(map[string]struct{})

	var wg sync.WaitGroup
	for _, svc := range httpServices {
		baseURL := strings.TrimRight(svc.URL, "/")
		for _, path := range graphqlPaths {
			testURL := baseURL + path
			wg.Add(1)
			go func(testURL, host string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				result, ok := probeGraphQLEndpoint(client, testURL, host)
				if !ok {
					return
				}

				mu.Lock()
				if _, dup := seen[testURL]; !dup {
					seen[testURL] = struct{}{}
					results = append(results, result)
				}
				mu.Unlock()
			}(testURL, svc.Host)
		}
	}
	wg.Wait()

	if len(results) > 0 {
		log.Printf("[survex] graphql: found %d GraphQL endpoints (%d with introspection enabled)",
			len(results), countIntrospectionEnabled(results))
	}
	return results
}

// probeGraphQLEndpoint sends an introspection query to a single URL.
func probeGraphQLEndpoint(client *http.Client, endpoint, host string) (models.GraphQLResult, bool) {
	// First: GET probe to check if the endpoint exists at all
	getReq, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return models.GraphQLResult{}, false
	}
	getReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Survex/1.0)")
	getReq.Header.Set("Accept", "application/json")

	getResp, err := client.Do(getReq)
	if err != nil {
		return models.GraphQLResult{}, false
	}
	getResp.Body.Close()

	// GraphQL endpoints typically return 200, 400, or 405 (method not allowed for GET)
	// Skip 404, 403 (unless it might be GraphQL behind auth)
	if getResp.StatusCode == 404 {
		return models.GraphQLResult{}, false
	}

	// POST with introspection query
	postReq, err := http.NewRequest("POST", endpoint, bytes.NewBufferString(introspectionQuery))
	if err != nil {
		return models.GraphQLResult{}, false
	}
	postReq.Header.Set("Content-Type", "application/json")
	postReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Survex/1.0)")
	postReq.Header.Set("Accept", "application/json")

	postResp, err := client.Do(postReq)
	if err != nil {
		return models.GraphQLResult{}, false
	}
	defer postResp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(postResp.Body, 256*1024))
	if err != nil {
		return models.GraphQLResult{}, false
	}

	bodyStr := string(body)

	// Check for GraphQL-shaped response
	isGraphQL := strings.Contains(bodyStr, `"data"`) &&
		(strings.Contains(bodyStr, `"__schema"`) ||
			strings.Contains(bodyStr, `"errors"`) ||
			strings.Contains(bodyStr, `"queryType"`))

	if !isGraphQL {
		// Also detect playground/GraphiQL HTML
		isGraphQL = strings.Contains(bodyStr, "GraphiQL") ||
			strings.Contains(bodyStr, "graphql-playground") ||
			strings.Contains(bodyStr, "GraphQL Playground")
	}

	if !isGraphQL {
		return models.GraphQLResult{}, false
	}

	result := models.GraphQLResult{
		Host:       host,
		URL:        endpoint,
		SchemaSize: len(body),
	}

	// Parse introspection response
	var introResp struct {
		Data struct {
			Schema struct {
				QueryType struct {
					Name string `json:"name"`
				} `json:"queryType"`
				MutationType struct {
					Name string `json:"name"`
				} `json:"mutationType"`
				Types []struct {
					Name string `json:"name"`
					Kind string `json:"kind"`
				} `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.Unmarshal(body, &introResp); err == nil {
		if introResp.Data.Schema.QueryType.Name != "" {
			result.IntrospectionEnabled = true
			for _, t := range introResp.Data.Schema.Types {
				// Skip built-in GraphQL types (prefixed with __)
				if !strings.HasPrefix(t.Name, "__") && t.Kind == "OBJECT" {
					result.Types = append(result.Types, t.Name)
				}
			}
		}

		// Check if introspection is disabled but endpoint exists
		for _, e := range introResp.Errors {
			if strings.Contains(strings.ToLower(e.Message), "introspection") {
				// Endpoint exists but introspection disabled — still interesting
				result.IntrospectionEnabled = false
			}
		}
	}

	return result, true
}

// countIntrospectionEnabled counts how many GraphQL results have introspection on.
func countIntrospectionEnabled(results []models.GraphQLResult) int {
	n := 0
	for _, r := range results {
		if r.IntrospectionEnabled {
			n++
		}
	}
	return n
}

// GraphQLEndpointSummary returns a one-line description of a GraphQL result.
func GraphQLEndpointSummary(r models.GraphQLResult) string {
	if r.IntrospectionEnabled {
		return fmt.Sprintf("%s — introspection ENABLED (%d types exposed)", r.URL, len(r.Types))
	}
	return fmt.Sprintf("%s — GraphQL detected (introspection disabled)", r.URL)
}
