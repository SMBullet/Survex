package tools

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

// apiProbes maps URL paths to their endpoint type classification.
var apiProbes = []struct {
	Path string
	Type string
}{
	// Swagger / OpenAPI
	{"/swagger.json", "swagger"},
	{"/swagger.yaml", "swagger"},
	{"/swagger/v1/swagger.json", "swagger"},
	{"/swagger/v2/swagger.json", "swagger"},
	{"/swagger-ui.html", "swagger"},
	{"/swagger-ui/index.html", "swagger"},
	{"/api-docs", "openapi"},
	{"/api-docs/swagger.json", "openapi"},
	{"/api/swagger.json", "openapi"},
	{"/openapi.json", "openapi"},
	{"/openapi.yaml", "openapi"},
	{"/openapi/v1", "openapi"},
	{"/openapi/v2", "openapi"},
	{"/openapi/v3", "openapi"},
	{"/v1/api-docs", "openapi"},
	{"/v2/api-docs", "openapi"},
	{"/v3/api-docs", "openapi"},
	{"/redoc", "openapi"},
	// WSDL / SOAP
	{"?wsdl", "wsdl"},
	{"/?wsdl", "wsdl"},
	{"/service?wsdl", "wsdl"},
	{"/api?wsdl", "wsdl"},
	{"/ws?wsdl", "wsdl"},
	// WADL
	{"/application.wadl", "wadl"},
	{"/api/application.wadl", "wadl"},
	// REST API base paths
	{"/api/v1", "rest"},
	{"/api/v2", "rest"},
	{"/api/v3", "rest"},
	{"/api/v1/", "rest"},
	{"/rest/v1", "rest"},
	{"/rest/api/2", "rest"},   // Jira REST API
	{"/api/2", "rest"},
	// Admin / dev consoles that indicate exposed APIs
	{"/graphiql", "graphql"},
	{"/graphql/console", "graphql"},
	{"/api/graphql", "graphql"},
	{"/graphql", "graphql"},
	// Well-known config/info endpoints
	{"/actuator", "rest"},        // Spring Boot actuator
	{"/actuator/env", "rest"},
	{"/actuator/health", "rest"},
	{"/actuator/mappings", "rest"},
	{"/actuator/beans", "rest"},
	{"/metrics", "rest"},
	{"/health", "rest"},
	{"/info", "rest"},
	{"/status", "rest"},
	{"/version", "rest"},
	{"/.well-known/openid-configuration", "openid"},
	{"/.well-known/oauth-authorization-server", "openid"},
	{"/oauth/.well-known/openid-configuration", "openid"},
}

// DiscoverAPIEndpoints probes all live HTTP services for exposed API docs,
// Swagger/OpenAPI specs, WSDL, actuator endpoints, and GraphQL consoles.
func DiscoverAPIEndpoints(httpServices []models.HTTPService, timeoutSecs int) []models.APIEndpoint {
	client := &http.Client{
		Timeout: time.Duration(timeoutSecs) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	sem := make(chan struct{}, 20)
	var mu sync.Mutex
	var results []models.APIEndpoint
	seen := make(map[string]struct{})

	var wg sync.WaitGroup
	for _, svc := range httpServices {
		baseURL := strings.TrimRight(svc.URL, "/")
		for _, probe := range apiProbes {
			testURL := baseURL + probe.Path
			endpointType := probe.Type

			wg.Add(1)
			go func(testURL, host, endpointType string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				statusCode, ok := probeAPIEndpoint(client, testURL, endpointType)
				if !ok {
					return
				}

				mu.Lock()
				if _, dup := seen[testURL]; !dup {
					seen[testURL] = struct{}{}
					results = append(results, models.APIEndpoint{
						Host:       host,
						URL:        testURL,
						Type:       endpointType,
						StatusCode: statusCode,
					})
				}
				mu.Unlock()
			}(testURL, svc.Host, endpointType)
		}
	}
	wg.Wait()

	if len(results) > 0 {
		log.Printf("[survex] api-discovery: found %d API endpoints", len(results))
	}
	return results
}

// probeAPIEndpoint sends a GET request and decides if the endpoint is interesting.
func probeAPIEndpoint(client *http.Client, endpoint, endpointType string) (int, bool) {
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return 0, false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Survex/1.0)")
	req.Header.Set("Accept", "application/json, text/html, */*")

	resp, err := client.Do(req)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()

	// Skip 404 and 4xx errors (except auth-related which still confirm existence)
	if resp.StatusCode == 404 || resp.StatusCode == 410 || resp.StatusCode == 400 {
		return 0, false
	}

	// Read a bit of the body to confirm the content type
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	if err != nil {
		return resp.StatusCode, resp.StatusCode < 404
	}

	bodyStr := string(body)
	ct := strings.ToLower(resp.Header.Get("Content-Type"))

	switch endpointType {
	case "swagger", "openapi":
		// Must look like JSON/YAML with swagger/openapi keys
		if isSwaggerContent(bodyStr, ct) {
			return resp.StatusCode, true
		}
		// swagger-ui HTML page
		if strings.Contains(bodyStr, "swagger") && strings.Contains(ct, "html") {
			return resp.StatusCode, true
		}
		return 0, false

	case "wsdl":
		if strings.Contains(bodyStr, "wsdl") || strings.Contains(bodyStr, "definitions") ||
			strings.Contains(ct, "xml") {
			return resp.StatusCode, true
		}
		return 0, false

	case "wadl":
		if strings.Contains(bodyStr, "application") && strings.Contains(ct, "xml") {
			return resp.StatusCode, true
		}
		return 0, false

	case "graphql":
		if strings.Contains(bodyStr, "GraphQL") || strings.Contains(bodyStr, "graphql") ||
			strings.Contains(bodyStr, `"__schema"`) {
			return resp.StatusCode, true
		}
		return 0, false

	case "openid":
		// OpenID config is always JSON with specific fields
		if strings.Contains(bodyStr, "issuer") && strings.Contains(bodyStr, "authorization_endpoint") {
			return resp.StatusCode, true
		}
		return 0, false

	case "rest":
		// REST endpoints: must return JSON and be accessible
		if resp.StatusCode < 400 && (strings.Contains(ct, "json") ||
			(len(bodyStr) > 0 && (bodyStr[0] == '{' || bodyStr[0] == '['))) {
			return resp.StatusCode, true
		}
		// Spring actuator sometimes returns 401/403 but still confirms existence
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			return resp.StatusCode, true
		}
		return 0, false
	}

	return resp.StatusCode, resp.StatusCode < 400
}

// isSwaggerContent checks if the body looks like a Swagger/OpenAPI spec.
func isSwaggerContent(body, contentType string) bool {
	if strings.Contains(contentType, "json") || strings.Contains(contentType, "yaml") {
		lower := strings.ToLower(body)
		return strings.Contains(lower, `"swagger"`) ||
			strings.Contains(lower, `"openapi"`) ||
			strings.Contains(lower, "swagger:") ||
			strings.Contains(lower, "openapi:")
	}
	return false
}

// ParseSwaggerPaths extracts path names from a Swagger/OpenAPI JSON spec.
// Used to feed ffuf and dalfox with additional targeted paths.
func ParseSwaggerPaths(apiEndpoints []models.APIEndpoint, timeoutSecs int) []string {
	client := &http.Client{Timeout: time.Duration(timeoutSecs) * time.Second}
	var paths []string
	seen := make(map[string]struct{})

	for _, ep := range apiEndpoints {
		if ep.Type != "swagger" && ep.Type != "openapi" {
			continue
		}
		if !strings.HasSuffix(ep.URL, ".json") && !strings.HasSuffix(ep.URL, ".yaml") &&
			!strings.Contains(ep.URL, "swagger.json") && !strings.Contains(ep.URL, "api-docs") {
			continue
		}

		resp, err := client.Get(ep.URL)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()

		var spec struct {
			Paths map[string]json.RawMessage `json:"paths"`
		}
		if err := json.Unmarshal(body, &spec); err != nil {
			continue
		}

		for path := range spec.Paths {
			if _, dup := seen[path]; !dup {
				seen[path] = struct{}{}
				paths = append(paths, path)
			}
		}
	}

	if len(paths) > 0 {
		log.Printf("[survex] api-discovery: extracted %d paths from API specs", len(paths))
	}
	return paths
}
