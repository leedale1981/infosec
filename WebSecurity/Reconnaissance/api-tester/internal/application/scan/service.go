package scan

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/leedale1981/infosec/tree/master/WebSecurity/Reconnaissance/api-tester/internal/domain"
)

// Prober issues HTTP requests for the scanner.
type Prober interface {
	Probe(ctx context.Context, baseURL, path, method string, query map[string]string, body map[string]any) (ProbeResponse, error)
}

// ProbeResponse is the normalized shape the scanner uses for decision making.
type ProbeResponse struct {
	StatusCode int
	Headers    http.Header
	Body       string
}

// Service probes endpoints and determines which methods/parameters appear accepted.
type Service struct {
	prober            Prober
	defaultMethods    []string
	defaultQueryProbe map[string]string
	defaultBodyProbe  map[string]any
}

func NewService(prober Prober) *Service {
	return &Service{
		prober:            prober,
		defaultMethods:    []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"},
		defaultQueryProbe: map[string]string{"id": "1", "q": "test", "page": "1", "limit": "10"},
		defaultBodyProbe:  map[string]any{"id": 1, "name": "test", "email": "tester@example.com"},
	}
}

func (s *Service) Discover(ctx context.Context, baseURL string, candidates []domain.EndpointCandidate) ([]domain.EndpointDiscovery, error) {
	found := make([]domain.EndpointDiscovery, 0)

	for _, candidate := range candidates {
		methods := candidate.MethodHints
		if len(methods) == 0 {
			methods = s.defaultMethods
		}

		methodResults := make([]domain.MethodDiscovery, 0)
		for _, method := range uniqueUpper(methods) {
			baseResp, err := s.prober.Probe(ctx, baseURL, candidate.Path, method, nil, nil)
			if err != nil {
				continue
			}

			if !isDiscovered(baseResp.StatusCode) {
				continue
			}

			result := domain.MethodDiscovery{
				Method:     method,
				StatusCode: baseResp.StatusCode,
			}

			if method == "GET" {
				queryResp, err := s.prober.Probe(ctx, baseURL, candidate.Path, method, s.defaultQueryProbe, nil)
				if err == nil && isParameterSignal(baseResp.StatusCode, queryResp.StatusCode) {
					result.QueryParamsAccepted = sortedKeys(s.defaultQueryProbe)
				}
			}

			if method == "POST" || method == "PUT" || method == "PATCH" {
				bodyResp, err := s.prober.Probe(ctx, baseURL, candidate.Path, method, nil, s.defaultBodyProbe)
				if err == nil && isParameterSignal(baseResp.StatusCode, bodyResp.StatusCode) {
					result.BodyFieldsAccepted = sortedBodyKeys(s.defaultBodyProbe)
				}
			}

			if allow := parseAllow(baseResp.Headers.Get("Allow")); len(allow) > 0 {
				result.Notes = fmt.Sprintf("Allow header: %s", strings.Join(allow, ", "))
			}

			methodResults = append(methodResults, result)
		}

		if len(methodResults) > 0 {
			sort.Slice(methodResults, func(i, j int) bool {
				return methodResults[i].Method < methodResults[j].Method
			})

			found = append(found, domain.EndpointDiscovery{
				Path:    candidate.Path,
				URL:     strings.TrimRight(baseURL, "/") + candidate.Path,
				Source:  candidate.Source,
				Methods: methodResults,
			})
		}
	}

	sort.Slice(found, func(i, j int) bool {
		return found[i].Path < found[j].Path
	})

	return found, nil
}

func isDiscovered(status int) bool {
	return status > 0 && status != http.StatusNotFound && status != http.StatusMethodNotAllowed
}

func isParameterSignal(baseStatus, probeStatus int) bool {
	if probeStatus == 0 || probeStatus == http.StatusNotFound || probeStatus == http.StatusMethodNotAllowed {
		return false
	}
	return probeStatus == baseStatus || (probeStatus >= 200 && probeStatus < 500)
}

func parseAllow(allow string) []string {
	if strings.TrimSpace(allow) == "" {
		return nil
	}
	parts := strings.Split(allow, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		m := strings.ToUpper(strings.TrimSpace(part))
		if m == "" {
			continue
		}
		if _, ok := seen[m]; ok {
			continue
		}
		seen[m] = struct{}{}
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

func uniqueUpper(items []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		u := strings.ToUpper(strings.TrimSpace(item))
		if u == "" {
			continue
		}
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedBodyKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
