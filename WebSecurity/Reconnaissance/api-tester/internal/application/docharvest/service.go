package docharvest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/leedale1981/infosec/tree/master/WebSecurity/Reconnaissance/api-tester/internal/domain"
)

var docURLPattern = regexp.MustCompile(`(?i)(https?://[^"'\s]+|/[a-z0-9._\-/{}]+(?:\.json|\.ya?ml)|/v[0-9]+/api-docs|/api-docs)`)

var pathParamPattern = regexp.MustCompile(`\{[^}]+\}`)

type Prober interface {
	Probe(ctx context.Context, baseURL, path, method string, query map[string]string, body map[string]any) (ProbeResponse, error)
}

type ProbeResponse struct {
	StatusCode int
	Headers    http.Header
	Body       string
}

type Service struct {
	prober Prober
}

func NewService(prober Prober) *Service {
	return &Service{prober: prober}
}

func (s *Service) DiscoverFromDocumentation(ctx context.Context, baseURL string, discoveries []domain.EndpointDiscovery) ([]domain.EndpointCandidate, error) {
	queue := make([]string, 0)
	seenDocs := map[string]struct{}{}
	for _, discovery := range discoveries {
		if !isDocumentationEndpoint(discovery.Path) {
			continue
		}
		if !hasMethodWith2xx(discovery.Methods, "GET") {
			continue
		}
		if _, exists := seenDocs[discovery.Path]; exists {
			continue
		}
		seenDocs[discovery.Path] = struct{}{}
		queue = append(queue, discovery.Path)
	}

	found := map[string]domain.EndpointCandidate{}
	visited := map[string]struct{}{}

	for len(queue) > 0 {
		docPath := queue[0]
		queue = queue[1:]
		if _, ok := visited[docPath]; ok {
			continue
		}
		visited[docPath] = struct{}{}

		resp, err := s.prober.Probe(ctx, baseURL, docPath, http.MethodGet, nil, nil)
		if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			continue
		}

		for _, ref := range extractDocReferences(baseURL, resp.Body) {
			if _, exists := visited[ref]; exists {
				continue
			}
			if isDocumentationEndpoint(ref) {
				queue = append(queue, ref)
			}
		}

		paths := parseSpecPaths(resp.Body)
		for path, methods := range paths {
			normalized := normalizeSpecPath(path)
			if normalized == "" {
				continue
			}
			existing, exists := found[normalized]
			if !exists {
				found[normalized] = domain.EndpointCandidate{
					Path:        normalized,
					MethodHints: methods,
					Source:      fmt.Sprintf("documentation:%s", docPath),
				}
				continue
			}
			existing.MethodHints = mergeMethods(existing.MethodHints, methods)
			found[normalized] = existing
		}
	}

	out := make([]domain.EndpointCandidate, 0, len(found))
	for _, candidate := range found {
		out = append(out, candidate)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func hasMethodWith2xx(methods []domain.MethodDiscovery, method string) bool {
	for _, item := range methods {
		if strings.EqualFold(item.Method, method) && item.StatusCode >= 200 && item.StatusCode < 300 {
			return true
		}
	}
	return false
}

func isDocumentationEndpoint(path string) bool {
	p := strings.ToLower(strings.TrimSpace(path))
	if p == "" {
		return false
	}
	indicators := []string{"openapi", "swagger", "api-docs", "redoc", "graphiql", "playground"}
	for _, indicator := range indicators {
		if strings.Contains(p, indicator) {
			return true
		}
	}
	if strings.HasSuffix(p, ".json") || strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml") {
		return true
	}
	return false
}

func extractDocReferences(baseURL, body string) []string {
	if strings.TrimSpace(body) == "" {
		return nil
	}
	matches := docURLPattern.FindAllString(body, -1)
	if len(matches) == 0 {
		return nil
	}

	baseParsed, _ := url.Parse(baseURL)
	seen := map[string]struct{}{}
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		candidate := strings.TrimSpace(match)
		if candidate == "" {
			continue
		}

		if strings.HasPrefix(candidate, "http://") || strings.HasPrefix(candidate, "https://") {
			parsed, err := url.Parse(candidate)
			if err != nil || parsed.Host == "" {
				continue
			}
			if baseParsed != nil && baseParsed.Host != "" && !strings.EqualFold(parsed.Host, baseParsed.Host) {
				continue
			}
			candidate = parsed.Path
		}

		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if !strings.HasPrefix(candidate, "/") {
			candidate = "/" + candidate
		}
		candidate = strings.TrimSuffix(candidate, "/")
		if candidate == "" {
			continue
		}
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	return out
}

type specDocument struct {
	OpenAPI string              `json:"openapi" yaml:"openapi"`
	Swagger string              `json:"swagger" yaml:"swagger"`
	Paths   map[string]pathItem `json:"paths" yaml:"paths"`
}

type pathItem struct {
	Get     *operation `json:"get" yaml:"get"`
	Post    *operation `json:"post" yaml:"post"`
	Put     *operation `json:"put" yaml:"put"`
	Patch   *operation `json:"patch" yaml:"patch"`
	Delete  *operation `json:"delete" yaml:"delete"`
	Head    *operation `json:"head" yaml:"head"`
	Options *operation `json:"options" yaml:"options"`
}

type operation struct{}

func parseSpecPaths(body string) map[string][]string {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return nil
	}

	var document specDocument
	if err := json.Unmarshal([]byte(trimmed), &document); err != nil {
		if yamlErr := yaml.Unmarshal([]byte(trimmed), &document); yamlErr != nil {
			return nil
		}
	}

	if len(document.Paths) == 0 {
		return nil
	}

	out := map[string][]string{}
	for path, item := range document.Paths {
		methods := itemMethods(item)
		if len(methods) == 0 {
			methods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}
		}
		out[path] = methods
	}
	return out
}

func itemMethods(item pathItem) []string {
	out := make([]string, 0, 7)
	if item.Get != nil {
		out = append(out, "GET")
	}
	if item.Post != nil {
		out = append(out, "POST")
	}
	if item.Put != nil {
		out = append(out, "PUT")
	}
	if item.Patch != nil {
		out = append(out, "PATCH")
	}
	if item.Delete != nil {
		out = append(out, "DELETE")
	}
	if item.Head != nil {
		out = append(out, "HEAD")
	}
	if item.Options != nil {
		out = append(out, "OPTIONS")
	}
	sort.Strings(out)
	return out
}

func normalizeSpecPath(path string) string {
	p := strings.TrimSpace(path)
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = pathParamPattern.ReplaceAllString(p, "1")
	if strings.Contains(p, " ") {
		return ""
	}
	return p
}

func mergeMethods(left, right []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(left)+len(right))
	for _, method := range append(append([]string(nil), left...), right...) {
		normalized := strings.ToUpper(strings.TrimSpace(method))
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out
}
