package endpoints

import (
	"context"
	"sort"
	"strings"

	"github.com/leedale1981/infosec/tree/master/WebSecurity/Reconnaissance/api-tester/internal/domain"
)

// Provider returns endpoint candidates from a source (file, curated list, remote wordlist, etc.).
type Provider interface {
	Name() string
	Load(ctx context.Context) ([]domain.EndpointCandidate, error)
}

// Service aggregates endpoint candidates from multiple providers.
type Service struct {
	providers []Provider
}

func NewService(providers []Provider) *Service {
	return &Service{providers: providers}
}

func (s *Service) Collect(ctx context.Context) ([]domain.EndpointCandidate, error) {
	dedup := map[string]domain.EndpointCandidate{}

	for _, provider := range s.providers {
		entries, err := provider.Load(ctx)
		if err != nil {
			return nil, err
		}

		for _, entry := range entries {
			path := entry.NormalizedPath()
			if path == "" {
				continue
			}

			existing, exists := dedup[path]
			if !exists {
				entry.Path = path
				entry.MethodHints = normalizeMethods(entry.MethodHints)
				dedup[path] = entry
				continue
			}

			existing.MethodHints = mergeMethods(existing.MethodHints, entry.MethodHints)
			if existing.Source == "" {
				existing.Source = entry.Source
			}
			dedup[path] = existing
		}
	}

	result := make([]domain.EndpointCandidate, 0, len(dedup))
	for _, candidate := range dedup {
		result = append(result, candidate)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Path < result[j].Path
	})

	return result, nil
}

func normalizeMethods(methods []string) []string {
	if len(methods) == 0 {
		return nil
	}
	out := make([]string, 0, len(methods))
	seen := map[string]struct{}{}
	for _, method := range methods {
		m := strings.ToUpper(strings.TrimSpace(method))
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

func mergeMethods(left, right []string) []string {
	all := make([]string, 0, len(left)+len(right))
	all = append(all, left...)
	all = append(all, right...)
	return normalizeMethods(all)
}
