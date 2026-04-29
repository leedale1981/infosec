package domain

import "strings"

// EndpointCandidate describes a possible API route to probe.
type EndpointCandidate struct {
	Path        string
	MethodHints []string
	Source      string
}

func (e EndpointCandidate) NormalizedPath() string {
	trimmed := strings.TrimSpace(e.Path)
	if trimmed == "" {
		return ""
	}
	if !strings.HasPrefix(trimmed, "/") {
		return "/" + trimmed
	}
	return trimmed
}
