package docharvest

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/leedale1981/infosec/tree/master/WebSecurity/Reconnaissance/api-tester/internal/domain"
)

type fakeDocProber struct {
	responses map[string]ProbeResponse
}

func (f *fakeDocProber) Probe(_ context.Context, _ string, path, method string, _ map[string]string, _ map[string]any) (ProbeResponse, error) {
	if method != http.MethodGet {
		return ProbeResponse{StatusCode: 405}, nil
	}
	if resp, ok := f.responses[path]; ok {
		return resp, nil
	}
	return ProbeResponse{StatusCode: 404}, nil
}

func TestDiscoverFromDocumentationExtractsSpecPaths(t *testing.T) {
	t.Parallel()

	prober := &fakeDocProber{responses: map[string]ProbeResponse{
		"/openapi/v1.json": {
			StatusCode: 200,
			Body: `{
				"openapi": "3.0.0",
				"paths": {
					"/users": {"get": {}},
					"/users/{id}": {"get": {}, "delete": {}}
				}
			}`,
		},
	}}

	svc := NewService(prober)
	candidates, err := svc.DiscoverFromDocumentation(context.Background(), "https://target.example.com", []domain.EndpointDiscovery{
		{
			Path: "/openapi/v1.json",
			Methods: []domain.MethodDiscovery{
				{Method: "GET", StatusCode: 200},
			},
		},
	})

	require.NoError(t, err)
	require.Len(t, candidates, 2)
	require.Equal(t, "/users", candidates[0].Path)
	require.Equal(t, "/users/1", candidates[1].Path)
	require.ElementsMatch(t, []string{"DELETE", "GET"}, candidates[1].MethodHints)
}

func TestDiscoverFromDocumentationFollowsSwaggerUIReference(t *testing.T) {
	t.Parallel()

	prober := &fakeDocProber{responses: map[string]ProbeResponse{
		"/swagger-ui.html": {
			StatusCode: 200,
			Body:       `<script>const url = "/openapi/v1.json";</script>`,
		},
		"/openapi/v1.json": {
			StatusCode: 200,
			Body: `swagger: "2.0"
paths:
  /health:
    get: {}
`,
		},
	}}

	svc := NewService(prober)
	candidates, err := svc.DiscoverFromDocumentation(context.Background(), "https://target.example.com", []domain.EndpointDiscovery{
		{
			Path: "/swagger-ui.html",
			Methods: []domain.MethodDiscovery{
				{Method: "GET", StatusCode: 200},
			},
		},
	})

	require.NoError(t, err)
	require.Len(t, candidates, 1)
	require.Equal(t, "/health", candidates[0].Path)
	require.ElementsMatch(t, []string{"GET"}, candidates[0].MethodHints)
}
