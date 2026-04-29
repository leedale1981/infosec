package scan

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/leedale1981/infosec/tree/master/WebSecurity/Reconnaissance/api-tester/internal/domain"
)

type fakeProber struct{}

func (f *fakeProber) Probe(_ context.Context, _ string, path, method string, query map[string]string, body map[string]any) (ProbeResponse, error) {
	switch {
	case path == "/swagger" && method == "GET" && query == nil:
		return ProbeResponse{StatusCode: 200, Headers: http.Header{"Allow": []string{"GET, OPTIONS"}}}, nil
	case path == "/swagger" && method == "GET" && query != nil:
		return ProbeResponse{StatusCode: 200, Headers: http.Header{}}, nil
	case path == "/graphql" && method == "POST" && body == nil:
		return ProbeResponse{StatusCode: 401, Headers: http.Header{}}, nil
	case path == "/graphql" && method == "POST" && body != nil:
		return ProbeResponse{StatusCode: 401, Headers: http.Header{}}, nil
	default:
		return ProbeResponse{StatusCode: 404, Headers: http.Header{}}, nil
	}
}

func TestDiscoverFindsMethodsAndParameters(t *testing.T) {
	t.Parallel()

	svc := NewService(&fakeProber{})
	results, err := svc.Discover(context.Background(), "https://target.local", []domain.EndpointCandidate{
		{Path: "/swagger", MethodHints: []string{"GET"}, Source: "test"},
		{Path: "/graphql", MethodHints: []string{"POST"}, Source: "test"},
	})

	require.NoError(t, err)
	require.Len(t, results, 2)

	require.Equal(t, "/graphql", results[0].Path)
	require.Equal(t, "POST", results[0].Methods[0].Method)
	require.NotEmpty(t, results[0].Methods[0].BodyFieldsAccepted)

	require.Equal(t, "/swagger", results[1].Path)
	require.Equal(t, "GET", results[1].Methods[0].Method)
	require.NotEmpty(t, results[1].Methods[0].QueryParamsAccepted)
	require.Contains(t, results[1].Methods[0].Notes, "Allow header")
}
