package endpoints

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/leedale1981/infosec/tree/master/WebSecurity/Reconnaissance/api-tester/internal/domain"
)

type fakeProvider struct {
	name    string
	results []domain.EndpointCandidate
}

func (f fakeProvider) Name() string {
	return f.name
}

func (f fakeProvider) Load(_ context.Context) ([]domain.EndpointCandidate, error) {
	return f.results, nil
}

func TestServiceCollectDeduplicatesAndNormalizes(t *testing.T) {
	t.Parallel()

	svc := NewService([]Provider{
		fakeProvider{
			name: "a",
			results: []domain.EndpointCandidate{
				{Path: "swagger", MethodHints: []string{"get"}, Source: "a"},
				{Path: "/graphql", MethodHints: []string{"post"}, Source: "a"},
			},
		},
		fakeProvider{
			name: "b",
			results: []domain.EndpointCandidate{
				{Path: "/swagger", MethodHints: []string{"OPTIONS"}, Source: "b"},
			},
		},
	})

	items, err := svc.Collect(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 2)

	require.Equal(t, "/graphql", items[0].Path)
	require.Equal(t, "/swagger", items[1].Path)
	require.ElementsMatch(t, []string{"GET", "OPTIONS"}, items[1].MethodHints)
}
