package ai

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/leedale1981/infosec/tree/master/WebSecurity/Reconnaissance/api-tester/internal/domain"
)

func TestBuildRiskPromptIncludesEvidence(t *testing.T) {
	t.Parallel()

	systemPrompt, userPrompt, err := buildRiskPrompt("https://target.example.com", []domain.EndpointDiscovery{
		{
			Path:   "/openapi/v1.json",
			URL:    "https://target.example.com/openapi/v1.json",
			Source: "OpenAPI modern docs patterns",
			Methods: []domain.MethodDiscovery{
				{Method: "GET", StatusCode: 200, QueryParamsAccepted: []string{"id", "q"}},
			},
		},
	})

	require.NoError(t, err)
	require.Contains(t, systemPrompt, "evidence-based")
	require.Contains(t, userPrompt, "Target base URL: https://target.example.com")
	require.Contains(t, userPrompt, "openapi/v1.json")
	require.Contains(t, userPrompt, "Executive Summary")
	require.Contains(t, userPrompt, "under 500 words")
}
