package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	openai "github.com/sashabaranov/go-openai"

	"github.com/leedale1981/infosec/tree/master/WebSecurity/Reconnaissance/api-tester/internal/domain"
)

type OpenAISummarizer struct {
	client *openai.Client
	model  string
}

func NewOpenAISummarizer(apiKey string) *OpenAISummarizer {
	config := openai.DefaultConfig(strings.TrimSpace(apiKey))
	client := openai.NewClientWithConfig(config)
	return &OpenAISummarizer{client: client, model: "gpt-4o-mini"}
}

func (s *OpenAISummarizer) Summarize(ctx context.Context, baseURL string, discoveries []domain.EndpointDiscovery) (string, error) {
	systemPrompt, userPrompt, err := buildRiskPrompt(baseURL, discoveries)
	if err != nil {
		return "", err
	}

	response, err := s.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: s.model,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleSystem, Content: systemPrompt},
			{Role: openai.ChatMessageRoleUser, Content: userPrompt},
		},
		Temperature: 0.2,
	})
	if err != nil {
		return "", fmt.Errorf("request completion: %w", err)
	}
	if len(response.Choices) == 0 {
		return "", fmt.Errorf("openai returned no choices")
	}

	return strings.TrimSpace(response.Choices[0].Message.Content), nil
}

func buildRiskPrompt(baseURL string, discoveries []domain.EndpointDiscovery) (string, string, error) {
	payload, err := json.MarshalIndent(discoveries, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("marshal discoveries: %w", err)
	}

	systemPrompt := "You are a senior API penetration testing analyst. Analyze scan findings and produce a concise, evidence-based risk summary for authorized security testing. Do not invent endpoints or vulnerabilities that are not supported by evidence."
	userPrompt := fmt.Sprintf("Target base URL: %s\n\nDiscovered endpoint data (JSON):\n%s\n\nReturn a report with exactly these sections:\n1) Executive Summary\n2) High-Risk Findings\n3) Medium-Risk Findings\n4) Low-Risk Findings\n5) Recommended Next Tests\n6) Defensive Remediation Notes\n\nRequirements:\n- Base each finding on the provided evidence (status codes, methods, params, notes).\n- Mention likely abuse paths only when supported by findings.\n- Include confidence labels: High, Medium, Low for each finding.\n- Keep the total response under 500 words.", baseURL, string(payload))

	return systemPrompt, userPrompt, nil
}
