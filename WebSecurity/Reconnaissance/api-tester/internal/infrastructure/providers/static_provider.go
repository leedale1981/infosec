package providers

import (
	"context"

	"github.com/leedale1981/infosec/tree/master/WebSecurity/Reconnaissance/api-tester/internal/domain"
)

type StaticProvider struct{}

func NewStaticProvider() *StaticProvider {
	return &StaticProvider{}
}

func (p *StaticProvider) Name() string {
	return "curated-owasp-portswigger"
}

func (p *StaticProvider) Load(_ context.Context) ([]domain.EndpointCandidate, error) {
	entries := []domain.EndpointCandidate{
		{Path: "/swagger", MethodHints: []string{"GET"}, Source: "OWASP API docs testing"},
		{Path: "/swagger/index.html", MethodHints: []string{"GET"}, Source: "OWASP API docs testing"},
		{Path: "/swagger-ui", MethodHints: []string{"GET"}, Source: "OWASP API docs testing"},
		{Path: "/swagger-ui.html", MethodHints: []string{"GET"}, Source: "OWASP API docs testing"},
		{Path: "/api-docs", MethodHints: []string{"GET"}, Source: "OWASP API docs testing"},
		{Path: "/openapi/v1.json", MethodHints: []string{"GET"}, Source: "OpenAPI modern docs patterns"},
		{Path: "/openapi/v2.json", MethodHints: []string{"GET"}, Source: "OpenAPI modern docs patterns"},
		{Path: "/openapi/v3.json", MethodHints: []string{"GET"}, Source: "OpenAPI modern docs patterns"},
		{Path: "/openapi/v1.yaml", MethodHints: []string{"GET"}, Source: "OpenAPI modern docs patterns"},
		{Path: "/openapi/v2.yaml", MethodHints: []string{"GET"}, Source: "OpenAPI modern docs patterns"},
		{Path: "/openapi/v3.yaml", MethodHints: []string{"GET"}, Source: "OpenAPI modern docs patterns"},
		{Path: "/openapi.json", MethodHints: []string{"GET"}, Source: "OWASP API docs testing"},
		{Path: "/v1/openapi.json", MethodHints: []string{"GET"}, Source: "OWASP API docs testing"},
		{Path: "/v2/api-docs", MethodHints: []string{"GET"}, Source: "OWASP API docs testing"},
		{Path: "/v3/api-docs", MethodHints: []string{"GET"}, Source: "OWASP API docs testing"},
		{Path: "/.well-known/openid-configuration", MethodHints: []string{"GET"}, Source: "RFC 8414"},
		{Path: "/.well-known/oauth-authorization-server", MethodHints: []string{"GET"}, Source: "RFC 8414"},
		{Path: "/.well-known/jwks.json", MethodHints: []string{"GET"}, Source: "RFC 7517"},
		{Path: "/graphql", MethodHints: []string{"GET", "POST", "OPTIONS"}, Source: "PortSwigger GraphQL testing"},
		{Path: "/graphiql", MethodHints: []string{"GET"}, Source: "PortSwigger GraphQL testing"},
		{Path: "/playground", MethodHints: []string{"GET"}, Source: "PortSwigger GraphQL testing"},
		{Path: "/actuator", MethodHints: []string{"GET"}, Source: "PortSwigger hidden endpoints"},
		{Path: "/actuator/health", MethodHints: []string{"GET"}, Source: "PortSwigger hidden endpoints"},
		{Path: "/actuator/env", MethodHints: []string{"GET"}, Source: "PortSwigger hidden endpoints"},
		{Path: "/health", MethodHints: []string{"GET"}, Source: "OWASP common endpoints"},
		{Path: "/healthz", MethodHints: []string{"GET"}, Source: "OWASP common endpoints"},
		{Path: "/metrics", MethodHints: []string{"GET"}, Source: "OWASP common endpoints"},
		{Path: "/version", MethodHints: []string{"GET"}, Source: "OWASP common endpoints"},
	}
	return entries, nil
}
