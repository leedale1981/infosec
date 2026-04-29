package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/spf13/cobra"

	"github.com/leedale1981/infosec/tree/master/WebSecurity/Reconnaissance/api-tester/internal/application/docharvest"
	"github.com/leedale1981/infosec/tree/master/WebSecurity/Reconnaissance/api-tester/internal/application/endpoints"
	"github.com/leedale1981/infosec/tree/master/WebSecurity/Reconnaissance/api-tester/internal/application/scan"
	"github.com/leedale1981/infosec/tree/master/WebSecurity/Reconnaissance/api-tester/internal/domain"
	"github.com/leedale1981/infosec/tree/master/WebSecurity/Reconnaissance/api-tester/internal/infrastructure/ai"
	httpinfra "github.com/leedale1981/infosec/tree/master/WebSecurity/Reconnaissance/api-tester/internal/infrastructure/http"
	"github.com/leedale1981/infosec/tree/master/WebSecurity/Reconnaissance/api-tester/internal/infrastructure/output"
	"github.com/leedale1981/infosec/tree/master/WebSecurity/Reconnaissance/api-tester/internal/infrastructure/providers"
)

func Execute() error {
	var (
		endpointsFile  string
		timeoutSeconds int
		useRemoteLists bool
		remoteMaxLines int
		withAIKey      string
	)

	cmd := &cobra.Command{
		Use:   "api-tester <base-url>",
		Short: "Probe common API endpoints against a base URL",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			baseURL := args[0]
			timeout := time.Duration(timeoutSeconds) * time.Second

			prober := httpinfra.NewRestyProber(timeout)
			scanService := scan.NewService(prober)

			providerList := []endpoints.Provider{
				providers.NewFileProvider(endpointsFile),
				providers.NewStaticProvider(),
			}

			if useRemoteLists {
				remoteClient := resty.New().SetTimeout(timeout)
				providerList = append(providerList, providers.NewRemoteWordlistProvider(remoteClient, remoteMaxLines))
			}

			endpointService := endpoints.NewService(providerList)
			ctx := context.Background()

			candidates, err := endpointService.Collect(ctx)
			if err != nil {
				return fmt.Errorf("collect endpoints: %w", err)
			}

			discoveries, err := scanService.Discover(ctx, baseURL, candidates)
			if err != nil {
				return fmt.Errorf("scan endpoints: %w", err)
			}

			docService := docharvest.NewService(scanProberAdapter{prober: prober})
			docCandidates, err := docService.DiscoverFromDocumentation(ctx, baseURL, discoveries)
			if err != nil {
				return fmt.Errorf("discover endpoints from documentation: %w", err)
			}

			if len(docCandidates) > 0 {
				missingCandidates := filterNewCandidates(candidates, docCandidates)
				if len(missingCandidates) > 0 {
					docDiscoveries, err := scanService.Discover(ctx, baseURL, missingCandidates)
					if err != nil {
						return fmt.Errorf("scan documentation-discovered endpoints: %w", err)
					}
					discoveries = mergeDiscoveries(discoveries, docDiscoveries)
				}
			}

			reporter := output.NewConsoleReporter(os.Stdout)
			reporter.Report(discoveries)

			if strings.TrimSpace(withAIKey) != "" {
				summarizer := ai.NewOpenAISummarizer(withAIKey)
				aiCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
				defer cancel()

				summary, err := summarizer.Summarize(aiCtx, baseURL, discoveries)
				if err != nil {
					return fmt.Errorf("generate ai summary: %w", err)
				}

				reporter.ReportAISummary(summary)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&endpointsFile, "endpoints-file", "f", "endpoint.txt", "Line-delimited endpoint list file")
	cmd.Flags().IntVarP(&timeoutSeconds, "timeout", "t", 8, "HTTP timeout in seconds")
	cmd.Flags().BoolVar(&useRemoteLists, "remote-lists", true, "Load extra endpoints from SecLists/PortSwigger/OWASP public wordlists")
	cmd.Flags().IntVar(&remoteMaxLines, "remote-max-lines", 250, "Max endpoint candidates per remote wordlist")
	cmd.Flags().StringVar(&withAIKey, "with-ai", "", "OpenAI API key for generating AI risk summary")

	return cmd.Execute()
}

type scanProberAdapter struct {
	prober *httpinfra.RestyProber
}

func (a scanProberAdapter) Probe(ctx context.Context, baseURL, path, method string, query map[string]string, body map[string]any) (docharvest.ProbeResponse, error) {
	resp, err := a.prober.Probe(ctx, baseURL, path, method, query, body)
	if err != nil {
		return docharvest.ProbeResponse{}, err
	}
	return docharvest.ProbeResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Headers,
		Body:       resp.Body,
	}, nil
}

func filterNewCandidates(existing []domain.EndpointCandidate, additional []domain.EndpointCandidate) []domain.EndpointCandidate {
	seen := map[string]struct{}{}
	for _, candidate := range existing {
		seen[candidate.Path] = struct{}{}
	}

	out := make([]domain.EndpointCandidate, 0, len(additional))
	for _, candidate := range additional {
		if candidate.NormalizedPath() == "" {
			continue
		}
		if _, exists := seen[candidate.NormalizedPath()]; exists {
			continue
		}
		seen[candidate.NormalizedPath()] = struct{}{}
		candidate.Path = candidate.NormalizedPath()
		out = append(out, candidate)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func mergeDiscoveries(base []domain.EndpointDiscovery, additional []domain.EndpointDiscovery) []domain.EndpointDiscovery {
	byPath := map[string]domain.EndpointDiscovery{}

	for _, item := range base {
		byPath[item.Path] = item
	}

	for _, item := range additional {
		existing, exists := byPath[item.Path]
		if !exists {
			byPath[item.Path] = item
			continue
		}

		methodMap := map[string]domain.MethodDiscovery{}
		for _, method := range existing.Methods {
			methodMap[strings.ToUpper(method.Method)] = method
		}
		for _, method := range item.Methods {
			methodMap[strings.ToUpper(method.Method)] = method
		}

		mergedMethods := make([]domain.MethodDiscovery, 0, len(methodMap))
		for _, method := range methodMap {
			mergedMethods = append(mergedMethods, method)
		}
		sort.Slice(mergedMethods, func(i, j int) bool { return mergedMethods[i].Method < mergedMethods[j].Method })

		existing.Methods = mergedMethods
		if existing.Source == "" {
			existing.Source = item.Source
		}
		byPath[item.Path] = existing
	}

	out := make([]domain.EndpointDiscovery, 0, len(byPath))
	for _, item := range byPath {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
