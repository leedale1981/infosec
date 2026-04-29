package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/spf13/cobra"

	"github.com/leedale1981/infosec/tree/master/WebSecurity/Reconnaissance/api-tester/internal/application/endpoints"
	"github.com/leedale1981/infosec/tree/master/WebSecurity/Reconnaissance/api-tester/internal/application/scan"
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

			reporter := output.NewConsoleReporter(os.Stdout)
			reporter.Report(discoveries)
			return nil
		},
	}

	cmd.Flags().StringVarP(&endpointsFile, "endpoints-file", "f", "endpoint.txt", "Line-delimited endpoint list file")
	cmd.Flags().IntVarP(&timeoutSeconds, "timeout", "t", 8, "HTTP timeout in seconds")
	cmd.Flags().BoolVar(&useRemoteLists, "remote-lists", true, "Load extra endpoints from SecLists/PortSwigger/OWASP public wordlists")
	cmd.Flags().IntVar(&remoteMaxLines, "remote-max-lines", 250, "Max endpoint candidates per remote wordlist")

	return cmd.Execute()
}
