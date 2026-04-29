package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
	"github.com/leedale1981/infosec/tree/master/WebSecurity/Reconnaissance/api-tester/internal/domain"
)

type ConsoleReporter struct {
	out io.Writer
}

func NewConsoleReporter(out io.Writer) *ConsoleReporter {
	return &ConsoleReporter{out: out}
}

func (r *ConsoleReporter) Report(discoveries []domain.EndpointDiscovery) {
	headline := color.New(color.FgHiCyan, color.Bold)
	success := color.New(color.FgHiGreen)
	warn := color.New(color.FgHiYellow)
	denied := color.New(color.FgHiRed)
	muted := color.New(color.FgHiBlack)

	headline.Fprintln(r.out, "Discovered Endpoints")
	if len(discoveries) == 0 {
		muted.Fprintln(r.out, "No endpoints discovered with current probes.")
		return
	}

	for _, endpoint := range discoveries {
		headline.Fprintf(r.out, "\n%s [%s]\n", endpoint.URL, endpoint.Source)
		for _, method := range endpoint.Methods {
			line := fmt.Sprintf("  %s -> %d", method.Method, method.StatusCode)
			switch {
			case method.StatusCode >= 200 && method.StatusCode < 300:
				success.Fprintln(r.out, line)
			case method.StatusCode == 401 || method.StatusCode == 403:
				warn.Fprintln(r.out, line+" (auth/authorization required)")
			default:
				denied.Fprintln(r.out, line)
			}

			if len(method.QueryParamsAccepted) > 0 {
				fmt.Fprintf(r.out, "    query params: %s\n", strings.Join(method.QueryParamsAccepted, ", "))
			}
			if len(method.BodyFieldsAccepted) > 0 {
				fmt.Fprintf(r.out, "    body fields: %s\n", strings.Join(method.BodyFieldsAccepted, ", "))
			}
			if strings.TrimSpace(method.Notes) != "" {
				fmt.Fprintf(r.out, "    notes: %s\n", method.Notes)
			}
		}
	}
}

func (r *ConsoleReporter) ReportAISummary(summary string) {
	headline := color.New(color.FgHiMagenta, color.Bold)
	muted := color.New(color.FgHiBlack)

	headline.Fprintln(r.out, "\nAI Risk Summary")
	if strings.TrimSpace(summary) == "" {
		muted.Fprintln(r.out, "No AI summary available.")
		return
	}

	fmt.Fprintln(r.out, summary)
}
