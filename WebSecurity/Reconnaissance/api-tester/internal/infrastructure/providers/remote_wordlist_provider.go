package providers

import (
	"bufio"
	"context"
	"strings"

	"github.com/go-resty/resty/v2"
	"github.com/leedale1981/infosec/tree/master/WebSecurity/Reconnaissance/api-tester/internal/domain"
)

type RemoteWordlistSource struct {
	Name string
	URL  string
}

type RemoteWordlistProvider struct {
	client     *resty.Client
	sources    []RemoteWordlistSource
	maxPerList int
}

func NewRemoteWordlistProvider(client *resty.Client, maxPerList int) *RemoteWordlistProvider {
	if maxPerList <= 0 {
		maxPerList = 250
	}

	return &RemoteWordlistProvider{
		client: client,
		sources: []RemoteWordlistSource{
			{
				Name: "SecLists raft-small-words",
				URL:  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-words-lowercase.txt",
			},
			{
				Name: "PortSwigger Param Miner words",
				URL:  "https://raw.githubusercontent.com/PortSwigger/param-miner/master/resources/words",
			},
			{
				Name: "OWASP Amass web wordlist",
				URL:  "https://raw.githubusercontent.com/owasp-amass/amass/master/wordlists/web.txt",
			},
		},
		maxPerList: maxPerList,
	}
}

func (p *RemoteWordlistProvider) Name() string {
	return "remote-wordlists"
}

func (p *RemoteWordlistProvider) Load(ctx context.Context) ([]domain.EndpointCandidate, error) {
	all := make([]domain.EndpointCandidate, 0)

	for _, source := range p.sources {
		resp, err := p.client.R().SetContext(ctx).Get(source.URL)
		if err != nil || resp.IsError() {
			continue
		}

		scanner := bufio.NewScanner(strings.NewReader(resp.String()))
		count := 0
		for scanner.Scan() {
			line := sanitizeWordlistLine(scanner.Text())
			if line == "" {
				continue
			}

			all = append(all, domain.EndpointCandidate{
				Path:   line,
				Source: source.Name,
			})

			count++
			if count >= p.maxPerList {
				break
			}
		}
	}

	return all, nil
}

func sanitizeWordlistLine(raw string) string {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}
	line = strings.TrimPrefix(line, "./")
	line = strings.Trim(line, " ")
	line = strings.Split(line, " ")[0]
	line = strings.Split(line, "\t")[0]
	line = strings.Trim(line, "/")
	if line == "" {
		return ""
	}
	if strings.Contains(line, " ") {
		return ""
	}
	return "/" + line
}
