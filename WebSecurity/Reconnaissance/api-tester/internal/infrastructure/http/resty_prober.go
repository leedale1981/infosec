package httpinfra

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/leedale1981/infosec/tree/master/WebSecurity/Reconnaissance/api-tester/internal/application/scan"
)

type RestyProber struct {
	client *resty.Client
}

func NewRestyProber(timeout time.Duration) *RestyProber {
	client := resty.New().
		SetTimeout(timeout).
		SetRetryCount(1).
		SetRetryWaitTime(250*time.Millisecond).
		SetHeader("User-Agent", "api-tester/1.0")

	return &RestyProber{client: client}
}

func (p *RestyProber) RestyClient() *resty.Client {
	return p.client
}

func (p *RestyProber) Probe(ctx context.Context, baseURL, path, method string, query map[string]string, body map[string]any) (scan.ProbeResponse, error) {
	url := strings.TrimRight(baseURL, "/") + path
	req := p.client.R().SetContext(ctx)

	if len(query) > 0 {
		req = req.SetQueryParams(query)
	}

	if len(body) > 0 {
		req = req.SetHeader("Content-Type", "application/json").SetBody(body)
	}

	resp, err := req.Execute(method, url)
	if err != nil {
		return scan.ProbeResponse{}, err
	}

	headers := http.Header{}
	for key, values := range resp.Header() {
		copied := append([]string(nil), values...)
		headers[key] = copied
	}

	return scan.ProbeResponse{
		StatusCode: resp.StatusCode(),
		Headers:    headers,
		Body:       resp.String(),
	}, nil
}
