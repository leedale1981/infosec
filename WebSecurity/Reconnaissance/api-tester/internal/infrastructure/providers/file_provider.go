package providers

import (
	"bufio"
	"context"
	"os"
	"strings"

	"github.com/leedale1981/infosec/tree/master/WebSecurity/Reconnaissance/api-tester/internal/domain"
)

type FileProvider struct {
	path string
}

func NewFileProvider(path string) *FileProvider {
	return &FileProvider{path: path}
}

func (p *FileProvider) Name() string {
	return "local-file"
}

func (p *FileProvider) Load(_ context.Context) ([]domain.EndpointCandidate, error) {
	file, err := os.Open(p.path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	candidates := make([]domain.EndpointCandidate, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		candidates = append(candidates, domain.EndpointCandidate{
			Path:   line,
			Source: p.Name(),
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return candidates, nil
}
