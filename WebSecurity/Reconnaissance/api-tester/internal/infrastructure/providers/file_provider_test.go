package providers

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFileProviderLoad(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	filePath := filepath.Join(tmp, "endpoints.txt")
	content := "\n# comment\n/swagger\nhealth\n\n"
	require.NoError(t, os.WriteFile(filePath, []byte(content), 0o644))

	provider := NewFileProvider(filePath)
	candidates, err := provider.Load(context.Background())
	require.NoError(t, err)
	require.Len(t, candidates, 2)
	require.Equal(t, "/swagger", candidates[0].Path)
	require.Equal(t, "health", candidates[1].Path)
	require.Equal(t, "local-file", candidates[0].Source)
}
