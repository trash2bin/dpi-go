package dns

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRunner struct {
	calls [][]string
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	entry := append([]string{name}, args...)
	f.calls = append(f.calls, entry)
	return "", nil
}

func TestRenderConfig(t *testing.T) {
	t.Parallel()

	content, err := RenderConfig([]string{"Example.com", "example.com", "rutracker.org"})
	if err != nil {
		t.Fatalf("RenderConfig() error = %v", err)
	}

	if !strings.Contains(content, "address=/example.com/0.0.0.0") {
		t.Fatalf("expected example.com block line, got:\n%s", content)
	}
	if !strings.Contains(content, "address=/rutracker.org/0.0.0.0") {
		t.Fatalf("expected rutracker.org block line, got:\n%s", content)
	}
	if strings.Count(content, "example.com") != 1 {
		t.Fatalf("expected deduplicated domain entries, got:\n%s", content)
	}
}

func TestApplyWritesConfigAndReloads(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "dpi-dns.conf")
	runner := &fakeRunner{}
	svc := NewService(runner, path, []string{"echo", "reload"})

	if err := svc.Apply(context.Background(), []string{"blocked.example"}); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(data), "blocked.example") {
		t.Fatalf("expected blocked domain in config, got:\n%s", string(data))
	}

	if len(runner.calls) != 1 {
		t.Fatalf("expected 1 reload command call, got %d", len(runner.calls))
	}
	if got := strings.Join(runner.calls[0], " "); got != "echo reload" {
		t.Fatalf("unexpected reload call: %s", got)
	}
}
