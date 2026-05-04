//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"dpi-kyrsach/internal/dns"
	"dpi-kyrsach/internal/firewall"
	"dpi-kyrsach/internal/runner"
)

func TestDNSConfigApplyWithRealRunner(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration test requires linux")
	}

	path := filepath.Join(t.TempDir(), "dpi-dns.conf")
	svc := dns.NewService(runner.OSRunner{}, path, []string{"true"})
	if err := svc.Apply(context.Background(), []string{"blocked.example"}); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(data), "address=/blocked.example/0.0.0.0") {
		t.Fatalf("unexpected config content:\n%s", string(data))
	}
}

func TestFirewallEnsureAndAddBlockedIP(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration test requires linux")
	}
	if os.Geteuid() != 0 {
		t.Skip("integration test requires root/privileged container")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("integration test requires nft command")
	}

	r := runner.OSRunner{}
	table := fmt.Sprintf("dpi_test_%d", time.Now().UnixNano())
	m := firewall.NewManager(r, "inet", table, "input", "blocked_ips")

	ctx := context.Background()
	if err := m.Ensure(ctx); err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	t.Cleanup(func() {
		_, _ = r.Run(context.Background(), "nft", "delete", "table", "inet", table)
	})

	ip := "198.51.100.10"
	if err := m.AddBlockedIPs(ctx, []string{ip}); err != nil {
		t.Fatalf("AddBlockedIPs() error = %v", err)
	}

	out, err := r.Run(ctx, "nft", "list", "set", "inet", table, "blocked_ips")
	if err != nil {
		t.Fatalf("list set error = %v", err)
	}
	if !strings.Contains(out, ip) {
		t.Fatalf("expected IP %s in nft set, got:\n%s", ip, out)
	}
}

func TestFirewallEnsureQueueRule(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("integration test requires linux")
	}
	if os.Geteuid() != 0 {
		t.Skip("integration test requires root/privileged container")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("integration test requires nft command")
	}

	r := runner.OSRunner{}
	table := fmt.Sprintf("dpi_queue_test_%d", time.Now().UnixNano())
	m := firewall.NewManager(r, "inet", table, "input", "blocked_ips")

	ctx := context.Background()
	if err := m.Ensure(ctx); err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	t.Cleanup(func() {
		_, _ = r.Run(context.Background(), "nft", "delete", "table", "inet", table)
	})

	const queueNum = uint16(6)
	if err := m.EnsureQueueRule(ctx, queueNum); err != nil {
		t.Fatalf("EnsureQueueRule() error = %v", err)
	}

	out, err := r.Run(ctx, "nft", "list", "chain", "inet", table, "input")
	if err != nil {
		t.Fatalf("list chain error = %v", err)
	}
	expectedCanonical := fmt.Sprintf("queue num %d bypass", queueNum)
	expectedRendered := fmt.Sprintf("queue flags bypass to %d", queueNum)
	if !strings.Contains(out, expectedCanonical) && !strings.Contains(out, expectedRendered) {
		t.Fatalf("expected queue rule in chain, got:\n%s", out)
	}
}
