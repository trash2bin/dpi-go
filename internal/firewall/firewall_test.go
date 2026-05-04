package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type response struct {
	out string
	err error
}

type scriptedRunner struct {
	script   map[string][]response
	commands []string
}

func (s *scriptedRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	s.commands = append(s.commands, cmd)

	if queue, ok := s.script[cmd]; ok && len(queue) > 0 {
		resp := queue[0]
		s.script[cmd] = queue[1:]
		return resp.out, resp.err
	}
	return "", nil
}

func TestEnsureCreatesMissingResources(t *testing.T) {
	t.Parallel()

	runner := &scriptedRunner{
		script: map[string][]response{
			"nft list table inet dpi":           {{err: errors.New("not found")}},
			"nft list chain inet dpi input":     {{err: errors.New("not found")}, {out: "chain input {}"}},
			"nft list set inet dpi blocked_ips": {{err: errors.New("not found")}},
			"nft add table inet dpi":            {{out: "ok"}},
			"nft add chain inet dpi input { type filter hook input priority 0; policy accept; }": {{out: "ok"}},
			"nft add set inet dpi blocked_ips { type ipv4_addr; }":                               {{out: "ok"}},
			"nft add rule inet dpi input ip daddr @blocked_ips drop":                             {{out: "ok"}},
		},
	}

	m := NewManager(runner, "inet", "dpi", "input", "blocked_ips")
	if err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}

	joined := strings.Join(runner.commands, "\n")
	for _, expected := range []string{
		"nft add table inet dpi",
		"nft add chain inet dpi input { type filter hook input priority 0; policy accept; }",
		"nft add set inet dpi blocked_ips { type ipv4_addr; }",
		"nft add rule inet dpi input ip daddr @blocked_ips drop",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("expected command %q in sequence:\n%s", expected, joined)
		}
	}
}

func TestAddBlockedIPsRejectsInvalidIP(t *testing.T) {
	t.Parallel()

	runner := &scriptedRunner{script: map[string][]response{}}
	m := NewManager(runner, "inet", "dpi", "input", "blocked_ips")

	err := m.AddBlockedIPs(context.Background(), []string{"1.1.1.1", "not-an-ip"})
	if err == nil {
		t.Fatal("AddBlockedIPs() expected error for invalid IP")
	}

	joined := strings.Join(runner.commands, "\n")
	if !strings.Contains(joined, "nft add element inet dpi blocked_ips { 1.1.1.1 }") {
		t.Fatalf("expected command for valid IP before invalid failure, got:\n%s", joined)
	}
}

func TestEnsureQueueRuleAddsRuleIfMissing(t *testing.T) {
	t.Parallel()

	runner := &scriptedRunner{
		script: map[string][]response{
			"nft list chain inet dpi input":                                   {{out: "chain input { type filter hook input priority filter; policy accept; }"}},
			"nft add rule inet dpi input meta l4proto tcp queue num 5 bypass": {{out: "ok"}},
		},
	}
	m := NewManager(runner, "inet", "dpi", "input", "blocked_ips")

	if err := m.EnsureQueueRule(context.Background(), 5); err != nil {
		t.Fatalf("EnsureQueueRule() error = %v", err)
	}

	joined := strings.Join(runner.commands, "\n")
	if !strings.Contains(joined, "nft add rule inet dpi input meta l4proto tcp queue num 5 bypass") {
		t.Fatalf("expected queue rule command in sequence:\n%s", joined)
	}
}

func TestEnsureQueueRuleSkipsWhenAlreadyPresent(t *testing.T) {
	t.Parallel()

	runner := &scriptedRunner{
		script: map[string][]response{
			"nft list chain inet dpi input":         {{out: "chain input { meta l4proto tcp queue num 7 bypass }"}},
			"nft list chain inet dpi input_forward": {{out: "chain input_forward { meta l4proto tcp queue num 7 bypass }"}},
		},
	}
	m := NewManager(runner, "inet", "dpi", "input", "blocked_ips")

	if err := m.EnsureQueueRule(context.Background(), 7); err != nil {
		t.Fatalf("EnsureQueueRule() error = %v", err)
	}

	joined := strings.Join(runner.commands, "\n")
	if strings.Contains(joined, "nft add rule inet dpi input ") ||
		strings.Contains(joined, "nft add rule inet dpi input_forward ") {
		t.Fatalf("did not expect add rule command when queue rule exists:\n%s", joined)
	}
}

func TestEnsureQueueRuleSkipsWhenPresentInNFTOutputFormat(t *testing.T) {
	t.Parallel()

	runner := &scriptedRunner{
		script: map[string][]response{
			"nft list chain inet dpi input":         {{out: "chain input { meta l4proto tcp queue flags bypass to 7 }"}},
			"nft list chain inet dpi input_forward": {{out: "chain input_forward { meta l4proto tcp queue flags bypass to 7 }"}},
		},
	}
	m := NewManager(runner, "inet", "dpi", "input", "blocked_ips")

	if err := m.EnsureQueueRule(context.Background(), 7); err != nil {
		t.Fatalf("EnsureQueueRule() error = %v", err)
	}

	joined := strings.Join(runner.commands, "\n")
	if strings.Contains(joined, "nft add rule inet dpi input ") ||
		strings.Contains(joined, "nft add rule inet dpi input_forward ") {
		t.Fatalf("did not expect add rule command when nft output already contains queue rule:\n%s", joined)
	}
}
