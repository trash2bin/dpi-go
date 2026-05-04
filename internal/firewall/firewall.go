package firewall

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"dpi-kyrsach/internal/runner"
)

// Manager manages nftables resources for IP blocklist
type Manager struct {
	Runner  runner.CommandRunner
	Family  string
	Table   string
	Chain   string
	SetName string
}

func NewManager(r runner.CommandRunner, family, table, chain, setName string) Manager {
	return Manager{
		Runner:  r,
		Family:  strings.TrimSpace(family),
		Table:   strings.TrimSpace(table),
		Chain:   strings.TrimSpace(chain),
		SetName: strings.TrimSpace(setName),
	}
}

// Ensure makes sure table/chain/set/rule exist
func (m Manager) Ensure(ctx context.Context) error {
	if err := m.validate(); err != nil {
		return err
	}

	if err := m.ensureTable(ctx); err != nil {
		return err
	}
	if err := m.ensureChain(ctx); err != nil {
		return err
	}
	if err := m.ensureSet(ctx); err != nil {
		return err
	}
	if err := m.ensureDropRule(ctx); err != nil {
		return err
	}

	return nil
}

// EnsureQueueRule creates an nfqueue rule for TCP packets if missing.
func (m Manager) EnsureQueueRule(ctx context.Context, queueNum uint16) error {
	if err := m.validate(); err != nil {
		return err
	}

	for _, chain := range []string{m.Chain, m.Chain + "_forward"} {
		out, err := m.Runner.Run(ctx, "nft", "list", "chain", m.Family, m.Table, chain)
		if err != nil {
			return fmt.Errorf("inspect chain %s/%s/%s for queue rule: %w", m.Family, m.Table, chain, err)
		}

		if hasQueueRule(out, queueNum) {
			continue
		}

		_, err = m.Runner.Run(ctx, "nft", "add", "rule", m.Family, m.Table, chain,
			"meta", "l4proto", "tcp", "queue", "num", strconv.Itoa(int(queueNum)), "bypass")
		if err != nil && !isAlreadyExists(err) {
			return fmt.Errorf("create queue rule for queue %d in chain %s: %w", queueNum, chain, err)
		}
	}
	return nil
}

func hasQueueRule(chainDump string, queueNum uint16) bool {
	canonical := fmt.Sprintf("queue num %d bypass", queueNum)
	nftRendered := fmt.Sprintf("queue flags bypass to %d", queueNum)
	return strings.Contains(chainDump, canonical) || strings.Contains(chainDump, nftRendered)
}

// AddBlockedIPs appends IPs to nftables set
func (m Manager) AddBlockedIPs(ctx context.Context, ips []string) error {
	if err := m.validate(); err != nil {
		return err
	}

	for _, rawIP := range normalizeValues(ips) {
		if net.ParseIP(rawIP) == nil {
			return fmt.Errorf("invalid IP address: %s", rawIP)
		}

		_, err := m.Runner.Run(ctx, "nft", "add", "element", m.Family, m.Table, m.SetName, "{ "+rawIP+" }")
		if err != nil && !isAlreadyExists(err) {
			return fmt.Errorf("add IP %s to set %s: %w", rawIP, m.SetName, err)
		}
	}

	return nil
}

func (m Manager) validate() error {
	if m.Runner == nil {
		return fmt.Errorf("firewall runner is required")
	}
	if m.Family == "" || m.Table == "" || m.Chain == "" || m.SetName == "" {
		return fmt.Errorf("firewall family/table/chain/set_name are required")
	}
	return nil
}

func (m Manager) ensureTable(ctx context.Context) error {
	if m.exists(ctx, "list", "table", m.Family, m.Table) {
		return nil
	}

	_, err := m.Runner.Run(ctx, "nft", "add", "table", m.Family, m.Table)
	if err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("create table %s/%s: %w", m.Family, m.Table, err)
	}
	return nil
}

func (m Manager) ensureChain(ctx context.Context) error {
	// input — трафик адресованный самому DPI
	if !m.exists(ctx, "list", "chain", m.Family, m.Table, m.Chain) {
		_, err := m.Runner.Run(ctx, "nft", "add", "chain", m.Family, m.Table, m.Chain,
			"{ type filter hook input priority 0; policy accept; }")
		if err != nil && !isAlreadyExists(err) {
			return fmt.Errorf("create input chain: %w", err)
		}
	}

	// forward — транзитный трафик клиента через DPI
	forwardChain := m.Chain + "_forward"
	if !m.exists(ctx, "list", "chain", m.Family, m.Table, forwardChain) {
		_, err := m.Runner.Run(ctx, "nft", "add", "chain", m.Family, m.Table, forwardChain,
			"{ type filter hook forward priority 0; policy accept; }")
		if err != nil && !isAlreadyExists(err) {
			return fmt.Errorf("create forward chain: %w", err)
		}
	}

	return nil
}

func (m Manager) ensureSet(ctx context.Context) error {
	if m.exists(ctx, "list", "set", m.Family, m.Table, m.SetName) {
		return nil
	}

	_, err := m.Runner.Run(ctx, "nft", "add", "set", m.Family, m.Table, m.SetName, "{ type ipv4_addr; }")
	if err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("create set %s/%s/%s: %w", m.Family, m.Table, m.SetName, err)
	}
	return nil
}

func (m Manager) ensureDropRule(ctx context.Context) error {
	for _, chain := range []string{m.Chain, m.Chain + "_forward"} {
		out, err := m.Runner.Run(ctx, "nft", "list", "chain", m.Family, m.Table, chain)
		if err != nil {
			// цепочка ещё не существует тогда пропускаем
			continue
		}

		needle := fmt.Sprintf("ip daddr @%s drop", m.SetName)
		if strings.Contains(out, needle) {
			continue
		}

		_, err = m.Runner.Run(ctx, "nft", "add", "rule", m.Family, m.Table, chain,
			"ip", "daddr", "@"+m.SetName, "drop")
		if err != nil && !isAlreadyExists(err) {
			return fmt.Errorf("create drop rule for set %s in chain %s: %w", m.SetName, chain, err)
		}
	}
	return nil
}

func (m Manager) exists(ctx context.Context, args ...string) bool {
	_, err := m.Runner.Run(ctx, "nft", args...)
	return err == nil
}

func isAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "file exists")
}

func normalizeValues(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		v := strings.TrimSpace(value)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
