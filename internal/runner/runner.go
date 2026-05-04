package runner

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// CommandRunner executes system commands and returns combined output.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// OSRunner executes commands using os/exec.
type OSRunner struct{}

// Run executes a command and returns trimmed stdout/stderr.
func (OSRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	result := strings.TrimSpace(string(out))
	if err != nil {
		if result == "" {
			return "", fmt.Errorf("command %q failed: %w", label(name, args), err)
		}
		return result, fmt.Errorf("command %q failed: %w: %s", label(name, args), err, result)
	}
	return result, nil
}

func label(name string, args []string) string {
	if len(args) == 0 {
		return name
	}
	return name + " " + strings.Join(args, " ")
}
