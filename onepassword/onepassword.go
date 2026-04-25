package onepassword

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const fetchTimeout = 10 * time.Second

// SecretsProvider resolves "op://<vault>/<item>/<field>" references by
// shelling out to the 1Password CLI ("op"). The CLI handles authentication —
// biometric desktop integration, "op signin" sessions, or a service account
// token via OP_SERVICE_ACCOUNT_TOKEN — so the provider has no auth knobs.
type SecretsProvider struct {
	binary string
}

// NewSecretsProvider locates the op binary on PATH and verifies it can
// access 1Password by invoking "op vault list". Returns an error if the
// binary is missing or the CLI cannot authenticate.
//
// "op vault list" is used instead of "op whoami" because the latter does
// not trigger biometric desktop integration and reports "not signed in"
// even when other commands work fine.
func NewSecretsProvider(ctx context.Context) (*SecretsProvider, error) {
	binary, err := exec.LookPath("op")
	if err != nil {
		return nil, fmt.Errorf("onepassword: locating op binary in PATH: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	var stderr bytes.Buffer
	cmd := exec.CommandContext(reqCtx, binary, "vault", "list")
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, fmt.Errorf("onepassword: verifying op CLI auth via vault list: %w: %s", err, msg)
		}
		return nil, fmt.Errorf("onepassword: verifying op CLI auth via vault list: %w", err)
	}

	return &SecretsProvider{binary: binary}, nil
}

func (p *SecretsProvider) FetchSecret(ctx context.Context, secretId string) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(reqCtx, p.binary, "read", secretId) //nolint:gosec // secretId comes from caller config, not external user input; exec runs without a shell
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if stderrMsg := strings.TrimSpace(stderr.String()); stderrMsg != "" {
			return "", fmt.Errorf("onepassword: read secret %q: %w: %s", secretId, err, stderrMsg)
		}
		return "", fmt.Errorf("onepassword: read secret %q: %w", secretId, err)
	}
	return strings.TrimSuffix(stdout.String(), "\n"), nil
}
