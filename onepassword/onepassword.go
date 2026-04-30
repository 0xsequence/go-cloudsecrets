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
	binary       string
	defaultVault string
	defaultItem  string
}

// Option configures a SecretsProvider.
type Option func(*SecretsProvider)

// WithDefaultPath scopes bare secret names (anything not starting with
// "op://") to the given vault and item. With this option set,
// "$SECRET:FOO" resolves as "op://<vault>/<item>/FOO". Useful for
// migrating configs that previously used short keys via the env provider.
//
// Bare names without a configured default path return an error.
func WithDefaultPath(vault, item string) Option {
	return func(p *SecretsProvider) {
		p.defaultVault = vault
		p.defaultItem = item
	}
}

// NewSecretsProvider locates the op binary on PATH and verifies it can
// access 1Password by invoking "op vault list". Returns an error if the
// binary is missing or the CLI cannot authenticate.
//
// "op vault list" is used instead of "op whoami" because the latter does
// not trigger biometric desktop integration and reports "not signed in"
// even when other commands work fine.
func NewSecretsProvider(ctx context.Context, opts ...Option) (*SecretsProvider, error) {
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

	p := &SecretsProvider{binary: binary}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

func (p *SecretsProvider) FetchSecret(ctx context.Context, secretId string) (string, error) {
	ref, err := p.resolveRef(secretId)
	if err != nil {
		return "", err
	}

	reqCtx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(reqCtx, p.binary, "read", ref) //nolint:gosec // ref is built from caller config and (optionally) configured defaults; exec runs without a shell
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if stderrMsg := strings.TrimSpace(stderr.String()); stderrMsg != "" {
			return "", fmt.Errorf("onepassword: read secret %q: %w: %s", ref, err, stderrMsg)
		}
		return "", fmt.Errorf("onepassword: read secret %q: %w", ref, err)
	}
	return strings.TrimSuffix(stdout.String(), "\n"), nil
}

// resolveRef returns a full "op://" URI for the given secretId. Pass-through
// when secretId already starts with "op://"; prepended with the configured
// default vault/item otherwise. Bare names with no default path error out.
func (p *SecretsProvider) resolveRef(secretId string) (string, error) {
	if strings.HasPrefix(secretId, "op://") {
		return secretId, nil
	}
	if p.defaultVault == "" || p.defaultItem == "" {
		return "", fmt.Errorf("onepassword: secret %q is not a full op:// URI and no default path configured (use WithDefaultPath)", secretId)
	}
	return fmt.Sprintf("op://%s/%s/%s", p.defaultVault, p.defaultItem, secretId), nil
}
