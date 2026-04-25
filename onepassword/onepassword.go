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

func NewSecretsProvider() (*SecretsProvider, error) {
	binary, err := exec.LookPath("op")
	if err != nil {
		return nil, fmt.Errorf("onepassword: locating op binary in PATH: %w", err)
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
