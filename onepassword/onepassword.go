package onepassword

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/1password/onepassword-sdk-go"
)

const (
	integrationName    = "go-cloudsecrets"
	integrationVersion = "v1.0.0"
	fetchTimeout       = 10 * time.Second
)

// SecretsProvider resolves "op://<vault>/<item>/<field>" references via the
// official 1Password Go SDK. The service account token is read from the
// OP_SERVICE_ACCOUNT_TOKEN environment variable.
type SecretsProvider struct {
	client *onepassword.Client
}

func NewSecretsProvider(ctx context.Context) (*SecretsProvider, error) {
	token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("onepassword: OP_SERVICE_ACCOUNT_TOKEN not set")
	}

	client, err := onepassword.NewClient(ctx,
		onepassword.WithServiceAccountToken(token),
		onepassword.WithIntegrationInfo(integrationName, integrationVersion),
	)
	if err != nil {
		return nil, fmt.Errorf("onepassword: new client: %w", err)
	}

	return &SecretsProvider{client: client}, nil
}

func (p *SecretsProvider) FetchSecret(ctx context.Context, secretId string) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	value, err := p.client.Secrets().Resolve(reqCtx, secretId)
	if err != nil {
		return "", fmt.Errorf("onepassword: resolve secret %q: %w", secretId, err)
	}
	return value, nil
}
