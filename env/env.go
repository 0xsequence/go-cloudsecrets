package env

import (
	"context"
	"fmt"
	"os"
)

// SecretsProvider fetches secrets from environment variables with a configurable prefix.
// It is used for testing and local development, allowing users to set secrets as environment variables.
type SecretsProvider struct {
	prefix string
}

func NewSecretsProvider(prefix string) (*SecretsProvider, error) {
	return &SecretsProvider{prefix: prefix}, nil
}

func (p SecretsProvider) FetchSecret(ctx context.Context, secretId string) (string, error) {
	value := os.Getenv(p.prefix + secretId)
	if value == "" {
		return "", fmt.Errorf("env: secret %q not found", secretId)
	}
	return value, nil
}
