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

func NewSecretsProvider(prefix string) *SecretsProvider {
	return &SecretsProvider{prefix: prefix}
}

func (p SecretsProvider) FetchSecret(ctx context.Context, secretId string) (string, error) {
	name := p.prefix + secretId
	value, ok := os.LookupEnv(name)
	if !ok {
		return "", fmt.Errorf("env: fetch secret %q: not found", name)
	}
	return value, nil
}
