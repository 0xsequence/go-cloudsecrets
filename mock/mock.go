package mock

import (
	"context"
	"fmt"
)

type SecretProvider struct {
	secrets map[string]string
}

func NewSecretProvider(secrets map[string]string) *SecretProvider {
	return &SecretProvider{secrets: secrets}
}

func (p SecretProvider) FetchSecret(ctx context.Context, secretId string) (string, error) {
	secret, ok := p.secrets[secretId]
	if !ok {
		return "", fmt.Errorf("failed to find secret %q", secretId)
	}

	return secret, nil
}
