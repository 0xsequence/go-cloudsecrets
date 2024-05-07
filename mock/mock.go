package mock

import (
	"context"
	"fmt"
)

type SecretsProvider struct {
	secrets map[string]string
}

func NewSecretsProvider(secrets map[string]string) *SecretsProvider {
	return &SecretsProvider{secrets: secrets}
}

func (p SecretsProvider) FetchSecret(ctx context.Context, secretId string) (string, error) {
	secret, ok := p.secrets[secretId]
	if !ok {
		return "", fmt.Errorf("find secret %q", secretId)
	}

	return secret, nil
}
