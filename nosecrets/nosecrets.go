package nosecrets

import (
	"context"
	"errors"
	"fmt"
)

var ErrNoSecretsProvider = errors.New("secret found but no secrets provider was configured")

// A default secret that fails on fetching any $SECRET:
type SecretsProvider struct{}

func NewSecretsProvider() *SecretsProvider {
	return &SecretsProvider{}
}

func (storage SecretsProvider) FetchSecret(ctx context.Context, secretId string) (string, error) {
	return "", fmt.Errorf("fetch secret %q: %w", secretId, ErrNoSecretsProvider)
}
