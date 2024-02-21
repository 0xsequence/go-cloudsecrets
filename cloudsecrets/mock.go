package cloudsecrets

import (
	"context"
	"fmt"
)

type MockSecretStorage struct {
	secrets map[string]string
}

func NewMockSecretStorage(secrets map[string]string) *MockSecretStorage {
	return &MockSecretStorage{secrets: secrets}
}

func (storage MockSecretStorage) FetchSecret(ctx context.Context, secretId string, versionId string) (string, error) {
	secret, ok := storage.secrets[secretId]
	if !ok {
		return "", fmt.Errorf("failed to find secret %s in storage", secretId)
	}

	return secret, nil
}
