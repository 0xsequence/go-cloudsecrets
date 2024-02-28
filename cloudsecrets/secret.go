package cloudsecrets

import (
	"context"
	"fmt"
)

type SecretStorageType string

const (
	GCP SecretStorageType = "gcp"
)

var initializeSecretStorage = func(secretStorageType SecretStorageType) (SecretStorage, error) {
	switch secretStorageType {
	case GCP:
		return NewGCPSecretStorage()
	}

	return nil, fmt.Errorf("failed to initialize storage: %v", secretStorageType)
}

type SecretStorage interface {
	// FetchSecret
	// Abstraction to fetch value from secret store
	// GCP uses versioning for each secret, you can always fetch the latest version by setting versionId="latest"
	FetchSecret(ctx context.Context, secretId string) (string, error)
}
