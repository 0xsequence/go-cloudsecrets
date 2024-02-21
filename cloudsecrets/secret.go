package cloudsecrets

import "context"

type SecretStorage interface {
	// FetchSecret
	// Abstraction to fetch value from secret store
	// GCP uses versioning for each secret, you can always fetch the latest version by setting versionId="latest"
	FetchSecret(ctx context.Context, secretId string, versionId string) (string, error)
}
