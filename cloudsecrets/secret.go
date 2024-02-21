package cloudsecrets

import "context"

type SecretStorage interface {
	FetchSecret(ctx context.Context, secretId string) (string, error)
}
