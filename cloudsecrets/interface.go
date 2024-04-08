package cloudsecrets

import (
	"context"
)

type secretsProvider interface {
	FetchSecret(ctx context.Context, secretId string) (string, error)

	// TODO: Support bulk operation, i.e. FetchSecrets(ctx, map[string]string).
	// TODO: Support version.
}
