package cloudsecrets

import (
	"context"
	"fmt"
	"reflect"

	"github.com/0xsequence/go-cloudsecrets/gcp"
	"github.com/0xsequence/go-cloudsecrets/nosecrets"
	"golang.org/x/sync/errgroup"
)

// Hydrate recursively walks a given config (struct pointer) and hydrates all
// string values matching "$SECRET:" prefix using a given Cloud secrets provider.
//
// The secret values to be replaced must have a format of "$SECRET:{name|path}".
//
// Supported providers:
// - "gcp": Google Cloud Secret Manager
// - "":    If no provider is given, walk the config and fail on any "$SECRET:".
func Hydrate(ctx context.Context, providerName string, config interface{}) error {
	var err error
	var provider secretsProvider

	switch providerName {
	case "":
		// No provider configured. If we see a $SECRET: value, we fail.
		provider = nosecrets.NewSecretsProvider()

	case "gcp":
		provider, err = gcp.NewSecretsProvider()
		if err != nil {
			return fmt.Errorf("creating gcp provider: %w", err)
		}

	default:
		return fmt.Errorf("unsupported provider %q", providerName)
	}

	v := reflect.ValueOf(config)
	return hydrateConfig(ctx, provider, v)
}

func hydrateConfig(ctx context.Context, provider secretsProvider, v reflect.Value) error {
	if v.Kind() != reflect.Ptr {
		return fmt.Errorf("passed config must be a pointer")
	}
	if v.IsNil() {
		return fmt.Errorf("passed config is nil")
	}

	v = ptrDeref(v)
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("passed config must be pointer to a struct, got pointer to %s", v.Kind())
	}

	secretKeys := collectSecretKeys(v)
	secrets := make([]secret, len(secretKeys))

	g := &errgroup.Group{}
	for i, key := range secretKeys {
		i, key := i, key

		g.Go(func() error {
			value, err := provider.FetchSecret(ctx, key)
			secrets[i] = secret{
				key:      key,
				value:    value,
				fetchErr: err,
			}

			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}

	return replaceSecrets(v, secrets)
}

func ptrDeref(v reflect.Value) reflect.Value {
	if v.Kind() == reflect.Ptr {
		if v = v.Elem(); v.Kind() == reflect.Ptr {
			return ptrDeref(v)
		}
	}
	return v
}

type secret struct {
	key      string
	value    string
	fetchErr error
}
