package cloudsecrets

import (
	"context"
	"fmt"
	"reflect"

	"golang.org/x/sync/errgroup"
)

// Hydrate recursively walks a given config (struct pointer) and hydrates all
// string values matching "$SECRET:" prefix using the given secrets provider.
//
// The secret values to be replaced must have a format of "$SECRET:{name|path}".
func Hydrate(ctx context.Context, provider SecretsProvider, config any) error {
	v := reflect.ValueOf(config)
	if v.Kind() != reflect.Pointer {
		return fmt.Errorf("passed config must be a pointer")
	}
	if v.IsNil() {
		return fmt.Errorf("passed config is nil")
	}

	for v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("passed config must be pointer to a struct, got pointer to %s", v.Kind())
	}

	keys := collectSecretKeys(v)

	secrets := make([]secret, len(keys))

	g := &errgroup.Group{}
	for i, key := range keys {
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
