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
			return fmt.Errorf("creating gcp secret provider: %w", err)
		}

	default:
		return fmt.Errorf("unsupported provider %q", providerName)
	}

	v := reflect.ValueOf(config)
	return hydrateConfig(ctx, provider, v)
}

func hydrateConfig(ctx context.Context, provider secretsProvider, v reflect.Value) error {
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return fmt.Errorf("passed config is nil")
		}
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return fmt.Errorf("passed config must be struct, actual %s", v.Kind())
	}

	c := &collector{}
	c.collectSecretFields(v, "config")
	if c.err != nil {
		return fmt.Errorf("failed to collect fields: %w", c.err)
	}

	g := &errgroup.Group{}
	for _, field := range c.fields {
		field := field

		g.Go(func() error {
			secretValue, err := provider.FetchSecret(ctx, field.secretName)
			if err != nil {
				return fmt.Errorf("failed to fetch secret %v=%q: %w", field.fieldPath, field.value.String(), err)
			}
			field.value.SetString(secretValue)

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("failed to hydrate config: %w", err)
	}

	for _, hook := range c.hooks {
		hook()
	}

	return nil
}
