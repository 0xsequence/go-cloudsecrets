package cloudsecrets

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/0xsequence/go-cloudsecrets/gcp"
	"github.com/0xsequence/go-cloudsecrets/nosecrets"
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
	return hydrateStruct(ctx, provider, v)
}

func hydrateStruct(ctx context.Context, provider secretsProvider, v reflect.Value) error {
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return fmt.Errorf("passed config is nil")
		}

		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return fmt.Errorf("passed config must be struct, actual %s", v.Kind())
	}

	errCh := make(chan error)
	wg := &sync.WaitGroup{}
	hydrateStructFields(ctx, provider, v, wg, errCh)
	go func() {
		wg.Wait()
		close(errCh)
	}()

	select {
	case err, ok := <-errCh:
		if !ok {
			return nil
		}
		if err != nil {
			return fmt.Errorf("walking struct fields: %w", err)
		}
	}

	return nil
}

func hydrateStructFields(ctx context.Context, provider secretsProvider, config reflect.Value, wg *sync.WaitGroup, errCh chan error) {
	for i := 0; i < config.NumField(); i++ {
		field := config.Field(i)

		switch field.Kind() {
		case reflect.Ptr:
			if field.IsNil() {
				continue
			}
			// Dereference pointer
			field = field.Elem()

		case reflect.Struct:
			hydrateStructFields(ctx, provider, field, wg, errCh)
			continue

		case reflect.String:
			if !field.CanSet() {
				continue
			}

			secretName, found := strings.CutPrefix(field.String(), "$SECRET:")
			if found {
				wg.Add(1)
				go func(fieldName string, field reflect.Value, secretName string) {
					defer wg.Done()
					secretValue, err := provider.FetchSecret(ctx, secretName)
					if err != nil {
						errCh <- fmt.Errorf("%v=%q: %w", fieldName, field.String(), err)
						return
					}
					field.SetString(secretValue)
				}(config.Type().Field(i).Name, field, secretName)
			}
		}
	}
}
