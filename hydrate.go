package cloudsecrets

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
)

// Hydrate hydrates "obj" secrets from a given Cloud secrets provider.
// Values are hydrated if they start with "$SECRET:" prefix following the name/path of the secret.
//
// Currently, only a pointer to struct is supported as an obj.
func Hydrate(ctx context.Context, cloudProvider string, obj interface{}) error {
	var (
		err      error
		provider secretsProvider
	)

	switch cloudProvider {
	case "gcp":
		provider, err = NewGCPSecretStorage()
		if err != nil {
			return fmt.Errorf("failed to init gcp secret store: %w", err)
		}

	default:
		return fmt.Errorf("unsupported provider %q", cloudProvider)
	}

	v := reflect.ValueOf(obj)
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
			return fmt.Errorf("failed to process config: %w", err)
		}
	}

	return nil
}

func hydrateStructFields(ctx context.Context, provider secretsProvider, config reflect.Value, wg *sync.WaitGroup, errCh chan error) {
	for i := 0; i < config.NumField(); i++ {
		field := config.Field(i)

		if field.Kind() == reflect.Ptr {
			if field.IsNil() {
				continue
			}
			// Dereference pointer
			field = field.Elem()
		}

		if field.Kind() == reflect.Struct {
			hydrateStructFields(ctx, provider, field, wg, errCh)
			continue
		}

		if field.Kind() == reflect.String && field.CanSet() {
			secretName, found := strings.CutPrefix(field.String(), "$SECRET:")
			if found {
				wg.Add(1)
				go func(field reflect.Value, secretName string) {
					defer wg.Done()
					secretValue, err := provider.FetchSecret(ctx, secretName)
					if err != nil {
						errCh <- fmt.Errorf("fetch secret failed for field %s: %w", secretName, err)
						return
					}
					field.SetString(secretValue)
				}(field, secretName)
			}
		}
	}
}
