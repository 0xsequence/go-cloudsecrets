package cloudsecrets

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
)

func HydrateSecrets(ctx context.Context, secretStorage SecretStorage, config any) error {
	configValue := reflect.ValueOf(config)

	if configValue.Kind() == reflect.Ptr {
		if configValue.IsNil() {
			return fmt.Errorf("passed config is nil")
		}

		configValue = configValue.Elem()
	}

	if configValue.Kind() != reflect.Struct {
		return fmt.Errorf("passed config must be struct, actual %s", configValue.Kind())
	}

	errCh := make(chan error)
	wg := &sync.WaitGroup{}
	hydrateStructFields(ctx, secretStorage, configValue, wg, errCh)
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

func hydrateStructFields(ctx context.Context, storage SecretStorage, config reflect.Value, wg *sync.WaitGroup, errCh chan error) {
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
			hydrateStructFields(ctx, storage, field, wg, errCh)
			continue
		}

		if field.Kind() == reflect.String && field.CanSet() && strings.Contains(field.String(), "SECRET:") {
			secretName, _ := strings.CutPrefix(field.String(), "SECRET:")

			wg.Add(1)
			go func(field reflect.Value, secretName string) {
				defer wg.Done()
				secretValue, err := storage.FetchSecret(ctx, secretName)
				if err != nil {
					errCh <- fmt.Errorf("fetch secret failed for field %s: %w", secretName, err)
					return
				}
				field.SetString(secretValue)
			}(field, secretName)
		}
	}
}
