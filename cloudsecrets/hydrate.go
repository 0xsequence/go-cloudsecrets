package cloudsecrets

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
)

func HydrateSecrets(ctx context.Context, secretStorage SecretStorage, config any) error {
	v := reflect.ValueOf(config)

	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return fmt.Errorf("passed config is nil")
		}

		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return fmt.Errorf("passed config must be struct, actual %s", v.Kind())
	}

	return hydrateStructFields(ctx, secretStorage, v)
}

func hydrateStructFields(ctx context.Context, storage SecretStorage, config reflect.Value) error {
	g, ctx := errgroup.WithContext(ctx)
	var mux sync.Mutex

	for i := 0; i < config.NumField(); i++ {
		field := config.Field(i)
		g.Go(func() error {
			if field.Kind() == reflect.Ptr {
				if field.IsNil() {
					return nil
				}
				// Dereference pointer
				field = field.Elem()
			}

			if field.Kind() == reflect.Struct {
				mux.Lock()
				err := hydrateStructFields(ctx, storage, field)
				mux.Unlock()
				if err != nil {
					return fmt.Errorf("failed to process config: %w", err)
				}
				return nil
			}

			if field.Kind() == reflect.String && field.CanSet() && strings.Contains(field.String(), "SECRET") {
				secretName, found := strings.CutPrefix(field.String(), "SECRET:")
				if !found {
					return fmt.Errorf("invalid config format: %s", field.String())
				}
				secretValue, err := storage.FetchSecret(ctx, secretName)
				if err != nil {
					return err
				}
				mux.Lock()
				field.SetString(secretValue)
				mux.Unlock()
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}
	return nil
}
