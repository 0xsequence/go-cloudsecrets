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

	return processConfig(ctx, secretStorage, v)
}

func processConfig(ctx context.Context, storage SecretStorage, config reflect.Value) error {
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
				err := processConfig(ctx, storage, field)
				mux.Unlock()
				if err != nil {
					return fmt.Errorf("failed to process config: %w", err)
				}
				return nil
			}

			if field.Kind() == reflect.String && field.CanSet() && strings.Contains(field.String(), "SECRET") {
				_, secretName, found := strings.Cut(field.String(), ":")
				if !found {
					return fmt.Errorf("invalid config format: %s", field.String())
				}
				secretValue, err := storage.FetchSecret(ctx, secretName, "latest")
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
