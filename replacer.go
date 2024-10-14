package cloudsecrets

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
)

// Replace values with "$SECRET:" prefix in v with values from secrets.
func replaceSecrets(v reflect.Value, secrets []secret) error {
	r := &replacer{
		secretValues: map[string]string{},
		fetchErrors:  map[string]error{},
	}
	for _, secret := range secrets {
		if secret.fetchErr != nil {
			r.fetchErrors[secret.key] = secret.fetchErr
		} else {
			r.secretValues[secret.key] = secret.value
		}
	}

	r.replaceSecrets(v, "config")
	if len(r.errs) > 0 {
		return fmt.Errorf("failed to replace %v field(s): %w", len(r.errs), errors.Join(r.errs...))
	}

	return nil
}

type replacer struct {
	secretValues map[string]string
	fetchErrors  map[string]error
	errs         []error
}

// Walk given v recursively and try to replace all secrets. Record errors along the way.
func (r *replacer) replaceSecrets(v reflect.Value, path string) {
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			return
		}
		r.replaceSecrets(v.Elem(), path)

	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			r.replaceSecrets(field, fmt.Sprintf("%v.%v", path, v.Type().Field(i).Name))
		}

	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			item := v.Index(i)
			r.replaceSecrets(item, fmt.Sprintf("%v[%v]", path, i))
		}

	case reflect.Map:
		for _, key := range v.MapKeys() {
			item := v.MapIndex(key)

			if item.Kind() == reflect.Struct {
				// If the value is a struct, create a pointer to it, update the value and reassign the map.
				ptr := reflect.New(item.Type())
				ptr.Elem().Set(item)
				r.replaceSecrets(ptr, fmt.Sprintf("%v[%v]", path, key))
				v.SetMapIndex(key, ptr.Elem())
			} else {
				r.replaceSecrets(item, fmt.Sprintf("%v[%v]", path, key))
			}
		}

	case reflect.String:
		secretKey, found := strings.CutPrefix(v.String(), "$SECRET:")
		if !found {
			return
		}

		if !v.CanSet() {
			r.errs = append(r.errs, fmt.Errorf("%v: reflect: can't set field", path))
			return
		}

		secretValue, ok := r.secretValues[secretKey]
		if !ok {
			err, _ := r.fetchErrors[secretKey]
			r.errs = append(r.errs, fmt.Errorf("%v: %w", path, err))
			return
		}
		v.SetString(secretValue)

	default:
		return
	}
}
