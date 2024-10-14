package cloudsecrets

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
)

func replaceSecrets(v reflect.Value, secretValues map[string]string) error {
	c := &replacer{
		secrets: secretValues,
	}
	c.replaceSecrets(v, "config")
	if c.err != nil {
		return fmt.Errorf("failed to collect fields: %w", c.err)
	}

	return nil
}

type replacer struct {
	secrets map[string]string
	err     error
}

// Walk given value recursively and replace all string fields matching $SECRET: prefix.
func (c *replacer) replaceSecrets(v reflect.Value, path string) {
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			return
		}

		// Dereference pointer
		c.replaceSecrets(v.Elem(), path)

	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			c.replaceSecrets(field, fmt.Sprintf("%v.%v", path, v.Type().Field(i).Name))
		}

	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			item := v.Index(i)
			c.replaceSecrets(item, fmt.Sprintf("%v[%v]", path, i))
		}

	case reflect.Map:
		for _, key := range v.MapKeys() {
			item := v.MapIndex(key)

			if item.Kind() == reflect.Struct {
				// If the value is a struct, create a pointer to the map value and modify via pointer
				ptr := reflect.New(item.Type())
				ptr.Elem().Set(item)

				c.replaceSecrets(ptr, fmt.Sprintf("%v[%v]", path, key))

				// Set the modified struct back into the map
				v.SetMapIndex(key, ptr.Elem())
			} else {
				c.replaceSecrets(item, fmt.Sprintf("%v[%v]", path, key))
			}
		}

	case reflect.String:
		secretName, found := strings.CutPrefix(v.String(), "$SECRET:")
		if !found {
			return
		}

		if !v.CanSet() {
			c.err = errors.Join(c.err, fmt.Errorf("can't set field %v", path))
			return
		}

		secretValue, ok := c.secrets[secretName]
		if !ok {
			c.err = errors.Join(c.err, fmt.Errorf("secret %v not found for field %v", secretName, path))
		}
		v.SetString(secretValue)

	default:
		return
	}
}
