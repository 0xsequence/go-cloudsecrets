package cloudsecrets

import (
	"fmt"
	"reflect"
	"strings"
)

func collectSecretFields(v reflect.Value) (map[string]string, error) {
	c := &collector{
		fields: map[string]string{},
	}
	c.collectSecretFields(v, "config")
	if c.err != nil {
		return nil, fmt.Errorf("failed to collect fields: %w", c.err)
	}

	return c.fields, nil
}

type collector struct {
	fields map[string]string
	err    error
}

// Walks given reflect value recursively and collects any string fields matching $SECRET: prefix.
func (c *collector) collectSecretFields(v reflect.Value, path string) {
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			return
		}

		// Dereference pointer
		c.collectSecretFields(v.Elem(), path)

	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			c.collectSecretFields(field, fmt.Sprintf("%v.%v", path, v.Type().Field(i).Name))
		}

	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			item := v.Index(i)
			c.collectSecretFields(item, fmt.Sprintf("%v[%v]", path, i))
		}

	case reflect.Map:
		for _, key := range v.MapKeys() {
			item := v.MapIndex(key)

			if item.Kind() == reflect.Struct {
				// If the value is a struct, create a pointer to the map value and modify via pointer
				ptr := reflect.New(item.Type())
				ptr.Elem().Set(item)

				c.collectSecretFields(ptr, fmt.Sprintf("%v[%v]", path, key))

				// Set the modified struct back into the map
				v.SetMapIndex(key, ptr.Elem())
			} else {
				c.collectSecretFields(item, fmt.Sprintf("%v[%v]", path, key))
			}
		}

	case reflect.String:
		secretName, found := strings.CutPrefix(v.String(), "$SECRET:")
		if !found {
			return
		}

		if _, ok := c.fields[secretName]; !ok {
			c.fields[secretName] = path
		}

	default:
		return
	}
}
