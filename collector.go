package cloudsecrets

import (
	"reflect"
	"slices"
	"strings"
)

// Returns de-duplicated secret keys found recursively in given v.
func collectSecretKeys(v reflect.Value) []string {
	c := collector{}
	c.collectSecretFields(v)

	slices.Sort(c)
	dedup := slices.Compact(c)

	return []string(dedup)
}

type collector []string

// Walk given reflect value recursively and collects any string fields matching $SECRET: prefix.
func (c *collector) collectSecretFields(v reflect.Value) {
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			return
		}
		c.collectSecretFields(v.Elem())

	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			c.collectSecretFields(field)
		}

	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			item := v.Index(i)
			c.collectSecretFields(item)
		}

	case reflect.Map:
		for _, key := range v.MapKeys() {
			item := v.MapIndex(key)
			c.collectSecretFields(item)
		}

	case reflect.String:
		secretName, found := strings.CutPrefix(v.String(), "$SECRET:")
		if !found {
			return
		}
		*c = append(*c, secretName)

	default:
		return
	}
}
