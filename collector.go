package cloudsecrets

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
)

type secretField struct {
	value      reflect.Value
	fieldPath  string
	secretName string
}

type collector struct {
	fields []*secretField
	err    error
}

// Walks given reflect value recursively and collects any string fields with $SECRET: prefix.
func (g *collector) collectSecretFields(v reflect.Value, path string) {
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			return
		}

		// Dereference pointer
		g.collectSecretFields(v.Elem(), path)

	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			g.collectSecretFields(field, fmt.Sprintf("%v.%v", path, v.Type().Field(i).Name))
		}

	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			item := v.Index(i)
			g.collectSecretFields(item, fmt.Sprintf("%v[%v]", path, i))
		}

	case reflect.Map:
		for _, key := range v.MapKeys() {
			item := v.MapIndex(key)
			g.collectSecretFields(item, fmt.Sprintf("%v[%v]", path, key))
		}

	case reflect.String:
		secretName, found := strings.CutPrefix(v.String(), "$SECRET:")
		if !found {
			return
		}

		if !v.CanSet() {
			g.err = errors.Join(g.err, fmt.Errorf("can't set field %v", path))
			return
		}

		g.fields = append(g.fields, &secretField{
			value:      v,
			fieldPath:  path,
			secretName: secretName,
		})

	default:
		return
	}
}
