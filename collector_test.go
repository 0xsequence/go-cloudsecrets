package cloudsecrets

import (
	"fmt"
	"reflect"
	"testing"
)

type config1 struct {
	DB         dbConfig
	JWTSecrets []jwtSecret
	Providers  map[string]*providerConfig
	DoublePtr  **providerConfig
	unexported dbConfig
}

type dbConfig struct {
	User     string
	Password string
}

type providerConfig struct {
	Name   string
	Secret string
}

type jwtSecret string

func TestCollectFields(t *testing.T) {
	tt := []struct {
		Name  string
		Input any
		Out   []string // field paths
		Error bool
	}{
		{
			Name: "Basic DB config with no creds",
			Input: &config1{
				DB: dbConfig{
					User:     "db-user",
					Password: "db-password",
				},
			},
			Out: []string{},
		},
		{
			Name: "Basic DB config with creds",
			Input: &config1{
				DB: dbConfig{
					User:     "db-user",
					Password: "$SECRET:db-password",
				},
			},
			Out: []string{"db-password"},
		},
		{
			Name: "Slice of secrets",
			Input: &config1{
				DB: dbConfig{
					User:     "db-user",
					Password: "$SECRET:secretName",
				},
				JWTSecrets: []jwtSecret{"$SECRET:jwtSecret1", "$SECRET:jwtSecret2", "nope"},
			},
			Out: []string{"secretName", "jwtSecret1", "jwtSecret2"},
		},
		{
			Name: "Map with secrets",
			Input: &config1{
				Providers: map[string]*providerConfig{
					"provider1": {Name: "provider1", Secret: "$SECRET:secretProvider1"},
					"provider2": {Name: "provider2", Secret: "$SECRET:secretProvider2"},
					"provider3": {Name: "provider3", Secret: "$SECRET:secretProvider3"},
				},
			},
			Out: []string{"secretProvider1", "secretProvider2", "secretProvider3"},
		},
		{
			Name: "Double pointer",
			Input: &config1{
				DoublePtr: ptr(&providerConfig{Name: "double-pointer", Secret: "$SECRET:double-pointer-secret"}),
			},
			Out: []string{"double-pointer-secret"},
		},
		{
			Name: "Unexported field should fail to hydrate",
			Input: &config1{
				unexported: dbConfig{ // unexported fields can't be updated via reflect pkg
					User:     "db-user",
					Password: "$SECRET:secretName", // match inside unexported field
				},
			},
			Out:   []string{},
			Error: true, // expect error
		},
	}

	for i, tc := range tt {
		i, tc := i, tc
		t.Run(fmt.Sprintf("tt[%v]: %v", i, tc.Name), func(t *testing.T) {
			v := reflect.ValueOf(tc.Input)

			c := &collector{}
			c.collectSecretFields(v, fmt.Sprintf("tt[%v].input", i))

			if tc.Error {
				if c.err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if c.err != nil {
					t.Errorf("unexpected error: %v", c.err)
				}
			}

			if len(c.fields) != len(tc.Out) {
				t.Errorf("expected %v secrets, got %v", len(tc.Out), len(c.fields))
			}
			for i := 0; i < len(c.fields); i++ {
				if c.fields[i].secretName != tc.Out[i] {
					t.Errorf("collected field[%v].secretName=%v doesn't match tc.Out[%v]=%v", i, c.fields[i].secretName, i, tc.Out[i])
				}
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }
