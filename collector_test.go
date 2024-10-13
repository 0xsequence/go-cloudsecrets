package cloudsecrets

import (
	"reflect"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestCollectFields(t *testing.T) {
	tt := []struct {
		Name  string
		Input any
		Out   []string // field paths
		Error bool
	}{
		{
			Name: "DB_config_with_no_creds",
			Input: &cfg{
				DB: dbConfig{
					User:     "db-user",
					Password: "db-password",
				},
				DBPtr: &dbConfig{
					User:     "db-user",
					Password: "db-password",
				},
				DBDoublePtr: ptr(&dbConfig{
					User:     "db-user",
					Password: "db-password",
				}),
			},
			Out: []string{},
		},
		{
			Name: "DB_config_with_creds",
			Input: &cfg{
				DB: dbConfig{
					User:     "db-user",
					Password: "$SECRET:db-password",
				},
			},
			Out: []string{"db-password"},
		},
		{
			Name: "DB config ptr with creds",
			Input: &cfg{
				DBPtr: &dbConfig{
					User:     "db-user",
					Password: "$SECRET:db-password",
				},
			},
			Out: []string{"db-password"},
		},
		{
			Name: "DB_config_double_ptr_with_creds",
			Input: &cfg{
				DBDoublePtr: ptr(&dbConfig{
					User:     "db-user",
					Password: "$SECRET:db-password",
				}),
			},
			Out: []string{"db-password"},
		},
		{
			Name: "Slice_of_secret_values",
			Input: &cfg{
				DB: dbConfig{
					User:     "db-user",
					Password: "$SECRET:secretName",
				},
				JWTSecrets: []jwtSecret{"$SECRET:jwtSecret1", "$SECRET:jwtSecret2", "nope"},
			},
			Out: []string{"jwtSecret1", "jwtSecret2", "secretName"},
		},
		{
			Name: "Slice_of_secret_pointer_values",
			Input: &cfg{
				DB: dbConfig{
					User:     "db-user",
					Password: "$SECRET:secretName",
				},
				JWTSecretsPtr: []*jwtSecret{ptr(jwtSecret("$SECRET:jwtSecret1")), ptr(jwtSecret("$SECRET:jwtSecret2")), ptr(jwtSecret("nope"))},
			},
			Out: []string{"jwtSecret1", "jwtSecret2", "secretName"},
		},
		{
			Name: "Map_with_values",
			Input: &cfg{
				Providers: map[string]providerConfig{
					"provider1": {Name: "provider1", Secret: "$SECRET:secretProvider1"},
					"provider2": {Name: "provider2", Secret: "$SECRET:secretProvider2"},
					"provider3": {Name: "provider3", Secret: "$SECRET:secretProvider3"},
				},
			},
			Out: []string{"secretProvider1", "secretProvider2", "secretProvider3"},
		},
		{
			Name: "Map_with_ptr_values",
			Input: &cfg{
				ProvidersPtr: map[string]*providerConfig{
					"provider1": {Name: "provider1", Secret: "$SECRET:secretProvider1"},
					"provider2": {Name: "provider2", Secret: "$SECRET:secretProvider2"},
					"provider3": {Name: "provider3", Secret: "$SECRET:secretProvider3"},
				},
			},
			Out: []string{"secretProvider1", "secretProvider2", "secretProvider3"},
		},
		{
			Name: "Duplicated_secret",
			Input: &cfg{
				DB: dbConfig{
					User:     "db-user",
					Password: "$SECRET:dup",
				},
				JWTSecrets: []jwtSecret{"$SECRET:dup", "$SECRET:dup"},
				ProvidersPtr: map[string]*providerConfig{
					"provider1": {Name: "provider1", Secret: "$SECRET:dup"},
					"provider2": {Name: "provider2", Secret: "$SECRET:dup"},
					"provider3": {Name: "provider3", Secret: "$SECRET:dup"},
				},
			},
			Out: []string{"dup"},
		},
		{
			Name: "Unexported_field_should_fail_to_hydrate",
			Input: &cfg{
				unexported: dbConfig{ // unexported fields can't be updated via reflect pkg
					User:     "db-user",
					Password: "$SECRET:secretName", // match inside unexported field
				},
			},
			Out:   []string{},
			Error: true, // expect error
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			v := reflect.ValueOf(tc.Input)

			secretFields, err := collectSecretFields(v)
			if tc.Error && err == nil {
				t.Error("expected error, got nil")
				return
			} else if !tc.Error && err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if !cmp.Equal(mapKeysSorted(secretFields), tc.Out) {
				t.Errorf(cmp.Diff(tc.Out, mapKeysSorted(secretFields)))
			}
		})
	}
}

type cfg struct {
	DB            dbConfig
	DBPtr         *dbConfig
	DBDoublePtr   **dbConfig
	JWTSecrets    []jwtSecret
	JWTSecretsPtr []*jwtSecret
	Providers     map[string]providerConfig
	ProvidersPtr  map[string]*providerConfig
	unexported    dbConfig
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

func ptr[T any](v T) *T { return &v }

func mapKeysSorted(m map[string]string) []string {
	keys := []string{}
	for key, _ := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
