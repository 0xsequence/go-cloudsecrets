package cloudsecrets

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestCollectSecretKeys(t *testing.T) {
	tt := []struct {
		Name  string
		Input any
		Out   []string // collected secret keys
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
					Password: "$SECRET:duplicatedKey",
				},
				JWTSecrets: []jwtSecret{"$SECRET:duplicatedKey", "$SECRET:duplicatedKey"},
				ProvidersPtr: map[string]*providerConfig{
					"provider1": {Name: "provider1", Secret: "$SECRET:duplicatedKey"},
					"provider2": {Name: "provider2", Secret: "$SECRET:duplicatedKey"},
					"provider3": {Name: "provider3", Secret: "$SECRET:duplicatedKey"},
				},
			},
			Out: []string{"duplicatedKey"},
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			v := reflect.ValueOf(tc.Input)

			secretFields := collectSecretKeys(v)
			if !cmp.Equal(secretFields, tc.Out) {
				t.Errorf(cmp.Diff(tc.Out, secretFields))
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
