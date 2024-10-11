package cloudsecrets

import (
	"context"
	"reflect"
	"testing"

	"github.com/0xsequence/go-cloudsecrets/mock"
	"github.com/stretchr/testify/assert"
)

type config struct {
	DB         db
	Analytics  analytics
	Pass       string
	JWTSecrets []string
	Services   map[string]service
}

type service struct {
	URL  string
	Auth string
	Pass string
}

type db struct {
	Host     string
	Username string
	Password string
}

type analytics struct {
	Enabled   bool
	Server    string
	AuthToken string
}

func TestFailWhenPassedValueIsNotStruct(t *testing.T) {
	input := "hello"

	assert.Error(t, Hydrate(context.Background(), "", input))
}

func TestReplacePlaceholdersWithSecrets(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		storage  map[string]string
		conf     *config
		wantErr  bool
		wantConf *config
	}{
		{
			name: "successful replacement",
			storage: map[string]string{
				"dbPassword":        "changethissecret",
				"analyticsPassword": "AuthTokenSecret",
				"pass":              "secret",
				"jwtSecretV1":       "some-old-secret",
				"jwtSecretV2":       "changeme-now",
				"auth":              "auth-secret",
			},
			conf: &config{
				Pass: "$SECRET:pass",
				DB: db{
					Host:     "localhost:9090",
					Username: "postgres",
					Password: "$SECRET:dbPassword",
				},
				Analytics: analytics{
					Enabled:   true,
					Server:    "http://localhost:8000",
					AuthToken: "$SECRET:analyticsPassword",
				},
				JWTSecrets: []string{"$SECRET:jwtSecretV2", "$SECRET:jwtSecretV1"},
				Services: map[string]service{
					"a": {
						URL:  "http://localhost:8000",
						Auth: "$SECRET:auth",
						Pass: "$SECRET:jwtSecretV2",
					},
				},
			},
			wantErr: false,
			wantConf: &config{
				Pass: "secret",
				DB: db{
					Host:     "localhost:9090",
					Username: "postgres",
					Password: "changethissecret",
				},
				Analytics: analytics{
					Enabled:   true,
					Server:    "http://localhost:8000",
					AuthToken: "AuthTokenSecret",
				},
				JWTSecrets: []string{
					"changeme-now",
					"some-old-secret",
				},
				Services: map[string]service{
					"a": {
						URL:  "http://localhost:8000",
						Auth: "auth-secret",
						Pass: "changeme-now",
					},
				},
			},
		},
		{
			name:    "failed secret lookup",
			storage: map[string]string{}, // empty storage, or with invalid keys
			conf: &config{
				DB: db{
					Host:     "localhost:9090",
					Username: "postgres",
					Password: "$SECRET:dbPassword",
				},
			},
			wantErr: true,
			// expected config is same as input, since no replacements occur
			wantConf: &config{
				DB: db{
					Host:     "localhost:9090",
					Username: "postgres",
					Password: "$SECRET:dbPassword",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := reflect.ValueOf(tt.conf)
			err := hydrateConfig(ctx, mock.NewSecretsProvider(tt.storage), v)
			if err != nil {
				if tt.wantErr {
					assert.Equal(t, tt.wantConf, tt.conf)
					return
				}
			}
			if tt.wantErr {
				t.Errorf("expected error, got none")
			}

			assert.Equal(t, tt.wantConf, tt.conf)
		})
	}
}
