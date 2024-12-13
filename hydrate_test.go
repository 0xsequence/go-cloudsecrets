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

type service struct {
	URL  string
	Auth string
	Pass string
}

func TestHydrateFailIfNotPointerToStruct(t *testing.T) {
	ctx := context.Background()

	str := "hello"
	assert.Error(t, Hydrate(ctx, "", str))
	assert.Error(t, Hydrate(ctx, "", &str))

	slice := []string{"hello", "hello2"}
	assert.Error(t, Hydrate(ctx, "", slice))
	assert.Error(t, Hydrate(ctx, "", &slice))

	cfg := struct {
		X, Y string
	}{}
	assert.Error(t, Hydrate(ctx, "", cfg))
	assert.NoError(t, Hydrate(ctx, "", &cfg))

	cfgPtr := &cfg
	assert.NoError(t, Hydrate(ctx, "", &cfgPtr))

	cfgPtrPtr := &cfgPtr
	assert.NoError(t, Hydrate(ctx, "", &cfgPtrPtr))
}

func TestHydrate(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		storage  map[string]string
		conf     *config
		wantErr  bool
		wantConf *config
	}{
		{
			name: "successful_replacement",
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
					"service-a": {
						URL:  "http://localhost:8000",
						Auth: "$SECRET:auth",
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
					"service-a": {
						URL:  "http://localhost:8000",
						Auth: "auth-secret",
					},
				},
			},
		},
		{
			name: "failed_secret_lookup",
			storage: map[string]string{
				"some":    "other",
				"secrets": "here",
			},
			conf: &config{
				DB: db{
					Host:     "localhost:9090",
					Username: "postgres",
					Password: "$SECRET:dbPassword",
				},
			},
			wantErr: true,
			// expected config is same as input, since no replacements occurred
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
