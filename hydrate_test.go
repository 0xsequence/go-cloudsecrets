package cloudsecrets

import (
	"context"
	"testing"

	"github.com/0xsequence/go-cloudsecrets/env"
	"github.com/0xsequence/go-cloudsecrets/mock"
	"github.com/0xsequence/go-cloudsecrets/nosecrets"
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
	provider := nosecrets.NewSecretsProvider()

	str := "hello"
	assert.Error(t, Hydrate(ctx, provider, str))
	assert.Error(t, Hydrate(ctx, provider, &str))

	slice := []string{"hello", "hello2"}
	assert.Error(t, Hydrate(ctx, provider, slice))
	assert.Error(t, Hydrate(ctx, provider, &slice))

	cfg := struct {
		X, Y string
	}{}
	assert.Error(t, Hydrate(ctx, provider, cfg))
	assert.NoError(t, Hydrate(ctx, provider, &cfg))

	cfgPtr := &cfg
	assert.NoError(t, Hydrate(ctx, provider, &cfgPtr))

	cfgPtrPtr := &cfgPtr
	assert.NoError(t, Hydrate(ctx, provider, &cfgPtrPtr))
}

func TestHydrateEnvProvider(t *testing.T) {
	ctx := context.Background()

	t.Setenv("secret_dbPassword", "changethissecret")
	t.Setenv("secret_analyticsPassword", "AuthTokenSecret")
	t.Setenv("secret_pass", "secret")
	t.Setenv("secret_jwtSecretV1", "some-old-secret")
	t.Setenv("secret_jwtSecretV2", "changeme-now")
	t.Setenv("secret_auth", "auth-secret")

	provider := env.NewSecretsProvider("secret_")

	conf := &config{
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
	}

	err := Hydrate(ctx, provider, conf)
	assert.NoError(t, err)

	assert.Equal(t, "secret", conf.Pass)
	assert.Equal(t, "changethissecret", conf.DB.Password)
	assert.Equal(t, "localhost:9090", conf.DB.Host)
	assert.Equal(t, "AuthTokenSecret", conf.Analytics.AuthToken)
	assert.Equal(t, []string{"changeme-now", "some-old-secret"}, conf.JWTSecrets)
	assert.Equal(t, "auth-secret", conf.Services["service-a"].Auth)
}

func TestHydrateEnvProviderCustomPrefix(t *testing.T) {
	ctx := context.Background()

	t.Setenv("MYAPP_dbPassword", "custom-secret")

	provider := env.NewSecretsProvider("MYAPP_")

	conf := &config{
		DB: db{
			Password: "$SECRET:dbPassword",
		},
	}

	err := Hydrate(ctx, provider, conf)
	assert.NoError(t, err)
	assert.Equal(t, "custom-secret", conf.DB.Password)
}

func TestHydrateEnvProviderMissingSecret(t *testing.T) {
	ctx := context.Background()

	provider := env.NewSecretsProvider("secret_")

	conf := &config{
		DB: db{
			Password: "$SECRET:missingKey",
		},
	}

	err := Hydrate(ctx, provider, conf)
	assert.Error(t, err)
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
			provider := mock.NewSecretsProvider(tt.storage)
			err := Hydrate(ctx, provider, tt.conf)
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
