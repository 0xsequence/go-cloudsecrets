package cloudsecrets

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

type config struct {
	DB        db
	Analytics analytics
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

func TestReplacePlaceholdersWithSecrets(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		storage  SecretStorage
		conf     *config
		wantErr  bool
		wantConf *config
	}{
		{
			name: "successful replacement",
			storage: NewMockSecretStorage(map[string]string{
				"dbPassword":        "changethissecret",
				"analyticsPassword": "AuthTokenSecret",
			}),
			conf: &config{
				DB: db{
					Host:     "localhost:9090",
					Username: "postgres",
					Password: "SECRET:dbPassword",
				},
				Analytics: analytics{
					Enabled:   true,
					Server:    "http://localhost:8000",
					AuthToken: "SECRET:analyticsPassword",
				},
			},
			wantErr: false,
			wantConf: &config{
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
			},
		},
		{
			name:    "failed secret lookup",
			storage: NewMockSecretStorage(map[string]string{}), // empty storage, or with invalid keys
			conf: &config{
				DB: db{
					Host:     "localhost:9090",
					Username: "postgres",
					Password: "SECRET:dbPassword",
				},
			},
			wantErr: true,
			// expected config is same as input, since no replacements occur
			wantConf: &config{
				DB: db{
					Host:     "localhost:9090",
					Username: "postgres",
					Password: "SECRET:dbPassword",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := HydrateSecrets(ctx, tt.storage, tt.conf)
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
