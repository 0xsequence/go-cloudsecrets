# go-cloudsecrets

Go package to hydrate runtime secrets from Cloud providers
- [x] GCP Secret Manager
- [ ] AWS Secrets Manager

```go
cloudsecrets.Hydrate(ctx, "gcp", &Config{})
```

`Hydrate()` recursively walks a given config (struct pointer) and hydrates all string
values matching `"$SECRET:"` prefix using a given Cloud secrets provider.

The secret values to be replaced must have a format of `"$SECRET:{name|path}"`.

## Usage
```go
import "github.com/0xsequence/go-cloudsecrets/cloudsecrets"

func main() {
	var cfg := &config.Config{
		DB: &config.DB{
			Database: "postgres",
			Host:     "localhost:5432",
			Username: "sequence",
			DPassword: "$SECRET:dbPassword", // to be hydrated
		},
	}

	err := cloudsecrets.Hydrate(context.Background(), "gcp", cfg)
	if err != nil {
		log.Fatalf("failed to hydrate config secrets: %v", err)
	}

	// cfg.DB.Password now contains value of "dbPassword" GCP secret (latest version)
}
```