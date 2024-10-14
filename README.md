# go-cloudsecrets

Go package for hydrating config secrets from Cloud secret managers
- [x] `"gcp"`, GCP Secret Manager
- [ ] `"aws"`, AWS Secrets Manager
- [ ] `""`, empty provider, which errors out on `$SECRET:` value

```go
cloudsecrets.Hydrate(ctx, "gcp", &Config{})
```

`Hydrate()` recursively walks given config (a `struct` pointer) and replaces all string
fields having `"$SECRET:"` prefix with a value fetched from a given Cloud secret provider.

The value to be replaced must have a format of `"$SECRET:{name|path}"`.

Secrets are de-duplicated and fetched only once.

The `Hydrate()` function tries to replace as many fields as possible before returning error.

## Usage
```go
import "github.com/0xsequence/go-cloudsecrets/cloudsecrets"

func main() {
	var cfg := &config.Config{
		DB: &config.DB{
			Database: "postgres",
			Host:     "localhost:5432",
			Username: "sequence",
			DPassword: "$SECRET:dbPassword", // will be hydrated (replaced with value of "dbPassword" secret)
		},
	}

	err := cloudsecrets.Hydrate(context.Background(), "gcp", cfg)
	if err != nil {
		log.Fatalf("failed to hydrate config secrets: %v", err)
	}

	// cfg.DB.Password now contains value of "dbPassword" GCP secret (latest version)
}
```