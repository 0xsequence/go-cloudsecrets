# go-cloudsecrets

Go package for hydrating config secrets from Cloud secret providers:
- [x] `gcp` — GCP Secret Manager
- [x] `env` — Environment variables (configurable prefix)
- [x] `nosecrets` — No provider (errors out on any `$SECRET:` value)

```go
provider, _ := gcp.NewSecretsProvider()
err := cloudsecrets.Hydrate(ctx, provider, &cfg)
```

The `Hydrate()` function recursively walks given `cfg` and replaces all fields matching `"$SECRET:{key}"` string format with a value fetched from the given provider.

All referenced secret keys are de-duplicated and fetched only once.

The `Hydrate()` function tries to replace all fields before returning any error(s). This means that the given struct might be partially hydrated.

## Usage
```go
import (
	"github.com/0xsequence/go-cloudsecrets"
	"github.com/0xsequence/go-cloudsecrets/gcp"
)

var cfg = config.Config{
	DB: &config.DB{
		Database: "postgres",
		Host:     "localhost:5432",
		Username: "sequence",
		Password: "$SECRET:dbPassword", // will be hydrated (replaced by value of "dbPassword" secret)
	},
}

func main() {
	provider, err := gcp.NewSecretsProvider()
	if err != nil {
		log.Fatalf("failed to create secrets provider: %v", err)
	}

	err = cloudsecrets.Hydrate(context.Background(), provider, &cfg)
	if err != nil {
		log.Fatalf("failed to hydrate config secrets: %v", err)
	}

	// cfg.DB.Password now contains value of latest "dbPassword" GCP secret
}
```

## License
[MIT](./LICENSE)
