# go-cloudsecrets

Go package for hydrating config secrets from Cloud secret providers:
- [x] `"gcp"` GCP Secret Manager
- [ ] `"aws"` AWS Secrets Manager
- [ ] `""` no provider (errors out on any `$SECRET:` value)

```go
err := cloudsecrets.Hydrate(ctx, "gcp", &cfg)
```

The `Hydrate()` function recursively walks given `cfg` and replaces all fields matching `"$SECRET:{key}"` string format with a value fetched from Cloud provider.

All referenced secret keys are de-duplicated and fetched only once.

The `Hydrate()` function tries to replace all fields before returning any error(s). This means that the given struct might be partially hydrated.

## Usage
```go
import "github.com/0xsequence/go-cloudsecrets/cloudsecrets"

var cfg = config.Config{
	DB: &config.DB{
		Database: "postgres",
		Host:     "localhost:5432",
		Username: "sequence",
		Password: "$SECRET:dbPassword", // will be hydrated (replaced by value of "dbPassword" secret)
	},
}

func main() {
	err := cloudsecrets.Hydrate(context.Background(), "gcp", &cfg)
	if err != nil {
		log.Fatalf("failed to hydrate config secrets: %v", err)
	}

	// cfg.DB.Password now contains value of latest "dbPassword" GCP secret
}
```

## License
[MIT](./LICENSE)
