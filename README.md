# go-cloudsecrets

Go package to hydrate runtime secrets from Cloud providers
- [x] GCP Secret Manager
- [ ] AWS Secrets Manager

```go
cloudsecrets.Hydrate(ctx, "gcp", &Config{})
```

`Hydrate()` recursively walks given struct (pointer) and for any field matching `$SECRET:`
string prefix, it will fetch secret from secret provider and replace the original value:
- `"$SECRET:{secretName}"` => `provider.fetchSecret("secretName", "latest")`


## Usage
```go
import "github.com/0xsequence/go-cloudsecrets/cloudsecrets"

func main() {
    var cfg := &config.Config{
    	DB: &config.DB{
    		Database: "postgres",
    		Host:     "localhost:5432",
    		Username: "sequence",
    		Password: "$SECRET:dbPassword", // to be hydrated
        },
    }

	err := cloudsecrets.Hydrate(context.Background(), "gcp", cfg)
	if err != nil {
		log.Fatal("failed to hydrate secrets: ", err)
	}

    // cfg.DB.Password now contains value of "dbPassword" GCP secret (latest version)
}
```