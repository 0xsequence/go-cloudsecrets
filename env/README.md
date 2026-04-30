# env

A `SecretsProvider` backed by environment variables. Intended for local development and tests, not production — process env is visible to anything that can read `/proc/<pid>/environ` on Linux or attach a debugger.

## Usage

```go
import (
    "github.com/0xsequence/go-cloudsecrets"
    "github.com/0xsequence/go-cloudsecrets/env"
)

type Config struct {
    DBPassword string
}

cfg := Config{
    DBPassword: "$SECRET:dbPassword",
}

func main() {
    ctx := context.Background()

    // The prefix is prepended to each secret ID before reading os.Getenv.
    // With prefix "MYAPP_SECRET_", "$SECRET:dbPassword" reads MYAPP_SECRET_dbPassword.
    provider := env.NewSecretsProvider("MYAPP_SECRET_")

    if err := cloudsecrets.Hydrate(ctx, provider, &cfg); err != nil {
        log.Fatalf("failed to hydrate config secrets: %v", err)
    }
}
```

Then run with the matching env vars:

```bash
MYAPP_SECRET_dbPassword=hunter2 ./myapp
```

## Reference format

Secret IDs are appended directly to the configured prefix. Use whatever naming convention you like — the env var is `<prefix><secretId>`.

## Caveats

- An empty value (`MYAPP_SECRET_dbPassword=`) is treated as "not set" and returns an error.
- No type coercion — values are returned as-is to the hydrator.
- Don't use this in production. Use `gcp` or `onepassword` instead.
