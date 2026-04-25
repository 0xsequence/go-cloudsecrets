# onepassword

A `SecretsProvider` backed by [1Password](https://1password.com) via the [official Go SDK](https://github.com/1Password/onepassword-sdk-go).

## Setup

### 1. Create a vault

In the 1Password web app, create a vault to hold your secrets (e.g. `prod-secrets`). Vaults are the access-control unit — service accounts get permissions per vault.

### 2. Add items with secrets

Inside the vault, create items. Item type doesn't matter (Login, Password, API Credential, Secure Note all work) — only field names matter for resolution.

Example: item `db` with field `password` becomes the reference `op://prod-secrets/db/password`.

For multi-line values (TLS certs, JSON keys, full DSNs), use a Secure Note or a multi-line text field — `Resolve` returns the raw string verbatim.

### 3. Create a service account

> Service accounts are a **1Password Business** feature. Teams plan does not include them.

In the 1Password web app: **Developer Tools** → **Service Accounts** → **Create Service Account**.

- Grant **Read** access to only the vaults this service needs.
- On creation, 1Password shows the token (starts with `ops_`) **once** — copy it immediately.

### 4. Provide the token at runtime

Set the `OP_SERVICE_ACCOUNT_TOKEN` environment variable. In production, load it from your platform's secret store (GCP Secret Manager, AWS SSM, Kubernetes Secret) and inject as env.

```bash
export OP_SERVICE_ACCOUNT_TOKEN=ops_eyJzaWdu...
```

### 5. Sanity-check with the `op` CLI

Before integrating, confirm the token and reference work:

```bash
op read "op://prod-secrets/db/password"
```

If `op read` returns the value, the Go provider will too. If it doesn't, fix the 1Password side first — the provider can't surface anything `op read` can't.

## Usage

```go
import (
    "github.com/0xsequence/go-cloudsecrets"
    "github.com/0xsequence/go-cloudsecrets/onepassword"
)

type Config struct {
    DBPassword string
}

cfg := Config{
    DBPassword: "$SECRET:op://prod-secrets/db/password",
}

func main() {
    ctx := context.Background()

    provider, err := onepassword.NewSecretsProvider(ctx)
    if err != nil {
        log.Fatalf("failed to create secrets provider: %v", err)
    }

    if err := cloudsecrets.Hydrate(ctx, provider, &cfg); err != nil {
        log.Fatalf("failed to hydrate config secrets: %v", err)
    }
}
```

## Reference format

Pass-through: secret IDs are full 1Password reference URIs of the form `op://<vault>/<item>/<field>`. Vault and item names with spaces are tolerated by 1Password but best avoided — name them with no spaces from day one.

## Caveats

- The 1Password Go SDK embeds a WASM core executed via `wazero`. Pure Go (no CGO), but expect ~10 MB additional binary size.
- The provider has no `Close()` — the SDK client holds no closeable resources.
- Per-call timeout is 10 seconds.
