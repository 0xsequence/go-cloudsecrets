# onepassword

A `SecretsProvider` backed by [1Password](https://1password.com), implemented as a thin wrapper around the [`op` CLI](https://developer.1password.com/docs/cli/get-started/). The CLI handles authentication, so this provider works with every 1Password plan (Personal, Teams, Business) and every supported auth mode.

## Why a CLI wrapper instead of the Go SDK

- **Plan-agnostic.** The official Go SDK requires a service account token (Business plan only). The CLI works with personal sign-in, biometric desktop integration, `op signin` session tokens, *and* service account tokens — anything the CLI can authenticate.
- **No vendored runtime.** The SDK ships a WASM core (~10 MB) executed via `wazero`. The CLI wrapper is plain `os/exec`, no extra deps.
- **Better local-dev UX.** Developers tap Touch ID once; secrets resolve. No service account tokens to copy into dotfiles.

## Prerequisites

Install the CLI (one-time per machine):

```bash
brew install --cask 1password-cli   # macOS
# Linux/Windows: see https://developer.1password.com/docs/cli/get-started/
```

Verify:

```bash
op --version
```

## Authenticating

The provider doesn't manage auth — it shells out to `op` and lets the CLI use whatever method is configured. Pick the one that matches your environment:

### Local dev — biometric desktop integration (recommended)

In the 1Password macOS/Windows app: **Settings → Developer → Integrate with 1Password CLI**. Enables Touch ID for `op` commands. Works on any plan.

### Local dev — interactive session

```bash
eval "$(op signin)"
```

Creates a session token in your shell. Works on any plan.

### Production / CI — service account token

```bash
export OP_SERVICE_ACCOUNT_TOKEN=ops_eyJzaWdu...
```

The CLI auto-detects this env var and uses it without prompting. Requires 1Password **Business** to provision service accounts.

## Reference format

Pass-through: secret IDs are full 1Password reference URIs of the form `op://<vault>/<item>/<field>`. Vault and item names with spaces are tolerated by 1Password but best avoided — name them with no spaces from day one.

## Sanity check

Before integrating, confirm the CLI and reference work:

```bash
op read "op://prod-secrets/db/password"
```

If `op read` returns the value, the Go provider will too. If it doesn't, fix the auth/permissions on the 1Password side first — the provider can't surface anything `op read` can't.

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

    provider, err := onepassword.NewSecretsProvider()
    if err != nil {
        log.Fatalf("failed to create secrets provider: %v", err)
    }

    if err := cloudsecrets.Hydrate(ctx, provider, &cfg); err != nil {
        log.Fatalf("failed to hydrate config secrets: %v", err)
    }
}
```

## Caveats

- Requires `op` on `PATH`. The constructor verifies this and returns an error if missing.
- Each `FetchSecret` spawns a subprocess. `Hydrate` parallelizes via `errgroup`, so at boot the cost is roughly one process spawn instead of one per secret in serial. Fine for startup config; not ideal for hot paths.
- Per-call timeout is 10 seconds, which includes any biometric prompt. If you tap Touch ID slowly, the call fails — sign-in interactively first via `eval "$(op signin)"` to skip the prompt.
- The provider has no `Close()` — there's no persistent resource to release.
