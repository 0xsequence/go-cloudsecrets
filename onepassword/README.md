# onepassword

A `SecretsProvider` backed by [1Password](https://1password.com), implemented as a thin wrapper around the [`op` CLI](https://developer.1password.com/docs/cli/get-started/). The CLI handles authentication, so this provider works with every 1Password plan (Personal, Teams, Business) and every supported auth mode.

## Why a CLI wrapper instead of the Go SDK

- **Plan-agnostic.** The official Go SDK requires a service account token (Business plan only by default). The CLI works with personal sign-in, biometric desktop integration, `op signin` session tokens, *and* service account tokens — anything the CLI can authenticate.
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

The provider doesn't manage auth — it shells out to `op` and lets the CLI use whatever method is configured. Pick the one that matches your environment.

### Local dev — biometric desktop integration (recommended)

Pairs the CLI with the 1Password desktop app so `op` commands authenticate via Touch ID. **Order matters** — these steps depend on each other:

1. **Install the `op` CLI first** (see Prerequisites above). The toggle in the next step stays grayed out until `op` is on `PATH`.
2. **Fully quit the 1Password desktop app** (`Cmd-Q` on macOS — closing the window is not enough) and reopen it. Without a restart, the app won't pick up that the CLI is now installed.
3. In the desktop app: **Settings → Developer → Integrate with 1Password CLI**. The checkbox should now be enabled — turn it on.
4. (Optional) **Settings → Developer → Integrate with other apps** also becomes enabled at this point. Leave it off unless you're also using the 1Password Go SDK.
5. Verify:
   ```bash
   op vault list
   ```
   First call prompts for biometric/Touch ID, then prints your accessible vaults.

If the toggle in step 3 is still grayed out after a CLI install + full app restart, your org has locked CLI integration via MDM/policy. Ask an admin to enable it in your 1Password Business policy.

### Local dev — interactive session

Alternative if you don't want desktop integration:

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

### Bare names via `WithDefaultPath`

If most of your secrets live in a single vault/item, configure a default path and use bare names — handy when migrating from the `env` provider's `$SECRET:KEY` style:

```go
provider, err := onepassword.NewSecretsProvider(ctx,
    onepassword.WithDefaultPath("omsx-local", "omsx"),
)
```

With this option, both shapes work side by side:

| Config value                                            | Resolves as                                       |
| ------------------------------------------------------- | ------------------------------------------------- |
| `$SECRET:FRONTEGG_ADMIN_CLIENT_ID`                      | `op://omsx-local/omsx/FRONTEGG_ADMIN_CLIENT_ID`   |
| `$SECRET:op://other-vault/other-item/SOME_KEY`          | `op://other-vault/other-item/SOME_KEY` (verbatim) |

Bare names without a configured default path return an error rather than guessing a vault.

## Sanity check

Before integrating, confirm the CLI and reference work:

```bash
op read "op://prod-secrets/db/password"
```

If `op read` returns the value, the Go provider will too. If it doesn't, fix the auth/permissions on the 1Password side first — the provider can't surface anything `op read` can't.

## Try the example

This repo's [`_examples/cmd/onepassword`](../_examples/cmd/onepassword/main.go) directory has a runnable demo. Provision a throwaway vault, run it end-to-end, then clean up:

```bash
# Create a test vault and item the example references
op vault create cloudsecrets-test
op item create --category=login --vault=cloudsecrets-test --title=db \
    username=test-user password=hunter2

# Run — should hydrate $SECRET:op://... placeholders with the values above
cd _examples
make run-onepassword

# Cleanup when you're done
op vault delete cloudsecrets-test
```

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

## Caveats

- Requires `op` on `PATH`. The constructor verifies this and returns an error if missing.
- The constructor also runs `op vault list` to fail fast if the CLI cannot access 1Password. First call may trigger a biometric prompt if desktop integration is on. (`op whoami` is *not* used because it doesn't trigger biometric integration and reports "not signed in" even when other commands work.)
- Each `FetchSecret` spawns a subprocess. `Hydrate` parallelizes via `errgroup`, so at boot the cost is roughly one process spawn instead of one per secret in serial. Fine for startup config; not ideal for hot paths.
- Per-call timeout is 10 seconds, which includes any biometric prompt. If you tap Touch ID slowly, the call fails — sign-in interactively first via `eval "$(op signin)"` to skip the prompt.
- The provider has no `Close()` — there's no persistent resource to release.
