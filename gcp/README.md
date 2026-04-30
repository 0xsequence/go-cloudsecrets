# gcp

A `SecretsProvider` backed by [GCP Secret Manager](https://cloud.google.com/secret-manager).

## Setup

### 1. Enable the Secret Manager API

```bash
gcloud services enable secretmanager.googleapis.com
```

### 2. Create secrets

```bash
echo -n "hunter2" | gcloud secrets create dbPassword --data-file=-
```

Secret IDs are arbitrary — use whatever identifier you want callers to reference (e.g. `dbPassword`, `stripe_key`).

### 3. Authenticate

The provider uses [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials).

**On GCE / GKE / Cloud Run / Cloud Functions:** ADC works automatically via the metadata server. No setup required beyond granting the workload identity the right role (next step).

**Locally:**

```bash
gcloud auth application-default login
```

### 4. Grant `secretAccessor` IAM

The identity running the workload (or your local user) needs `roles/secretmanager.secretAccessor` on the project — or, more narrowly, on individual secrets.

```bash
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:my-service@$PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"
```

### 5. Project resolution

The provider needs the project **number** (not project ID) for the Secret Manager API. It resolves this automatically:

- On GCE / GKE / etc.: from the metadata server.
- Locally: from `GOOGLE_CLOUD_PROJECT` env var if set, otherwise from `gcloud config get-value project`.

## Usage

```go
import (
    "github.com/0xsequence/go-cloudsecrets"
    "github.com/0xsequence/go-cloudsecrets/gcp"
)

type Config struct {
    DBPassword string
}

cfg := Config{
    DBPassword: "$SECRET:dbPassword",
}

func main() {
    ctx := context.Background()

    provider, err := gcp.NewSecretsProvider(ctx)
    if err != nil {
        log.Fatalf("failed to create secrets provider: %v", err)
    }
    defer provider.Close()

    if err := cloudsecrets.Hydrate(ctx, provider, &cfg); err != nil {
        log.Fatalf("failed to hydrate config secrets: %v", err)
    }
}
```

## Reference format

Secret IDs are passed verbatim as the GCP secret name. The provider always reads version `latest`.

## Caveats

- Per-call timeout is 10 seconds.
- Always call `provider.Close()` to release the underlying gRPC connection.
