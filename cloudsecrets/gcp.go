package cloudsecrets

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"cloud.google.com/go/compute/metadata"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

type GCPSecretStorage struct {
	projectNumber string
	client        *secretmanager.Client
}

func NewGCPSecretStorage() (*GCPSecretStorage, error) {
	gcpClient, err := secretmanager.NewClient(context.Background())
	if err != nil {
		return nil, fmt.Errorf("initializing GCP secret manager: %w", err)
	}
	// TODO: gcpClient.Close()

	var projectNumber string
	if metadata.OnGCE() {
		projectNumber, err = metadata.NumericProjectID()
		if err != nil {
			return nil, fmt.Errorf("getting project ID from metadata: %w", err)
		}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		projectNumber, err = getProjectNumberFromGcloud(ctx)
		if err != nil {
			return nil, fmt.Errorf("getting project ID from gcloud: %w", err)
		}
	}

	return &GCPSecretStorage{
		projectNumber: projectNumber,
		client:        gcpClient,
	}, nil
}

func (storage GCPSecretStorage) FetchSecret(ctx context.Context, secretId string) (string, error) {
	versionId := "latest"

	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/%s", storage.projectNumber, secretId, versionId),
	}

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Access the secret version
	result, err := storage.client.AccessSecretVersion(reqCtx, req)
	if err != nil {
		return "", fmt.Errorf("failed to access secret %s: %w", secretId, err)
	}

	// Return the secret value
	return string(result.Payload.Data), nil
}

func getProjectNumberFromGcloud(ctx context.Context) (string, error) {
	// Inferring ProjectId using
	// creds, err := google.FindDefaultCredentials(ctx, "")
	// doesn't work. See https://github.com/golang/oauth2/issues/241.

	projectId := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if projectId == "" {
		out, err := exec.CommandContext(ctx, "gcloud", "config", "get-value", "project").Output()
		if err != nil {
			return "", fmt.Errorf("getting current gcloud project (try `gcloud auth application-default login'): %w", err)
		}
		projectId = strings.TrimSpace(string(out))
	}

	// We need projectNumber (not projectName!) for GCP Secret Manager APIs.
	out, err := exec.CommandContext(ctx, "gcloud", "projects", "describe", projectId, "--format=value(projectNumber)").Output()
	if err != nil {
		return "", fmt.Errorf("getting projectNumber from projectId %q: %w", projectId, err)
	}
	return strings.TrimSpace(string(out)), nil
}
