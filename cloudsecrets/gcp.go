package cloudsecrets

import (
	"context"
	"fmt"
	"os"
	"time"

	"cloud.google.com/go/compute/metadata"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

type GCPSecretStorage struct {
	projectId string
	client    *secretmanager.Client
}

func NewGCPSecretStorage() (*GCPSecretStorage, error) {
	gcpClient, err := secretmanager.NewClient(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize google secret manager: %w", err)
	}

	// fetch a projectId depends if you running project locally vs GKE
	var projectId string
	if metadata.OnGCE() {
		projectId, err = metadata.ProjectID()
		if err != nil {
			return nil, fmt.Errorf("failed to get project ID from metadata: %w", err)
		}
	} else {
		projectId = os.Getenv("GOOGLE_CLOUD_PROJECT")
	}

	return &GCPSecretStorage{
		projectId: projectId,
		client:    gcpClient,
	}, nil
}

func (storage GCPSecretStorage) FetchSecret(ctx context.Context, secretId string) (string, error) {
	versionId := "latest"

	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/%s", storage.projectId, secretId, versionId),
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
