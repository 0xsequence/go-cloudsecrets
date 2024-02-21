package cloudsecrets

import (
	"context"
	"fmt"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

type GCPSecretStorage struct {
	projectId string
	client    *secretmanager.Client
}

func NewGCPSecretStorage(projectId string, client *secretmanager.Client) *GCPSecretStorage {
	return &GCPSecretStorage{
		projectId: projectId,
		client:    client,
	}
}

func (storage GCPSecretStorage) FetchSecret(ctx context.Context, secretId string, versionId string) (string, error) {
	if versionId == "" {
		versionId = "latest"
	}

	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/%s", storage.projectId, secretId, versionId),
	}

	fmt.Println("secret: ", req.Name)

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
