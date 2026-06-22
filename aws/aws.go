package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type SecretsProvider struct {
	client *secretsmanager.Client
}

func NewSecretsProvider(ctx context.Context, optFns ...func(*config.LoadOptions) error) (*SecretsProvider, error) {
	cfg, err := config.LoadDefaultConfig(ctx, optFns...)
	if err != nil {
		return nil, fmt.Errorf("aws: loading config: %w", err)
	}

	client := secretsmanager.NewFromConfig(cfg)

	return &SecretsProvider{
		client: client,
	}, nil
}

func (p *SecretsProvider) FetchSecret(ctx context.Context, secretId string) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	result, err := p.client.GetSecretValue(reqCtx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretId),
	})
	if err != nil {
		return "", fmt.Errorf("aws: get secret %q: %w", secretId, err)
	}

	if result.SecretString != nil {
		return *result.SecretString, nil
	}

	return "", fmt.Errorf("aws: secret %q has no string value (binary secrets are not supported)", secretId)
}
