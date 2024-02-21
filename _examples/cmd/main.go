package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"cloud.google.com/go/compute/metadata"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"github.com/0xsequence/go-cloudsecrets/_examples/config"
	"github.com/0xsequence/go-cloudsecrets/cloudsecrets"
	"github.com/kr/pretty"
)

var cfg = &config.Config{
	DB: &config.DB{
		Database: "postgres",
		Host:     "localhost:5432",
		Username: "sequence",
		Password: "SECRET:apiDbPassword",
	},
}

func main() {
	gcpClient, err := secretmanager.NewClient(context.Background())
	if err != nil {
		log.Fatal("failed to initialize google secret manager:", err)
	}

	// fetch a projectId depends if you running project locally vs GKE
	var projectId string
	if metadata.OnGCE() {
		projectId, err = metadata.ProjectID()
		if err != nil {
			log.Fatal("failed to get project ID from metadata: ", err)
		}
	} else {
		projectId = os.Getenv("GOOGLE_CLOUD_PROJECT")
	}

	secretStorageClient := cloudsecrets.NewGCPSecretStorage(projectId, gcpClient)
	// cfg = application config can be any struct
	err = cloudsecrets.HydrateSecrets(context.Background(), secretStorageClient, cfg)
	if err != nil {
		log.Fatal("failed to replace secret placeholders with real values: ", err)
	}

	fmt.Printf("%# v", pretty.Formatter(cfg))
}
