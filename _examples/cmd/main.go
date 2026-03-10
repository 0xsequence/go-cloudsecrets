package main

import (
	"context"
	"fmt"
	"log"

	"github.com/0xsequence/go-cloudsecrets"
	"github.com/0xsequence/go-cloudsecrets/_examples/config"
	"github.com/0xsequence/go-cloudsecrets/gcp"
	"github.com/kr/pretty"
)

func main() {
	var cfg = &config.Config{
		DB: &config.DB{
			Database: "db_name",
			Host:     "localhost:5432",
			Username: "$SECRET:dbUsername",
			Password: "$SECRET:dbPassword",
		},
	}

	provider, err := gcp.NewSecretsProvider()
	if err != nil {
		log.Fatalf("failed to create secrets provider: %v", err)
	}

	err = cloudsecrets.Hydrate(context.Background(), provider, cfg)
	if err != nil {
		log.Fatalf("failed to hydrate config secrets: %v", err)
	}

	fmt.Printf("%# v", pretty.Formatter(cfg))
}
