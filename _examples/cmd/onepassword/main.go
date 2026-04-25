package main

import (
	"context"
	"fmt"
	"log"

	"github.com/kr/pretty"

	"github.com/0xsequence/go-cloudsecrets"
	"github.com/0xsequence/go-cloudsecrets/_examples/config"
	"github.com/0xsequence/go-cloudsecrets/onepassword"
)

func main() {
	// Adjust the op:// references to point at items in a vault your 1Password
	// CLI session can read. Authenticate via biometric desktop integration,
	// `eval "$(op signin)"`, or OP_SERVICE_ACCOUNT_TOKEN before running.
	var cfg = &config.Config{
		DB: &config.DB{
			Database: "db_name",
			Host:     "localhost:5432",
			Username: "$SECRET:op://cloudsecrets-test/db/username",
			Password: "$SECRET:op://cloudsecrets-test/db/password",
		},
	}

	ctx := context.Background()

	provider, err := onepassword.NewSecretsProvider()
	if err != nil {
		log.Fatalf("failed to create secrets provider: %v", err)
	}

	err = cloudsecrets.Hydrate(ctx, provider, cfg)
	if err != nil {
		log.Fatalf("failed to hydrate config secrets: %v", err)
	}

	fmt.Printf("%# v", pretty.Formatter(cfg))
}
