package main

import (
	"context"
	"fmt"
	"log"

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
	// cfg = application config can be any struct
	err := cloudsecrets.HydrateSecrets(context.Background(), cloudsecrets.GCP, cfg)
	if err != nil {
		log.Fatal("failed to replace secret placeholders with real values: ", err)
	}

	fmt.Printf("%# v", pretty.Formatter(cfg))
}
