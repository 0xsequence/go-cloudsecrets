package main

import (
	"context"
	"fmt"
	"log"

	"github.com/0xsequence/go-cloudsecrets"
	"github.com/0xsequence/go-cloudsecrets/_examples/config"
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

	err := cloudsecrets.Hydrate(context.Background(), "gcp", cfg)
	if err != nil {
		log.Fatal("failed to hydrate config secrets:", err)
	}

	fmt.Printf("%# v", pretty.Formatter(cfg))
}
