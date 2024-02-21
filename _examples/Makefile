SHELL = bash -o pipefail

GOOGLE_APPLICATION_CREDENTIALS 	?= "/home/lukas-jenicek/.config/gcloud/application_default_credentials.json"
GOOGLE_CLOUD_PROJECT ?= "359787419277"

vendor:
	go mod tidy && go mod vendor

run:
	go run cmd/main.go
