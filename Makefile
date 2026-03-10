test:
	go test -race ./...

lint:
	go tool golangci-lint run ./... --fix -c .golangci.yml

vendor:
	go mod vendor && go mod tidy
