test:
	go test -race ./...

lint:
	cd tools && go tool golangci-lint run ../... --fix -c ../.golangci.yml

vendor:
	go mod vendor && go mod tidy
