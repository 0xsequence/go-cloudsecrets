test:
	go test -race ./...

vendor:
	go mod vendor && go mod tidy