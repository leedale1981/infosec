BINARY_NAME := api-tester

.PHONY: build build-linux build-windows release-snapshot test

build:
	go build -o dist/$(BINARY_NAME) .

build-linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o dist/$(BINARY_NAME)-linux-amd64 .

build-windows:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o dist/$(BINARY_NAME)-windows-amd64.exe .

release-snapshot:
	goreleaser release --snapshot --clean

test:
	go test ./...
