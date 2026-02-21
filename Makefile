BINARY   = survex
CMD      = ./cmd/survex
VERSION  = $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS  = -ldflags "-X main.version=$(VERSION)"

.PHONY: build build-linux build-mac run test clean fmt vet

## Build for current OS
build:
	go build $(LDFLAGS) -o $(BINARY) $(CMD)

## Build for Linux amd64 (primary target)
build-linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-linux-amd64 $(CMD)

## Build for Linux arm64 (e.g. Raspberry Pi, AWS Graviton)
build-linux-arm:
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY)-linux-arm64 $(CMD)

## Build for macOS
build-mac:
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-darwin-amd64 $(CMD)

## Run a test scan using the scanme config
run-test:
	go run $(CMD) scan --config clients/scanme.yaml

## Run tests
test:
	go test ./...

## Format code
fmt:
	gofmt -w .

## Run linter
vet:
	go vet ./...

## Remove build artifacts
clean:
	rm -f $(BINARY) $(BINARY)-linux-amd64 $(BINARY)-linux-arm64 $(BINARY)-darwin-amd64
