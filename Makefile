VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0-dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
BINARY  := liaprobe
GOFLAGS := -trimpath
LDFLAGS := -s -w \
	-X github.com/mo0ogly/liaprob/internal/version.Version=$(VERSION) \
	-X github.com/mo0ogly/liaprob/internal/version.Commit=$(COMMIT) \
	-X github.com/mo0ogly/liaprob/internal/version.BuildDate=$(DATE)

.PHONY: build test lint vet clean release install help

## build: Build the binary
build:
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/liaprobe/

## test: Run all tests
test:
	go test ./... -count=1 -timeout 60s -race

## cover: Run tests with coverage report
cover:
	go test ./... -count=1 -timeout 60s -coverprofile=coverage.out
	go tool cover -func=coverage.out
	@rm -f coverage.out

## vet: Run go vet
vet:
	go vet ./...

## lint: Run staticcheck if available, fallback to vet
lint: vet
	@which staticcheck >/dev/null 2>&1 && staticcheck ./... || echo "staticcheck not installed, skipping"

## clean: Remove build artifacts
clean:
	rm -rf bin/ coverage.out

## install: Install to GOPATH/bin
install:
	go install $(GOFLAGS) -ldflags '$(LDFLAGS)' ./cmd/liaprobe/

## release: Build release binaries for linux/darwin/windows amd64+arm64
release: clean
	@mkdir -p bin/release
	GOOS=linux   GOARCH=amd64 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/release/$(BINARY)-linux-amd64   ./cmd/liaprobe/
	GOOS=linux   GOARCH=arm64 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/release/$(BINARY)-linux-arm64   ./cmd/liaprobe/
	GOOS=darwin  GOARCH=amd64 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/release/$(BINARY)-darwin-amd64  ./cmd/liaprobe/
	GOOS=darwin  GOARCH=arm64 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/release/$(BINARY)-darwin-arm64  ./cmd/liaprobe/
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/release/$(BINARY)-windows-amd64.exe ./cmd/liaprobe/
	@echo "Release binaries in bin/release/"
	@ls -lh bin/release/

## version: Print version info
version:
	@echo "Version: $(VERSION)"
	@echo "Commit:  $(COMMIT)"
	@echo "Date:    $(DATE)"

## help: Show this help
help:
	@grep -E '^## ' Makefile | sed 's/## //' | column -t -s ':'
