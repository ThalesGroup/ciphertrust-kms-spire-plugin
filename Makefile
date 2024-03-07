ROOT_DIR := .
SOURCES := $(wildcard pkg/ciphertrustkms/*.go) $(wildcard pkg/keymanager/*.go) cmd/server/keymanager_server.go
TESTS := $(shell find . -name '*_test.go')
GO_DIRS := $(shell find $(ROOT_DIR) -name '*.go' -exec dirname {} \; | sort -u)

build: fmt staticcheck vet goreportcard $(SOURCES)
	@echo "Building..."
	GOOS=linux GOARCH=amd64 go build -o bin/ciphertrust-kms-spire-plugin cmd/server/keymanager_server.go

fmt:
	@echo "Running gofmt..."
	@gofmt -s -w $(SOURCES)
	@gofmt -s -w $(TESTS)

staticcheck:
	@echo "Running staticcheck..."
	@for dir in $(GO_DIRS); do \
		echo "-> $$dir..."; \
		staticcheck $$dir/... || exit 1; \
	done
	
vet:
	@echo "Running go vet..."
	@for dir in $(GO_DIRS); do \
		echo "-> $$dir..."; \
		go vet $$dir/... || exit 1; \
	done
goreportcard:
	@echo "Running goreportcard"
	goreportcard-cli -v
