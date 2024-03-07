ROOT_DIR := .
SOURCE_MAIN := cmd/server/keymanager_server.go
SOURCES := $(wildcard pkg/ciphertrustkms/*.go) $(wildcard pkg/keymanager/*.go) $(SOURCE_MAIN)
TESTS := $(shell find . -name '*_test.go')
GO_DIRS := $(shell find $(ROOT_DIR) -name '*.go' -exec dirname {} \; | sort -u)


BIN_DIR := ./bin
BIN_FILE:= $(BIN_DIR)/ciphertrust-kms-spire-plugin
BIN_HASH_FILE := $(BIN_DIR)/ciphertrust-kms-spire-plugin.sha256

build: fmt staticcheck vet goreportcard $(SOURCES)
	@echo "Building..."
	GOOS=linux GOARCH=amd64 go build -o $(BIN_FILE) $(SOURCE_MAIN)
	@echo "Generating binary hash in $(BIN_HASH_FILE)"
	sha256sum $(BIN_FILE) > $(BIN_HASH_FILE)

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
	@echo "Running goreportcard..."
	goreportcard-cli -v
