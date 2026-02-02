SHELL := /bin/sh

GO ?= go
BIN := filecrusher
CMD := ./cmd/filecrusher
DIST_DIR := dist

.PHONY: help fmt test build clean dist dist-all dist-linux-amd64 dist-linux-arm64 dist-darwin-amd64 dist-darwin-arm64 dist-windows-amd64

help:
	@printf '%s\n' \
		"Targets:" \
		"  make fmt            Format Go code" \
		"  make test           Run tests" \
		"  make build          Build ./$(BIN)" \
		"  make dist           Build $(DIST_DIR)/$(BIN)" \
		"  make dist-all       Cross-build into $(DIST_DIR)/" \
		"  make clean          Remove build outputs"

fmt:
	$(GO) fmt ./...
	gofmt -w ./

test:
	$(GO) test ./...

build:
	$(GO) build -o $(BIN) $(CMD)

dist:
	mkdir -p $(DIST_DIR)
	$(GO) build -trimpath -ldflags "-s -w" -o $(DIST_DIR)/$(BIN) $(CMD)

dist-all: dist-linux-amd64 dist-linux-arm64 dist-darwin-amd64 dist-darwin-arm64 dist-windows-amd64

dist-linux-amd64:
	mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "-s -w" -o $(DIST_DIR)/$(BIN)-linux-amd64 $(CMD)

dist-linux-arm64:
	mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags "-s -w" -o $(DIST_DIR)/$(BIN)-linux-arm64 $(CMD)

dist-darwin-amd64:
	mkdir -p $(DIST_DIR)
	GOOS=darwin GOARCH=amd64 $(GO) build -trimpath -ldflags "-s -w" -o $(DIST_DIR)/$(BIN)-darwin-amd64 $(CMD)

dist-darwin-arm64:
	mkdir -p $(DIST_DIR)
	GOOS=darwin GOARCH=arm64 $(GO) build -trimpath -ldflags "-s -w" -o $(DIST_DIR)/$(BIN)-darwin-arm64 $(CMD)

dist-windows-amd64:
	mkdir -p $(DIST_DIR)
	GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags "-s -w" -o $(DIST_DIR)/$(BIN)-windows-amd64.exe $(CMD)

clean:
	rm -rf $(DIST_DIR) $(BIN)
