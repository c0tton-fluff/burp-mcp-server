VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

.PHONY: all cli test clean release

all: cli

cli:
	go build -ldflags="-s -w -X github.com/c0tton-fluff/burp-mcp-server/cmd.version=$(VERSION)" \
		-o releases/burp .

test:
	go test ./...

clean:
	rm -rf releases/burp

release: all
	@echo "Built $(VERSION):"
	@ls -lh releases/burp
