VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

.PHONY: all cli extension install-ext test clean release

all: cli extension

cli:
	go build -ldflags="-s -w -X github.com/c0tton-fluff/burp-mcp-server/cmd.version=$(VERSION)" \
		-o releases/burp .

extension:
	cd extension && ./gradlew shadowJar
	@echo "JAR: extension/build/libs/burp-bridge-*.jar"

install-ext: extension
	@mkdir -p ~/BurpSuitePro/extensions/
	cp extension/build/libs/burp-bridge-*.jar ~/BurpSuitePro/extensions/burp-bridge.jar
	@echo "Installed to ~/BurpSuitePro/extensions/burp-bridge.jar"

test:
	go test ./...
	cd extension && ./gradlew test

clean:
	rm -rf releases/burp
	cd extension && ./gradlew clean

release: all
	@echo "Built $(VERSION):"
	@ls -lh releases/burp extension/build/libs/burp-bridge-*.jar
