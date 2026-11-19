VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test vet clean dist

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o wazuhmcp .

test:
	go vet ./...
	go test -race -count=1 ./...

# Install bundle for a plain Ubuntu host (systemd, no container): see deploy/INSTALL.md
DIST := wazuhmcp-$(VERSION)-linux-amd64
dist:
	rm -rf dist/$(DIST) && mkdir -p dist/$(DIST)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o dist/$(DIST)/wazuhmcp .
	cp deploy/wazuhmcp.service deploy/wazuhmcp.env.example deploy/INSTALL.md dist/$(DIST)/
	tar -C dist -czf dist/$(DIST).tar.gz $(DIST)
	@echo dist/$(DIST).tar.gz

clean:
	rm -rf wazuhmcp dist
