VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test vet clean dist release

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o wazuhmcp .

test:
	go vet ./...
	go test -race -count=1 ./...
	scripts/test-update.sh

# Install bundle for a plain Ubuntu host (systemd, no container): see deploy/INSTALL.md
DIST := wazuhmcp-$(VERSION)-linux-amd64
dist:
	rm -rf dist/$(DIST) && mkdir -p dist/$(DIST)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o dist/$(DIST)/wazuhmcp .
	cp deploy/wazuhmcp.service deploy/wazuhmcp.env.example deploy/INSTALL.md \
	   deploy/create-wazuhmcp-users.sh deploy/wazuhmcp-update deploy/wazuhmcp-update.service \
	   deploy/wazuhmcp-update.timer docs/akses-dan-kewenangan.md dist/$(DIST)/
	if [ -f deploy/allowed_signers ]; then cp deploy/allowed_signers dist/$(DIST)/; fi
	tar -C dist -czf dist/$(DIST).tar.gz $(DIST)
	@echo dist/$(DIST).tar.gz

# Signed release for wazuhmcp-update: needs a clean tree on a vX.Y.Z tag. Upload both
# files to the GitHub release of that tag under these exact names.
SIGNING_KEY ?= $(HOME)/.ssh/wazuhmcp-release
release: test
	@echo "$(VERSION)" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$$' || { echo "release needs a clean tree on a vX.Y.Z tag (got $(VERSION))"; exit 1; }
	$(MAKE) dist
	cp dist/$(DIST).tar.gz dist/wazuhmcp-linux-amd64.tar.gz
	rm -f dist/wazuhmcp-linux-amd64.tar.gz.sig
	ssh-keygen -Y sign -f $(SIGNING_KEY) -n wazuhmcp-release dist/wazuhmcp-linux-amd64.tar.gz
	@echo "upload: dist/wazuhmcp-linux-amd64.tar.gz dist/wazuhmcp-linux-amd64.tar.gz.sig"

clean:
	rm -rf wazuhmcp dist
