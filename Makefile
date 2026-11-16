VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test vet clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o wazuhmcp .

test:
	go vet ./...
	go test -race -count=1 ./...

clean:
	rm -f wazuhmcp
