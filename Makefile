VERSION ?= $(shell tr -d '\r\n' < VERSION)
LDFLAGS := -s -w -buildid= -X main.version=$(VERSION)
RELEASE_NAME := go-nftables-portbridge

.PHONY: build test race dist package clean
build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o build/portbridge ./cmd/portbridge

test:
	go test ./...

race:
	go test -race ./...

dist:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(RELEASE_NAME)-linux-amd64 ./cmd/portbridge
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(RELEASE_NAME)-linux-arm64 ./cmd/portbridge

package:
	./scripts/package-release.sh

clean:
	rm -rf build dist
