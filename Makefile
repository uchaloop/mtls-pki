MODULE = github.com/uchaloop/mtls-pki
VERSION ?= dev
COMMIT ?= unknown
BUILD_DATE ?= unknown
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
LDFLAGS = -s -w -X $(MODULE)/internal/mtlspki.Version=$(VERSION) -X $(MODULE)/internal/mtlspki.Commit=$(COMMIT) -X $(MODULE)/internal/mtlspki.BuildDate=$(BUILD_DATE)

# Platforms published for a release. Override to build a subset: make dist PLATFORMS=linux/amd64
PLATFORMS ?= linux/amd64 linux/arm64 linux/386 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64 windows/386 freebsd/amd64

.PHONY: build install release dist cross test fmt vet modernize-check integration clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/mtls-pki ./cmd/mtls-pki

install:
	go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/mtls-pki

release:
	mkdir -p dist
	@binary="mtls-pki_$(VERSION)_$(GOOS)_$(GOARCH)"; \
	if [ "$(GOOS)" = "windows" ]; then binary="$$binary.exe"; fi; \
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o "dist/$$binary" ./cmd/mtls-pki

dist:
	@mkdir -p dist
	@for platform in $(PLATFORMS); do \
		goos="$${platform%/*}"; \
		goarch="$${platform#*/}"; \
		binary="mtls-pki"; \
		if [ "$$goos" = "windows" ]; then binary="mtls-pki.exe"; fi; \
		echo "building $$goos/$$goarch"; \
		CGO_ENABLED=0 GOOS="$$goos" GOARCH="$$goarch" go build -trimpath -ldflags "$(LDFLAGS)" \
			-o "dist/mtls-pki_$(VERSION)_$${goos}_$${goarch}/$$binary" ./cmd/mtls-pki || exit 1; \
	done

# Compile every published platform without producing artifacts.
cross:
	@for platform in $(PLATFORMS); do \
		goos="$${platform%/*}"; \
		goarch="$${platform#*/}"; \
		echo "checking $$goos/$$goarch"; \
		CGO_ENABLED=0 GOOS="$$goos" GOARCH="$$goarch" go build -o /dev/null ./... || exit 1; \
	done

test:
	go test ./...

fmt:
	gofmt -w $$(find . -name '*.go' -type f)

vet:
	go vet ./...

modernize-check:
	go fix -diff ./...

integration: build
	bash tests/integration.sh

clean:
	rm -rf bin dist
