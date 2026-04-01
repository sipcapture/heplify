NAME?=heplify
VERSION?=$(shell \
	if git describe --tags --abbrev=0 >/dev/null 2>&1; then \
		git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//'; \
	else \
		echo "dev"; \
	fi)
BUILD_DATE?=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS=-ldflags "-s -w -X main.Version=$(VERSION) -X main.BuildDate=$(BUILD_DATE) -X main.GitCommit=$(GIT_COMMIT)"

PKGLIST=$(shell go list ./... | grep -Ev '/vendor')

# Local libpcap built without DBus/RDMA — used for the static target
LIBPCAP_LOCAL_DIR?=$(CURDIR)/build/libpcap

all: build

build:
	go build $(LDFLAGS) -o $(NAME) ./src/cmd/heplify

debug:
	go build -o $(NAME) ./src/cmd/heplify

linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(NAME)-linux-amd64 ./src/cmd/heplify

## libpcap-local — download and build a minimal static libpcap (no DBus, no RDMA)
libpcap-local:
	chmod +x scripts/build_libpcap.sh
	./scripts/build_libpcap.sh

## linux-static — fully static binary using the locally built libpcap
## GOARCH defaults to the native arch; override with: make linux-static GOARCH=arm64
GOARCH?=$(shell go env GOARCH)
linux-static: $(LIBPCAP_LOCAL_DIR)/lib/libpcap.a
	CGO_ENABLED=1 GOOS=linux GOARCH=$(GOARCH) \
	CGO_CFLAGS="-I$(LIBPCAP_LOCAL_DIR)/include" \
	CGO_LDFLAGS="-L$(LIBPCAP_LOCAL_DIR)/lib" \
	go build \
		-ldflags "-s -w \
			-X main.Version=$(VERSION) \
			-X main.BuildDate=$(BUILD_DATE) \
			-X main.GitCommit=$(GIT_COMMIT) \
			-linkmode external \
			-extldflags '-static'" \
		-trimpath \
		-o $(NAME)-linux-static ./src/cmd/heplify

$(LIBPCAP_LOCAL_DIR)/lib/libpcap.a:
	@echo "==> Local libpcap not found. Run 'make libpcap-local' first, or it will build now."
	$(MAKE) libpcap-local

test:
	go test $(PKGLIST)

test-race:
	go test -race $(PKGLIST)

test-coverage:
	go test -coverprofile=coverage.out $(PKGLIST)
	go tool cover -func=coverage.out

lint:
	go vet $(PKGLIST)

lint-golangci:
	golangci-lint run ./...

lint-all: lint lint-golangci fmt-check

fmt:
	go fmt $(PKGLIST)

fmt-check:
	@out=$$(gofmt -l $$(go list -f '{{.Dir}}' $(PKGLIST) | xargs -I{} find {} -maxdepth 1 -name '*.go')); \
	if [ -n "$$out" ]; then \
		echo "The following files need gofmt:"; \
		echo "$$out"; \
		exit 1; \
	fi

tidy:
	go mod tidy

deps:
	go mod download

## update-version — write VERSION into src/cmd/heplify/version.go (mirrors heplify.go pattern)
update-version:
	chmod +x scripts/update_version.sh
	VERSION=$(VERSION) bash scripts/update_version.sh

## release — bump version.go, commit, tag and push (triggers GoReleaser CI)
release: update-version
	git add src/cmd/heplify/version.go
	git diff --cached --quiet || git commit -m "chore: bump version to $(VERSION)"
	git tag -a v$(VERSION) -m "Release v$(VERSION)"
	git push origin HEAD --tags

package: $(LIBPCAP_LOCAL_DIR)/lib/libpcap.a
	@if ! command -v nfpm >/dev/null 2>&1 && ! command -v docker >/dev/null 2>&1; then \
		echo "Error: nfpm or docker is required for packaging"; exit 1; \
	fi
	$(MAKE) linux-static
	cp $(NAME)-linux-static $(NAME)
	chmod +x scripts/build_package.sh
	./scripts/build_package.sh $(VERSION)
	rm -f $(NAME)

run: build
	./$(NAME)

.PHONY: all build debug linux linux-static libpcap-local test test-race test-coverage lint lint-golangci lint-all fmt fmt-check tidy deps run package update-version release clean clean-libpcap

clean:
	rm -f $(NAME) $(NAME)-linux-amd64 $(NAME)-linux-static
	rm -f $(NAME)-*.deb $(NAME)-*.rpm

clean-libpcap:
	rm -rf build/
