NAME?=heplify-ng
VERSION?=$(shell \
	if git describe --tags --abbrev=0 >/dev/null 2>&1; then \
		git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//'; \
	else \
		echo "dev"; \
	fi)
BUILD_DATE?=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-s -w -X main.Version=$(VERSION) -X main.BuildDate=$(BUILD_DATE)"

PKGLIST=$(shell go list ./... | grep -Ev '/vendor')

all: build

build:
	go build $(LDFLAGS) -o $(NAME) ./src/cmd/heplify-ng

debug:
	go build -o $(NAME) ./src/cmd/heplify-ng

linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(NAME)-linux-amd64 ./src/cmd/heplify-ng

linux-static:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X main.Version=$(VERSION) -X main.BuildDate=$(BUILD_DATE) -linkmode external -extldflags '-static'" -o $(NAME)-linux-static ./src/cmd/heplify-ng

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

lint-all: lint lint-golangci

fmt:
	go fmt $(PKGLIST)

tidy:
	go mod tidy

deps:
	go mod download

## update-version — write VERSION into src/cmd/heplify-ng/version.go (mirrors heplify.go pattern)
update-version:
	chmod +x scripts/update_version.sh
	VERSION=$(VERSION) bash scripts/update_version.sh

## release — bump version.go, commit, tag and push (triggers GoReleaser CI)
release: update-version
	git add src/cmd/heplify-ng/version.go
	git diff --cached --quiet || git commit -m "chore: bump version to $(VERSION)"
	git tag -a v$(VERSION) -m "Release v$(VERSION)"
	git push origin HEAD --tags

package: build
	@if [ ! -x "$(shell command -v docker 2>/dev/null)" ]; then \
		echo "Error: docker is required for packaging"; exit 1; \
	fi
	chmod +x scripts/build_package.sh
	./scripts/build_package.sh $(VERSION)

run: build
	./$(NAME)

.PHONY: all build debug linux linux-static test test-race test-coverage lint lint-golangci lint-all fmt tidy deps run package update-version release clean

clean:
	rm -f $(NAME) $(NAME)-linux-amd64 $(NAME)-linux-static
	rm -f $(NAME)-*.deb $(NAME)-*.rpm
