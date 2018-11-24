NAME?=heplify

PKGLIST=$(shell go list ./... | grep -Ev '/vendor|decoder/internal')

all:
	go build -ldflags "-s -w"  -o $(NAME) *.go

debug:
	go build -o $(NAME) *.go

test:
	go vet $(PKGLIST)
	go test $(PKGLIST)

.PHONY: clean
clean:
	rm -fr $(NAME)