NAME?=heplify
#export CGO_LDFLAGS += -Wl,-static -L/usr/lib/x86_64-linux-gnu/libpcap.a -lpcap -Wl,-Bdynamic

PKGLIST=$(shell go list ./... | grep -Ev '/vendor|decoder/internal')

all:
	go build -ldflags "-s -w"  -o $(NAME) *.go

debug:
	go build -o $(NAME) *.go

test:
	go vet $(PKGLIST)
	go test $(PKGLIST) -race

.PHONY: clean
clean:
	rm -fr $(NAME)