NAME?=heplify

all:
	go build -ldflags "-s -w"  -o $(NAME) *.go

debug:
	go build -o $(NAME) *.go

.PHONY: clean
clean:
	rm -fr $(NAME)