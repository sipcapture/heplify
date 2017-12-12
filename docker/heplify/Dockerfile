# sudo docker build -t negbie/heplify:latest .

FROM alpine:latest as builder
RUN apk --update add linux-headers musl-dev gcc go libpcap-dev ca-certificates git
RUN go get -d -v -u github.com/negbie/heplify
WORKDIR /root/go/src/github.com/negbie/heplify/
RUN CGO_ENABLED=1 GOOS=linux go build -a --ldflags '-linkmode external -extldflags "-static -s -w"' -o heplify .

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder root/go/src/github.com/negbie/heplify/heplify .
CMD ["./heplify", "-h"]