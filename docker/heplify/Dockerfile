# sudo docker build -t negbie/heplify:latest .

FROM golang:alpine as builder
RUN apk --update add linux-headers musl-dev gcc libpcap-dev ca-certificates git
COPY . /heplify
WORKDIR /heplify
RUN CGO_ENABLED=1 GOOS=linux go build -a --ldflags '-linkmode external -extldflags "-static -s -w"' -o heplify .

FROM alpine
RUN apk --no-cache add ca-certificates tzdata libcap
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /heplify/heplify .
RUN /usr/sbin/setcap cap_net_raw,cap_net_admin=eip heplify
CMD ["./heplify", "-h"]
