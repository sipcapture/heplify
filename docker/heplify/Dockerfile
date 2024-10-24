FROM golang:alpine3.19 as builder
RUN apk --update add linux-headers musl-dev gcc libpcap-dev ca-certificates git
RUN apk --update add --no-cache git build-base 
RUN git clone https://luajit.org/git/luajit-2.0.git \
 && cd luajit-2.0 \
 && git checkout v2.1 \
 && make CCOPT="-static -fPIC" BUILDMODE="static" && make install
COPY . /heplify
WORKDIR /heplify
RUN CGO_ENABLED=1 GOOS=linux go build -a --ldflags '-linkmode external -extldflags "-static -s -w"' -o heplify .

FROM alpine:3.19
RUN apk --no-cache add ca-certificates tzdata libcap
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /heplify/heplify .
RUN /usr/sbin/setcap cap_bpf,cap_net_raw,cap_net_admin=eip heplify
CMD ["./heplify", "-h"]
