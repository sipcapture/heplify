FROM golang:1.24-bookworm AS builder

WORKDIR /build

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG BUILD_DATE=unknown
ARG GIT_COMMIT=unknown

RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags "-s -w -X main.Version=${VERSION} -X main.BuildDate=${BUILD_DATE} -X main.GitCommit=${GIT_COMMIT}" \
    -trimpath \
    -o heplify \
    ./src/cmd/heplify

# ──────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends libpcap0.8 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/heplify /usr/local/bin/heplify

COPY examples/heplify.json  /etc/heplify/heplify.json
COPY examples/example.lua   /etc/heplify/example.lua

ENV HEPLIFY_CONFIG=/etc/heplify/heplify.json

ENTRYPOINT ["heplify"]
CMD ["-config", "/etc/heplify/heplify.json"]
