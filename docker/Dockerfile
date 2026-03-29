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

RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags "-s -w -X main.Version=${VERSION} -X main.BuildDate=${BUILD_DATE}" \
    -o heplify-ng \
    ./src/cmd/heplify-ng

# ──────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends libpcap0.8 ca-certificates libcap2-bin && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/heplify-ng /usr/local/bin/heplify-ng

# Allow non-root users with CAP_NET_RAW + CAP_NET_ADMIN to run capture
RUN setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/heplify-ng
COPY heplify.json            /etc/heplify-ng/heplify.json
COPY example.lua              /etc/heplify-ng/example.lua

ENV HEPLIFY_CONFIG=/etc/heplify-ng/heplify.json

ENTRYPOINT ["heplify-ng"]
CMD ["-config", "/etc/heplify-ng/heplify.json"]
