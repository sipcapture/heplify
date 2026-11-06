ARG GOLANG_VERSION=1.26
ARG DEBIAN_RELEASE=bookworm

FROM golang:${GOLANG_VERSION}-${DEBIAN_RELEASE} AS builder

WORKDIR /build

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends libpcap-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

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
FROM debian:${DEBIAN_RELEASE}-slim

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends libpcap0.8 ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Same user and group as the other HOMER components, so files shared
# with them (pcap dumps, buffer files on a volume) have one owner.
RUN groupadd --system homer && \
    useradd --system --gid homer --home-dir /var/lib/heplify --create-home \
            --shell /usr/sbin/nologin homer

COPY --from=builder /build/heplify /usr/local/bin/heplify

# Give the binary the capture capabilities so it can run as a normal user.
# Only capabilities that Docker grants by default are set: a file capability
# missing from the container's bounding set makes exec fail outright.
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends libcap2-bin && \
    setcap cap_net_raw,cap_net_bind_service+ep /usr/local/bin/heplify && \
    apt-get purge -y libcap2-bin && apt-get autoremove -y && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY examples/heplify.json  /etc/heplify/heplify.json
COPY examples/example.lua   /etc/heplify/example.lua

ENV HEPLIFY_CONFIG=/etc/heplify/heplify.json

# Runs unprivileged with NET_RAW, which is enough for AF_PACKET and pcap
# capture. Putting an interface into promiscuous mode needs NET_ADMIN as
# well: either enable promisc on the host interface, or run the container
# with --user root --cap-add NET_ADMIN.
# Relative output paths (buffer file, pcap dumps) land in /var/lib/heplify,
# so a mounted output volume must be writable by the homer user.
USER homer:homer
WORKDIR /var/lib/heplify

ENTRYPOINT ["heplify"]
CMD ["-config", "/etc/heplify/heplify.json"]
