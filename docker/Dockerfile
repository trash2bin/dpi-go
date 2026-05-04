FROM golang:1.26-bookworm AS test

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    dnsmasq \
    iproute2 \
    iputils-ping \
    make \
    nftables \
    tcpdump \
    htop \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV GOCACHE=/tmp/go-build \
    GOTMPDIR=/tmp/go-tmp
RUN mkdir -p "$GOCACHE" "$GOTMPDIR"

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o /usr/local/bin/dpi ./cmd/dpi \
    && chmod +x docker/entrypoint.sh \
    && rm -rf "$GOCACHE" "$GOTMPDIR"

ENTRYPOINT ["docker/entrypoint.sh"]
CMD ["dpi", "-config", "/app/configs/dpi.docker.toml"]

FROM test AS runtime

ENTRYPOINT ["docker/entrypoint.sh"]
CMD ["dpi", "-config", "/app/configs/dpi.docker.toml"]
