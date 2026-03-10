FROM golang:1.25-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags "-s -w" \
    -o /out/filecrusher ./cmd/filecrusher

FROM alpine:3.21

RUN addgroup -g 10001 filecrusher && \
    adduser -u 10001 -G filecrusher -s /sbin/nologin -D filecrusher && \
    mkdir -p /data /etc/filecrusher && \
    chown filecrusher:filecrusher /data /etc/filecrusher

COPY --from=builder /out/filecrusher /usr/local/bin/filecrusher
COPY deploy/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

VOLUME ["/data"]

EXPOSE 5132 2022 2121 2122

USER filecrusher

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["server", "--config", "/etc/filecrusher/filecrusher.yaml"]
