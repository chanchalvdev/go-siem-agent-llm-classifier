# syntax=docker/dockerfile:1.7
# API image: static Go binary on distroless, running as non-root.

FROM golang:1.25-bookworm AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=auto
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/siemagent ./cmd/siemagent

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/siemagent /usr/local/bin/siemagent
# HTTP API, and the optional syslog listener (SYSLOG_UDP_ADDR / SYSLOG_TCP_ADDR).
EXPOSE 8080 5514/udp 5514/tcp
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/siemagent"]
CMD ["--serve"]
