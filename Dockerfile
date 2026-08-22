# syntax=docker/dockerfile:1

ARG GO_VERSION=1.26.5
FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src
ENV CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN go build -trimpath \
      -ldflags "-s -w -X github.com/soffchen/oixproxy/internal/run.Version=${VERSION}" \
      -o /out/oixproxy ./cmd/oixproxy \
 && mkdir -p /out/data && chmod 0700 /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build --chown=nonroot:nonroot /out/oixproxy /oixproxy
COPY --from=build --chown=nonroot:nonroot /out/data /data
USER nonroot
ENV OIXCLOUD_DATA=/data
EXPOSE 6172/tcp
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["/oixproxy", "--healthcheck", "127.0.0.1:6172"]
ENTRYPOINT ["/oixproxy"]
CMD ["--map", "--listen", "0.0.0.0:6172", "--bind", "0.0.0.0", "--config", "/config/config.json"]
