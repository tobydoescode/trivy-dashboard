# syntax=docker/dockerfile:1.25
# Multi-arch via BUILDPLATFORM; final image is built for $TARGETARCH (linux/arm64 in-cluster).
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY main.go ./
COPY internal/ ./internal/
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/trivy-dashboard ./

FROM gcr.io/distroless/static-debian13:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6
LABEL org.opencontainers.image.source="https://github.com/tobydoescode/trivy-dashboard" \
      org.opencontainers.image.description="Trivy Operator vulnerability dashboard" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/trivy-dashboard /trivy-dashboard
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/trivy-dashboard"]
