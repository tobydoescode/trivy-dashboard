# syntax=docker/dockerfile:1.27
# Multi-arch via BUILDPLATFORM; final image is built for $TARGETARCH (linux/arm64 in-cluster).
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
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

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
LABEL org.opencontainers.image.source="https://github.com/tobydoescode/trivy-dashboard" \
      org.opencontainers.image.description="Trivy Operator vulnerability dashboard" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/trivy-dashboard /trivy-dashboard
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/trivy-dashboard"]
