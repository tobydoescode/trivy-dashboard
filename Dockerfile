# syntax=docker/dockerfile:1.23
# Multi-arch via BUILDPLATFORM; final image is built for $TARGETARCH (linux/arm64 in-cluster).
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/trivy-dashboard ./

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/trivy-dashboard /trivy-dashboard
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/trivy-dashboard"]
