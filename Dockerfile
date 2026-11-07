# syntax=docker/dockerfile:1
# OpenPak Terraria service: the cross-play relay (UDP 22950, game transport) and its internal HTTP surface (20260).
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false \
    -ldflags="-s -w -X main.version=${VERSION}" -o /out/terraria ./cmd/terraria

FROM gcr.io/distroless/static
COPY --from=build /out/terraria /terraria
USER nonroot:nonroot
EXPOSE 20260 22950/udp
HEALTHCHECK CMD ["/terraria", "healthcheck"]
ENTRYPOINT ["/terraria"]
