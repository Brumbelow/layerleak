# syntax=docker/dockerfile:1.7

# Keep the readable tag next to the immutable multi-platform digest so dependency
# updates remain reviewable.
FROM --platform=$BUILDPLATFORM golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
	go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
# Release builds pass the version tag; local builds report "dev".
ARG LAYERLEAK_VERSION=dev

RUN --mount=type=cache,target=/go/pkg/mod \
	--mount=type=cache,target=/root/.cache/go-build \
	ldflags="-s -w -X github.com/brumbelow/layerleak/v3/internal/version.Version=${LAYERLEAK_VERSION}" \
	&& CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -mod=readonly -trimpath -ldflags="${ldflags}" -o /out/layerleak-api ./cmd/api \
	&& CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -mod=readonly -trimpath -ldflags="${ldflags}" -o /out/layerleak-migrate-up ./cmd/migrate \
	&& CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -mod=readonly -trimpath -ldflags="${ldflags}" -o /out/layerleak-purge-raw-secrets ./cmd/purge \
	&& CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -mod=readonly -trimpath -ldflags="${ldflags}" -o /out/layerleak-healthcheck ./cmd/healthcheck \
	&& install -d -m 1777 /out/rootfs/tmp

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/layerleak-api /usr/local/bin/layerleak-api
COPY --from=build /out/layerleak-migrate-up /usr/local/bin/layerleak-migrate-up
COPY --from=build /out/layerleak-purge-raw-secrets /usr/local/bin/layerleak-purge-raw-secrets
COPY --from=build /out/layerleak-healthcheck /usr/local/bin/layerleak-healthcheck
COPY --from=build --chown=10001:10001 /out/rootfs/tmp /tmp
COPY migrations /app/migrations

WORKDIR /app

ENV LAYERLEAK_API_ADDR=0.0.0.0:8080
ENV LAYERLEAK_FINDINGS_DIR=/tmp/layerleak/findings

EXPOSE 8080

USER 10001:10001

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=6 \
	CMD ["/usr/local/bin/layerleak-healthcheck"]

ENTRYPOINT ["/usr/local/bin/layerleak-api"]
