# syntax=docker/dockerfile:1.7

# Keep the readable tag next to the immutable multi-platform digest so dependency
# updates remain reviewable.
FROM golang:1.27.0-bookworm@sha256:ded31c68586d2e49e760acc2e65a884b23d032e9bbbed0ae0c55abd3fcaf4452 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
	go mod download

COPY . .

ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN --mount=type=cache,target=/go/pkg/mod \
	--mount=type=cache,target=/root/.cache/go-build \
	CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -mod=readonly -trimpath -ldflags="-s -w" -o /out/layerleak-api ./cmd/api \
	&& CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -mod=readonly -trimpath -ldflags="-s -w" -o /out/layerleak-migrate-up ./cmd/migrate \
	&& CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -mod=readonly -trimpath -ldflags="-s -w" -o /out/layerleak-purge-raw-secrets ./cmd/purge \
	&& CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -mod=readonly -trimpath -ldflags="-s -w" -o /out/layerleak-healthcheck ./cmd/healthcheck \
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
