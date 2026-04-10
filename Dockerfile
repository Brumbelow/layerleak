# syntax=docker/dockerfile:1.7

FROM golang:1.25-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
	go build -trimpath -ldflags="-s -w" -o /out/layerleak-api ./cmd/api

FROM ubuntu:24.04

ARG MIN_PGDG_CLIENT_VERSION=16.13-1.pgdg24.04+1

RUN apt-get update \
	&& apt-get install --yes --no-install-recommends ca-certificates curl gnupg \
	&& install -d -m 0755 /etc/apt/keyrings \
	&& curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /etc/apt/keyrings/postgresql.gpg \
	&& chmod a+r /etc/apt/keyrings/postgresql.gpg \
	&& echo "deb [signed-by=/etc/apt/keyrings/postgresql.gpg] https://apt.postgresql.org/pub/repos/apt noble-pgdg main" > /etc/apt/sources.list.d/pgdg.list \
	&& apt-get update \
	&& apt-get install --yes --no-install-recommends postgresql-client-16 \
	&& client_version="$(dpkg-query --showformat='${Version}' --show postgresql-client-16)" \
	&& case "$client_version" in *.pgdg24.04+*) ;; *) echo "unexpected postgresql-client-16 lineage: $client_version" >&2; exit 1 ;; esac \
	&& dpkg --compare-versions "$client_version" ge "$MIN_PGDG_CLIENT_VERSION" \
FROM debian:bookworm-slim

RUN apt-get update \
	&& apt-get install --yes --no-install-recommends ca-certificates postgresql-client \
	&& rm -rf /var/lib/apt/lists/*

RUN useradd --uid 10001 --home-dir /app --shell /usr/sbin/nologin --create-home layerleak

WORKDIR /app

COPY --from=build /out/layerleak-api /usr/local/bin/layerleak-api
COPY migrations /app/migrations
COPY scripts/layerleak-migrate-up.sh /usr/local/bin/layerleak-migrate-up

RUN chmod 0755 /usr/local/bin/layerleak-api /usr/local/bin/layerleak-migrate-up \
	&& chown -R layerleak:layerleak /app

ENV LAYERLEAK_API_ADDR=0.0.0.0:8080

EXPOSE 8080

USER layerleak

CMD ["/usr/local/bin/layerleak-api"]
