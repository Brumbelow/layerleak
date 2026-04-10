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
