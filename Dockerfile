FROM rust:1.98-bookworm AS build
WORKDIR /app
COPY . .
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /data lighthouse \
    && mkdir /data && chown lighthouse:lighthouse /data
COPY --from=build /app/target/release/mesh-lighthouse /usr/local/bin/mesh-lighthouse
USER lighthouse
EXPOSE 8080
CMD ["mesh-lighthouse", "serve-http", "/data", "0.0.0.0:8080"]
