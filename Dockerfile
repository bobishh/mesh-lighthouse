FROM rust:1.98-bookworm AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY vendor ./vendor
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /data lighthouse \
    && mkdir /data && chown lighthouse:lighthouse /data
COPY --from=build /app/target/release/mesh-lighthouse /usr/local/bin/mesh-lighthouse
COPY entrypoint.sh /usr/local/bin/lighthouse-entrypoint
USER lighthouse
EXPOSE 8080
CMD ["/bin/sh", "/usr/local/bin/lighthouse-entrypoint"]
