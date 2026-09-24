FROM rust:1.98-bookworm AS build
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY vendor ./vendor

# Compile the stable dependency graph before copying Lighthouse sources. This
# layer is reused until Cargo manifests or vendored MetaMesh code change.
RUN mkdir src \
    && printf 'pub fn dependency_cache() {}\n' > src/lib.rs \
    && printf 'fn main() {}\n' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY src ./src
# Rebuild only the root package after replacing the placeholder sources.
RUN touch src/lib.rs src/main.rs \
    && cargo build --release --locked

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
