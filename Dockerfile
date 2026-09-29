FROM node:22-bookworm-slim AS frontend
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml ./
# Reuse Match components at the same revision as the native authority library.
RUN MATCH_UI_REV=$(node -e 'const fs = require("fs"); const line = fs.readFileSync("Cargo.toml", "utf8").split("\n").find(line => line.startsWith("match-authority =")); process.stdout.write(line.match(/rev = "([a-f0-9]+)"/)[1]);') \
    && git init /match \
    && git -C /match remote add origin https://github.com/bobishh/match.git \
    && git -C /match fetch --depth=1 origin "$MATCH_UI_REV" \
    && git -C /match checkout --detach FETCH_HEAD
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
ENV MATCH_UI_SOURCE=/match/src
RUN npm run build

FROM rust:1.98-bookworm AS build
WORKDIR /app

COPY Cargo.toml Cargo.lock ./

# Compile the stable dependency graph before copying Lighthouse sources. This
# layer is reused until Cargo manifests or pinned dependencies change.
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
COPY --from=frontend /app/frontend/dist /app/frontend/dist
ENV LIGHTHOUSE_FRONTEND_DIR=/app/frontend/dist
COPY entrypoint.sh /usr/local/bin/lighthouse-entrypoint
USER lighthouse
EXPOSE 8080
CMD ["/bin/sh", "/usr/local/bin/lighthouse-entrypoint"]
