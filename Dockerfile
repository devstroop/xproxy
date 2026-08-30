# syntax=docker/dockerfile:1.7
# ── Build stage ───────────────────────────────────────────────
FROM rust:1.75-bookworm AS builder

RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Cache deps
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs \
 && cargo build --release \
 && rm -rf src

# Build
COPY src ./src
COPY crates ./crates
RUN touch src/main.rs && cargo build --release

RUN mkdir -p /out \
 && cp target/release/xproxy /out/xproxy \
 && strip /out/xproxy || true

# ── Runtime stage ─────────────────────────────────────────────
FROM gcr.io/distroless/cc-debian12

COPY --from=builder /out/xproxy /usr/local/bin/xproxy
COPY config.example.toml /app/config.example.toml

WORKDIR /app

# xproxy listens on forward 3128 and reverse 8080 by default
EXPOSE 3128 8080

# distroless has no shell; use direct binary entrypoint
ENTRYPOINT ["/usr/local/bin/xproxy"]
