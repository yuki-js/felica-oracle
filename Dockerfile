# syntax=docker/dockerfile:1
# FeliCa oracle server (stateless JSON-RPC over POST /).
# Build context: repository root (needs server/ + prover/).
# No cluster changes are made by this file.

FROM rust:1.89-slim-bookworm AS builder
WORKDIR /build

# Cache dependency compilation before copying sources.
COPY server/Cargo.toml server/Cargo.lock ./server/
COPY prover/Cargo.toml prover/Cargo.lock ./prover/
RUN mkdir -p server/src prover/src \
  && echo 'fn main() {}' > server/src/main.rs \
  && echo '' > server/src/lib.rs \
  && echo '' > prover/src/lib.rs \
  && (cd server && cargo fetch) \
  && rm -rf server/src prover/src

COPY server ./server
COPY prover ./prover
RUN cd server && cargo build --release --locked \
  && strip target/release/felica-oracle

FROM debian:bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl \
  && rm -rf /var/lib/apt/lists/* \
  && useradd -u 65532 -r -s /usr/sbin/nologin appuser
COPY --from=builder /build/server/target/release/felica-oracle /usr/local/bin/felica-oracle
USER 65532:65532
EXPOSE 3000
# jsonrpsee serves POST / only (GET / -> 405). Ping via JSON-RPC.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -sf -X POST http://127.0.0.1:3000 \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"ping","params":[]}' | grep -q pong
ENTRYPOINT ["/usr/local/bin/felica-oracle"]
