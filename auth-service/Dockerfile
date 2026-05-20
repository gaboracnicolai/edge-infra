# Multi-stage build for the Rust ext_authz service.
# Build context is auth-service/ (not the repo root) — see Makefile target.

# The spec called for rust:1.79-slim, but the Cargo.lock locked in during
# Phase 4 (under Rust 1.95) pulls transitive deps requiring rustc 1.88+
# (time, time-core, time-macros). Pinning to 1.95-slim matches the toolchain
# that produced Cargo.lock — fully reproducible without touching source.
FROM rust:1.95-slim AS builder
WORKDIR /app

# Cache dependency compilation by building a stub crate first.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
 && echo 'fn main(){}' > src/main.rs \
 && cargo build --release \
 && rm -rf src

# Now bring in the real sources and rebuild.
COPY src ./src
RUN touch src/main.rs \
 && cargo build --release


FROM gcr.io/distroless/cc:nonroot
COPY --from=builder /app/target/release/auth-service /auth-service
USER nonroot:nonroot
EXPOSE 50051 9090
ENTRYPOINT ["/auth-service"]
