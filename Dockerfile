# Stage 1: Chef — prepare dependency recipe
# Floor at 1.88: Cargo must understand edition2024 for crates.io deps; cargo-chef current release
# also needs a recent toolchain. `rust-toolchain.toml` uses `stable`, so the first `cargo` run may
# rustup-install a newer stable than the base image (expected).
FROM rust:1.88-bookworm AS chef
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev cmake build-essential \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked
WORKDIR /app

# Stage 2: Planner — compute dependency recipe
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: Builder — build dependencies then application
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
# CLI package binary name is `agentfirewall` (see crates/agentfirewall-cli/Cargo.toml).
RUN cargo build --release --bin agentfirewall-server --bin agentfirewall

# Stage 4: Runtime — minimal image
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 libpq5 \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --shell /bin/bash agentfirewall
WORKDIR /app
COPY --from=builder /app/target/release/agentfirewall-server /app/agentfirewall-server
COPY --from=builder /app/target/release/agentfirewall /app/agentfirewall-cli
COPY migrations/ /app/migrations/
USER agentfirewall
EXPOSE 8080 50051 9090
ENTRYPOINT ["/app/agentfirewall-server"]
