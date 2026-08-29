# --- Stage 1: Build Rust Vella Native Engine ---
FROM rust:1.80-slim as rust-builder
WORKDIR /usr/src/jia/native
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY native/Cargo.toml native/Cargo.lock ./
COPY native/src ./src
# Copy Vella local dependency path if applicable or cargo build
# Build optimized release binary
RUN cargo build --release

# --- Stage 2: Final Runtime Container ---
FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy built native engine binary
COPY --from=rust-builder /usr/src/jia/native/target/release/jia_native /app/jia_native
COPY start_jia.sh /app/start_jia.sh
RUN chmod +x /app/start_jia.sh /app/jia_native

EXPOSE 9090 8000

ENV RUST_LOG=info
ENV PORT=9090

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD curl -f http://localhost:9090/api/v1/health || exit 1

ENTRYPOINT ["/app/jia_native"]
