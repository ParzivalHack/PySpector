# STAGE 1: BUILDER
FROM python:3.12-slim-bookworm as builder

# Install Rust and build dependencies
RUN apt-get update && apt-get install -y \
    curl build-essential pkg-config libssl-dev
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app
COPY . .

# Build the workspace binary
RUN cargo build --release

# STAGE 2: RUNNER
FROM python:3.12-slim-bookworm

# Copy the binary from the builder stage
COPY --from=builder /app/target/release/pyspector-api /usr/local/bin/pyspector-api

EXPOSE 10000
CMD ["pyspector-api"]
