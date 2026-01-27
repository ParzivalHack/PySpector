# BUILDER STAGE
FROM rust:1.75-slim-bookworm as builder
RUN apt-get update && apt-get install -y python3.12-dev libpython3.12-dev pkg-config
WORKDIR /app
COPY . .
# Build the workspace binary
RUN cargo build --release

# RUNNER STAGE
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y python3.12 libpython3.12
# Copy the binary from the workspace target folder
COPY --from=builder /app/target/release/pyspector-api /usr/local/bin/pyspector-api
EXPOSE 10000
CMD ["pyspector-api"]