# Build the Rust binary
FROM rust:1.75-slim-bookworm as builder
RUN apt-get update && apt-get install -y python3-dev pkg-config libpython3-dev
WORKDIR /app
COPY . .
RUN cargo build --release

# Lightweight image
FROM python:3.12-slim-bookworm
# Simply copy the Rust binary into an image that has Python 3.12
COPY --from=builder /app/target/release/pyspector-api /usr/local/bin/pyspector-api
EXPOSE 10000
CMD ["pyspector-api"]
