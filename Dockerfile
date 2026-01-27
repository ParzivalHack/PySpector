FROM python:3.12-slim-bookworm as builder

RUN apt-get update && apt-get install -y \
    curl build-essential pkg-config libssl-dev

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app
COPY . .

ENV PYO3_PYTHON=/usr/local/bin/python3

ENV RUSTFLAGS="-C link-arg=-lpython3.12"

# Build with -j 1 to prevent memory crashes
RUN cargo build --release -j 1

# STAGE 2: RUNNER
FROM python:3.12-slim-bookworm
COPY --from=builder /app/target/release/pyspector-api /usr/local/bin/pyspector-api
EXPOSE 10000
CMD ["pyspector-api"]