FROM python:3.12-slim-bookworm as builder

RUN apt-get update && apt-get install -y \
    curl build-essential pkg-config libssl-dev

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app
COPY . .

ENV PYO3_PYTHON=/usr/local/bin/python3.12

RUN cargo build --release -j 1 --config 'target.x86_64-unknown-linux-gnu.rustflags=["-C", "link-arg=-L/usr/local/lib", "-C", "link-arg=-lpython3.12"]'

FROM python:3.12-slim-bookworm

ENV LD_LIBRARY_PATH=/usr/local/lib

COPY --from=builder /app/target/release/pyspector-api /usr/local/bin/pyspector-api
EXPOSE 10000
CMD ["pyspector-api"]