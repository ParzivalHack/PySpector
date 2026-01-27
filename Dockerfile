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

# Install git for cloning repositories
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the binary
COPY --from=builder /app/target/release/pyspector-api /usr/local/bin/pyspector-api

# Copy the python source code so PyO3 can import it
COPY src /app/src

# Verify critical dependencies are importable
RUN python3 -c "import click; import requests; import toml; import sarif_om; import jinja2; import textual"

EXPOSE 10000
CMD ["pyspector-api"]