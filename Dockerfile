FROM python:3.12-slim-bookworm as builder

RUN apt-get update && apt-get install -y \
    curl build-essential pkg-config libssl-dev git

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app
COPY . .

ENV PYO3_PYTHON=/usr/local/bin/python3.12

# Build the Rust API binary
RUN cargo build --release -j 1 --config 'target.x86_64-unknown-linux-gnu.rustflags=["-C", "link-arg=-L/usr/local/lib", "-C", "link-arg=-lpython3.12"]'

FROM python:3.12-slim-bookworm

ENV LD_LIBRARY_PATH=/usr/local/lib

# Install git AND Rust compiler tools for the pip install step
RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the binary from builder
COPY --from=builder /app/target/release/pyspector-api /usr/local/bin/pyspector-api

# Install PySpector as a package
COPY setup.py setup.cfg pyproject.toml MANIFEST.in README.md ./
COPY src ./src

# Install PySpector properly so it's importable
RUN pip install --no-cache-dir -e .

# Verify installation
RUN python3 -c "import pyspector.cli; import pyspector.config; import pyspector.reporting; import pyspector._rust_core; print('✓ All imports successful')"

EXPOSE 10000
CMD ["pyspector-api"]