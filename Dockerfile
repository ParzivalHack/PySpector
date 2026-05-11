    FROM python:3.12-slim-bookworm as builder

    RUN apt-get update && apt-get install -y \
        curl build-essential pkg-config libssl-dev git \
        && rm -rf /var/lib/apt/lists/*

    # Installazione di Rust
    RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    ENV PATH="/root/.cargo/bin:${PATH}"
    ENV PYO3_PYTHON=/usr/local/bin/python3.12

    WORKDIR /app

    COPY Cargo.toml Cargo.lock* ./
    COPY requirements.txt ./

    RUN mkdir src && echo "fn main() {}" > src/main.rs && \
        cargo build --release -j $(nproc) && \
        rm -rf src

    # 2. Copiamo tutto il codice sorgente
    COPY . .

    RUN cargo build --release -j $(nproc) --config 'target.x86_64-unknown-linux-gnu.rustflags=["-C", "link-arg=-L/usr/local/lib", "-C", "link-arg=-lpython3.12"]'

    # --- STAGE 2: Runtime (Immagine finale) ---
    FROM python:3.12-slim-bookworm

    # Definiamo le variabili d'ambiente necessarie
    ENV PYTHONDONTWRITEBYTECODE=1 \
        PYTHONUNBUFFERED=1 \
        LD_LIBRARY_PATH=/usr/local/lib

    WORKDIR /app

    RUN apt-get update && apt-get install -y \
        libssl3 \
        && rm -rf /var/lib/apt/lists/*

    COPY --from=builder /app/target/release/pyspector-api /usr/local/bin/pyspector-api

    COPY requirements.txt .
    RUN pip install --no-cache-dir -r requirements.txt

    COPY . .
    RUN pip install --no-cache-dir .

    RUN python3 -c "import pyspector._rust_core; print('✓ Rust core loaded successfully')"

    # Esposizione porta e comando di avvio
    EXPOSE 10000

    # Usiamo ENTRYPOINT per permettere di passare argomenti al binario se necessario
    ENTRYPOINT ["pyspector-api"]
