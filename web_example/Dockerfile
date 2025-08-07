# Builder

FROM rust:slim-bookworm AS builder

RUN apt-get update && \
  apt-get install -y \
  pkg-config \
  musl-tools \
  build-essential \
  cmake \
  && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /usr/src/app

ENV RUSTFLAGS='-C target-feature=+crt-static -C linker=musl-gcc'

COPY Cargo.toml Cargo.lock* ./

RUN mkdir src && \
  echo "fn main() {}" > src/main.rs && \
  cargo build --release --target x86_64-unknown-linux-musl && \
  rm -rf src/

COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl

# Production

FROM gcr.io/distroless/static-debian12

COPY --from=builder /usr/src/app/target/x86_64-unknown-linux-musl/release/service_actix /service_actix

EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT ["/service_actix"]
