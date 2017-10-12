FROM japaric/x86_64-unknown-linux-musl:v0.1.10 as builder
ENV PATH "/root/.cargo/bin:${PATH}"

ARG RUST_VERSION=nightly-2017-10-11
ARG ARCHITECTURE=x86_64-unknown-linux-musl
RUN set -x \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
                                          build-essential \
                                          ca-certificates \
                                          curl \
                                          libcurl3 \
                                          git \
                                          file \
                                          libssl-dev \
                                          pkg-config \
                                          libmysqlclient-dev \
    && curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain ${RUST_VERSION} \
    && rustup target add "${ARCHITECTURE}" \
    && apt-get remove -y --auto-remove curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /app/src
COPY Cargo.toml Cargo.lock ./
COPY cli/Cargo.toml ./cli/Cargo.toml
COPY diesel/Cargo.toml ./diesel/Cargo.toml
RUN cargo fetch --locked -v

COPY ./ ./
RUN cargo build --release --package rowdy-cli --target "${ARCHITECTURE}" -v --frozen

# Runtime Image

FROM alpine:3.5
ARG ARCHITECTURE=x86_64-unknown-linux-musl

# See https://github.com/japaric/cross/issues/119
RUN apk add --update ca-certificates \
    && rm -rf /var/cache/apk/* /tmp/*
ENV SSL_CERT_DIR /etc/ssl/certs

WORKDIR /app
COPY --from=builder /app/src/target/${ARCHITECTURE}/release/rowdy-cli .
