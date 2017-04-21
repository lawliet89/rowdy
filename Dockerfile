FROM debian:jessie
MAINTAINER Yong Wen Chua <me@yongwen.xyz>

ARG RUST_VERSION=nightly-2017-04-16

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
                                          libldap-dev \
    && curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain ${RUST_VERSION} \
    && apt-get remove -y --auto-remove curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV PATH "/root/.cargo/bin:${PATH}"
WORKDIR /app/src

COPY . ./
RUN cargo build --release --all --locked --all-features
