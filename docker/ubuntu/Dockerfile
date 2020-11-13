# Copyright contributors to Hyperledger Ursa
# SPDX-License-Identifier: Apache-2.0

FROM ubuntu:18.04

ENV PATH /root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV SODIUM_LIB_DIR /usr/local/lib
ENV SODIUM_INCLUDE_DIR /usr/local/include
ENV LD_LIBRARY_PATH /usr/local/lib
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get dist-upgrade -y

# Install dependencies and required tools
RUN apt-get install -y \
    git \
    vim \
    cmake \
    sudo \
    autoconf \
    libtool \
    curl \
    python3 \
    pkg-config \
    libssl1.0.0 \
    libssl-dev \
    llvm \
    llvm-dev \
    clang

WORKDIR /root

RUN cd /usr/lib/x86_64-linux-gnu \
    && ln -s libssl.so.1.0.0 libssl.so.10 \
    && ln -s libcrypto.so.1.0.0 libcrypto.so.10 \
    && curl -fsSL https://github.com/jedisct1/libsodium/archive/1.0.18.tar.gz | tar -xz \
    && cd libsodium-1.0.18 \
    && ./autogen.sh \
    && ./configure \
    && make install \
    && cd .. \
    && rm -rf libsodium-1.0.18 \
    && curl https://sh.rustup.rs -sSf | sh -s -- -y \
    && cargo install cargo-deb

