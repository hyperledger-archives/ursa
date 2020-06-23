FROM ubuntu:20.04

LABEL maintainer="Cam Parra <caeparra@gmail.com>"

ENV PATH /root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV SODIUM_LIB_DIR /usr/local/lib
ENV SODIUM_INCLUDE_DIR /usr/local/include
ENV LD_LIBRARY_PATH /usr/local/lib
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get dist-upgrade -y

# very common packages
RUN apt-get update && apt-get install -y \
    git \
    wget \
    vim \
    apt-transport-https \
    ca-certificates \
    apt-utils \
    cmake \
    sudo \
    autoconf \
    libtool \
    curl \
    python3 \
    pkg-config \
    libssl-dev

RUN wget http://archive.ubuntu.com/ubuntu/pool/main/o/openssl1.0/libssl1.0.0_1.0.2n-1ubuntu5.3_amd64.deb  && \
    dpkg -i libssl1.0.0_1.0.2n-1ubuntu5.3_amd64.deb 

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
    && curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain nightly-2020-04-12

