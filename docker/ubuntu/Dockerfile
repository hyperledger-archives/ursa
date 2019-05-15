FROM ubuntu:18.04

LABEL maintainer="Michael Lodder <redmike7@gmail.com>"

ENV PATH /root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV SODIUM_LIB_DIR /usr/local/lib
ENV LD_LIBRARY_PATH /usr/local/lib

WORKDIR /root

RUN apt-get update 2>&1 > /dev/null \
    && apt-get install -qq -y sudo cmake autoconf libtool curl python3 pkg-config libssl1.0.0 libssl-dev 2>&1 > /dev/null \
    && cd /usr/lib/x86_64-linux-gnu \
    && ln -s libssl.so.1.0.0 libssl.so.10 \
    && ln -s libcrypto.so.1.0.0 libcrypto.so.10 \
    && curl -fsSL https://download.libsodium.org/libsodium/releases/libsodium-1.0.16.tar.gz | tar -xz \
    && cd libsodium-1.0.16 \ 
    && ./autogen.sh \
    && ./configure \
    && make install \
    && cd .. \
    && rm -rf libsodium-1.0.16 \
    && curl https://sh.rustup.rs -sSf | sh -s -- -y
