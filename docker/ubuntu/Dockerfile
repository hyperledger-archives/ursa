FROM ubuntu:18.04

LABEL maintainer="Michael Lodder <redmike7@gmail.com>"

ENV PATH /root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV SODIUM_LIB_DIR /usr/local/lib

WORKDIR /root

RUN apt-get update 2>&1 > /dev/null \
    && apt-get install -qq -y sudo cmake autoconf libtool curl python3 pkg-config libssl-dev 2>&1 > /dev/null \
    && curl -fsSL https://download.libsodium.org/libsodium/releases/libsodium-1.0.14.tar.gz | tar -xz \
    && cd libsodium-1.0.14 \ 
    && ./autogen.sh \
    && ./configure --prefix=/usr/local \
    && make \
    && make install \
    && cd .. \
    && rm -rf libsodium-1.0.14 \
    && curl https://sh.rustup.rs -sSf | sh -s -- -y
