FROM opensuse:leap

LABEL maintainer="Michael Lodder <redmike7@gmail.com>"

ENV PATH /root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV SODIUM_LIB_DIR /usr/local/lib
ENV LD_LIBRARY_PATH /usr/local/lib

WORKDIR /root

RUN zypper --non-interactive update && zypper --non-interactive install sudo make gcc autoconf libtool curl python3 pkg-config openssl-devel 2>&1 > /dev/null \
    && curl -fsSL https://github.com/jedisct1/libsodium/archive/1.0.18.tar.gz | tar -xz \
    && cd libsodium-1.0.18 \
    && ./autogen.sh \
    && ./configure \
    && make \
    && make install \
    && cd .. \
    && rm -rf libsodium-1.0.18 \
    && curl https://sh.rustup.rs -sSf | sh -s -- -y
