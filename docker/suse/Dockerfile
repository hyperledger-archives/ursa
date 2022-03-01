FROM opensuse:leap

LABEL maintainer="Michael Lodder <redmike7@gmail.com>"

ENV PATH /root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV LD_LIBRARY_PATH /usr/local/lib

WORKDIR /root

RUN zypper --non-interactive update \
    && zypper --non-interactive install sudo make gcc autoconf libtool curl python3 pkg-config openssl-devel 2>&1 > /dev/null \
    && curl https://sh.rustup.rs -sSf | sh -s -- -y
