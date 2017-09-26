FROM ubuntu:16.04

ARG uid=1000

RUN apt-get update && \
    apt-get install -y \
      pkg-config \
      curl \
      build-essential \
      cmake \
      git \
      python3.5 \
      python3-pip \
      python-setuptools \
      apt-transport-https \
      ca-certificates \
      debhelper \
      wget

RUN pip3 install -U \
	pip \
	setuptools \
	virtualenv

ENV RUST_ARCHIVE=rust-1.20.0-x86_64-unknown-linux-gnu.tar.gz
ENV RUST_DOWNLOAD_URL=https://static.rust-lang.org/dist/$RUST_ARCHIVE

RUN mkdir -p /rust
WORKDIR /rust

RUN curl -fsOSL $RUST_DOWNLOAD_URL \
    && curl -s $RUST_DOWNLOAD_URL.sha256 | sha256sum -c - \
    && tar -C /rust -xzf $RUST_ARCHIVE --strip-components=1 \
    && rm $RUST_ARCHIVE \
    && ./install.sh

ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/.cargo/bin"

RUN useradd -ms /bin/bash -u $uid indy
USER indy

RUN cargo install --git https://github.com/DSRCorporation/cargo-test-xunit

WORKDIR /home/indy

USER root
RUN pip3 install \
twine

USER indy
RUN virtualenv -p python3.5 /home/indy/test
USER root
RUN ln -sf /home/indy/test/bin/python /usr/local/bin/python3
RUN ln -sf /home/indy/test/bin/pip /usr/local/bin/pip3

RUN pip3 install -U pip plumbum
RUN apt-get install -y ruby-dev
RUN gem install fpm