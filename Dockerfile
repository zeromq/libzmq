FROM debian:buster-slim AS builder
LABEL maintainer="ZeroMQ Project <zeromq@imatix.com>"
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq \
    && apt-get install -qq --yes --no-install-recommends \
        autoconf \
        automake \
        build-essential \
        git \
        libkrb5-dev \
        libsodium-dev \
        libtool \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/libzmq
COPY . .
RUN ./autogen.sh \
    && ./configure --prefix=/usr/local --with-libsodium --with-libgssapi_krb5 \
    && make \
    && make check \
    && make install

FROM debian:buster-slim
LABEL maintainer="ZeroMQ Project <zeromq@imatix.com>"
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq \
    && apt-get install -qq --yes --no-install-recommends \
        libkrb5-dev \
        libsodium23 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local /usr/local
RUN ldconfig && ldconfig -p | grep libzmq
