ARG BASE_IMAGE=golang:1.24-bookworm
FROM ${BASE_IMAGE}

ARG UB_GID
ARG UB_UID

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ldap-utils \
        net-tools \
        iproute2 \
        inetutils-ping \
        inetutils-traceroute \
        netcat-traditional \
        dnsutils \
        nmap \
        curl \
        wget \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g ${UB_GID} ubuntu \
    && useradd -g ${UB_GID} -u ${UB_UID} -m -s /bin/bash ubuntu \
    && mkdir /work \
    && chown ubuntu:ubuntu /work

USER ubuntu

WORKDIR /work