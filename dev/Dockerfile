ARG BASE_IMAGE=golang:1.24-bookworm
FROM ${BASE_IMAGE}

ARG UNAME
ARG UID
ARG GID

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

RUN groupadd -g ${GID} ${UNAME} \
    && useradd -g ${GID} -u ${UID} -m -s /bin/bash ${UNAME} \
    && mkdir /work \
    && chown ${UID}:${GID} /work

USER ${UNAME}

WORKDIR /work