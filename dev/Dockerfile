ARG BASE_IMAGE=golang:1.24-bookworm
FROM ${BASE_IMAGE}

ARG UB_GID
ARG UB_UID

RUN groupadd -g ${UB_GID} ubuntu \
    && useradd -g ${UB_GID} -u ${UB_UID} -m -s /bin/bash ubuntu \
    && mkdir /work \
    && chown ubuntu:ubuntu /work

USER ubuntu

WORKDIR /work