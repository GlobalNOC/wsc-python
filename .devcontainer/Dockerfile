FROM docker.io/oraclelinux:8-slim

LABEL org.opencontainers.image.source=https://github.grnoc.iu.edu/shared/wsc-python

ARG UV_VERSION=0.10.9
ARG UV_SHA256="20d79708222611fa540b5c9ed84f352bcd3937740e51aacc0f8b15b271c57594"

# Don't autocompile python
ENV PYTHONDONTWRITEBYTECODE=1

# set UV_LINK_MODE to copy as the venv will be a bind mount
ENV UV_LINK_MODE=copy

# Install required packages
RUN microdnf install -y \
    bash-completion \
    git \
    jq \
    less \
    make \
    procps-ng \
    python3.11-devel \
    python3.11-pip \
    python3.11-rpm-macros \
    rpm-build \
    rpm-sign \
    rpmlint \
    tar \
    which

# Install uv
RUN set -eux; \
    url="https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-x86_64-unknown-linux-gnu.tar.gz"; \
    curl -fsSL "${url}" -o /tmp/uv.tar.gz; \
    echo "${UV_SHA256}  /tmp/uv.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/uv.tar.gz -C /tmp; \
    install -m 0755 /tmp/uv*/uv /usr/local/bin/uv; \
    rm -rf /tmp/uv* /tmp/uv.tar.gz; \
    uv --version

COPY .devcontainer/prompt.sh /etc/profile.d/prompt.sh
RUN echo '[ -f /etc/bashrc ] && . /etc/bashrc' >> /root/.bashrc

WORKDIR /workspace
