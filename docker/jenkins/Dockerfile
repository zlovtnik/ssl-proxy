FROM jenkins/jenkins:2.568.1-jdk21@sha256:f4f65e6cd1405cd889b7f5ac33f9d5cdc2a099de6b87fe8a3933b9c5d53d1d02

USER root

ARG DOCKER_BUILDX_VERSION=0.36.1-1~debian.13~trixie
ARG DOCKER_CE_CLI_VERSION=5:29.7.2-1~debian.13~trixie
ARG DOCKER_COMPOSE_VERSION=5.4.0-1~debian.13~trixie

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      git \
      gnupg \
      make \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg \
      -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && . /etc/os-release \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian ${VERSION_CODENAME} stable" \
      > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
      docker-buildx-plugin="${DOCKER_BUILDX_VERSION}" \
      docker-ce-cli="${DOCKER_CE_CLI_VERSION}" \
      docker-compose-plugin="${DOCKER_COMPOSE_VERSION}" \
    && rm -rf /var/lib/apt/lists/*

COPY plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt

COPY casc /usr/share/jenkins/ref/casc

USER jenkins
