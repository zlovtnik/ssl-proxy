FROM jenkins/jenkins:2.568.2-lts-jdk21@sha256:8547df3b0db2803d158ecc9499207a056bb30c23fddc18bb5b4a4dc14e77dd09

USER root

ARG DOCKER_BUILDX_VERSION=0.36.1-1~debian.13~trixie
ARG DOCKER_CE_CLI_VERSION=5:29.7.2-1~debian.13~trixie
ARG DOCKER_COMPOSE_VERSION=5.4.0-1~debian.13~trixie
ARG KUSTOMIZE_VERSION=5.7.0
ARG KUBECTL_VERSION=1.36.3
ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      git \
      gnupg \
      make \
      python3 \
      python3-yaml \
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
    && case "${TARGETARCH}" in \
      amd64) \
        KUSTOMIZE_SHA256="0d98f06d6d2c2c0ff8923cc136a517af74aaa187f1b9f3e17ff370d0625ede84"; \
        KUBECTL_SHA256="ebbd080e7c2e275093b55915722043257eb24004363e20acb3c4d71919f88336" \
        ;; \
      arm64) \
        KUSTOMIZE_SHA256="744bb1bc1854b6634dea9eaf6db2f401a734ed25d6837baa6f91157d79c27d5e"; \
        KUBECTL_SHA256="3d86f24401c41ae5a46ac50eef8865fe891d3647d324a0836f6c63757a126e62" \
        ;; \
      *) echo "unsupported target architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && curl -fsSL \
      "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/v${KUSTOMIZE_VERSION}/kustomize_v${KUSTOMIZE_VERSION}_linux_${TARGETARCH}.tar.gz" \
      -o /tmp/kustomize.tar.gz \
    && echo "${KUSTOMIZE_SHA256}  /tmp/kustomize.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/kustomize.tar.gz -C /usr/local/bin kustomize \
    && chmod 0755 /usr/local/bin/kustomize \
    && curl -fsSL \
      "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl" \
      -o /tmp/kubectl \
    && echo "${KUBECTL_SHA256}  /tmp/kubectl" | sha256sum -c - \
    && install -m 0755 /tmp/kubectl /usr/local/bin/kubectl \
    && rm -f /tmp/kustomize.tar.gz \
    && rm -f /tmp/kubectl \
    && rm -rf /var/lib/apt/lists/*

COPY plugins.lock.txt /usr/share/jenkins/ref/plugins.lock.txt
RUN jenkins-plugin-cli \
      --plugin-file /usr/share/jenkins/ref/plugins.lock.txt \
      --latest=false

COPY casc /usr/share/jenkins/ref/casc

USER jenkins
