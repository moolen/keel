FROM debian:trixie-slim

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG GO_VERSION=1.26.2
ARG YQ_VERSION=v4.53.2
ARG GRYPE_VERSION=v0.111.1
ARG HADOLINT_VERSION=v2.14.0
ARG CRANE_VERSION=v0.21.5
ARG GOLANGCI_LINT_VERSION=v2.11.4
ARG GOVULNCHECK_VERSION=v1.3.0
ARG OPENCODE_VERSION=v1.14.28

ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/home/agent/go
ENV PATH=/usr/local/go/bin:/home/agent/go/bin:${PATH}

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
 && install -m 0755 -d /etc/apt/keyrings \
 && curl --retry 5 --retry-all-errors -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
 && chmod a+r /etc/apt/keyrings/docker.asc \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian trixie stable" > /etc/apt/sources.list.d/docker.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
    awscli \
    bash \
    bpftool \
    build-essential \
    ca-certificates \
    clang \
    curl \
    containerd.io \
    docker-buildx-plugin \
    docker-ce \
    docker-ce-cli \
    docker-ce-rootless-extras \
    docker-compose-plugin \
    file \
    fuse-overlayfs \
    g++ \
    gcc \
    gh \
    git \
    iproute2 \
    iptables \
    jq \
    less \
    libbpf-dev \
    libffi-dev \
    libssl-dev \
    linux-libc-dev \
    make \
    netcat-openbsd \
    openssh-client \
    pkg-config \
    procps \
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    ripgrep \
    rsync \
    slirp4netns \
    socat \
    strace \
    tar \
    uidmap \
    unzip \
    llvm \
    vim-tiny \
    wget \
    xz-utils \
    zip \
    vim \
 && rm -rf /var/lib/apt/lists/*

RUN set -euo pipefail \
 && tmpdir="$(mktemp -d)" \
 && trap 'rm -rf "${tmpdir}"' EXIT \
 && curl --retry 5 --retry-all-errors -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o "${tmpdir}/go.tgz" \
 && rm -rf /usr/local/go \
 && tar -C /usr/local -xzf "${tmpdir}/go.tgz"

RUN set -euo pipefail \
 && tmpdir="$(mktemp -d)" \
 && trap 'rm -rf "${tmpdir}"' EXIT \
 && download() { curl --retry 5 --retry-delay 2 --retry-all-errors -fsSL "$1" -o "$2"; } \
 && download "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_amd64" /usr/local/bin/yq \
 && chmod +x /usr/local/bin/yq \
 && download "https://github.com/hadolint/hadolint/releases/download/${HADOLINT_VERSION}/hadolint-linux-x86_64" /usr/local/bin/hadolint \
 && chmod +x /usr/local/bin/hadolint \
 && download "https://github.com/anchore/grype/releases/download/${GRYPE_VERSION}/grype_${GRYPE_VERSION#v}_linux_amd64.tar.gz" "${tmpdir}/grype.tar.gz" \
 && tar -xzf "${tmpdir}/grype.tar.gz" -C "${tmpdir}" grype \
 && install -m 0755 "${tmpdir}/grype" /usr/local/bin/grype \
 && download "https://github.com/google/go-containerregistry/releases/download/${CRANE_VERSION}/go-containerregistry_Linux_x86_64.tar.gz" "${tmpdir}/crane.tar.gz" \
 && tar -xzf "${tmpdir}/crane.tar.gz" -C "${tmpdir}" crane gcrane \
 && install -m 0755 "${tmpdir}/crane" /usr/local/bin/crane \
 && install -m 0755 "${tmpdir}/gcrane" /usr/local/bin/gcrane \
 && download "https://github.com/golangci/golangci-lint/releases/download/${GOLANGCI_LINT_VERSION}/golangci-lint-${GOLANGCI_LINT_VERSION#v}-linux-amd64.tar.gz" "${tmpdir}/golangci-lint.tar.gz" \
 && tar -xzf "${tmpdir}/golangci-lint.tar.gz" -C "${tmpdir}" --strip-components=1 "golangci-lint-${GOLANGCI_LINT_VERSION#v}-linux-amd64/golangci-lint" \
 && install -m 0755 "${tmpdir}/golangci-lint" /usr/local/bin/golangci-lint \
 && GOBIN=/usr/local/bin go install "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}"

RUN set -euo pipefail \
 && tmpdir="$(mktemp -d)" \
 && trap 'rm -rf "${tmpdir}"' EXIT \
 && curl --retry 5 --retry-delay 2 --retry-all-errors -fsSL "https://github.com/anomalyco/opencode/releases/download/${OPENCODE_VERSION}/opencode-linux-x64.tar.gz" -o "${tmpdir}/opencode.tar.gz" \
 && tar -xzf "${tmpdir}/opencode.tar.gz" -C "${tmpdir}" \
 && install -m 0755 "${tmpdir}/opencode" /usr/local/bin/opencode

RUN if [[ ! -e /usr/local/bin/python ]]; then ln -s /usr/bin/python3 /usr/local/bin/python; fi

RUN printf '%s\n' "export GOPATH=/home/agent/go" "export PATH=/usr/local/go/bin:/home/agent/go/bin:\${PATH}" > /etc/profile.d/keel-devtools-path.sh \
 && chmod 0644 /etc/profile.d/keel-devtools-path.sh

RUN groupadd --gid 1000 agent \
 && useradd --uid 1000 --gid 1000 --create-home --shell /bin/bash agent \
 && mkdir -p /workspace /home/agent/go \
 && chown -R agent:agent /workspace /home/agent

WORKDIR /workspace
USER agent

LABEL org.opencontainers.image.source="https://github.com/moolen/keel"
LABEL org.opencontainers.image.description="Feature-rich development image for coding agents and Firecracker workflows"
