FROM node:22-bookworm-slim

ENV NODE_ENV=production
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git jq unzip tar \
  && rm -rf /var/lib/apt/lists/*

# Install pinned-by-build open-source scanner binaries from official GitHub releases.
# Override the build args for reproducible production releases after validation.
ARG NUCLEI_VERSION=latest
ARG TRIVY_VERSION=latest
ARG GITLEAKS_VERSION=latest

RUN set -eux; \
  arch="$(dpkg --print-architecture)"; \
  case "$arch" in amd64) narch="amd64"; tarch="64bit"; garch="x64" ;; arm64) narch="arm64"; tarch="ARM64"; garch="arm64" ;; *) echo "unsupported arch $arch"; exit 1 ;; esac; \
  if [ "$NUCLEI_VERSION" = "latest" ]; then NUCLEI_VERSION="$(curl -fsSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r .tag_name)"; fi; \
  nv="${NUCLEI_VERSION#v}"; \
  curl -fsSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${nv}_linux_${narch}.zip"; \
  unzip -q /tmp/nuclei.zip -d /tmp/nuclei; install /tmp/nuclei/nuclei /usr/local/bin/nuclei; \
  if [ "$TRIVY_VERSION" = "latest" ]; then TRIVY_VERSION="$(curl -fsSL https://api.github.com/repos/aquasecurity/trivy/releases/latest | jq -r .tag_name)"; fi; \
  tv="${TRIVY_VERSION#v}"; \
  curl -fsSL -o /tmp/trivy.tar.gz "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_${tv}_Linux-${tarch}.tar.gz"; \
  tar -xzf /tmp/trivy.tar.gz -C /tmp trivy; install /tmp/trivy /usr/local/bin/trivy; \
  if [ "$GITLEAKS_VERSION" = "latest" ]; then GITLEAKS_VERSION="$(curl -fsSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r .tag_name)"; fi; \
  gv="${GITLEAKS_VERSION#v}"; \
  curl -fsSL -o /tmp/gitleaks.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${gv}_linux_${garch}.tar.gz"; \
  tar -xzf /tmp/gitleaks.tar.gz -C /tmp gitleaks; install /tmp/gitleaks /usr/local/bin/gitleaks; \
  rm -rf /tmp/*

COPY package.json ./
COPY server.js ./

# Cache the community nuclei templates into the image. A production image should
# be rebuilt on a controlled cadence to update this content.
RUN nuclei -update-templates -silent || true

USER node
EXPOSE 8080
CMD ["node","server.js"]
