FROM python:3.12-slim

ARG TARGETARCH=amd64
ARG NUCLEI_VERSION=3.3.7
ARG TRIVY_VERSION=0.74.0
ARG WITH_CLAMAV=0

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        curl \
        ca-certificates \
        unzip \
    && if [ "${WITH_CLAMAV}" = "1" ]; then \
         apt-get install -y --no-install-recommends clamav clamav-freshclam \
         && (freshclam || true); \
       fi \
    && rm -rf /var/lib/apt/lists/*

# Nuclei: versioned GitHub release. Templates download on first scan, not at build.
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) NARCH=amd64 ;; \
      arm64) NARCH=arm64 ;; \
      *) NARCH=amd64 ;; \
    esac; \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NARCH}.zip" -o /tmp/nuclei.zip; \
    unzip /tmp/nuclei.zip -d /usr/local/bin/; \
    chmod +x /usr/local/bin/nuclei; \
    rm /tmp/nuclei.zip

# Trivy: versioned tarball, no curl|sh
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) TARCH=64bit ;; \
      arm64) TARCH=ARM64 ;; \
      *) TARCH=64bit ;; \
    esac; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TARCH}.tar.gz" -o /tmp/trivy.tgz; \
    tar -xzf /tmp/trivy.tgz -C /usr/local/bin trivy; \
    chmod +x /usr/local/bin/trivy; \
    rm /tmp/trivy.tgz

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir semgrep

COPY . .

RUN mkdir -p /app/data /tmp/scans

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

EXPOSE 8080

CMD ["python", "-m", "app.main"]
