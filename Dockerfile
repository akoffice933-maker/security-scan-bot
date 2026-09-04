FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    clamav \
    clamav-daemon \
    && rm -rf /var/lib/apt/lists/*

RUN freshclam || true

RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.7_linux_amd64.zip -o /tmp/nuclei.zip \
    && apt-get update && apt-get install -y unzip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip \
    && nuclei -update-templates || true

RUN pip install --no-cache-dir semgrep bandit

RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/data

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

CMD ["python", "-m", "app.main"]
