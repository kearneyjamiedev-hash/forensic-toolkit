FROM python:3.12.14-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    ENABLE_API_DOCS=0 \
    HTTP_ALLOWED_HOSTS=127.0.0.1,localhost,::1 \
    HTTP_ALLOWED_ORIGIN_HOSTS=127.0.0.1,localhost,::1

WORKDIR /app

# ExifTool is installed natively in Linux. The application resolves it from PATH.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libimage-exiftool-perl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt

RUN python -m pip install --upgrade pip setuptools wheel \
    && python -m pip install --requirement /app/requirements.txt

# Fixed unprivileged runtime identity.
RUN groupadd --gid 10001 forensic \
    && useradd \
        --uid 10001 \
        --gid 10001 \
        --no-create-home \
        --shell /usr/sbin/nologin \
        forensic

COPY --chown=forensic:forensic app /app/app
COPY --chown=forensic:forensic forensics /app/forensics
COPY --chown=forensic:forensic static /app/static
COPY --chown=forensic:forensic scripts/container_healthcheck.py /app/scripts/container_healthcheck.py

RUN mkdir -p /app/data/uploads \
    && chown -R forensic:forensic /app/data /app/scripts

USER 10001:10001

EXPOSE 8000

HEALTHCHECK \
    --interval=30s \
    --timeout=5s \
    --start-period=15s \
    --retries=3 \
    CMD ["python", "/app/scripts/container_healthcheck.py"]

# Binding to 0.0.0.0 is required *inside* the container.
# compose.yaml publishes the port on host loopback only.
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
