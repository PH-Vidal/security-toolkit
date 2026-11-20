# Hardened minimal Python runtime image
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Install ping utility for network sweep module and remove apt cache
RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root user
RUN groupadd --gid 10001 secgroup \
    && useradd --uid 10001 --gid secgroup --shell /usr/sbin/nologin --create-home secuser

WORKDIR /app

COPY pyproject.toml README.md ./
COPY security_toolkit/ ./security_toolkit/
COPY samples/ ./samples/

RUN pip install --no-cache-dir . \
    && chown -R secuser:secgroup /app

USER secuser

ENTRYPOINT ["sec-toolkit"]
CMD ["--help"]
