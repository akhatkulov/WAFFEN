FROM python:3.12-slim

LABEL maintainer="Akhatkulov (Me262)"
LABEL description="WAFFEN — WAF evasion-path research tool"
LABEL org.opencontainers.image.source="https://github.com/akhatkulov/WAFFEN"

WORKDIR /waffen

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY waffen/ waffen/

RUN pip install --no-cache-dir -e .

ENTRYPOINT ["waffen"]
CMD ["--help"]
