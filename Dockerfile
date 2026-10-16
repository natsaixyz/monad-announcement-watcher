FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends gnupg ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -g 10001 watcher && useradd -u 10001 -g watcher -M watcher && \
    mkdir /state && chown 10001:10001 /state
WORKDIR /app
COPY watcher.py notifiers.py verifier.py config.json ./
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
CMD ["python", "watcher.py"]
