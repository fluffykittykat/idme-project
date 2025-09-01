# Dockerfile
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=5000 \
    WEB_CONCURRENCY=2 \
    THREADS=4

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 10001 appuser
WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . .
USER appuser
EXPOSE 5000

# Shell-form so ${...} expands; `exec` makes Gunicorn PID 1 for clean signals
CMD exec gunicorn -w ${WEB_CONCURRENCY} -k gthread --threads ${THREADS} \
    -b 0.0.0.0:${PORT} --access-logfile - --error-logfile - app:app
