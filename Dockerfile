FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY datasets ./datasets
COPY knowledge ./knowledge

RUN addgroup --system opsguard \
    && adduser --system --ingroup opsguard opsguard \
    && mkdir -p /run/opsguard/work \
    && chown -R opsguard:opsguard /run/opsguard

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

USER opsguard

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "opsguard.web.app:app", "--host", "0.0.0.0", "--port", "8000"]
