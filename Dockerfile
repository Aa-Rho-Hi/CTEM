FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml /workspace/pyproject.toml
RUN pip install --upgrade pip && pip install -e .[dev] && pip install "bcrypt==3.2.2"

COPY . /workspace

CMD ["sh", "-c", "if [ \"$SERVICE_ROLE\" = \"worker\" ]; then python -m http.server ${PORT:-8000} & celery -A celery_app.celery_app worker --loglevel=info --pool=solo -Q celery,scoring; else alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}; fi"]
