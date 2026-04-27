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
