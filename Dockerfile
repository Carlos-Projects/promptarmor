FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/Carlos-Projects/promptarmor"
LABEL org.opencontainers.image.description="PromptArmor - Runtime defense against prompt injection"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

EXPOSE 8080

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["promptarmor"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
