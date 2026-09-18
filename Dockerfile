# syntax=docker/dockerfile:1
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY iam ./iam
RUN pip install --no-cache-dir .
ENV DATABASE_URL=sqlite:///./data/iam.db
RUN mkdir -p /app/data
EXPOSE 8000
CMD ["sh", "-c", "python -m iam.seed && uvicorn iam.api:app --host 0.0.0.0 --port 8000"]
