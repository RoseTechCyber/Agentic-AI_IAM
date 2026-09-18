# Agentic AI IAM

Self-hostable proof of concept for identity lifecycle governance,
authentication, authorization, audit analysis, and anomaly response.

## Included

- FastAPI API and Swagger UI
- WorkIQ, DatabaseIQ, FoundryIQ, and WebIQ boundaries
- Database-backed users, roles, entitlements, policies, and playbooks
- Identification, authentication, authorization, and audit stages
- Threshold-based risk scoring
- Wrong-time check-in detection
- Access-matrix evaluation
- Local policy retrieval/RAG
- Optional self-hosted OpenAI-compatible LLM adapter
- Docker and GitHub Actions test configuration

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
python -m iam.seed
pytest -q
uvicorn iam.api:app --reload
