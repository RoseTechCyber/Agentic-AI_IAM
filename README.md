# Agentic AI IAM

A self-hostable proof of concept for identity lifecycle governance, authentication, authorization, audit analysis, and anomaly response.

> **Architecture note:** Microsoft Foundry is an Azure service and is not currently a standalone self-hosted product. This POC therefore exposes a `FoundryIQ` provider boundary and defaults to a local OpenAI-compatible model (Ollama, vLLM, or LocalAI). A hosted Foundry adapter can be added without changing the workflow or database contracts.

## What is included

- FastAPI web API and Swagger UI at `/docs`.
- SQLite by default; PostgreSQL is supported through `DATABASE_URL`.
- Database-backed policies, playbooks, users, roles, entitlements, access events, and anomaly cases.
- Four reasoning boundaries: `WorkIQ` (policy/governance), `FoundryIQ` (LLM reasoning), `DatabaseIQ` (facts/playbooks), and `WebIQ` (enrichment boundary).
- Identification, authentication, authorization, and audit stages.
- Threshold/clipping controls for risk scores and wrong-time check-in detection.
- Deterministic anomaly scoring that works without an LLM.
- Lightweight local RAG over policy/playbook text. Optional embeddings can be supplied by an OpenAI-compatible embedding endpoint.
- Seed data and a runnable demo workflow.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
python -m iam.seed
uvicorn iam.api:app --reload
```

Open http://127.0.0.1:8000/docs. Run the demo:

```bash
curl -X POST http://127.0.0.1:8000/demo/run
```

## Docker

```bash
docker compose up --build
```

The default compose profile is deliberately local-only. To use a local model, run Ollama separately and set `LLM_BASE_URL`, `LLM_MODEL`, and `EMBEDDING_MODEL` in `.env`.

## Important API calls

```bash
# Evaluate one identity event
curl -X POST http://localhost:8000/evaluate \
  -H 'content-type: application/json' \
  -d '{"user_id":"u-100","event_type":"login","source_ip":"203.0.113.10","occurred_at":"2026-01-15T02:30:00Z","device_trust":0.2,"mfa_satisfied":false,"requested_resource":"finance/payroll"}'

# Inspect effective policy and cross-matrix decisions
curl http://localhost:8000/users/u-100/access-matrix
curl http://localhost:8000/playbooks
curl http://localhost:8000/cases
```

## Security and production hardening

This is a POC, not a complete IAM control plane. Before production use, add OIDC/mTLS for the API, secret management, immutable/WORM audit storage, tenant isolation, encryption at rest, database migrations, rate limiting, approval workflows, model-output validation, and a real vector index (pgvector/Qdrant/OpenSearch). Do not send raw credentials, tokens, or unnecessary personal data to an LLM or external web service.

## Repository layout

- `iam/api.py` - HTTP API and demo endpoint
- `iam/workflow.py` - stage orchestration and anomaly decisions
- `iam/agents.py` - WorkIQ, FoundryIQ, DatabaseIQ, and WebIQ boundaries
- `iam/repository.py` - SQLite/PostgreSQL-friendly persistence boundary
- `iam/rag.py` - local retrieval and optional embedding adapter
- `iam/schema.sql` - relational schema
- `iam/seed.py` - sample IAM policies, matrix, users, and events
