# RoseTech Agentic-AI IAM POC

A lightweight proof-of-concept identity and access management (IAM) service that combines:

- a canonical SQLite datastore
- event-driven queueing via SQLite triggers
- policy and playbook evaluation
- anomaly detection and case generation
- FastAPI endpoints for secure identity evaluation

This project demonstrates a simplified but realistic agentic IAM pattern for:
- identity evaluation
- access matrix enforcement
- anomaly scoring
- event queue processing
- policy-driven response workflows

---

## Overview

This POC models the following flow:

1. A user action is evaluated
2. Access is checked against role + permission entitlements
3. Risk is scored against policy rules
4. If the score crosses a configured threshold:
   - an anomaly case is created
   - a recommended policy action is generated
   - the event is enqueued for downstream processing
5. The event queue can be consumed by a worker or orchestration service

---

## Core architecture

```text
Client / API
   ↓
FastAPI app
   ↓
Repository / DB access layer
   ↓
SQLite datastore
   ├── identities
   ├── roles
   ├── permissions
   ├── identity_roles
   ├── role_permissions
   ├── access_events
   ├── anomaly_cases
   ├── policies
   ├── playbooks
   └── event_queue
## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
python -m iam.seed
pytest -q
uvicorn iam.api:app --reload
