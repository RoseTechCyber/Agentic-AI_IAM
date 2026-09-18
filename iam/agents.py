from __future__ import annotations

import json
import math
import os
from typing import Any

import httpx

from .repository import Repository


class DatabaseIQ:
    def __init__(self, repo: Repository): self.repo = repo
    def user_context(self, user_id: str) -> dict[str, Any]:
        user = self.repo.user(user_id)
        if not user: raise ValueError(f"Unknown identity: {user_id}")
        roles = self.repo.execute("SELECT r.* FROM roles r JOIN user_roles ur ON ur.role_id=r.id WHERE ur.user_id=?", (user_id,))
        entitlements = self.repo.execute("SELECT e.* FROM entitlements e JOIN role_entitlements re ON re.entitlement_id=e.id JOIN user_roles ur ON ur.role_id=re.role_id WHERE ur.user_id=?", (user_id,))
        return {"user": user, "roles": roles, "entitlements": entitlements, "recent_events": self.repo.events_for_user(user_id)}
    def playbooks(self) -> list[dict[str, Any]]: return self.repo.playbooks()


class WorkIQ:
    """Policy and governance reasoning; rules are database playbooks, not hard-coded prompts."""
    def __init__(self, repo: Repository): self.repo = repo
    def policy_context(self, stage: str) -> list[dict[str, Any]]:
        return [{**p, "rule": json.loads(p["rule_json"])} for p in self.repo.policies(stage)]


class WebIQ:
    """Safe enrichment boundary. It is intentionally disabled unless an allow-listed service is configured."""
    def enrich(self, source_ip: str | None) -> dict[str, Any]:
        return {"source_ip": source_ip, "reputation": "unknown", "external_lookup": False}


class FoundryIQ:
    """Foundry-compatible reasoning adapter; local OpenAI-compatible endpoint by default."""
    def __init__(self) -> None:
        self.base_url = os.getenv("LLM_BASE_URL", "").rstrip("/")
        self.model = os.getenv("LLM_MODEL", "")
    def explain(self, incident: dict[str, Any], evidence: list[dict[str, Any]]) -> str:
        if not self.base_url or not self.model:
            return "Contain access, require step-up MFA, review the identity and preserve audit evidence."
        prompt = {"model": self.model, "messages": [{"role": "system", "content": "You are a cautious IAM incident analyst. Return one concise recommendation; never invent facts."}, {"role": "user", "content": json.dumps({"incident": incident, "evidence": evidence})}], "temperature": 0}
        try:
            response = httpx.post(f"{self.base_url}/v1/chat/completions", json=prompt, timeout=20)
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
        except Exception:
            return "LLM unavailable: contain access, require step-up MFA, and review the identity using the stored evidence."


class LocalRAG:
    def __init__(self, repo: Repository): self.repo = repo
    @staticmethod
    def _tokens(text: str) -> set[str]: return {x.lower().strip(".,:;()") for x in text.split() if len(x) > 2}
    def search(self, query: str, limit: int = 3) -> list[dict[str, Any]]:
        q = self._tokens(query); scored = []
        for row in self.repo.execute("SELECT id,name,stage,text FROM policies WHERE enabled=1"):
            words = self._tokens(row["text"]); score = len(q & words) / max(1, len(q | words))
            scored.append((score, row))
        return [row | {"similarity": round(score, 4)} for score, row in sorted(scored, key=lambda x: x[0], reverse=True)[:limit]]
