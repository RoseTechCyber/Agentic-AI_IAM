from __future__ import annotations

import json
import os
from typing import Any

import httpx

from .repository import Repository


class DatabaseIQ:
    """Reads user facts, access matrices, and database playbooks."""

    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    def user_context(self, user_id: str) -> dict[str, Any]:
        user = self.repo.user(user_id)

        if not user:
            raise ValueError(f"Unknown identity: {user_id}")

        roles = self.repo.execute(
            """
            SELECT r.*
            FROM roles r
            JOIN identity_roles ir ON ir.role_id = r.id
            WHERE ir.identity_id=?
            """,
            (user_id,),
        )

        return {
            "user": user,
            "roles": roles,
            "entitlements": self.repo.access_matrix(user_id),
            "recent_events": self.repo.events_for_user(user_id),
        }

    def playbooks(self, stage: str) -> list[dict[str, Any]]:
        result = []

        for row in self.repo.playbooks(stage):
            result.append(
                {
                    **row,
                    "trigger": json.loads(row["trigger_json"]),
                    "steps": json.loads(row["steps_json"]),
                }
            )

        return result


class WorkIQ:
    """Policy and governance reasoning boundary."""

    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    def policy_context(self, stage: str) -> list[dict[str, Any]]:
        return [
            {
                **policy,
                "rule": json.loads(policy["rule_json"]),
            }
            for policy in self.repo.policies(stage)
        ]


class WebIQ:
    """Optional external enrichment boundary."""

    def enrich(self, source_ip: str | None) -> dict[str, Any]:
        # Deliberately disabled by default.
        return {
            "source_ip": source_ip,
            "reputation": "unknown",
            "external_lookup": False,
        }


class FoundryIQ:
    """
    Foundry-compatible reasoning adapter.

    The adapter expects an OpenAI-compatible endpoint, such as Ollama,
    vLLM, or LocalAI. It falls back to a deterministic recommendation.
    """

    def __init__(self) -> None:
        self.base_url = os.getenv("LLM_BASE_URL", "").rstrip("/")
        self.model = os.getenv("LLM_MODEL", "")

    def explain(
        self,
        incident: dict[str, Any],
        evidence: list[dict[str, Any]],
    ) -> str:
        fallback = (
            "Contain access, require step-up MFA, review the identity, "
            "and preserve audit evidence."
        )

        if not self.base_url or not self.model:
            return fallback

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a cautious IAM incident analyst. "
                        "Return one concise recommendation grounded only "
                        "in the supplied evidence."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "incident": incident,
                            "evidence": evidence,
                        }
                    ),
                },
            ],
            "temperature": 0,
        }

        try:
            response = httpx.post(
                f"{self.base_url}/v1/chat/completions",
                json=payload,
                timeout=20,
            )
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
        except (
            httpx.HTTPError,
            KeyError,
            IndexError,
            TypeError,
            ValueError,
        ):
            return fallback


class LocalRAG:
    """Lightweight local retrieval (policy search) adapter."""

    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    @staticmethod
    def _tokens(text: str) -> set[str]:
        # basic normalization: lowercase, strip punctuation, split on whitespace
        # ignore very short tokens
        return {
            word.lower().strip(".,:;()[]{}\"'`")
            for word in text.split()
            if len(word) > 2
        }

    def search(
        self,
        query: str,
        limit: int = 3,
        stage: str | None = None,
    ) -> list[dict[str, Any]]:
        query_tokens = self._tokens(query)
        scored: list[tuple[float, dict[str, Any]]] = []

        sql = "SELECT id, name, stage, text, priority FROM policies WHERE enabled=1"
        params: tuple = ()
        if stage:
            sql += " AND (stage=? OR stage='any')"
            params = (stage,)

        rows = self.repo.execute(sql, params)

        for row in rows:
            document_tokens = self._tokens(row["text"])
            # Jaccard similarity
            score = 0.0
            union = query_tokens | document_tokens
            if union:
                score = len(query_tokens & document_tokens) / len(union)
            scored.append((score, row))

        # sort primarily by score, secondarily by policy priority so low-similarity but high-priority policies surface
        scored.sort(key=lambda item: (item[0], item[1].get("priority", 0)), reverse=True)

        results = []
        for score, row in scored[:limit]:
            results.append(
                {
                    **row,
                    "similarity": round(score, 4),
                }
            )
        return results
