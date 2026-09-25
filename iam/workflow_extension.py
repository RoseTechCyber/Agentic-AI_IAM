from __future__ import annotations

from typing import Any

from .orchestrator import IAMOrchestrator
from .repository import Repository


class IAMWorkflow:
    def __init__(self, repo: Repository | None = None) -> None:
        self.repo = repo or Repository()
        self.orchestrator = IAMOrchestrator(self.repo)

    def evaluate(self, event: dict[str, Any]) -> dict[str, Any]:
        return self.orchestrator.run(
            user_id=event["user_id"],
            event=event,
        )