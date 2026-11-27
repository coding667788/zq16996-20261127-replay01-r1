"""Public Python API for proofinterlock."""
from __future__ import annotations

from typing import Any

from .case import Case
from .engine import as_case, evaluate_mask, prove_request
from .migration import migrate
from .replay import replay_plan

__all__ = [
    "Case",
    "ProofInterlock",
    "evaluate_mask",
    "prove_request",
    "replay_plan",
    "migrate",
    "solve",
]


class ProofInterlock:
    """Object-oriented convenience facade over the functional API."""

    def __init__(self, source: Case | dict[str, Any] | str):
        self.case = as_case(source)

    def prove(self, request: dict[str, Any] | str | None = None, *, mask: int = 0) -> dict[str, Any]:
        return prove_request(self.case, request, mask=mask)

    def evaluate(self, mask: int) -> dict[str, Any]:
        return evaluate_mask(self.case, mask)

    def replay(self, plan: Any | None = None) -> dict[str, Any]:
        return replay_plan(self.case, plan)

    def migrate(self) -> dict[str, Any]:
        return migrate(self.case)

    def solve(self, *, request_id: str | None = None) -> dict[str, Any]:
        return solve(self.case, request_id=request_id)


def solve(source: Case | dict[str, Any] | str, *, request_id: str | None = None) -> dict[str, Any]:
    """Run proof, current-plan replay, and minimum migration analysis."""
    case = source if isinstance(source, Case) else Case.load(source) if isinstance(source, str) else Case(source)

    if request_id is not None:
        from .engine import find_request

        request = find_request(case.doc, request_id) or {"id": request_id, "rule": request_id}
        proof = prove_request(case, request)
    else:
        proof = prove_request(case)

    return {
        "schema": "proofinterlock/result@1",
        "proof": proof,
        "replay": replay_plan(case),
        "migration": migrate(case),
    }
