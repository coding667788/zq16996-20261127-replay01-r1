"""proofinterlock: deterministic proofs and safe policy-shard migration planning."""

from .api import ProofInterlock, solve
from .case import Case
from .engine import evaluate_mask, prove_request
from .migration import migrate
from .replay import replay_plan

__version__ = "1.0.0"

__all__ = [
    "Case",
    "ProofInterlock",
    "evaluate_mask",
    "prove_request",
    "replay_plan",
    "migrate",
    "solve",
    "__version__",
]
