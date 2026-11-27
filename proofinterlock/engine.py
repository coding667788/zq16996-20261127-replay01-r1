"""Invariant evaluation for a fixed switched-shard policy state."""
from __future__ import annotations

from typing import Any

from .case import Case
from .proof import Prover
from .utility import as_tuple, first_present


def as_case(source: Case | dict[str, Any] | str) -> Case:
    if isinstance(source, Case):
        return source
    if isinstance(source, str):
        return Case.load(source)
    if isinstance(source, dict):
        return Case(source)
    raise TypeError("input must be a Case, path, or JSON object")


def prove_request(source: Case | dict[str, Any] | str, request: dict[str, Any] | str | None = None, *, mask: int = 0) -> dict[str, Any]:
    case = as_case(source)
    if request is None:
        req = _default_request(case.doc)
    elif isinstance(request, str):
        req = find_request(case.doc, request) or {"rule": request}
    else:
        req = request
    return Prover(case, mask, req).prove()


def _default_request(doc: dict[str, Any]) -> dict[str, Any]:
    req = first_present(doc, ("request", "execution_request"))
    if isinstance(req, dict):
        return req
    requests = first_present(doc, ("requests", "execution_requests"), [])
    if isinstance(requests, dict) and requests:
        first_id = next(iter(requests))
        item = requests[first_id]
        if isinstance(item, dict):
            result = dict(item)
            result.setdefault("id", first_id)
            return result
    for item in as_tuple(requests):
        if isinstance(item, dict):
            return item
    if isinstance(req, str):
        return {"rule": req}
    return {}


def find_request(doc: dict[str, Any], request_id: str) -> dict[str, Any] | None:
    requests = first_present(doc, ("requests", "execution_requests"), [])
    if isinstance(requests, dict):
        for rid, item in requests.items():
            if rid == request_id and isinstance(item, dict):
                result = dict(item)
                result.setdefault("id", rid)
                return result
    for item in as_tuple(requests):
        if isinstance(item, dict) and str(first_present(item, ("id", "request_id", "name"))) == request_id:
            return item
    req = first_present(doc, ("request", "execution_request"))
    if isinstance(req, dict) and str(first_present(req, ("id", "request_id", "name"))) == request_id:
        return req
    return None


def _entries(value: Any) -> list[Any]:
    if isinstance(value, dict):
        result = []
        for key, item in value.items():
            if isinstance(item, dict):
                data = dict(item)
                data.setdefault("id", key)
                result.append(data)
            else:
                result.append(item)
        return result
    return list(as_tuple(value))


def collect_invariants(case: Case) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    doc = case.doc
    inv = first_present(doc, ("invariants", "invariant", "safety_invariants"), {})
    if isinstance(inv, list):
        auth_raw = [x for x in inv if isinstance(x, dict) and str(x.get("kind", x.get("type", ""))).lower() in {"authenticatable", "allow", "must_allow", "always_authenticatable"}]
        deny_raw = [x for x in inv if isinstance(x, dict) and str(x.get("kind", x.get("type", ""))).lower() in {"deny", "always_deny", "must_deny", "denied"}]
        if not auth_raw and not deny_raw:
            auth_raw = inv
    elif isinstance(inv, dict):
        auth_raw = first_present(inv, ("always_authenticatable", "authenticatable", "must_authenticate", "allow", "always_allow"), [])
        deny_raw = first_present(inv, ("always_deny", "always_denied", "must_deny", "deny", "denied"), [])
    else:
        auth_raw, deny_raw = [], []

    # Top-level aliases are convenient for small examples.
    auth_raw = _entries(auth_raw) + _entries(first_present(doc, ("always_authenticatable", "authenticatable"), []))
    deny_raw = _entries(deny_raw) + _entries(first_present(doc, ("always_deny", "always_denied", "must_deny"), []))

    auth = [_invariant_to_request(case, item, index, "auth") for index, item in enumerate(auth_raw)]
    deny = [_invariant_to_request(case, item, index, "deny") for index, item in enumerate(deny_raw)]
    return auth, deny


def _invariant_to_request(case: Case, item: Any, index: int, kind: str) -> dict[str, Any]:
    if isinstance(item, str):
        found = find_request(case.doc, item)
        if found is not None:
            req = dict(found)
        elif "/" in item:
            person, service = item.split("/", 1)
            req = {"person": person, "service": service}
        else:
            req = {"rule": item}
        req.setdefault("id", f"{kind}-{index + 1}")
        req["invariant_kind"] = kind
        return req
    if not isinstance(item, dict):
        req = {"id": f"{kind}-{index + 1}"}
    else:
        req = dict(item)
    ref = first_present(req, ("request", "request_id", "use_request"))
    if ref is not None:
        base = find_request(case.doc, str(ref))
        if base:
            merged = dict(base)
            merged.update({k: v for k, v in req.items() if v is not None})
            req = merged
    req.setdefault("id", f"{kind}-{index + 1}")
    req["invariant_kind"] = kind
    return req


def check_mask(case: Case, mask: int) -> dict[str, Any]:
    """Lightweight invariant result used by subset-lattice search.

    The proof engine itself memoizes rule expansion per Prover; this cache
    ensures each policy subset is checked once, regardless of how many
    migration plans/orders reach it.
    """
    cache_key = ("invariant_check", mask)
    cached = case._report_cache.get(cache_key)
    if cached is not None:
        return cached
    report = _evaluate_mask(case, mask, include_proofs=False)
    case._report_cache[cache_key] = report
    return report


def evaluate_mask(case: Case, mask: int) -> dict[str, Any]:
    """Full invariant report, including minimal/violating proof trees."""
    cache_key = ("invariant_report", mask)
    cached = case._report_cache.get(cache_key)
    if cached is not None:
        return cached
    report = _evaluate_mask(case, mask, include_proofs=True)
    case._report_cache[cache_key] = report
    return report


def _evaluate_mask(case: Case, mask: int, *, include_proofs: bool) -> dict[str, Any]:
    auth_reqs, deny_reqs = collect_invariants(case)
    switched = [s["id"] for s in case.shards if mask & (1 << s["order"])]

    auth_results = []
    violations: list[dict[str, Any]] = []
    for req in auth_reqs:
        proof = Prover(case, mask, req).prove()
        person_ref = first_present(req, ("person", "person_id", "stable_person_id", "subject", "account"))
        entry = {
            "invariant_id": req.get("id"),
            "kind": "always_authenticatable",
            "person": person_ref,
            "stable_person": case.identity.person(person_ref),
            "service": req.get("service"),
            "allowed": proof["allowed"],
        }
        if proof["allowed"]:
            if include_proofs:
                entry["minimal_proof"] = proof
        else:
            failure = {k: proof.get(k) for k in ("error_code", "error", "notes", "budget")}
            entry["failure"] = failure
            violations.append({"invariant_id": req.get("id"), "kind": "always_authenticatable", "reason": "not_authenticatable", "detail": failure})
        auth_results.append(entry)

    deny_results = []
    for req in deny_reqs:
        proof = Prover(case, mask, req).prove()
        person_ref = first_present(req, ("person", "person_id", "stable_person_id", "subject", "account"))
        entry = {
            "invariant_id": req.get("id"),
            "kind": "always_deny",
            "person": person_ref,
            "stable_person": case.identity.person(person_ref),
            "service": req.get("service"),
            "allowed": proof["allowed"],
        }
        if proof["allowed"]:
            # The minimal proof is evidence that a must-deny request was admitted.
            if include_proofs:
                entry["violating_proof"] = proof
            violation = {
                "invariant_id": req.get("id"),
                "kind": "always_deny",
                "reason": "request_allowed",
            }
            if include_proofs:
                violation["minimal_proof"] = proof
            violations.append(violation)
        deny_results.append(entry)

    return {
        "mask": mask,
        "switched_shards": switched,
        "compliant": not violations,
        "authenticatable": auth_results,
        "always_deny": deny_results,
        "violations": violations,
    }
