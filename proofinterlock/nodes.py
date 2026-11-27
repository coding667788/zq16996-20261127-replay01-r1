"""Proof/policy graph node normalization."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .utility import as_tuple, first_present

AND_WORDS = {"and", "all", "all_of", "every", "both", "∧", "且", "与"}
OR_WORDS = {"or", "any", "any_of", "one_of", "either", "∨", "或"}
THRESHOLD_WORDS = {
    "threshold",
    "at_least",
    "atleast",
    "at_least_k",
    "k_of",
    "quorum",
    "independent",
    "independent_sources",
    "m_of_n",
    "至少",
}
CREDENTIAL_WORDS = {"credential", "certificate", "cert", "signed_credential", "证件", "凭据"}
REF_WORDS = {"ref", "reference", "rule_ref", "rule_reference"}


@dataclass(slots=True)
class Node:
    kind: str
    children: tuple["Node", ...] = ()
    k: int | None = None
    ref: str | None = None
    query: dict[str, Any] = field(default_factory=dict)
    raw_type: str | None = None


def _kind_from_type(spec_type: Any) -> str | None:
    if spec_type is None:
        return None
    text = str(spec_type).strip().lower().replace("-", "_").replace(" ", "_")
    if text in AND_WORDS:
        return "and"
    if text in OR_WORDS:
        return "or"
    if text in THRESHOLD_WORDS or text.startswith("at_least_"):
        return "threshold"
    if text in CREDENTIAL_WORDS:
        return "credential"
    if text in REF_WORDS:
        return "ref"
    return None


def parse_node(spec: Any) -> Node:
    """Normalize one JSON rule node.

    Strings are references.  A mapping with ``ref``/``rule`` is a reference.
    Mappings containing child collections default to AND, except that ``k``
    makes them threshold nodes.
    """
    if isinstance(spec, str):
        return Node(kind="ref", ref=spec, query={"ref": spec})
    if isinstance(spec, (int, float, bool)) or spec is None:
        # A non-string scalar is not a meaningful policy node.  Keep it as an
        # impossible matcher rather than accidentally treating it as allow-all.
        return Node(kind="credential", query={"__invalid_scalar__": spec})
    if not isinstance(spec, dict):
        return Node(kind="credential", query={"__invalid_type__": type(spec).__name__})

    raw_type = first_present(spec, ("type", "kind", "op", "operator", "node_type"))
    kind = _kind_from_type(raw_type)

    ref = first_present(spec, ("ref", "$ref", "rule_ref", "reference", "target"))
    # "rule"/"rule_id" can name the rule itself in some schemas; only treat it
    # as a reference when no child/type says otherwise.
    child_value = first_present(
        spec,
        ("children", "terms", "branches", "proofs", "subproofs", "sources", "args", "all", "any"),
    )
    if kind is None and ref is not None:
        return Node(kind="ref", ref=str(ref), query=dict(spec), raw_type=str(raw_type) if raw_type else None)

    if kind is None and first_present(spec, ("rule", "rule_id")) is not None and child_value is None:
        rid = first_present(spec, ("rule", "rule_id"))
        return Node(kind="ref", ref=str(rid), query=dict(spec))

    if kind == "credential" or (kind is None and raw_type is None and _looks_like_credential_query(spec) and child_value is None):
        return Node(kind="credential", query=dict(spec), raw_type=raw_type)

    children_raw = child_value
    if children_raw is None and kind in {"and", "or", "threshold"}:
        # Some compact forms use the operator name as the field containing children.
        for key in AND_WORDS | OR_WORDS | THRESHOLD_WORDS:
            if key in spec and isinstance(spec[key], (list, tuple, dict)):
                children_raw = spec[key]
                break
    children = tuple(parse_node(child) for child in as_tuple(children_raw))

    k = first_present(spec, ("k", "at_least", "threshold", "min", "minimum", "count", "min_sources", "required"))
    if isinstance(k, str) and k.isdigit():
        k = int(k)

    if kind is None:
        normalized_raw = None if raw_type is None else str(raw_type).strip().lower().replace("-", "_")
        if normalized_raw in {"allow_all", "permit_all", "allowall", "permitall", "true", "allow", "permit"}:
            # The planner never synthesizes these; if an input contains one it
            # must not silently become a broad credential matcher.
            return Node(kind="unsupported", query=dict(spec), raw_type=str(raw_type))
        if k is not None:
            kind = "threshold"
        elif children:
            kind = "and"
        elif ref is not None:
            return Node(kind="ref", ref=str(ref), query=dict(spec))
        elif raw_type is not None:
            # An explicit but unrecognized/forbidden node type must not be
            # reinterpreted as a broad credential matcher.
            return Node(kind="unsupported", query=dict(spec), raw_type=str(raw_type))
        else:
            # An empty/credential-query object is a request-scoped credential
            # leaf.  Missing policy is never interpreted as permit-all.
            return Node(kind="credential", query=dict(spec))

    if kind == "threshold":
        if k is None:
            k = len(children)
        # Support {"k_of": [2, [a,b]]}
        if raw_type is not None and str(raw_type).endswith("k_of") and isinstance(children_raw, list) and len(children_raw) == 2 and isinstance(children_raw[0], int):
            k = children_raw[0]
            children = tuple(parse_node(x) for x in as_tuple(children_raw[1]))
        k = int(k)

    return Node(kind=kind, children=children, k=k, query=dict(spec), raw_type=str(raw_type) if raw_type else None)


def _looks_like_credential_query(spec: dict[str, Any]) -> bool:
    keys = {str(k).lower() for k in spec}
    markers = {
        "credential",
        "credential_id",
        "certificate",
        "cert",
        "cert_id",
        "id",
        "issuer",
        "issuer_id",
        "signer",
        "role",
        "post",
        "position",
        "service",
        "person",
        "person_id",
        "subject",
    }
    return bool(keys & markers)
