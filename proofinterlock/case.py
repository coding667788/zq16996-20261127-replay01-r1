"""Input document loading and policy assembly for switched shards."""
from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

from .identity import IdentityIndex
from .nodes import Node, parse_node
from .utility import as_tuple, first_present, iter_named_items

CREDENTIAL_KEYS = ("credentials", "certificates", "certs", "issued_credentials")
RULE_KEYS = ("rules", "rule_graph", "policies", "proof_rules")
ANCHOR_KEYS = ("trust_anchors", "anchors", "common_anchors", "public_anchors")


def fragment_view(doc: dict[str, Any] | None) -> dict[str, Any]:
    """Extract known policy fragment keys from an arbitrary mapping."""
    if not isinstance(doc, dict):
        return {}
    view: dict[str, Any] = {}
    for key in CREDENTIAL_KEYS + RULE_KEYS + ANCHOR_KEYS:
        if key in doc:
            view[key] = doc[key]
    return view


def merge_fragment(target: dict[str, Any], fragment: dict[str, Any] | None) -> None:
    """Merge a fragment in place.

    Named credentials/rules are upserted.  A mapping with ``"$remove": true``
    or ``"removed": true`` removes that id.  Trust anchors are appended.
    """
    if not fragment:
        return

    for key in CREDENTIAL_KEYS:
        if key not in fragment:
            continue
        store = target.setdefault("credentials", {})
        for cid, item in iter_named_items(fragment[key], "credential"):
            if _is_removal(item):
                store.pop(cid, None)
            else:
                store[cid] = item

    for key in RULE_KEYS:
        if key not in fragment:
            continue
        store = target.setdefault("rules", {})
        value = fragment[key]
        if isinstance(value, dict):
            for rid, item in value.items():
                if _is_removal(item):
                    store.pop(str(rid), None)
                else:
                    store[str(rid)] = item
        else:
            for rid, item in iter_named_items(value, "rule"):
                if _is_removal(item):
                    store.pop(rid, None)
                else:
                    store[rid] = item

    anchors = target.setdefault("trust_anchors", [])
    for key in ANCHOR_KEYS:
        if key in fragment:
            anchors.extend(as_tuple(fragment[key]))


def _is_removal(item: Any) -> bool:
    return isinstance(item, dict) and bool(
        first_present(item, ("$remove", "_remove", "remove", "removed", "delete"), False)
    )


@dataclass(slots=True)
class Credential:
    order: int
    cid: str
    data: dict[str, Any]
    subject: str | None
    issuer_raw: str | None
    issuer_person: str | None
    role: str | None
    services: tuple[str, ...]
    cost: int
    tier: int | None
    domains: frozenset[str]
    anchor_declared: bool
    revoked: bool

    def covers_service(self, service: str | None) -> bool:
        if service is None:
            return True
        if not self.services:
            return False
        return service in self.services or "*" in self.services or "all" in self.services


@dataclass(slots=True)
class Rule:
    rid: str
    order: int
    spec: Any
    node: Node


@dataclass(slots=True)
class Policy:
    case: "Case"
    mask: int
    credentials: tuple[Credential, ...]
    cred_by_id: dict[str, Credential]
    rules: dict[str, Rule]
    anchors: frozenset[str]
    person_bits: dict[str, int]
    domain_bits: dict[str, int]

    def issuer_bit(self, person: str | None) -> int:
        if person is None:
            person = "__unknown_issuer__"
        bit = self.person_bits.get(person)
        if bit is None:
            return 0
        return 1 << bit

    def domain_mask(self, domains: frozenset[str]) -> int:
        mask = 0
        for domain in domains:
            bit = self.domain_bits.get(domain)
            if bit is not None:
                mask |= 1 << bit
        return mask

    def mask_cost(self, cred_mask: int) -> int:
        total = 0
        for cred in self.credentials:
            if cred_mask & (1 << cred.order):
                total += cred.cost
        return total


class Case:
    """A loaded input document and cache for switched policy subsets."""

    def __init__(self, document: dict[str, Any], *, source_name: str = "<json>"):
        if not isinstance(document, dict):
            raise ValueError("top-level JSON input must be an object")
        self.doc = document
        self.source_name = source_name
        self.identity = IdentityIndex.from_document(document)
        self.shards = self._parse_shards(first_present(document, ("shards", "switches", "shard_switches"), []))
        self.shard_by_id = {s["id"]: s for s in self.shards}
        self.all_mask = (1 << len(self.shards)) - 1
        self.default_budget = first_present(document, ("budget", "tier_budget", "max_budget", "budget_cap"))
        self.default_max_tier = first_present(document, ("max_tier", "tier_cap", "maximum_tier"))
        self._policy_cache: dict[int, Policy] = {}
        self._report_cache: dict[tuple[Any, ...], dict[str, Any]] = {}

    @classmethod
    def load(cls, path: str) -> "Case":
        import json

        # The CLI passes a path argument.  Using normal open is safe for files
        # the user explicitly asks proofinterlock to process.
        with open(path, "r", encoding="utf-8-sig") as handle:
            doc = json.load(handle)
        return cls(doc, source_name=path)

    def _parse_shards(self, value: Any) -> list[dict[str, Any]]:
        shards: list[dict[str, Any]] = []
        for index, item in enumerate(as_tuple(value)):
            if isinstance(item, str):
                item = {"id": item}
            if not isinstance(item, dict):
                continue
            sid = str(first_present(item, ("id", "shard_id", "switch_id", "name"), f"s{index + 1}"))
            cost = first_present(item, ("cost", "switch_cost", "total_cost", "price"), 1)
            try:
                cost = int(cost)
            except (TypeError, ValueError):
                cost = 1
            shards.append(
                {
                    "id": sid,
                    "order": index,
                    "cost": max(0, cost),
                    "publisher": first_present(item, ("publisher", "publisher_id", "owner")),
                    "batch": first_present(item, ("batch", "release_batch", "batch_id", "wave")),
                    "data": item,
                }
            )
        return shards

    # ------------------------------------------------------------------
    # Policy assembly
    # ------------------------------------------------------------------
    def raw_fragment_for_mask(self, mask: int) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        merge_fragment(merged, fragment_view(self.doc))
        for key in ("initial_policy", "base_policy", "policy"):
            candidate = self.doc.get(key)
            if isinstance(candidate, dict):
                merge_fragment(merged, fragment_view(candidate))
                # A policy object may itself use credential/rules keys directly.
                merge_fragment(merged, candidate)

        for shard in self.shards:
            bit = 1 << shard["order"]
            data = shard["data"]
            if mask & bit:
                frag = first_present(
                    data,
                    ("after", "new", "switched", "new_policy", "switched_policy", "policy", "fragment", "effective"),
                    {},
                )
                # Additive/removal shorthand.
                shorthand: dict[str, Any] = {}
                for target_key, source_keys in (
                    ("credentials", ("activate_credentials", "enable_credentials", "add_credentials")),
                    ("rules", ("activate_rules", "enable_rules", "add_rules")),
                ):
                    vals: list[Any] = []
                    for sk in source_keys:
                        vals.extend(as_tuple(data.get(sk)))
                    if vals:
                        shorthand[target_key] = [{ "id": x } if isinstance(x, str) else x for x in vals]
                for cid in as_tuple(first_present(data, ("deactivate_credentials", "disable_credentials", "remove_credentials"), ())):
                    shorthand.setdefault("credentials", []).append({"id": cid, "$remove": True})
                for rid in as_tuple(first_present(data, ("deactivate_rules", "disable_rules", "remove_rules"), ())):
                    shorthand.setdefault("rules", []).append({"id": rid, "$remove": True})
                merge_fragment(merged, frag if isinstance(frag, dict) else {})
                merge_fragment(merged, shorthand)
            else:
                frag = first_present(data, ("before", "old", "unswitched", "initial", "old_policy", "before_policy"), {})
                merge_fragment(merged, frag if isinstance(frag, dict) else {})
        return merged

    def policy(self, mask: int) -> Policy:
        if mask in self._policy_cache:
            return self._policy_cache[mask]
        if not 0 <= mask <= self.all_mask:
            raise ValueError(f"mask {mask} outside shard range")
        raw = self.raw_fragment_for_mask(mask)

        # Build identity bit tables first from normalized credentials.
        cred_items = list(iter_named_items(raw.get("credentials", []), "credential"))
        credentials: list[Credential] = []
        person_bits: dict[str, int] = {}
        domain_bits: dict[str, int] = {}

        anchors = self._anchor_ids(raw.get("trust_anchors", []))

        for order, (cid, data) in enumerate(cred_items):
            subject_raw = first_present(
                data, ("person_id", "stable_person_id", "person", "holder", "subject", "subject_id", "account")
            )
            issuer_raw = first_present(data, ("issuer", "issuer_id", "signer", "signer_id", "issued_by", "ca"))
            issuer_person = self.identity.person(issuer_raw) if issuer_raw is not None else None
            if issuer_person is None:
                issuer_person = "__unknown_issuer__"
            if issuer_person not in person_bits:
                person_bits[issuer_person] = len(person_bits)
            domains = set(
                str(d)
                for d in as_tuple(first_present(data, ("failure_domains", "domains", "domain", "fault_domains"), ()))
            )
            if issuer_raw is not None:
                domains.update(self.identity.domains_for(issuer_raw))
            for domain in domains:
                if domain not in domain_bits:
                    domain_bits[domain] = len(domain_bits)

            services = tuple(str(s) for s in as_tuple(first_present(data, ("services", "applicable_services", "service"), ())))
            tier_value = first_present(data, ("tier", "level", "grade"))
            tier = int(tier_value) if isinstance(tier_value, (int, float)) or (isinstance(tier_value, str) and tier_value.isdigit()) else None
            cost_value = first_present(
                data, ("cost", "budget_cost", "tier_cost", "weight", "budget", "slot_cost"), None
            )
            if cost_value is None:
                cost = int(tier) if tier is not None else 1
            else:
                cost = int(cost_value)
            anchor_declared = bool(first_present(data, ("trust_anchor", "anchor", "is_anchor"), False))
            revoked = bool(first_present(data, ("revoked", "disabled", "inactive"), False))
            credentials.append(
                Credential(
                    order=order,
                    cid=cid,
                    data=data,
                    subject=self.identity.person(subject_raw),
                    issuer_raw=str(issuer_raw) if issuer_raw is not None else None,
                    issuer_person=issuer_person,
                    role=(str(first_present(data, ("role", "post", "position", "job_title"))) if first_present(data, ("role", "post", "position", "job_title")) is not None else None),
                    services=services,
                    cost=cost,
                    tier=tier,
                    domains=frozenset(domains),
                    anchor_declared=anchor_declared,
                    revoked=revoked,
                )
            )

        cred_by_id = {c.cid: c for c in credentials}

        rules: dict[str, Rule] = {}
        raw_rules = raw.get("rules", {})
        for order, (rid, spec) in enumerate(iter_named_items(raw_rules, "rule")):
            # iter_named_items wraps bare values in {"value": ...}; unwrap.
            if isinstance(spec, dict) and set(spec.keys()) == {"id", "value"}:
                spec = spec["value"]
            rules[rid] = Rule(rid=rid, order=order, spec=spec, node=parse_node(spec))

        policy = Policy(
            case=self,
            mask=mask,
            credentials=tuple(credentials),
            cred_by_id=cred_by_id,
            rules=rules,
            anchors=frozenset(anchors),
            person_bits=person_bits,
            domain_bits=domain_bits,
        )
        self._policy_cache[mask] = policy
        return policy

    def _anchor_ids(self, raw_anchors: Any) -> set[str]:
        anchors: set[str] = set()
        for anchor in as_tuple(raw_anchors):
            if isinstance(anchor, str):
                anchors.add(anchor)
                anchors.add(self.identity.person(anchor) or anchor)
            elif isinstance(anchor, dict):
                aid = first_present(anchor, ("id", "anchor_id", "issuer", "person_id", "credential_id"))
                if aid is not None:
                    anchors.add(str(aid))
                    canonical = self.identity.person(aid)
                    if canonical:
                        anchors.add(canonical)
        # Credential-level anchor flags are interpreted after credentials exist;
        # Policy checks Credential.anchor_declared directly.
        return anchors

    def copy_document(self) -> dict[str, Any]:
        return copy.deepcopy(self.doc)
