"""Deterministic minimal proof construction and source independence checks."""
from __future__ import annotations

from typing import Any

from .case import Case, Credential, Policy
from .nodes import Node, parse_node
from .utility import first_present, stable_json

KIND_RANK = {"credential": 0, "ref": 1, "and": 2, "or": 3, "threshold": 4}


class Candidate:
    """A finite expanded proof alternative.

    ``cred_mask`` identifies unique credentials; the tree may still display a
    shared credential at more than one leaf.  Person/domain masks contain only
    non-anchor reachable issuers/failure domains.
    """

    __slots__ = (
        "kind",
        "rule_id",
        "rule_order",
        "k",
        "slot_mask",
        "children",
        "cred_mask",
        "person_mask",
        "domain_mask",
        "anchors",
        "cost",
        "key",
        "credential_order",
        "_tree",
    )

    def __init__(
        self,
        *,
        kind: str,
        policy: Policy,
        rule_id: str | None,
        rule_order: int | None,
        children: tuple["Candidate", ...] = (),
        cred: Credential | None = None,
        k: int | None = None,
        slot_mask: int = 0,
        credential_order: int = -1,
    ) -> None:
        self.kind = kind
        self.rule_id = rule_id
        self.rule_order = rule_order if rule_order is not None else -1
        self.k = k
        self.slot_mask = slot_mask
        self.children = children
        self.credential_order = credential_order

        if cred is not None:
            self.cred_mask = 1 << cred.order
            self.cost = cred.cost
            if _is_anchor_credential(policy, cred):
                self.person_mask = 0
                self.domain_mask = 0
                self.anchors = frozenset({f"credential:{cred.cid}", f"issuer:{cred.issuer_person}"})
            else:
                self.person_mask = policy.issuer_bit(cred.issuer_person)
                self.domain_mask = policy.domain_mask(cred.domains)
                self.anchors = frozenset()
        else:
            mask = 0
            persons = 0
            domains = 0
            anchors: set[str] = set()
            for child in children:
                mask |= child.cred_mask
                persons |= child.person_mask
                domains |= child.domain_mask
                anchors.update(child.anchors)
            self.cred_mask = mask
            self.person_mask = persons
            self.domain_mask = domains
            self.anchors = frozenset(anchors)
            self.cost = policy.mask_cost(mask)

        child_keys = tuple(child.key for child in children)
        # The visible tree (kind/rule/k/children/credential id) is compared
        # before the hidden slot mask.  Slot mask is only a final deterministic
        # discriminator when two expansions serialize identically.
        self.key = (
            KIND_RANK[kind],
            self.rule_order,
            int(k) if k is not None else 0,
            child_keys,
            credential_order,
            slot_mask,
        )
        self._tree: dict[str, Any] | None = None

    @property
    def unique_count(self) -> int:
        return self.cred_mask.bit_count()

    def independent_with(self, other: "Candidate") -> bool:
        return (self.person_mask & other.person_mask) == 0 and (self.domain_mask & other.domain_mask) == 0

    def credential_ids(self, policy: Policy) -> list[str]:
        return [cred.cid for cred in policy.credentials if self.cred_mask & (1 << cred.order)]

    def to_tree(self) -> dict[str, Any]:
        # Build a fresh dict on every call: the same Candidate can occur in
        # two proof branches (credential sharing), and callers mutate ids into
        # the serialized tree.
        if self.kind == "credential":
            tree: dict[str, Any] = {"type": "credential"}
            if self.rule_id is not None:
                tree["rule_id"] = self.rule_id
            # credential_order is resolved to an id by Prover because Candidate
            # intentionally does not retain a Policy reference.
            tree["credential_order"] = self.credential_order
        elif self.kind == "ref":
            tree = {
                "type": "rule_ref",
                "rule_id": self.rule_id,
                "child": self.children[0].to_tree(),
            }
        else:
            tree = {"type": self.kind}
            if self.rule_id is not None:
                tree["rule_id"] = self.rule_id
            if self.kind == "threshold":
                tree["k"] = self.k
            tree["children"] = [child.to_tree() for child in self.children]
        return tree


def _is_anchor_credential(policy: Policy, cred: Credential) -> bool:
    if cred.anchor_declared:
        return True
    if cred.cid in policy.anchors:
        return True
    if cred.issuer_raw is not None and cred.issuer_raw in policy.anchors:
        return True
    if cred.issuer_person is not None and cred.issuer_person in policy.anchors:
        return True
    return False


def prune_frontier(candidates: list[Candidate]) -> list[Candidate]:
    """Keep best tree per cred mask, then remove safely dominated alternatives.

    B dominates A when B uses a subset of A's unique credentials and its
    input-order serialization key is no larger.  In any parent context, union
    with B stays a subset and the lexicographic order remains no worse.
    """
    best_by_mask: dict[int, Candidate] = {}
    for cand in candidates:
        old = best_by_mask.get(cand.cred_mask)
        if old is None or cand.key < old.key:
            best_by_mask[cand.cred_mask] = cand
    vals = list(best_by_mask.values())
    if len(vals) <= 64:
        kept: list[Candidate] = []
        for i, cand in enumerate(vals):
            dominated = False
            for j, other in enumerate(vals):
                if i == j:
                    continue
                if other.cred_mask & ~cand.cred_mask:
                    continue
                if other.key <= cand.key:
                    dominated = True
                    break
            if not dominated:
                kept.append(cand)
        kept.sort(key=lambda c: c.key)
        return kept

    # Large frontiers: a dominator must have one of the exact submasks of this
    # candidate's 30-bit credential mask.  Query those masks directly.
    kept = []
    for cand in vals:
        dominated = False
        mask = cand.cred_mask
        sub = mask
        while True:
            other = best_by_mask.get(sub)
            if other is not None and other is not cand and other.key <= cand.key:
                dominated = True
                break
            if sub == 0:
                break
            sub = (sub - 1) & mask
        if not dominated:
            kept.append(cand)
    kept.sort(key=lambda c: c.key)
    return kept


class Prover:
    def __init__(self, case: Case, mask: int, request: dict[str, Any]):
        self.case = case
        self.policy = case.policy(mask)
        self.request = request
        person_raw = first_present(request, ("person", "person_id", "stable_person_id", "subject", "account", "requester"))
        self.person = case.identity.person(person_raw) if person_raw is not None else None
        self.service = first_present(request, ("service", "applicable_service", "target_service", "resource"))
        budget = first_present(request, ("budget", "tier_budget", "max_budget", "budget_cap"))
        if budget is None:
            budget = case.default_budget
        self.budget = None if budget is None else int(budget)
        max_tier = first_present(request, ("max_tier", "tier_cap", "maximum_tier"))
        if max_tier is None:
            max_tier = case.default_max_tier
        self.max_tier = None if max_tier is None else int(max_tier)
        self._match_cache: dict[str, list[Credential]] = {}
        self._ref_cache: dict[tuple[str, tuple[str, ...]], list[Candidate]] = {}
        self.notes: list[str] = []

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    def prove(self) -> dict[str, Any]:
        node, root_rule_id, root_order = self._root_node()
        if node is None:
            return self._failure("no_proof_rule", "request does not name a proof rule or inline proof tree")

        if root_rule_id is not None:
            candidates = self.solve_ref(root_rule_id, ())
        else:
            candidates = self.solve_node(node, (), rule_id=None, rule_order=None)

        feasible = [c for c in candidates if self.budget is None or c.cost <= self.budget]
        if not feasible:
            return self._failure("no_feasible_proof", "no active proof satisfies matching, independence, cycle, and budget constraints")

        chosen = min(feasible, key=lambda c: (c.unique_count, c.key))
        tree = self._public_tree(chosen)
        ids = chosen.credential_ids(self.policy)
        result = {
            "allowed": True,
            "proof": tree,
            "minimal_proof": tree,
            "canonical_json": stable_json(tree),
            "order_key": list(_tuple_to_list(chosen.key)),
            "unique_credential_count": chosen.unique_count,
            "minimal_unique_credential_count": chosen.unique_count,
            "credentials": ids,
            "tier_cost": chosen.cost,
            "budget": self.budget,
            "actual_issuers": self._actual_issuers(chosen),
            "independence_profiles": self._profiles(chosen),
            "shared_trust_anchors": sorted(chosen.anchors),
        }
        return result

    def _failure(self, code: str, message: str) -> dict[str, Any]:
        return {
            "allowed": False,
            "error_code": code,
            "error": message,
            "budget": self.budget,
            "notes": self.notes[-10:],
        }

    def _root_node(self) -> tuple[Node | None, str | None, int | None]:
        inline = first_present(self.request, ("proof_tree", "tree", "inline_proof"))
        if inline is not None:
            return parse_node(inline), None, None
        rid = first_present(self.request, ("rule", "rule_id", "root", "policy_rule", "proof_rule"))
        if rid is None and self.service is not None:
            service_rules = self.case.doc.get("service_rules") or self.case.doc.get("authentication_rules") or {}
            if isinstance(service_rules, dict):
                rid = service_rules.get(str(self.service))
            services_doc = self.case.doc.get("services")
            if rid is None and isinstance(services_doc, dict):
                service_spec = services_doc.get(str(self.service))
                if isinstance(service_spec, dict):
                    rid = first_present(service_spec, ("rule", "rule_id", "authentication_rule", "policy"))
            if rid is None:
                candidates = (
                    f"auth_{self.service}",
                    f"{self.service}_auth",
                    f"{self.service}_policy",
                    f"policy_{self.service}",
                    f"{self.service}_authentication",
                )
                rid = next((candidate for candidate in candidates if candidate in self.policy.rules), None)
        if rid is None:
            rid = first_present(self.request, ("authentication_rule",))
        if rid is None:
            rid = first_present(self.case.doc, ("authentication_rule", "default_rule", "root_rule"))
        if rid is None:
            # Implicit authentication: one matching active credential.  This is
            # used for compact person/service availability invariants.
            return Node(kind="credential", query={}), None, None
        if isinstance(rid, dict):
            return parse_node(rid), None, None
        rid = str(rid)
        rule = self.policy.rules.get(rid)
        if rule is None:
            # Allow a credential id as a direct request root.
            if rid in self.policy.cred_by_id:
                return Node(kind="credential", query={"credential_id": rid}), None, None
            return None, rid, None
        return rule.node, rule.rid, rule.order

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------
    def matching_credentials(self, node: Node) -> list[Credential]:
        query = node.query if isinstance(node.query, dict) else {}
        cache_key = stable_json(query)
        cached = self._match_cache.get(cache_key)
        if cached is not None:
            return cached

        wanted_id = first_present(
            query, ("credential_id", "credential", "certificate_id", "cert_id", "cid")
        )
        # A credential node shaped {"type":"credential","id":"c1"} uses id.
        if wanted_id is None and str(query.get("type", "")).lower() in {"credential", "certificate", "cert"}:
            wanted_id = query.get("id")
        if wanted_id is None and node.raw_type is None and "id" in query and len(query) <= 2:
            wanted_id = query.get("id")

        q_person_raw = first_present(query, ("person", "person_id", "stable_person_id", "subject", "account"))
        q_person = "*" if q_person_raw == "*" else (self.case.identity.person(q_person_raw) if q_person_raw is not None else self.person)
        q_service = first_present(query, ("service", "applicable_service", "target_service"))
        if q_service is None and "service" not in query:
            q_service = self.service
        q_role = first_present(query, ("role", "post", "position", "job_title"))
        q_issuer_raw = first_present(query, ("issuer", "issuer_id", "signer", "signer_id"))
        q_issuer = self.case.identity.person(q_issuer_raw) if q_issuer_raw is not None else None

        matches: list[Credential] = []
        for cred in self.policy.credentials:
            if cred.revoked:
                continue
            if self.max_tier is not None and cred.tier is not None and cred.tier > self.max_tier:
                continue
            if wanted_id is not None and cred.cid != str(wanted_id):
                continue
            if q_person not in (None, "*") and cred.subject != q_person:
                continue
            if q_service not in (None, "*") and not cred.covers_service(str(q_service)):
                continue
            if q_role is not None and cred.role != str(q_role):
                continue
            if q_issuer is not None and cred.issuer_person != q_issuer:
                continue
            matches.append(cred)
        self._match_cache[cache_key] = matches
        return matches

    # ------------------------------------------------------------------
    # Recursive proof expansion
    # ------------------------------------------------------------------
    def solve_ref(self, rid: str, stack: tuple[str, ...]) -> list[Candidate]:
        cache_key = (rid, stack)
        if cache_key in self._ref_cache:
            return self._ref_cache[cache_key]
        if rid in stack:
            # Repeating a rule id on one branch would make an infinite expansion.
            self._ref_cache[cache_key] = []
            return []
        rule = self.policy.rules.get(rid)
        if rule is None:
            if rid in self.policy.cred_by_id:
                node = Node(kind="credential", query={"credential_id": rid})
                result = self.solve_node(node, stack + (rid,), rule_id=rid, rule_order=self._fallback_rule_order(rid))
            else:
                self.notes.append(f"unknown rule reference: {rid}")
                result = []
            self._ref_cache[cache_key] = result
            return result
        result = self.solve_node(rule.node, stack + (rid,), rule_id=rule.rid, rule_order=rule.order)
        self._ref_cache[cache_key] = result
        return result

    def _fallback_rule_order(self, rid: str) -> int:
        # Credential ids are ordered after actual rules for canonical traces.
        return len(self.policy.rules) + (self.policy.cred_by_id[rid].order if rid in self.policy.cred_by_id else 0)

    def solve_node(
        self,
        node: Node,
        stack: tuple[str, ...],
        *,
        rule_id: str | None,
        rule_order: int | None,
    ) -> list[Candidate]:
        if node.kind == "ref" and node.ref is not None:
            target_candidates = self.solve_ref(node.ref, stack)
            wrapped = [
                Candidate(
                    kind="ref",
                    policy=self.policy,
                    rule_id=rule_id,
                    rule_order=rule_order,
                    children=(child,),
                )
                for child in target_candidates
            ]
            return prune_frontier(wrapped)

        if node.kind == "credential":
            result = []
            for cred in self.matching_credentials(node):
                cand = Candidate(
                    kind="credential",
                    policy=self.policy,
                    rule_id=rule_id,
                    rule_order=rule_order,
                    cred=cred,
                    credential_order=cred.order,
                )
                if self.budget is None or cand.cost <= self.budget:
                    result.append(cand)
            return prune_frontier(result)

        child_lists = [
            self.solve_node(child, stack, rule_id=None, rule_order=None) if child.kind != "ref" or child.ref is None
            else self.solve_ref(child.ref, stack)
            for child in node.children
        ]
        # An OR branch may be empty; it is simply omitted.  AND explicitly
        # rejects below when one required child has no alternative.
        if node.kind == "and" and any(not alternatives for alternatives in child_lists):
            return []

        if node.kind == "or":
            wrapped: list[Candidate] = []
            for alternatives in child_lists:
                for child in alternatives:
                    cand = Candidate(
                        kind="or",
                        policy=self.policy,
                        rule_id=rule_id,
                        rule_order=rule_order,
                        children=(child,),
                    )
                    if self.budget is None or cand.cost <= self.budget:
                        wrapped.append(cand)
            return prune_frontier(wrapped)

        if node.kind == "and":
            partials = [
                Candidate(
                    kind="and",
                    policy=self.policy,
                    rule_id=rule_id,
                    rule_order=rule_order,
                    children=(),
                )
            ]
            for alternatives in child_lists:
                new_partials: list[Candidate] = []
                for base in partials:
                    for child in alternatives:
                        cand = Candidate(
                            kind="and",
                            policy=self.policy,
                            rule_id=rule_id,
                            rule_order=rule_order,
                            children=base.children + (child,),
                        )
                        if self.budget is None or cand.cost <= self.budget:
                            new_partials.append(cand)
                partials = prune_frontier(new_partials)
                if not partials:
                    return []
            return partials

        if node.kind == "threshold":
            k = int(node.k or 0)
            n = len(child_lists)
            if k <= 0:
                k = n
            if k > n:
                return []
            results: list[Candidate] = []
            from itertools import combinations

            for slots in combinations(range(n), k):
                partials = [
                    Candidate(
                        kind="threshold",
                        policy=self.policy,
                        rule_id=rule_id,
                        rule_order=rule_order,
                        k=k,
                        slot_mask=0,
                        children=(),
                    )
                ]
                for slot in slots:
                    new_partials = []
                    slot_bit = 1 << slot
                    for base in partials:
                        for child in child_lists[slot]:
                            if not all(child.independent_with(existing) for existing in base.children):
                                continue
                            cand = Candidate(
                                kind="threshold",
                                policy=self.policy,
                                rule_id=rule_id,
                                rule_order=rule_order,
                                k=k,
                                slot_mask=base.slot_mask | slot_bit,
                                children=base.children + (child,),
                            )
                            if self.budget is None or cand.cost <= self.budget:
                                new_partials.append(cand)
                    partials = prune_frontier(new_partials)
                    if not partials:
                        break
                results.extend(partials)
            return prune_frontier(results)

        self.notes.append(f"unknown node kind: {node.kind}")
        return []

    # ------------------------------------------------------------------
    # Output enrichment
    # ------------------------------------------------------------------
    def _public_tree(self, cand: Candidate) -> dict[str, Any]:
        tree = cand.to_tree()
        self._fix_credential_ids(tree)
        return tree

    def _fix_credential_ids(self, node: dict[str, Any]) -> None:
        if node.get("type") == "credential":
            order = node.pop("credential_order", -1)
            rule_id = node.get("rule_id")
            cred = next((c for c in self.policy.credentials if c.order == order), None)
            node.clear()
            node["type"] = "credential"
            if rule_id is not None:
                node["rule_id"] = rule_id
            if cred is not None:
                node["credential_id"] = cred.cid
            else:
                node["credential_order"] = order
            return
        if node.get("type") == "rule_ref":
            child = node.get("child")
            if isinstance(child, dict):
                self._fix_credential_ids(child)
        for child in node.get("children", []) or []:
            if isinstance(child, dict):
                self._fix_credential_ids(child)

    def _actual_issuers(self, cand: Candidate) -> list[dict[str, Any]]:
        result = []
        for cred in self.policy.credentials:
            if not cand.cred_mask & (1 << cred.order):
                continue
            result.append(
                {
                    "credential_id": cred.cid,
                    "issuer_account": cred.issuer_raw,
                    "stable_issuer_person": cred.issuer_person,
                    "failure_domains": sorted(cred.domains),
                    "trust_anchor": _is_anchor_credential(self.policy, cred),
                }
            )
        return result

    def _profiles(self, cand: Candidate) -> list[dict[str, Any]]:
        profiles: list[dict[str, Any]] = []

        def visit(c: Candidate) -> None:
            if c.kind == "threshold":
                for child in c.children:
                    profiles.append(
                        {
                            "rule_id": child.rule_id,
                            "persons": sorted(_bits_to_names(child.person_mask, self.policy.person_bits)),
                            "domains": sorted(_bits_to_names(child.domain_mask, self.policy.domain_bits)),
                            "anchors": sorted(child.anchors),
                        }
                    )
            for child in c.children:
                visit(child)

        visit(cand)
        return profiles


def _bits_to_names(mask: int, mapping: dict[str, int]) -> set[str]:
    reverse = {bit: name for name, bit in mapping.items()}
    names = set()
    bit = 0
    while mask:
        if mask & 1:
            names.add(reverse.get(bit, f"bit-{bit}"))
        mask >>= 1
        bit += 1
    return names


def _tuple_to_list(value: Any) -> Any:
    if isinstance(value, tuple):
        return [_tuple_to_list(v) for v in value]
    return value
