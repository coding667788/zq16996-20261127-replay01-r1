"""Minimum-cost migration planning over the shard-subset lattice."""
from __future__ import annotations

from collections import deque
from typing import Any

from .case import Case
from .engine import as_case, check_mask, evaluate_mask
from .utility import as_tuple, first_present


def migrate(source: Case | dict[str, Any] | str) -> dict[str, Any]:
    case = as_case(source)
    model = build_migration_model(case)

    initial_report = evaluate_mask(case, 0)
    final_report = evaluate_mask(case, case.all_mask)

    endpoint = {
        "initial": _endpoint_summary(0, initial_report),
        "final": _endpoint_summary(case.all_mask, final_report),
        "initial_report": initial_report,
        "final_report": final_report,
    }

    if model["errors"]:
        return {
            "status": "invalid_migration_input",
            "feasible": False,
            "classification": "invalid_input",
            "minimum_total_cost": None,
            "minimum_cost": None,
            "temporary_allow_all_added": False,
            "endpoint_states": endpoint,
            "model_errors": model["errors"],
        }

    if not initial_report["compliant"]:
        return {
            "status": "initial_invariant_violation",
            "feasible": False,
            "classification": "initial_state_invalid",
            "minimum_total_cost": None,
            "minimum_cost": None,
            "temporary_allow_all_added": False,
            "endpoint_states": endpoint,
            "reason": "initial policy state does not satisfy all invariants",
        }
    if not final_report["compliant"]:
        return {
            "status": "final_invariant_violation",
            "feasible": False,
            "classification": "final_state_invalid",
            "minimum_total_cost": None,
            "minimum_cost": None,
            "temporary_allow_all_added": False,
            "endpoint_states": endpoint,
            "reason": "fully switched/final policy state does not satisfy all invariants",
        }

    n = len(case.shards)
    all_mask = case.all_mask
    actions = model["actions"]
    edges = model["edges"]

    def state_edge_ok(mask: int) -> bool:
        for before_bit, after_bit, _eid in edges:
            if (mask & after_bit) and not (mask & before_bit):
                return False
        return True

    safe_cache: dict[int, bool] = {}

    def state_safe(mask: int) -> bool:
        if mask not in safe_cache:
            safe_cache[mask] = state_edge_ok(mask) and check_mask(case, mask)["compliant"]
        return safe_cache[mask]

    def check_transition(action: dict[str, Any], start: int) -> dict[str, Any]:
        add = action["mask"]
        new_mask = start | add
        if action["kind"] == "atomic":
            for before_bit, after_bit, eid in edges:
                if (add & after_bit) and (add & before_bit) and not (start & before_bit):
                    return {"ok": False, "reason": "strict_precedence_violated_by_atomic_action", "edge_id": eid, "mask": new_mask}
            if not state_edge_ok(new_mask):
                return {"ok": False, "reason": "precedence_edge_violated", "mask": new_mask}
            check = check_mask(case, new_mask)
            if not check["compliant"]:
                return {"ok": False, "reason": "invariant_violation", "mask": new_mask, "report": evaluate_mask(case, new_mask)}
            return {"ok": True, "observable_masks": [new_mask]}

        if action["kind"] == "single":
            if not state_edge_ok(new_mask):
                return {"ok": False, "reason": "precedence_edge_violated", "mask": new_mask}
            check = check_mask(case, new_mask)
            if not check["compliant"]:
                return {"ok": False, "reason": "invariant_violation", "mask": new_mask, "report": evaluate_mask(case, new_mask)}
            return {"ok": True, "observable_masks": [new_mask]}

        if action["kind"] == "ordered_batch":
            observable = []
            prefix = 0
            for bit in action["ordered_bits"]:
                prefix |= bit
                current = start | prefix
                observable.append(current)
                if not state_edge_ok(current):
                    return {"ok": False, "reason": "precedence_edge_violated", "mask": current}
                check = check_mask(case, current)
                if not check["compliant"]:
                    return {"ok": False, "reason": "invariant_violation", "mask": current, "report": evaluate_mask(case, current)}
            return {"ok": True, "observable_masks": observable}

        # Arbitrary-order non-atomic batch.  Every precedence-reachable subset
        # must preserve invariants because publishers may land in any order.
        member_mask = action["mask"]
        sub = member_mask
        observable = []
        while sub:
            current = start | sub
            if state_edge_ok(current):
                observable.append(current)
                check = check_mask(case, current)
                if not check["compliant"]:
                    return {"ok": False, "reason": "invariant_violation_under_arbitrary_order", "mask": current, "report": evaluate_mask(case, current)}
            sub = (sub - 1) & member_mask
        return {"ok": True, "observable_masks": observable}

    def applicable(action: dict[str, Any], mask: int) -> bool:
        if action["kind"] == "single":
            return not (mask & action["mask"])
        # Macro release groups/batches are selected as complete units from a
        # state where none of their members has landed yet.
        return (mask & action["mask"]) == 0

    # Backward subset DP.  Every edge only adds bits, so new_mask > mask and
    # descending numeric iteration has the successor value ready.
    infinity: Any = None
    dp: dict[int, int | None] = {all_mask: 0}
    tie: dict[int, tuple[Any, ...] | None] = {all_mask: ((), (), ())}
    choice: dict[int, tuple[str, int, tuple[Any, ...]] | None] = {all_mask: None}

    for mask in range(all_mask - 1, -1, -1):
        if not state_safe(mask):
            dp[mask] = None
            tie[mask] = None
            choice[mask] = None
            continue
        best_cost: int | None = None
        best_tie: tuple[Any, ...] | None = None
        best_action: str | None = None
        best_next: int | None = None
        for action in actions:
            if not applicable(action, mask):
                continue
            checked = check_transition(action, mask)
            if not checked["ok"]:
                continue
            new_mask = mask | action["mask"]
            future_cost = dp.get(new_mask)
            future_tie = tie.get(new_mask)
            if future_cost is None or future_tie is None:
                continue
            total = action["cost"] + future_cost
            constraints = tuple(sorted(set(action["constraint_ids"]) | set(future_tie[0])))
            batches = (action["batch_id"],) + tuple(future_tie[1])
            order = tuple(action["reference_order"]) + tuple(future_tie[2])
            candidate_tie = (constraints, batches, order)
            if best_cost is None or total < best_cost or (total == best_cost and candidate_tie < best_tie):  # type: ignore[operator]
                best_cost = total
                best_tie = candidate_tie
                best_action = action["action_id"]
                best_next = new_mask
        dp[mask] = best_cost
        tie[mask] = best_tie
        choice[mask] = (best_action, best_next, best_tie) if best_action is not None and best_next is not None else None

    if dp.get(0) is None:
        middle = _middle_failure_diagnostics(case, model, state_safe, applicable, check_transition)
        return {
            "status": "no_safe_migration_path",
            "feasible": False,
            "classification": "endpoints_valid_but_intermediate_state_infeasible",
            "minimum_total_cost": None,
            "minimum_cost": None,
            "temporary_allow_all_added": False,
            "endpoint_states": endpoint,
            "middle": middle,
            "reason": "initial and final states are compliant, but no allowed release order/grouping preserves invariants in every reached intermediate state",
        }

    # Reconstruct deterministic optimum.
    by_id = {a["action_id"]: a for a in actions}
    mask = 0
    planned_actions: list[dict[str, Any]] = []
    total_order: list[str] = []
    release_batches: list[str] = []
    selected_constraints: set[str] = set()
    checked_states: list[dict[str, Any]] = []
    while mask != all_mask:
        chosen = choice[mask]
        assert chosen is not None
        action_id, new_mask, plan_tie = chosen
        action = by_id[action_id]
        checked = check_transition(action, mask)
        planned_actions.append(_public_action(case, action, checked))
        total_order.extend(_bits_to_shard_ids(case, action["reference_order"]))
        release_batches.append(action["batch_id"] or action["action_id"])
        selected_constraints.update(action["constraint_ids"])
        observable_masks = sorted(checked.get("observable_masks", []), key=lambda observed: (observed.bit_count(), observed))
        for observed in observable_masks:
            rep = evaluate_mask(case, observed)
            checked_states.append(
                {
                    "mask": observed,
                    "switched_shards": rep["switched_shards"],
                    "compliant": rep["compliant"],
                    "violation_ids": [v.get("invariant_id") for v in rep["violations"]],
                }
            )
        mask = new_mask

    final_tie = tie[0]
    return {
        "status": "ok",
        "feasible": True,
        "classification": "solution",
        "minimum_total_cost": dp[0],
        "minimum_cost": dp[0],
        "total_cost": dp[0],
        "temporary_allow_all_added": False,
        "selected_constraint_ids": list(final_tie[0]) if final_tie else sorted(selected_constraints),
        "release_batches": list(final_tie[1]) if final_tie else release_batches,
        "release_total_order": total_order,
        "tie_break_key": list(final_tie) if final_tie else None,
        "actions": planned_actions,
        "observable_states": checked_states,
        "honored_precedence_edge_ids": [eid for _a, _b, eid in edges],
        "endpoint_states": endpoint,
        "limits": {
            "switches": n,
            "additional_constraints": len(model["raw_constraints"]),
            "credentials_initial": len(case.policy(0).credentials),
            "credentials_final": len(case.policy(case.all_mask).credentials),
            "credentials_union": len(set(case.policy(0).cred_by_id) | set(case.policy(case.all_mask).cred_by_id)),
        },
    }


def build_migration_model(case: Case) -> dict[str, Any]:
    n = len(case.shards)
    shard_bit = {s["id"]: 1 << s["order"] for s in case.shards}
    errors: list[str] = []
    raw_constraints_value = first_present(case.doc, ("constraints", "additional_constraints", "migration_constraints"), [])
    if isinstance(raw_constraints_value, dict):
        raw_constraints: list[Any] = []
        for cid, con in raw_constraints_value.items():
            if isinstance(con, dict):
                data = dict(con)
                data.setdefault("id", cid)
                raw_constraints.append(data)
            else:
                raw_constraints.append(con)
    else:
        raw_constraints = list(as_tuple(raw_constraints_value))

    actions: list[dict[str, Any]] = []
    for shard in case.shards:
        i = shard["order"]
        actions.append(
            {
                "action_id": f"switch:{shard['id']}",
                "kind": "single",
                "title": shard["id"],
                "mask": 1 << i,
                "reference_bits": 1 << i,
                "reference_order": (i,),
                "ordered_bits": [1 << i],
                "cost": shard["cost"],
                "batch_id": shard.get("batch") or "",
                "constraint_ids": (),
                "source_id": shard["id"],
            }
        )

    # Predefined atomic groups and ordinary release batches.
    group_sources: list[tuple[Any, str, bool]] = []
    for key in ("atomic_groups",):
        for item in as_tuple(case.doc.get(key, [])):
            group_sources.append((item, key, True))
    for key in ("release_groups", "groups"):
        for item in as_tuple(case.doc.get(key, [])):
            atomic = bool(item.get("atomic", True)) if isinstance(item, dict) else True
            group_sources.append((item, key, atomic))
    for key in ("release_batches", "batches", "waves"):
        for item in as_tuple(case.doc.get(key, [])):
            atomic = bool(item.get("atomic", False)) if isinstance(item, dict) else False
            group_sources.append((item, key, atomic))

    # Additional named constraints can themselves declare an atomic group or
    # release batch.  Precedence constraints are parsed with edges below.
    for index, con in enumerate(raw_constraints):
        if not isinstance(con, dict):
            continue
        ctype = str(first_present(con, ("type", "kind", "constraint"), "")).lower().replace("-", "_")
        cid = str(first_present(con, ("id", "constraint_id", "name"), f"constraint-{index + 1}"))
        data = dict(con)
        data.setdefault("id", cid)
        if ctype in {"atomic", "atomic_group", "all_at_once", "same_batch"}:
            group_sources.append((data, "constraints", True))
        elif ctype in {"batch", "release_batch", "arbitrary_batch", "ordered_batch"}:
            group_sources.append((data, "constraints", bool(con.get("atomic", False))))

    seen_macro: set[tuple[str, int]] = set()
    for item, collection, default_atomic in group_sources:
        if isinstance(item, str):
            gid = item
            member_ids = [item] if item in shard_bit else []
            data: dict[str, Any] = {"id": gid}
        elif isinstance(item, dict):
            gid = str(first_present(item, ("id", "group_id", "batch_id", "name"), f"{collection}-{len(actions) + 1}"))
            member_ids = [str(x) for x in as_tuple(first_present(item, ("shards", "shard_ids", "switches", "members"), ()))]
            data = item
        else:
            continue
        member_indices: list[int] = []
        valid = True
        for sid in member_ids:
            if sid not in case.shard_by_id:
                errors.append(f"{gid}: unknown shard id {sid}")
                valid = False
            else:
                member_indices.append(case.shard_by_id[sid]["order"])
        if not valid or not member_indices:
            continue
        member_indices = sorted(set(member_indices))
        mask = sum(1 << i for i in member_indices)
        dedupe_key = (gid, mask)
        if dedupe_key in seen_macro:
            continue
        seen_macro.add(dedupe_key)

        atomic = bool(first_present(data, ("atomic", "is_atomic", "all_at_once"), default_atomic))
        order_ids = [str(x) for x in as_tuple(first_present(data, ("order", "landing_order", "sequence"), ()))]
        ordered_indices = [case.shard_by_id[sid]["order"] for sid in order_ids if sid in case.shard_by_id]
        if len(ordered_indices) != len(member_indices):
            ordered_indices = []

        cost_value = first_present(data, ("cost", "total_cost", "switch_cost"))
        if cost_value is None:
            cost = sum(case.shards[i]["cost"] for i in member_indices) + int(first_present(data, ("extra_cost", "surcharge"), 0) or 0)
        else:
            cost = int(cost_value)

        constraint_ids = tuple(str(x) for x in as_tuple(first_present(data, ("constraint_ids", "selected_constraint_ids"), ())))
        if collection in {"atomic_groups"} or str(data.get("type", "")).lower() in {"atomic", "atomic_group"}:
            constraint_ids = tuple(sorted(set(constraint_ids + (gid,))))

        if atomic:
            kind = "atomic"
            reference_indices = tuple(member_indices)
        elif ordered_indices:
            kind = "ordered_batch"
            reference_indices = tuple(ordered_indices)
        else:
            kind = "batch"
            internal_edges = _internal_edge_pairs(case, raw_constraints, case.doc, shard_bit)
            topo = _topological_order(member_indices, internal_edges)
            if topo is None:
                errors.append(f"{gid}: precedence graph inside arbitrary batch has a cycle")
                continue
            reference_indices = tuple(topo)

        actions.append(
            {
                "action_id": f"{kind}:{gid}",
                "kind": kind,
                "title": gid,
                "mask": mask,
                "reference_bits": mask,
                "reference_order": reference_indices,
                "ordered_bits": [1 << i for i in (ordered_indices if kind == "ordered_batch" else reference_indices)],
                "cost": max(0, cost),
                "batch_id": str(first_present(data, ("release_batch", "batch_id", "batch"), gid)),
                "constraint_ids": constraint_ids,
                "source_id": gid,
            }
        )

    edges = _parse_edges(case, raw_constraints, shard_bit, errors)
    return {"actions": actions, "edges": edges, "raw_constraints": raw_constraints, "errors": errors}


def _endpoint_mask(case: Case, token: Any, shard_bit: dict[str, int], groups: dict[str, list[str]] | None = None) -> int:
    text = str(token)
    if text in shard_bit:
        return shard_bit[text]
    # Resolve group/batch references.
    for key in ("atomic_groups", "release_groups", "groups", "release_batches", "batches", "waves"):
        for item in as_tuple(case.doc.get(key, [])):
            if isinstance(item, dict) and str(first_present(item, ("id", "group_id", "batch_id", "name"))) == text:
                return sum(shard_bit.get(str(s), 0) for s in as_tuple(first_present(item, ("shards", "shard_ids", "switches", "members"), ())))
    for con in as_tuple(first_present(case.doc, ("constraints", "additional_constraints", "migration_constraints"), [])):
        if isinstance(con, dict) and str(first_present(con, ("id", "constraint_id", "name"))) == text:
            members = first_present(con, ("shards", "members", "group"))
            return sum(shard_bit.get(str(s), 0) for s in as_tuple(members))
    return 0


def _parse_edges(case: Case, constraints: list[Any], shard_bit: dict[str, int], errors: list[str]) -> list[tuple[int, int, str]]:
    raw_edges: list[tuple[Any, Any, str]] = []
    for index, edge in enumerate(as_tuple(first_present(case.doc, ("precedence_edges", "order_edges", "edges", "precedence"), []))):
        eid = f"edge-{index + 1}"
        if isinstance(edge, list) and len(edge) == 2:
            raw_edges.append((edge[0], edge[1], eid))
        elif isinstance(edge, str) and "<" in edge:
            left, right = edge.split("<", 1)
            raw_edges.append((left.strip(), right.strip(), eid))
        elif isinstance(edge, dict):
            eid = str(first_present(edge, ("id", "edge_id", "name"), eid))
            before = first_present(edge, ("before", "first", "predecessor", "must_precede", "source", "from"))
            after = first_present(edge, ("after", "then", "successor", "must_follow", "target", "to"))
            if before is not None and after is not None:
                raw_edges.append((before, after, eid))

    for index, con in enumerate(constraints):
        if not isinstance(con, dict):
            continue
        ctype = str(first_present(con, ("type", "kind", "constraint"), "")).lower().replace("-", "_")
        cid = str(first_present(con, ("id", "constraint_id", "name"), f"constraint-{index + 1}"))
        if ctype in {"precedence", "order", "before_after", "edge", "explicit_edge", "precedence_edge", "order_constraint", "requires_before"}:
            before = first_present(con, ("before", "first", "predecessor", "must_precede"))
            after = first_present(con, ("after", "then", "successor", "must_follow"))
            if before is not None and after is not None:
                raw_edges.append((before, after, cid))

    edges: list[tuple[int, int, str]] = []
    for before_token, after_token, eid in raw_edges:
        before_mask = _endpoint_mask(case, before_token, shard_bit)
        after_mask = _endpoint_mask(case, after_token, shard_bit)
        if not before_mask or not after_mask:
            errors.append(f"{eid}: precedence endpoint could not be resolved: {before_token} -> {after_token}")
            continue
        for bi in _bits(before_mask):
            for ai in _bits(after_mask):
                edges.append((1 << bi, 1 << ai, eid))
    return edges


def _internal_edge_pairs(case: Case, constraints: list[Any], doc: dict[str, Any], shard_bit: dict[str, int]) -> list[tuple[int, int]]:
    edges = _parse_edges(case, constraints, shard_bit, [])
    return [(a.bit_length() - 1, b.bit_length() - 1) for a, b, _eid in edges]


def _topological_order(members: list[int], edges: list[tuple[int, int]]) -> list[int] | None:
    member_set = set(members)
    adjacency: dict[int, set[int]] = {i: set() for i in members}
    indegree = {i: 0 for i in members}
    for a, b in edges:
        if a in member_set and b in member_set and b not in adjacency[a]:
            adjacency[a].add(b)
            indegree[b] += 1
    ready = sorted(i for i in members if indegree[i] == 0)
    order: list[int] = []
    while ready:
        i = ready.pop(0)
        order.append(i)
        for j in sorted(adjacency[i]):
            indegree[j] -= 1
            if indegree[j] == 0:
                ready.append(j)
        ready.sort()
    return order if len(order) == len(members) else None


def _bits(mask: int) -> list[int]:
    result = []
    i = 0
    while mask:
        if mask & 1:
            result.append(i)
        mask >>= 1
        i += 1
    return result


def _bits_to_shard_ids(case: Case, bits: tuple[int, ...] | list[int]) -> list[str]:
    return [case.shards[i]["id"] for i in bits if 0 <= i < len(case.shards)]


def _public_action(case: Case, action: dict[str, Any], checked: dict[str, Any]) -> dict[str, Any]:
    shard_ids = _bits_to_shard_ids(case, action["reference_order"])
    publishers = sorted({str(case.shards[i].get("publisher")) for i in action["reference_order"] if case.shards[i].get("publisher") is not None})
    return {
        "action_id": action["action_id"],
        "kind": action["kind"],
        "id": action["source_id"],
        "shards": shard_ids,
        "publishers": publishers,
        "cost": action["cost"],
        "release_batch": action["batch_id"],
        "selected_constraint_ids": list(action["constraint_ids"]),
        "reference_total_order": _bits_to_shard_ids(case, action["reference_order"]),
        "observable_state_count": len(checked.get("observable_masks", [])),
    }


def _endpoint_summary(mask: int, report: dict[str, Any]) -> dict[str, Any]:
    return {
        "mask": mask,
        "switched_shards": report["switched_shards"],
        "compliant": report["compliant"],
        "violation_ids": [v.get("invariant_id") for v in report["violations"]],
    }


def _middle_failure_diagnostics(case: Case, model: dict[str, Any], state_safe: Any, applicable: Any, check_transition: Any) -> dict[str, Any]:
    start_safe = state_safe(0)
    seen = {0}
    queue = deque([0])
    safe_reachable = 0
    blockers: list[dict[str, Any]] = []
    while queue:
        mask = queue.popleft()
        if not state_safe(mask):
            continue
        safe_reachable += 1
        for action in model["actions"]:
            if not applicable(action, mask):
                continue
            checked = check_transition(action, mask)
            new_mask = mask | action["mask"]
            if not checked["ok"]:
                if len(blockers) < 12:
                    report = checked.get("report")
                    blockers.append(
                        {
                            "from_mask": mask,
                            "from_shards": evaluate_mask(case, mask)["switched_shards"],
                            "action_id": action["action_id"],
                            "reason": checked.get("reason"),
                            "failed_mask": checked.get("mask", new_mask),
                            "failed_shards": evaluate_mask(case, checked["mask"])["switched_shards"] if checked.get("mask") is not None else None,
                            "violation_ids": [v.get("invariant_id") for v in report.get("violations", [])] if report else None,
                        }
                    )
                continue
            if state_safe(new_mask) and new_mask not in seen:
                seen.add(new_mask)
                queue.append(new_mask)
    return {
        "initial_edge_and_invariants_ok": start_safe,
        "reachable_safe_state_count": safe_reachable,
        "reachable_safe_masks": sorted(seen),
        "blocked_transitions_sample": blockers,
        "interpretation": "Both mask 0 and the all-switched mask are compliant, but the safe subset lattice has no directed path between them under the selected groups/edges.",
    }
