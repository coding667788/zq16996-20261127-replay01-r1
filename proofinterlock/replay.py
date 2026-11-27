"""Replay an existing switch plan and locate its first failing prefix."""
from __future__ import annotations

from typing import Any

from .case import Case
from .engine import as_case, evaluate_mask
from .utility import as_tuple, first_present


def resolve_release_item(case: Case, token: str) -> dict[str, Any] | None:
    doc = case.doc
    for key in ("atomic_groups", "release_groups", "groups", "release_batches", "batches", "waves"):
        for item in as_tuple(doc.get(key, [])):
            if isinstance(item, dict) and str(first_present(item, ("id", "group_id", "batch_id", "name"))) == token:
                data = dict(item)
                data.setdefault("id", token)
                data["_collection"] = key
                return data
            if isinstance(item, str) and item == token:
                return {"id": token, "shards": [token], "_collection": key}
    for con in _constraints(case):
        if con.get("id") == token and con.get("type_norm") in {"atomic_group", "batch"}:
            return con
    return None


def _constraints(case: Case) -> list[dict[str, Any]]:
    raw = first_present(case.doc, ("constraints", "additional_constraints", "migration_constraints"), [])
    if isinstance(raw, dict):
        items: list[Any] = []
        for cid, con in raw.items():
            if isinstance(con, dict):
                data = dict(con)
                data.setdefault("id", cid)
                items.append(data)
    else:
        items = list(as_tuple(raw))
    result = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        cid = str(first_present(item, ("id", "constraint_id", "name"), f"constraint-{index + 1}"))
        ctype = str(first_present(item, ("type", "kind", "constraint"), "")).lower().replace("-", "_")
        result.append({"id": cid, "type_norm": ctype, "data": item})
    return result


def normalize_plan_actions(case: Case, plan: Any | None = None) -> list[dict[str, Any]]:
    if plan is None:
        plan = first_present(case.doc, ("current_plan", "existing_plan", "plan", "replay_plan"))
    if plan is None:
        return []
    if isinstance(plan, dict):
        steps = first_present(plan, ("steps", "actions", "sequence", "batches", "waves"), [])
        plan_id = plan.get("id") or plan.get("name") or "current-plan"
    else:
        steps = plan
        plan_id = "current-plan"

    actions: list[dict[str, Any]] = []
    for index, step in enumerate(as_tuple(steps)):
        action = _normalize_step(case, step, index)
        if action is not None:
            action["plan_id"] = plan_id
            actions.append(action)
    return actions


def _normalize_step(case: Case, step: Any, index: int) -> dict[str, Any] | None:
    if isinstance(step, str):
        resolved = resolve_release_item(case, step)
        if resolved is not None and "shards" in resolved:
            return _action_from_group_like(case, resolved, index, reference_id=step)
        if step in case.shard_by_id:
            return _single_action(case, step, index)
        return {"kind": "unknown", "id": step, "shards": [], "step_index": index}

    if not isinstance(step, dict):
        return None

    token = first_present(step, ("batch", "batch_id", "release_batch", "group", "group_id", "atomic_group", "wave", "ref"))
    if token is not None and not first_present(step, ("shards", "shard_ids", "switches")):
        resolved = resolve_release_item(case, str(token))
        if resolved is not None:
            merged = dict(resolved)
            merged.update(step)
            return _action_from_group_like(case, merged, index, reference_id=str(token))

    shard_values = first_present(step, ("shards", "shard_ids", "switches", "switch_ids"), [])
    shard_ids = [str(x) for x in as_tuple(shard_values)]
    if not shard_ids:
        sid = first_present(step, ("shard", "shard_id", "switch", "switch_id"))
        if sid is not None:
            shard_ids = [str(sid)]
    if not shard_ids and token is not None and token in case.shard_by_id:
        shard_ids = [str(token)]

    if not shard_ids:
        return {"kind": "unknown", "id": str(first_present(step, ("id", "name"), f"step-{index + 1}")), "shards": [], "step_index": index, "raw": step}

    sid0 = str(first_present(step, ("id", "name", "batch_id", "group_id"), f"step-{index + 1}"))
    atomic = bool(first_present(step, ("atomic", "is_atomic", "all_at_once"), False))
    order = first_present(step, ("order", "landing_order", "sequence"))
    order_ids = [str(x) for x in as_tuple(order)] if order is not None else None
    if atomic:
        kind = "atomic_group"
        replay_order: list[str] = []
    elif order_ids:
        kind = "ordered_batch"
        replay_order = [x for x in order_ids if x in shard_ids]
        # Include any omitted shards deterministically at the end.
        replay_order.extend(x for x in shard_ids if x not in replay_order)
    else:
        kind = "arbitrary_batch"
        # The input list is the deterministic reference replay order.  The
        # arbitrary-order witness routine can search other landings.
        replay_order = list(shard_ids)
    return {
        "kind": kind,
        "id": sid0,
        "step_index": index,
        "shards": shard_ids,
        "replay_order": replay_order,
        "atomic": atomic,
        "order_policy": "atomic" if atomic else ("explicit" if order_ids else "arbitrary"),
        "batch_id": str(first_present(step, ("batch_id", "batch", "release_batch"), sid0)),
    }


def _action_from_group_like(case: Case, item: dict[str, Any], index: int, *, reference_id: str) -> dict[str, Any]:
    shard_ids = [str(x) for x in as_tuple(first_present(item, ("shards", "shard_ids", "switches", "switch_ids", "members"), ()))]
    atomic_default = "_collection" in item and "atomic_group" in str(item.get("_collection"))
    atomic = bool(first_present(item, ("atomic", "is_atomic", "all_at_once"), atomic_default))
    order = first_present(item, ("order", "landing_order", "sequence"))
    order_ids = [str(x) for x in as_tuple(order)] if order is not None else None
    if atomic:
        kind = "atomic_group"
        replay_order: list[str] = []
    elif order_ids:
        kind = "ordered_batch"
        replay_order = [x for x in order_ids if x in shard_ids] + [x for x in shard_ids if x not in (order_ids or [])]
    else:
        kind = "arbitrary_batch"
        replay_order = sorted(shard_ids, key=lambda sid: case.shard_by_id[sid]["order"] if sid in case.shard_by_id else 10**9)
    return {
        "kind": kind,
        "id": str(item.get("id", reference_id)),
        "step_index": index,
        "shards": shard_ids,
        "replay_order": replay_order,
        "atomic": atomic,
        "order_policy": "atomic" if atomic else ("explicit" if order_ids else "arbitrary"),
        "batch_id": str(first_present(item, ("batch_id", "batch", "release_batch"), item.get("id", reference_id))),
    }


def _single_action(case: Case, sid: str, index: int) -> dict[str, Any]:
    shard = case.shard_by_id[sid]
    return {
        "kind": "shard",
        "id": sid,
        "step_index": index,
        "shards": [sid],
        "replay_order": [sid],
        "atomic": False,
        "order_policy": "single",
        "batch_id": shard.get("batch") or "",
    }


def replay_plan(source: Case | dict[str, Any] | str, plan: Any | None = None) -> dict[str, Any]:
    case = as_case(source)
    actions = normalize_plan_actions(case, plan)
    shard_index = {s["id"]: s["order"] for s in case.shards}

    prefixes: list[dict[str, Any]] = []
    mask = 0
    initial = evaluate_mask(case, 0)
    prefixes.append(
        {
            "prefix_length": 0,
            "landing_count": 0,
            "action_index": None,
            "action": None,
            "mask": 0,
            "landed_shards": [],
            "compliant": initial["compliant"],
            "violation_ids": [v.get("invariant_id") for v in initial["violations"]],
            "report": initial,
        }
    )

    first_failure: dict[str, Any] | None = None
    landing_count = 0
    landed: list[str] = []

    def record(action: dict[str, Any] | None, action_index: int | None, atomic: bool) -> None:
        nonlocal first_failure
        report = evaluate_mask(case, mask)
        entry = {
            "prefix_length": landing_count,
            "prefix_record": len(prefixes),
            "landing_count": landing_count,
            "action_index": action_index,
            "action": _public_action(action),
            "atomic_landing": atomic,
            "mask": mask,
            "landed_shards": list(landed),
            "compliant": report["compliant"],
            "violation_ids": [v.get("invariant_id") for v in report["violations"]],
            "report": report,
        }
        prefixes.append(entry)
        if first_failure is None and not report["compliant"]:
            first_failure = _failure_prefix(case, entry, actions)

    if not initial["compliant"]:
        first_failure = _failure_prefix(case, prefixes[0], actions)

    for action_index, action in enumerate(actions):
        if first_failure is not None:
            break
        unknown = [sid for sid in action.get("shards", []) if sid not in shard_index]
        if unknown:
            # An unresolvable plan step is itself the first replayable failure.
            entry = {
                "prefix_length": len(prefixes),
                "landing_count": landing_count,
                "action_index": action_index,
                "action": _public_action(action),
                "mask": mask,
                "landed_shards": list(landed),
                "compliant": False,
                "violation_ids": [],
                "plan_error": f"unknown shard(s): {unknown}",
                "report": None,
            }
            prefixes.append(entry)
            first_failure = _failure_prefix(case, entry, actions)
            break

        if action["kind"] == "atomic_group":
            for sid in action["shards"]:
                mask |= 1 << shard_index[sid]
                landed.append(sid)
                landing_count += 1
            record(action, action_index, True)
        else:
            for sid in action.get("replay_order", action["shards"]):
                if mask & (1 << shard_index[sid]):
                    continue
                mask |= 1 << shard_index[sid]
                landed.append(sid)
                landing_count += 1
                record(action, action_index, False)
                if first_failure is not None:
                    break

    witness = earliest_replayable_failure(case, actions)
    result = {
        "status": "failure" if (first_failure is not None or witness is not None) else "complete_compliant",
        "reference_order_status": "failure" if first_failure is not None else "complete_compliant",
        "action_count": len(actions),
        "landing_count": landing_count,
        "first_failure_prefix": witness or first_failure,
        "reference_order_failure_prefix": first_failure,
        "arbitrary_order_failure_witness": witness if witness is not None and witness.get("order_search") == "arbitrary_witness" else None,
        "prefixes": prefixes,
        "final_report": evaluate_mask(case, mask),
        "replay_manifest": {
            "actions": [_public_action(a) for a in actions],
            "deterministic_total_order": landed,
        },
    }
    primary_failure = witness or first_failure
    result["first_failure"] = primary_failure
    if primary_failure is not None:
        result["replay_prefix_plan"] = primary_failure["prefix_plan"]
    return result


def earliest_replayable_failure(case: Case, actions: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Find a concrete shortest failure prefix allowed by arbitrary batch order.

    Explicit/ordered steps follow their stated order.  For arbitrary batches,
    BFS over shard subsets gives the shortest failing landing sequence; shard
    input order makes the witness deterministic.
    """
    from .migration import build_migration_model

    edge_bits = [(a, b) for a, b, _eid in build_migration_model(case)["edges"]]

    def edges_ok(mask: int) -> bool:
        return all(not (mask & b) or (mask & a) for a, b in edge_bits)

    initial = evaluate_mask(case, 0)
    if not initial["compliant"]:
        entry = {
            "prefix_length": 0,
            "landing_count": 0,
            "action_index": None,
            "action": None,
            "mask": 0,
            "landed_shards": [],
            "compliant": False,
            "violation_ids": [v.get("invariant_id") for v in initial["violations"]],
            "report": initial,
            "order_search": "initial",
        }
        return _failure_prefix(case, entry, actions)

    shard_index = {s["id"]: s["order"] for s in case.shards}
    mask = 0
    landed: list[str] = []

    for action_index, action in enumerate(actions):
        ids = action.get("shards", [])
        if any(sid not in shard_index for sid in ids):
            entry = {
                "prefix_length": len(landed) + 1,
                "landing_count": len(landed) + 1,
                "action_index": action_index,
                "action": _public_action(action),
                "mask": mask,
                "landed_shards": list(landed),
                "compliant": False,
                "violation_ids": [],
                "plan_error": "unknown shard in step",
                "report": None,
            }
            return _failure_prefix(case, entry, actions)

        if action.get("kind") == "atomic_group":
            for sid in ids:
                mask |= 1 << shard_index[sid]
                landed.append(sid)
            report = evaluate_mask(case, mask)
            if not edges_ok(mask) or not report["compliant"]:
                entry = {
                    "prefix_length": len(landed),
                    "landing_count": len(landed),
                    "action_index": action_index,
                    "action": _public_action(action),
                    "mask": mask,
                    "landed_shards": list(landed),
                    "compliant": False,
                    "violation_ids": [v.get("invariant_id") for v in report["violations"]] if edges_ok(mask) else [],
                    "report": report,
                    "order_search": "atomic",
                }
                return _failure_prefix(case, entry, actions)
            continue

        if action.get("order_policy") != "arbitrary":
            for sid in action.get("replay_order", ids):
                mask |= 1 << shard_index[sid]
                landed.append(sid)
                if not edges_ok(mask):
                    report = evaluate_mask(case, mask)
                    entry = _edge_failure_entry(action_index, action, mask, landed, len(landed))
                    entry["report"] = report
                    entry["violation_ids"] = [v.get("invariant_id") for v in report["violations"]]
                    return _failure_prefix(case, entry, actions)
                report = evaluate_mask(case, mask)
                if not report["compliant"]:
                    entry = {
                        "prefix_length": len(landed),
                        "landing_count": len(landed),
                        "action_index": action_index,
                        "action": _public_action(action),
                        "mask": mask,
                        "landed_shards": list(landed),
                        "compliant": False,
                        "violation_ids": [v.get("invariant_id") for v in report["violations"]],
                        "report": report,
                        "order_search": "explicit_order",
                    }
                    return _failure_prefix(case, entry, actions)
            continue

        # Arbitrary-order batch: deterministic BFS by global shard input order.
        member_ids = sorted(ids, key=lambda sid: shard_index[sid])
        start_mask = mask
        queue: list[tuple[int, tuple[str, ...]]] = [(start_mask, ())]
        visited = {start_mask}
        witness_entry: dict[str, Any] | None = None
        completed_order: tuple[str, ...] | None = None
        head = 0
        while head < len(queue):
            current_mask, internal_order = queue[head]
            head += 1
            if len(internal_order) == len(member_ids):
                completed_order = internal_order
                continue
            for sid in member_ids:
                if sid in internal_order:
                    continue
                new_mask = current_mask | (1 << shard_index[sid])
                next_order = internal_order + (sid,)
                global_landed = landed + list(next_order)
                if not edges_ok(new_mask):
                    # An edge-forbidden order is not a reachable arbitrary order.
                    continue
                report = evaluate_mask(case, new_mask)
                if not report["compliant"]:
                    witness_entry = {
                        "prefix_length": len(global_landed),
                        "landing_count": len(global_landed),
                        "action_index": action_index,
                        "action": _public_action(action),
                        "mask": new_mask,
                        "landed_shards": global_landed,
                        "compliant": False,
                        "violation_ids": [v.get("invariant_id") for v in report["violations"]],
                        "report": report,
                        "order_search": "arbitrary_witness",
                        "chosen_order_within_batch": list(next_order),
                    }
                    break
                if new_mask not in visited:
                    visited.add(new_mask)
                    queue.append((new_mask, next_order))
            if witness_entry is not None:
                return _failure_prefix(case, witness_entry, actions)

        # No failing arbitrary prefix.  Advance to the all-landed batch state.
        mask = start_mask | sum(1 << shard_index[sid] for sid in ids)
        if completed_order is None:
            # Precedence may leave no complete order; migration diagnostics deal
            # with that as an invalid/no-path model.  Keep input order for replay.
            completed_order = tuple(member_ids)
        landed.extend(completed_order)

    return None


def _edge_failure_entry(action_index: int, action: dict[str, Any], mask: int, landed: list[str], prefix_length: int) -> dict[str, Any]:
    return {
        "prefix_length": prefix_length,
        "landing_count": prefix_length,
        "action_index": action_index,
        "action": _public_action(action),
        "mask": mask,
        "landed_shards": list(landed),
        "compliant": False,
        "violation_ids": [],
        "plan_error": "precedence edge violated",
        "report": None,
        "order_search": "explicit_order",
    }


def _public_action(action: dict[str, Any] | None) -> dict[str, Any] | None:
    if action is None:
        return None
    return {k: v for k, v in action.items() if k != "raw"}


def _failure_prefix(case: Case, entry: dict[str, Any], all_actions: list[dict[str, Any]]) -> dict[str, Any]:
    action_index = entry.get("action_index")
    prefix_actions = []
    if action_index is not None:
        for action in all_actions[: action_index + 1]:
            public = _public_action(action)
            if action.get("kind") != "atomic_group" and entry.get("action") and action.get("step_index") == entry["action"].get("step_index"):
                # Truncate the failing non-atomic step to the landings actually made.
                landed = entry.get("landed_shards", [])
                before_count = sum(len(a.get("replay_order", a.get("shards", []))) for a in all_actions[:action_index] if a.get("kind") != "atomic_group")
                # The exact prefix is more safely represented as singleton switches.
                public = {"shards": landed, "order": landed, "order_policy": "explicit_replay_prefix"}
            prefix_actions.append(public)
    return {
        "prefix_length": entry["prefix_length"],
        "landing_count": entry["landing_count"],
        "mask": entry["mask"],
        "landed_shards": entry["landed_shards"],
        "action": entry.get("action"),
        "violation_ids": entry.get("violation_ids"),
        "plan_error": entry.get("plan_error"),
        "order_search": entry.get("order_search", "reference_prefix"),
        "chosen_order_within_batch": entry.get("chosen_order_within_batch"),
        "state_report": entry.get("report"),
        "prefix_plan": {"steps": [sid for sid in entry.get("landed_shards", [])]},
        "replay_hint": "python -m proofinterlock replay <case.json> --prefix-length " + str(entry["prefix_length"]),
    }
