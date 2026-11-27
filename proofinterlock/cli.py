"""JSON command-line interface for proofinterlock."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .api import solve
from .case import Case
from .engine import evaluate_mask, find_request, prove_request
from .migration import migrate
from .replay import replay_plan

COMMANDS = {"solve", "all", "prove", "proof", "replay", "migrate", "plan", "evaluate", "validate"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m proofinterlock",
        description="Minimal proofs, replayable plan failures, and safe shard migration optimization.",
    )
    parser.add_argument("command", nargs="?", help="prove | replay | migrate | solve | validate")
    parser.add_argument("input", nargs="?", help="Path to JSON input, or - for stdin")
    parser.add_argument("-i", "--input", dest="input_opt", help="Path to JSON input")
    parser.add_argument("-r", "--request", dest="request_id", help="Request id for prove/solve")
    parser.add_argument("--rule", dest="rule", help="Rule id for an ad hoc prove command")
    parser.add_argument("--person", help="Person/account for an ad hoc prove command")
    parser.add_argument("--service", help="Service for an ad hoc prove command")
    parser.add_argument("--mask", type=int, default=0, help="Shard bitmask for prove/evaluate (default 0)")
    parser.add_argument("--prefix-length", type=int, help="Return one numbered prefix entry from replay")
    parser.add_argument("--plan", help="Optional plan JSON file or inline JSON for replay")
    parser.add_argument("-o", "--output", help="Write JSON output to this file as well as stdout")
    parser.add_argument("--pretty", action="store_true", default=True, help="Pretty-print JSON (default)")
    parser.add_argument("--compact", action="store_true", help="Compact JSON output")
    return parser


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    args = build_parser().parse_args(argv)

    command = args.command
    input_ref = args.input_opt or args.input
    # Allow `proofinterlock case.json --request req` without a command.
    if command is not None and command not in COMMANDS and input_ref is None:
        input_ref = command
        command = "solve"
    if command is None:
        command = "solve"
    command = {"proof": "prove", "plan": "migrate", "all": "solve"}.get(command, command)

    if not input_ref:
        print(json.dumps({"status": "usage_error", "error": "an input JSON path or - for stdin is required"}, ensure_ascii=False), file=sys.stderr)
        return 2

    try:
        case = _load_case(input_ref)
        result = _dispatch(case, command, args)
    except FileNotFoundError as exc:
        result = {"status": "io_error", "error": str(exc)}
        _emit(result, args)
        return 2
    except json.JSONDecodeError as exc:
        result = {"status": "invalid_json", "error": str(exc)}
        _emit(result, args)
        return 2
    except Exception as exc:  # CLI boundary: always return JSON.
        result = {"status": "error", "error_type": type(exc).__name__, "error": str(exc)}
        _emit(result, args)
        return 1

    _emit(result, args)
    return 0 if _exit_ok(result) else 3


def _load_case(ref: str) -> Case:
    if ref == "-":
        doc = json.load(sys.stdin)
        return Case(doc, source_name="<stdin>")
    path = Path(ref)
    with path.open("r", encoding="utf-8-sig") as handle:
        doc = json.load(handle)
    return Case(doc, source_name=str(path))


def _dispatch(case: Case, command: str, args: argparse.Namespace) -> dict[str, Any]:
    if command == "validate":
        initial = case.policy(0)
        final = case.policy(case.all_mask)
        credential_union = len(set(initial.cred_by_id) | set(final.cred_by_id))
        constraint_value = case.doc.get("constraints", case.doc.get("additional_constraints", []))
        constraint_count = len(constraint_value) if isinstance(constraint_value, list) else 0
        field_warnings = []
        for cred in list(initial.credentials) + [c for c in final.credentials if c.cid not in initial.cred_by_id]:
            missing = []
            if cred.subject is None:
                missing.append("person_id")
            if cred.issuer_raw is None:
                missing.append("issuer")
            if cred.role is None:
                missing.append("role/post")
            if not cred.services:
                missing.append("services")
            if missing:
                field_warnings.append({"credential_id": cred.cid, "missing": missing})
        return {
            "status": "ok",
            "shards": len(case.shards),
            "publishers": sorted({str(s["publisher"]) for s in case.shards if s.get("publisher") is not None}),
            "credentials_in_initial_policy": len(initial.credentials),
            "credentials_in_final_policy": len(final.credentials),
            "credential_id_union": credential_union,
            "rules_in_initial_policy": len(initial.rules),
            "identity_conflicts": case.identity.conflicts,
            "credential_field_warnings": field_warnings,
            "all_mask": case.all_mask,
            "within_stated_limits": {
                "switches_max_14": len(case.shards) <= 14,
                "additional_constraints_max_8": constraint_count <= 8,
                "credentials_max_30": credential_union <= 30,
            },
        }

    if command == "prove":
        request: dict[str, Any] | str | None
        if args.rule or args.person or args.service:
            request = {
                "id": args.request_id or "adhoc",
                "rule": args.rule,
                "person": args.person,
                "service": args.service,
            }
            request = {k: v for k, v in request.items() if v is not None}
        elif args.request_id:
            request = find_request(case.doc, args.request_id) or args.request_id
        else:
            request = None
        return prove_request(case, request, mask=args.mask)

    if command == "evaluate":
        return evaluate_mask(case, args.mask)

    if command == "replay":
        plan_override = None
        if getattr(args, "plan", None):
            plan_ref = args.plan
            maybe_path = Path(plan_ref)
            if maybe_path.exists():
                plan_override = json.loads(maybe_path.read_text(encoding="utf-8-sig"))
            else:
                plan_override = json.loads(plan_ref)
        result = replay_plan(case, plan_override)
        if args.prefix_length is not None:
            failure = result.get("first_failure_prefix") or {}
            if failure.get("prefix_length") == args.prefix_length or failure.get("landing_count") == args.prefix_length:
                return failure
            for entry in result.get("prefixes", []):
                if entry.get("prefix_length") == args.prefix_length or entry.get("landing_count") == args.prefix_length:
                    return entry
            return {"status": "prefix_not_found", "requested_prefix_length": args.prefix_length}
        return result

    if command == "migrate":
        return migrate(case)

    if command == "solve":
        return solve(case, request_id=args.request_id)

    return {"status": "usage_error", "error": f"unknown command {command}"}


def _emit(result: Any, args: argparse.Namespace) -> None:
    indent = None if getattr(args, "compact", False) else 2
    text = json.dumps(result, ensure_ascii=False, indent=indent, sort_keys=False, default=_json_default)
    print(text)
    output = getattr(args, "output", None)
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")


def _json_default(value: Any) -> Any:
    if isinstance(value, (set, frozenset)):
        return sorted(value, key=str)
    if isinstance(value, tuple):
        return list(value)
    return str(value)


def _exit_ok(result: Any) -> bool:
    if not isinstance(result, dict):
        return True
    status = result.get("status")
    if status in {"error", "invalid_json", "io_error", "usage_error", "invalid_migration_input"}:
        return False
    # A denied proof is a successful CLI computation, not a CLI failure.
    return True


if __name__ == "__main__":
    raise SystemExit(main())
