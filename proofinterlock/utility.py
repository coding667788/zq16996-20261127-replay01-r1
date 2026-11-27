"""Small standard-library helpers used throughout proofinterlock."""
from __future__ import annotations

import json
import re
from typing import Any, Iterable, Iterator, TypeVar

T = TypeVar("T")

_ID_KEYS = ("id", "ID", "identifier", "rule_id", "shard_id", "group_id")


def first_present(mapping: dict[str, Any], keys: Iterable[str], default: Any = None) -> Any:
    """Return the first non-None value stored under one of *keys*."""
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return default


def as_tuple(value: Any) -> tuple[Any, ...]:
    if value is None:
        return ()
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(value)
    return (value,)


def as_str_tuple(value: Any) -> tuple[str, ...]:
    return tuple(str(v) for v in as_tuple(value))


def item_id(item: Any, default: str | None = None) -> str | None:
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        value = first_present(item, _ID_KEYS)
        return None if value is None else str(value)
    return default


def iter_named_items(value: Any, default_id_prefix: str = "item") -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield ``(id, mapping)`` from a dict, list, or mapping item.

    A bare string is represented as ``{"id": "..."}``.  List entries without an
    id receive a deterministic positional id only when necessary.
    """
    if value is None:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, dict):
                data = dict(item)
                data.setdefault("id", str(key))
                yield str(key), data
            else:
                yield str(key), {"id": str(key), "value": item}
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            if isinstance(item, dict):
                ident = item_id(item)
                if ident is None:
                    ident = f"{default_id_prefix}-{index + 1}"
                    data = dict(item)
                    data["id"] = ident
                else:
                    data = item
                yield str(ident), data
            elif isinstance(item, str):
                yield item, {"id": item}
            else:
                ident = f"{default_id_prefix}-{index + 1}"
                yield ident, {"id": ident, "value": item}
        return
    raise TypeError(f"expected dict/list of named items, got {type(value).__name__}")


def stable_json(value: Any, *, pretty: bool = False) -> str:
    """JSON encoding that preserves Python/JSON input insertion order."""
    if pretty:
        return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=False)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=False)


def safe_filename_slug(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip())
    return value.strip("-") or "proofinterlock"


def chunk_bits(mask: int, limit: int | None = None) -> Iterator[int]:
    count = 0
    while mask:
        low = mask & -mask
        bit = low.bit_length() - 1
        yield bit
        mask ^= low
        count += 1
        if limit is not None and count >= limit:
            return
