"""Stable person resolution through proxy/agent account names."""
from __future__ import annotations

from typing import Any

from .utility import as_tuple, first_present


class IdentityIndex:
    """Maps every observed account/issuer alias to one stable person id."""

    def __init__(self) -> None:
        self.canonical: dict[str, str] = {}
        self.people: dict[str, dict[str, Any]] = {}
        self.person_domains: dict[str, frozenset[str]] = {}
        self.conflicts: list[dict[str, str]] = []

    @classmethod
    def from_document(cls, doc: dict[str, Any]) -> "IdentityIndex":
        index = cls()

        # Explicit stable person records.
        people = first_present(doc, ("people", "persons", "principals", "identities"), [])
        for person in as_tuple(people):
            if isinstance(person, str):
                pid = person
                data: dict[str, Any] = {"id": pid}
            elif isinstance(person, dict):
                pid = str(first_present(person, ("id", "person_id", "stable_person_id", "stable_id")))
                data = person
            else:
                continue
            domains = frozenset(
                str(d)
                for d in as_tuple(first_present(data, ("failure_domains", "domains", "domain"), ()))
            )
            index.people[pid] = data
            index.person_domains[pid] = domains
            index.bind(pid, pid)
            for alias in as_tuple(first_present(data, ("aliases", "accounts", "agent_accounts", "proxy_accounts"), ())):
                index.bind(str(alias), pid)
            for domain in domains:
                # A domain name is not an identity, but reserve nothing here;
                # this loop intentionally documents person-domain extraction.
                _ = domain

        # Flat alias maps / lists are also accepted.
        aliases = first_present(doc, ("aliases", "account_aliases", "identity_aliases"), {})
        if isinstance(aliases, dict):
            for alias, pid in aliases.items():
                index.bind(str(alias), str(pid))
        else:
            for entry in as_tuple(aliases):
                if isinstance(entry, dict):
                    alias = first_present(entry, ("account", "alias", "identity", "from"))
                    pid = first_present(entry, ("person", "person_id", "stable_person_id", "to", "id"))
                    if alias is not None and pid is not None:
                        index.bind(str(alias), str(pid))
                elif isinstance(entry, (list, tuple)) and len(entry) == 2:
                    index.bind(str(entry[0]), str(entry[1]))

        # Credentials and shard fragments may introduce previously undeclared
        # issuer/subject names.  They remain their own stable person unless an
        # explicit alias says otherwise.
        for cred in _iter_credential_like(doc):
            for key in ("person_id", "stable_person_id", "person", "holder", "subject", "subject_id"):
                value = cred.get(key)
                if value is not None:
                    index.bind(str(value), index.person(str(value)))
            for key in ("issuer", "issuer_id", "signer", "signer_id", "issued_by"):
                value = cred.get(key)
                if value is not None:
                    index.bind(str(value), index.person(str(value)))
        return index

    def bind(self, identity: str, person_id: str) -> None:
        identity = str(identity)
        person_id = str(person_id)
        existing = self.canonical.get(identity)
        if existing is not None and existing != person_id:
            self.conflicts.append({"identity": identity, "existing": existing, "attempted": person_id})
            # First explicit declaration wins deterministically.
            return
        self.canonical[identity] = person_id
        self.canonical.setdefault(person_id, person_id)

    def person(self, identity: Any) -> str | None:
        if identity is None:
            return None
        key = str(identity)
        return self.canonical.get(key, key)

    def domains_for(self, identity: Any) -> frozenset[str]:
        pid = self.person(identity)
        if pid is None:
            return frozenset()
        return self.person_domains.get(pid, frozenset())


def _iter_credential_like(doc: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []

    def visit_fragment(fragment: Any) -> None:
        if not isinstance(fragment, dict):
            return
        for key in ("credentials", "certificates", "certs", "issued_credentials"):
            value = fragment.get(key)
            if isinstance(value, list):
                result.extend(x for x in value if isinstance(x, dict))
            elif isinstance(value, dict):
                result.extend(x for x in value.values() if isinstance(x, dict))

    visit_fragment(doc)
    policy = doc.get("policy")
    visit_fragment(policy)
    for shard in as_tuple(first_present(doc, ("shards", "switches"), ())):
        if not isinstance(shard, dict):
            continue
        for key in ("before", "old", "unswitched", "initial", "after", "new", "switched", "fragment", "policy"):
            visit_fragment(shard.get(key))
    return result
