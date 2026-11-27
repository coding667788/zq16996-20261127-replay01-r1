# proofinterlock

`proofinterlock` is a zero-dependency Python 3.12 standard-library toolkit for:

1. building minimal replayable proofs for approval-gateway requests;
2. checking proxy-stable identities, common trust anchors, and independent
   sources by **real issuer person and failure domain**;
3. replaying an existing shard-switch plan up to its first failing prefix;
4. finding the minimum-cost migration from the initial policy to the fully
   switched policy while preserving authentication/denial invariants.

It is intentionally file/JSON/CLI oriented. No service, database, or external
package is required.

## Quick start

```powershell
# from the repository directory
python -m unittest discover -s tests -v

python main.py examples\proof_case.json          # solve alias
python -m proofinterlock prove examples\proof_case.json --request shared-anchor-good
python -m proofinterlock prove examples\proof_case.json --request shared-subordinate-issuer-bad
python -m proofinterlock replay examples\migration_case.json
python -m proofinterlock migrate examples\migration_case.json
python -m proofinterlock solve examples\proof_case.json --pretty
```

PowerShell quote paths if needed. Use `-` as the input path to read JSON from
stdin. Add `--compact` for one-line JSON.

If input JSON is untrusted and Python must run in isolated mode, use the
root launcher with an absolute path; it adds only its own adjacent directory
to `sys.path` (not the current working directory):

```powershell
python -I D:\path\to\proofinterlock_cli.py prove D:\path\to\case.json
```

## CLI

```text
python -m proofinterlock solve     CASE.json [--request ID]
python -m proofinterlock prove     CASE.json [--request ID] [--mask MASK]
python -m proofinterlock replay    CASE.json [--prefix-length N] [--plan plan.json]
python -m proofinterlock migrate   CASE.json
python -m proofinterlock evaluate  CASE.json --mask MASK
python -m proofinterlock validate  CASE.json
```

`solve` returns proof, current-plan replay, and migration sections together.
A denied proof or an impossible migration is still a successful CLI computation:
the JSON `allowed` / `status` fields carry the result. CLI/JSON/IO errors return
non-zero status.

## Input document

A complete example is [`examples/proof_case.json`](examples/proof_case.json).
The most important fields are:

```jsonc
{
  "people": [
    {
      "id": "p_alice",                    // stable person id
      "aliases": ["alice-phone", "alice-agent-7"],
      "failure_domains": ["fd-alice"]
    }
  ],

  "trust_anchors": ["c_root_anchor", "p_root"],

  "budget": 6,                            // optional unique-credential tier cap
  "max_tier": 3,                          // optional per-credential tier cap

  "credentials": [
    {
      "id": "c_dana_source",
      "person_id": "p_alice",             // stable holder id / account alias
      "issuer": "dana-issuer-prod",       // issuer account; aliases resolve it
      "role": "independent-source-a",     // post/position
      "services": ["deploy"],            // applicable services; "*" is allowed
      "tier": 2,                          // used as cost if no explicit cost
      "cost": 2,
      "failure_domains": ["fd-dana"]
    }
  ],

  "rules": {
    "dana_credential": { "type": "credential", "credential_id": "c_dana_source" },
    "dana_source": { "type": "and", "children": ["root_anchor", "dana_credential"] },
    "good_two_sources": {
      "type": "threshold",
      "k": 2,                             // at least k independent sources
      "children": ["dana_source", "erin_source"]
    }
  },

  "requests": [
    { "id": "req", "person": "alice-phone", "service": "deploy", "rule": "good_two_sources" }
  ],

  "invariants": {
    "always_authenticatable": ["req"],
    "always_deny": [{ "id": "bad", "person": "p_alice", "service": "deploy", "rule": "bad_two_sources" }]
  }
}
```

Accepted aliases include `certificates` for credentials, `shards` / `switches`,
`post` / `position` for role, `domains` for failure domains, and
`at_least` / `k_of` / `quorum` for threshold nodes.

### Proxy identities

Every account or issuer name is resolved through `people[].aliases` and the
optional top-level `aliases` map. Thus `frank-proxy-one` and
`frank-proxy-two` can both resolve to stable person `p_frank`. Independence
uses the stable issuer person, not the visible proxy account name.

### Trust anchors and independence

For every proof candidate, proofinterlock computes bitmasks of:

- reachable non-anchor stable issuer persons;
- reachable non-anchor failure domains;
- encountered declared anchors.

A credential is anchor-excluded when its id, issuer account, or stable issuer
is listed in `trust_anchors`, or when it has `"trust_anchor": true`. At a
threshold node, every pair of selected child proofs must satisfy:

```text
persons(child_a) ∩ persons(child_b) = ∅
domains(child_a) ∩ domains(child_b) = ∅
```

Shared anchor credentials are therefore allowed. Any other shared credential
shares its real issuer person and fails independence unless that issuer is a
declared anchor. This catches “two independent proofs” that secretly use two
proxy accounts belonging to the same subordinate issuer.

### Rule graph cycles

Rule children may reference other rule ids, including cycles. Expansion carries
a per-branch rule stack. A reference to a rule already on that branch yields
no candidate; other OR alternatives can still produce a finite proof. The same
rule may occur in separate branches because neither branch repeats it.

### Budget and deduplication

A proof's credential set is an integer bitmask over at most 30 credentials.
Repeated occurrences of the same credential are displayed where used but count
once toward:

- `unique_credential_count`;
- total tier/budget cost.

Independence still inspects the issuer behind every actual signature/credential.

### Minimal-proof tie-break

Feasible proofs are selected by:

1. smaller `unique_credential_count`;
2. deterministic input-order proof-tree key.

The JSON output includes both `proof` and `canonical_json`. `order_key` is the
input-order token tree used for tie-breaking: rule and credential positions
come from JSON insertion/input order, threshold children stay in declared
order, and hidden slot masks are only a final discriminator for identical
serializations.

## Current-plan replay

A plan may be top-level `current_plan`, `existing_plan`, or `plan`, or supplied
with `--plan`. Steps may be strings, singleton switches, explicit ordered
batches, arbitrary-order batches, or references to `release_batches` /
`atomic_groups`.

```jsonc
{
  "current_plan": {
    "steps": [
      { "batch": "wave-one", "order": ["s_harden", "s_add_erin"] }
    ]
  }
}
```

`replay` checks the initial state and every landed prefix. The first
non-compliant prefix is returned as `first_failure_prefix`, including:

- exact `landed_shards`;
- shard bitmask;
- violating invariant ids;
- full state report;
- minimal proof for an `always_deny` request that was incorrectly allowed;
- `prefix_plan`, a replayable JSON plan fragment.

Use `--prefix-length N` to extract one numbered prefix entry.

## Migration optimization

Shards describe policy-document substitutions:

```jsonc
{
  "shards": [
    {
      "id": "s_add_erin",
      "cost": 1,
      "publisher": "publisher-erin",
      "after": {
        "credentials": [ /* new/upserted credentials */ ],
        "rules": { "erin_cred": { /* ... */ } }
      }
    },
    {
      "id": "s_harden",
      "cost": 1,
      "after": {
        "rules": { "deploy_policy": { /* replacement */ } }
      }
    }
  ],

  "precedence_edges": [
    { "id": "e_erin_before_harden", "before": "s_add_erin", "after": "s_harden" }
  ],

  "atomic_groups": [
    { "id": "g_both", "shards": ["s_open", "s_close"], "cost": 1 }
  ],

  "release_batches": [
    { "id": "wave-one", "shards": ["s_add_erin", "s_harden"], "atomic": false }
  ]
}
```

For a shard bitmask `M`, bit `i=1` selects shard `i`'s `after` fragment;
otherwise its `before` fragment is used. Fragments are merged over the base
policy by stable id. Removal markers (`"$remove": true`) are supported.

The optimizer performs dynamic programming over the monotone shard-subset
lattice (`2^14 = 16384` maximum masks):

- singleton switches produce a reference total order;
- explicit precedence edges reject states where `after` is present without
  `before`;
- atomic groups jump directly to the post-group state and expose no internal
  subset;
- ordered batches check every declared prefix;
- arbitrary-order batches check every precedence-reachable subset, because
  different publishers may land their shards in any order;
- all shards must be switched (`mask = (1 << n) - 1`).

No temporary permit-all rule is generated or inserted. The result contains
`temporary_allow_all_added: false`.

Equal-cost plans are deterministically ordered by:

1. sorted selected constraint ids;
2. release-batch id sequence;
3. global shard input-order sequence.

### No-solution statuses

`migrate` returns one of:

- `ok`;
- `initial_invariant_violation`;
- `final_invariant_violation`;
- `no_safe_migration_path` — both endpoint reports are compliant, but the safe
  subset lattice has no path under the supplied groups/edges;
- `invalid_migration_input`.

The JSON always includes `endpoint_states.initial_report` and
`endpoint_states.final_report`. For a middle-state failure it also includes
reachable safe masks and a deterministic sample of blocked transitions.

## Worked examples

### Proof interlocks

[`examples/proof_case.json`](examples/proof_case.json) covers all three required
semantic traps:

- `proxy-login`: `alice-phone` resolves to `p_alice`;
- `shared-anchor-good`: two sources share `c_root_anchor` / `p_root`, but their
  non-anchor issuers and domains are disjoint;
- `shared-subordinate-issuer-bad`: `frank-proxy-one` and `frank-proxy-two`
  resolve to the same real issuer `p_frank`, so the threshold proof is rejected.

A compact expected proof reference is in
[`examples/proof_tree.reference.json`](examples/proof_tree.reference.json).

### Release total order

[`examples/migration_case.json`](examples/migration_case.json) has a bad current
order that hardens policy before adding the second source. Replay reports
`s_harden` as the first failure. Migration finds:

```json
{
  "status": "ok",
  "minimum_total_cost": 2,
  "release_total_order": ["s_add_erin", "s_harden"],
  "honored_precedence_edge_ids": ["e_erin_before_harden"]
}
```

See [`examples/release_order.reference.json`](examples/release_order.reference.json).

[`examples/atomic_group_case.json`](examples/atomic_group_case.json) shows a
case where both singleton landings fail but a discounted atomic group succeeds
with cost `1`. Removing the group gives
[`examples/no_middle_case.json`](examples/no_middle_case.json), which reports
`no_safe_migration_path`.

## Performance approach

- proxy identities and person/domain bit tables are built once per document;
- policy fragments are assembled and normalized once per shard mask and cached;
- invariant checks are cached by mask, so many possible release orders do not
  cause repeated full-policy checks;
- rule expansion memoizes `(rule_id, branch_stack)` alternatives;
- credential sets and independence profiles use 30-bit integer masks;
- migration visits subset states through one subset DP rather than enumerating
  every identity/path combination for every release plan.

## Testing

```powershell
python -m unittest discover -s tests -v
```

The unittest suite covers proxy de-aliasing, shared anchors, shared subordinate
issuers, domain overlap, credential deduplication under budget, input-order
ties, cyclic rule graphs, replay prefixes, minimum migration order, atomic
groups, initial/final/middle no-solution reporting, determinism, and the JSON
CLI.

## Package layout

```text
proofinterlock/
  case.py       # JSON loading, identity tables, shard-fragment merge
  identity.py   # stable person/proxy alias resolution
  nodes.py      # AND/OR/threshold/ref/credential normalization
  proof.py      # memoized finite expansion, minimization, independence
  engine.py     # per-mask invariant evaluation
  replay.py     # current-plan normalization and prefix replay
  migration.py  # subset DP, batches/groups/edges, no-solution diagnostics
  cli.py        # JSON command line
  api.py        # solve() convenience entry point
tests/
examples/
```
