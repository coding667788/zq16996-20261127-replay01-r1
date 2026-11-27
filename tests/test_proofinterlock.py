from __future__ import annotations

import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from proofinterlock import Case, evaluate_mask, migrate, prove_request, replay_plan  # noqa: E402
from proofinterlock.cli import main as cli_main  # noqa: E402

PROOF_EXAMPLE = ROOT / "examples" / "proof_case.json"
MIGRATION_EXAMPLE = ROOT / "examples" / "migration_case.json"


def credential(cid, *, person="p_alice", issuer="issuer-one", services=("svc",), cost=1, domains=("fd-one",), **extra):
    data = {
        "id": cid,
        "person_id": person,
        "issuer": issuer,
        "role": "operator",
        "services": list(services),
        "cost": cost,
        "failure_domains": list(domains),
    }
    data.update(extra)
    return data


class ProofInterlockTests(unittest.TestCase):
    def test_proxy_account_resolves_to_stable_person(self):
        doc = {
            "people": [{"id": "p_alice", "aliases": ["alice-phone", "alice-laptop"]}],
            "credentials": [credential("c1")],
            "rules": {"r1": {"type": "credential", "credential_id": "c1"}},
        }
        result = prove_request(doc, {"person": "alice-phone", "service": "svc", "rule": "r1"})
        self.assertTrue(result["allowed"], result)
        self.assertEqual(result["credentials"], ["c1"])

    def test_shared_trust_anchor_is_allowed_but_other_sources_checked(self):
        result = prove_request(str(PROOF_EXAMPLE), "shared-anchor-good")
        self.assertTrue(result["allowed"], result)
        self.assertEqual(result["unique_credential_count"], 3)
        persons = [set(p["persons"]) for p in result["independence_profiles"]]
        self.assertEqual(persons, [{"p_dana"}, {"p_erin"}])
        self.assertTrue(any("p_root" in anchor for anchor in result["shared_trust_anchors"]))

    def test_two_proofs_sharing_proxied_subordinate_issuer_are_rejected(self):
        result = prove_request(str(PROOF_EXAMPLE), "shared-subordinate-issuer-bad")
        self.assertFalse(result["allowed"])
        self.assertEqual(result["error_code"], "no_feasible_proof")

        # A compact direct regression for proxy issuer de-aliasing.
        doc = {
            "people": [{"id": "p_frank", "aliases": ["frank-a", "frank-b"]}],
            "credentials": [
                credential("c1", issuer="frank-a", domains=("fd-a",)),
                credential("c2", issuer="frank-b", domains=("fd-b",)),
            ],
            "rules": {
                "r1": {"type": "credential", "credential_id": "c1"},
                "r2": {"type": "credential", "credential_id": "c2"},
                "root": {"type": "threshold", "k": 2, "children": ["r1", "r2"]},
            },
        }
        result = prove_request(doc, {"person": "p_alice", "service": "svc", "rule": "root"})
        self.assertFalse(result["allowed"])

    def test_same_failure_domain_blocks_even_with_distinct_issuers(self):
        doc = {
            "credentials": [
                credential("c1", issuer="issuer-a", domains=("shared-fd",)),
                credential("c2", issuer="issuer-b", domains=("shared-fd",)),
            ],
            "rules": {
                "r1": {"type": "credential", "credential_id": "c1"},
                "r2": {"type": "credential", "credential_id": "c2"},
                "root": {"type": "threshold", "k": 2, "children": ["r1", "r2"]},
            },
        }
        result = prove_request(doc, {"person": "p_alice", "service": "svc", "rule": "root"})
        self.assertFalse(result["allowed"])

    def test_shared_credential_is_deduped_for_budget(self):
        doc = {
            "budget": 3,
            "credentials": [credential("c1", cost=3)],
            "rules": {
                "leaf": {"type": "credential", "credential_id": "c1"},
                "root": {"type": "and", "children": ["leaf", "leaf"]},
            },
        }
        result = prove_request(doc, {"person": "p_alice", "service": "svc", "rule": "root"})
        self.assertTrue(result["allowed"], result)
        self.assertEqual(result["unique_credential_count"], 1)
        self.assertEqual(result["tier_cost"], 3)
        # The shared leaf is still visibly expanded on both AND branches.
        self.assertEqual(result["canonical_json"].count('"credential_id":"c1"'), 2)

    def test_or_tie_uses_input_order(self):
        doc = {
            "credentials": [
                credential("c_first", issuer="i1"),
                credential("c_second", issuer="i2", domains=("fd-two",)),
            ],
            "rules": {
                "first_rule": {"type": "credential", "credential_id": "c_first"},
                "second_rule": {"type": "credential", "credential_id": "c_second"},
                "root": {"type": "or", "children": ["first_rule", "second_rule"]},
            },
        }
        result = prove_request(doc, {"person": "p_alice", "service": "svc", "rule": "root"})
        self.assertTrue(result["allowed"])
        self.assertEqual(result["credentials"], ["c_first"])
        self.assertIn("first_rule", result["canonical_json"])

    def test_cycles_expand_without_repeating_rule_on_a_branch(self):
        allowed = prove_request(str(PROOF_EXAMPLE), "cycle-proof")
        self.assertTrue(allowed["allowed"], allowed)

        cyclic_only = {
            "rules": {
                "a": {"type": "or", "children": ["b"]},
                "b": {"type": "and", "children": ["a"]},
            }
        }
        result = prove_request(cyclic_only, {"rule": "a"})
        self.assertFalse(result["allowed"])

    def test_explicit_allow_all_node_is_not_treated_as_a_proof(self):
        doc = {
            "credentials": [credential("c1")],
            "rules": {"root": {"type": "allow_all"}},
        }
        result = prove_request(doc, {"person": "p_alice", "service": "svc", "rule": "root"})
        self.assertFalse(result["allowed"])

    def test_example_invariants_are_compliant(self):
        report = evaluate_mask(Case.load(str(PROOF_EXAMPLE)), 0)
        self.assertTrue(report["compliant"], report["violations"])


class MigrationTests(unittest.TestCase):
    def test_current_plan_reports_first_replayable_failure_prefix(self):
        result = replay_plan(str(MIGRATION_EXAMPLE))
        self.assertEqual(result["status"], "failure")
        failure = result["first_failure_prefix"]
        self.assertEqual(failure["landed_shards"], ["s_harden"])
        self.assertIn("deploy-ok", failure["violation_ids"])
        self.assertIn("prefix_plan", failure)

    def test_minimum_migration_uses_safe_total_order(self):
        result = migrate(str(MIGRATION_EXAMPLE))
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual(result["minimum_total_cost"], 2)
        self.assertEqual(result["release_total_order"], ["s_add_erin", "s_harden"])
        self.assertEqual(result["release_batches"], ["wave-one"])
        self.assertEqual(result["actions"][0]["kind"], "batch")
        self.assertIn("e_erin_before_harden", result["honored_precedence_edge_ids"])
        self.assertFalse(result["temporary_allow_all_added"])

    def _middle_conflict_doc(self, *, with_atomic_group=False):
        doc = {
            "budget": 5,
            "credentials": [credential("c_a", issuer="issuer-a", domains=("fd-a",))],
            "rules": {
                "a_cred": {"type": "credential", "credential_id": "c_a"},
                "auth_policy": {"type": "threshold", "k": 1, "children": ["a_cred"]},
            },
            "requests": [
                {"id": "auth", "person": "p_alice", "service": "svc", "rule": "auth_policy"},
                {"id": "deny", "person": "p_alice", "service": "svc", "rule": "deny_policy"},
            ],
            "invariants": {"always_authenticatable": ["auth"], "always_deny": ["deny"]},
            "shards": [
                {
                    "id": "s_open",
                    "cost": 1,
                    "after": {
                        "credentials": [credential("c_b", issuer="issuer-b", domains=("fd-b",))],
                        "rules": {"b_cred": {"type": "credential", "credential_id": "c_b"}, "deny_policy": {"type": "credential", "credential_id": "c_b"}},
                    },
                },
                {
                    "id": "s_close",
                    "cost": 1,
                    "after": {
                        "rules": {
                            "auth_policy": {"type": "and", "children": ["a_cred", "b_cred"]},
                            "deny_policy": {"type": "credential", "credential_id": "does_not_exist"},
                        }
                    },
                },
            ],
        }
        if with_atomic_group:
            doc["atomic_groups"] = [{"id": "g_both", "shards": ["s_open", "s_close"], "cost": 1}]
        return doc

    def test_both_endpoints_ok_but_middle_has_no_path(self):
        result = migrate(self._middle_conflict_doc())
        self.assertEqual(result["status"], "no_safe_migration_path", result)
        self.assertTrue(result["endpoint_states"]["initial"]["compliant"])
        self.assertTrue(result["endpoint_states"]["final"]["compliant"])
        self.assertIn("middle", result)
        self.assertGreater(len(result["middle"]["blocked_transitions_sample"]), 0)

    def test_discounted_atomic_group_is_selected_and_bypasses_middle(self):
        result = migrate(self._middle_conflict_doc(with_atomic_group=True))
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual(result["minimum_total_cost"], 1)
        self.assertEqual(result["actions"][0]["kind"], "atomic")
        self.assertEqual(result["actions"][0]["id"], "g_both")
        self.assertEqual(result["release_total_order"], ["s_open", "s_close"])

    def test_arbitrary_batch_order_produces_replayable_witness(self):
        doc = self._middle_conflict_doc()
        result = replay_plan(doc, {"steps": [{"shards": ["s_close", "s_open"]}]})
        self.assertEqual(result["status"], "failure")
        failure = result["first_failure_prefix"]
        self.assertEqual(failure["order_search"], "arbitrary_witness")
        # Input shard order, not the step's displayed set order, chooses s_open first.
        self.assertEqual(failure["landed_shards"], ["s_open"])
        self.assertIn("deny", failure["violation_ids"])

    def test_initial_and_final_failure_are_reported_separately(self):
        initial_bad = {
            "invariants": {"always_authenticatable": [{"id": "auth", "person": "nobody", "service": "svc"}]},
            "shards": [{"id": "s1", "after": {}}],
        }
        result = migrate(initial_bad)
        self.assertEqual(result["status"], "initial_invariant_violation")
        self.assertFalse(result["endpoint_states"]["initial"]["compliant"])
        self.assertIn("final_report", result["endpoint_states"])

        final_bad = {
            "credentials": [credential("c1")],
            "rules": {"r1": {"type": "credential", "credential_id": "c1"}},
            "invariants": {"always_authenticatable": [{"id": "auth", "person": "p_alice", "service": "svc", "rule": "r1"}]},
            "shards": [
                {
                    "id": "s1",
                    "after": {"rules": {"r1": {"type": "credential", "credential_id": "missing"}}},
                }
            ],
        }
        result = migrate(final_bad)
        self.assertEqual(result["status"], "final_invariant_violation")
        self.assertTrue(result["endpoint_states"]["initial"]["compliant"])
        self.assertFalse(result["endpoint_states"]["final"]["compliant"])

    def test_deterministic_total_order_for_independent_shards(self):
        doc = {
            "invariants": {"always_deny": [{"id": "deny", "person": "ghost", "service": "svc"}]},
            "shards": [{"id": "s_b", "after": {}}, {"id": "s_a", "after": {}}],
        }
        first = migrate(doc)
        second = migrate(doc)
        self.assertEqual(first["release_total_order"], ["s_b", "s_a"])
        self.assertEqual(first["tie_break_key"], second["tie_break_key"])


class CliTests(unittest.TestCase):
    def test_json_cli_prove(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli_main(["prove", str(PROOF_EXAMPLE), "--request", "proxy-login", "--compact"])
        self.assertEqual(code, 0)
        payload = json.loads(buf.getvalue())
        self.assertTrue(payload["allowed"])

    def test_json_cli_solve(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli_main(["solve", str(MIGRATION_EXAMPLE), "--compact"])
        self.assertEqual(code, 0)
        payload = json.loads(buf.getvalue())
        self.assertIn("migration", payload)
        self.assertIn("replay", payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
