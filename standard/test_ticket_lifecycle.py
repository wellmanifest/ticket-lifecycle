"""Unit and security hardening tests for wellmanifest/ticket-lifecycle."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

STD_DIR = Path(__file__).resolve().parent
if str(STD_DIR) not in sys.path:
    sys.path.insert(0, str(STD_DIR))

import conformance
import lease_conformance
import split_plan
import ticket_io


class TicketLifecycleHardeningTests(unittest.TestCase):
    def test_all_conformance_suites_pass(self) -> None:
        tl = conformance.run_all()
        self.assertTrue(tl["ok"])
        lease = lease_conformance.run_all()
        self.assertTrue(lease["ok"])
        sp = split_plan.self_test()
        self.assertTrue(sp["ok"])
        self.assertEqual(len(sp["adversarialRejected"]), 17)

    def test_conformance_rejects_unhashable_evidence_non_strings_secrets_and_depth(
        self,
    ) -> None:
        req: dict[str, Any] = {
            "schema": "wellmanifest.ticket-lifecycle/v1",
            "kind": "transition-request",
            "requestId": "request:allocate",
            "repositoryRef": "repository:demo",
            "workstreamRef": "workstream:integration",
            "action": "allocate",
            "ticket": None,
            "expectedState": "unallocated",
            "targetState": "allocated",
            "intentRef": None,
            "authorizationRef": None,
            "evidenceRefs": ["artifact:request"],
            "idempotencyKey": "idempotency:allocate",
        }
        for bad_ev in ([{"nested": 1}], [123], ["invalid-ref"]):
            cand = copy.deepcopy(req)
            cand["evidenceRefs"] = bad_ev
            with self.assertRaises(conformance.ContractError):
                conformance.validate_request(cand)

        non_str = copy.deepcopy(req)
        non_str["requestId"] = 123
        with self.assertRaises(conformance.ContractError):
            conformance.validate_request(non_str)

        secret_val = copy.deepcopy(req)
        secret_val["idempotencyKey"] = "AK" + "IA1234567890ABCDEF"
        with self.assertRaises(conformance.ContractError):
            conformance.validate_request(secret_val)

        deep: Any = "leaf"
        for _ in range(70):
            deep = {"nested": deep}
        with self.assertRaises(conformance.ContractError):
            conformance.reject_sensitive(deep)

    def test_lease_conformance_rejects_non_string_types_traversal_and_bad_rfc3339(
        self,
    ) -> None:
        base_lease = {
            "schema": lease_conformance.LEASE_SCHEMA,
            "kind": "execution-lease",
            "leaseId": "lease:ticket-011",
            "repositoryRef": "repository:demo",
            "ticket": "ticket-011",
            "workstreamRef": "workstream:integration",
            "branchRef": "branch:ticket-011-execution-lease",
            "worktreeId": "worktree:ticket-011",
            "ownerActor": "actor:agent-a",
            "ownerSession": "session:alpha",
            "scopeHash": "a" * 64,
            "headSha": "b" * 40,
            "state": "active",
            "generation": 1,
            "fencing": 1,
            "issuedAt": "2026-09-14T10:00:00.123456789Z",
            "leaseExpiresAt": "2026-09-14T11:00:00.123456789Z",
            "takeoverAt": "2026-09-14T11:10:00.123456789Z",
            "lastRenewedAt": "2026-09-14T10:00:00.123456789Z",
            "ttlSeconds": 3600,
            "graceSeconds": 600,
            "eventSequence": 1,
        }
        lease_conformance.validate_lease(base_lease)

        for field, bad_val in (
            ("leaseId", 999),
            ("branchRef", "branch:a/../../etc"),
            ("ttlSeconds", True),
            ("issuedAt", "2026-09-14 10:00:00+00:00"),
            ("issuedAt", "2026-09-14T10:00:00.1234567890Z"),
        ):
            bad_lease = copy.deepcopy(base_lease)
            bad_lease[field] = bad_val
            with self.assertRaises(lease_conformance.ContractError):
                lease_conformance.validate_lease(bad_lease)

        takeover_req: dict[str, Any] = {
            "schema": lease_conformance.REQUEST_SCHEMA,
            "kind": "lease-transition-request",
            "requestId": "request:takeover",
            "leaseId": "lease:ticket-011",
            "action": "takeover",
            "expectedGeneration": 1,
            "expectedFencing": 1,
            "requestedBy": "actor:agent-b",
            "newOwnerActor": "actor:agent-b",
            "newOwnerSession": "session:beta",
            "newWorktreeId": None,
            "requestedAt": "2026-09-14T11:10:00Z",
            "authorityRef": "authority:controller",
            "evidenceRefs": ["receipt:lease.start"],
            "idempotencyKey": "idempotency:takeover",
        }
        with self.assertRaises(lease_conformance.ContractError):
            lease_conformance.validate_request(takeover_req)

        trav_wt = copy.deepcopy(takeover_req)
        trav_wt["newWorktreeId"] = "worktree:../../../etc"
        with self.assertRaises(lease_conformance.ContractError):
            lease_conformance.validate_request(trav_wt)

        unhashable_ev = copy.deepcopy(takeover_req)
        unhashable_ev["newWorktreeId"] = "worktree:ticket-011-next"
        unhashable_ev["evidenceRefs"] = [{"bad": 1}]
        with self.assertRaises(lease_conformance.ContractError):
            lease_conformance.validate_request(unhashable_ev)

    def test_split_plan_cli_and_strict_json_io_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            real = root / "real"
            real.mkdir()
            valid_doc = split_plan.example_document()
            plan_path = real / "plan.json"
            plan_path.write_text(json.dumps(valid_doc), encoding="utf-8")
            with (
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(split_plan.main([str(plan_path)]), 0)

                sym = root / "sym.json"
                sym.symlink_to(plan_path)
                self.assertEqual(split_plan.main([str(sym)]), 1)

                sym_dir = root / "sym_dir"
                sym_dir.symlink_to(real)
                self.assertEqual(split_plan.main([f"{sym_dir}/../real/plan.json"]), 1)

                sub = root / "sub"
                sub.mkdir()
                old_cwd = Path.cwd()
                try:
                    os.chdir(sub)
                    with self.assertRaises(ValueError):
                        ticket_io.read_strict_json("../sym_dir/plan.json")
                finally:
                    os.chdir(old_cwd)

                for idx, payload in enumerate(
                    (
                        '{"a": 1, "a": 2}',
                        '{"a": NaN}',
                        '{"a": ' + ("9" * 5000) + "}",
                        '{"a": "\\ud800"}',
                    )
                ):
                    bad = real / f"bad-{idx}.json"
                    bad.write_text(payload, encoding="utf-8")
                    self.assertEqual(split_plan.main([str(bad)]), 1)

    def test_owned_standard_modules_stay_below_500_lines(self) -> None:
        owned = (
            "ticket_io.py",
            "split_plan.py",
            "conformance.py",
            "lease_conformance.py",
            "test_ticket_lifecycle.py",
        )
        for name in owned:
            path = STD_DIR / name
            with path.open("r", encoding="utf-8") as fh:
                lines = sum(1 for _ in fh)
            self.assertLess(lines, 500, f"{name} has {lines} lines (>= 500)")


if __name__ == "__main__":
    unittest.main()
