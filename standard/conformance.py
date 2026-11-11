#!/usr/bin/env python3
"""Dependency-free semantic conformance for wellmanifest.ticket-lifecycle/v1."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

try:
    from . import lifecycle, split_plan
    from .ticket_io import _out, read_strict_json, scan_no_sensitive
    from .ticket_io import canonical_bytes as _io_canonical
except ImportError:
    if str(Path(__file__).resolve().parent) not in sys.path:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
    import lifecycle  # type: ignore[no-redef]
    import split_plan  # type: ignore[no-redef]
    from ticket_io import (  # type: ignore[no-redef]
        _out,
        read_strict_json,
        scan_no_sensitive,
    )
    from ticket_io import canonical_bytes as _io_canonical  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "ticket-lifecycle.schema.json"
GRAMMAR_PATH = ROOT / "ticket-lifecycle.v1.gbnf"
LIFECYCLE_PATH = ROOT / "ticket-lifecycle.lifecycle"
LIFECYCLE_VALIDATOR_PATH = ROOT / "lifecycle.py"
SCHEMA_DIGEST = "0bcfe15aa82105e716e47e298a73ce9c67c9fb4b3629a8a0f0518d8c48b05dda"
GRAMMAR_DIGEST = "154b052441ef0695164ba0c513b4fe4dcadbd07184292add47f89fc7443864f5"
LIFECYCLE_SOURCE_REVISION = "1ea2a90bd5b90a768ad2b36a9c1c330523bc80b4"
LIFECYCLE_VALIDATOR_DIGEST = (
    "7f7f1c45b7611e186cc640ada69cf2849d16841564c4028b9fc06dd0a05c2b3a"
)
LIFECYCLE_PROFILE_DIGEST = (
    "cdff1cdea09fea94a23dbe26bcf7720fd472e14f0e720db7fff4547b920f8534"
)

TRANSITIONS = {
    "allocate": ("unallocated", "allocated"),
    "plan": ("allocated", "planned"),
    "authorize": ("planned", "authorized"),
    "edit": ("authorized", "editing"),
    "validate": ("editing", "validating"),
    "publish": ("validating", "publication"),
    "close": ("publication", "done"),
    "resume": ("blocked", "planned"),
}
BLOCK_SOURCES = {
    "allocated",
    "planned",
    "authorized",
    "editing",
    "validating",
    "publication",
}
CHECKPOINT_STATES = {"authorized", "editing", "validating", "publication", "blocked"}
REQUEST_KEYS = {
    "schema",
    "kind",
    "requestId",
    "repositoryRef",
    "workstreamRef",
    "action",
    "ticket",
    "expectedState",
    "targetState",
    "intentRef",
    "authorizationRef",
    "evidenceRefs",
    "idempotencyKey",
}
RECEIPT_ALLOW_KEYS = frozenset({"secretsRedacted"})
REFS = {
    "requestId": re.compile(r"\Arequest:[a-z][a-z0-9._-]{0,95}\Z"),
    "repositoryRef": re.compile(r"\Arepository:[a-z][a-z0-9._-]{0,95}\Z"),
    "workstreamRef": re.compile(r"\Aworkstream:[a-z][a-z0-9-]{0,63}\Z"),
    "ticket": re.compile(r"\Aticket-[0-9]{3,}\Z"),
    "intentRef": re.compile(r"\Aartifact:[a-z][a-z0-9._:-]{0,159}\Z"),
    "authorizationRef": re.compile(r"\Aauthorization:[a-z][a-z0-9._-]{0,127}\Z"),
    "idempotencyKey": re.compile(r"\Aidempotency:[a-z][a-z0-9._-]{0,127}\Z"),
}
EVIDENCE_REF = re.compile(
    r"\A(artifact|receipt|decision|knowledge):[a-z][a-z0-9._:-]{0,159}\Z"
)
CONTINUITY_REF = re.compile(r"\Areceipt:continuity[.][a-z0-9._:-]{1,148}\Z")
SHA40 = re.compile(r"\A[0-9a-f]{40}\Z")


class ContractError(ValueError):
    pass


def canonical(value: object) -> bytes:
    return _io_canonical(value, error_cls=ContractError)


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def lifecycle_name(value: str) -> str:
    return value.upper().replace("-", "_")


def _match_str(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ContractError(f"invalid reference: {label}")
    return value


def _validate_evidence_list(value: object, *, nonempty: bool, label: str) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value):
        raise ContractError(f"{label} must be nonempty and unique")
    items = [_match_str(item, EVIDENCE_REF, label) for item in value]
    if len(items) != len(set(items)):
        raise ContractError(f"{label} must be nonempty and unique")
    return items


def validate_lifecycle_profile(schema: dict[str, Any]) -> None:
    if digest(LIFECYCLE_VALIDATOR_PATH.read_bytes()) != LIFECYCLE_VALIDATOR_DIGEST:
        raise ContractError("pinned lifecycle validator digest mismatch")
    if digest(LIFECYCLE_PATH.read_bytes()) != LIFECYCLE_PROFILE_DIGEST:
        raise ContractError("pinned lifecycle profile digest mismatch")
    report = lifecycle.validate_path(LIFECYCLE_PATH, lifecycle.embedded_catalog())
    if not report.valid or len(report.lifecycles) != 1:
        raise ContractError("Lifecycle DSL profile is invalid")
    if lifecycle.audit_path(LIFECYCLE_PATH)["finding_count"] != 0:
        raise ContractError("Lifecycle DSL profile has compaction findings")
    model = report.lifecycles[0]
    state_values = schema["$defs"]["state"]["enum"]
    expected_states = {lifecycle_name(str(value)) for value in state_values}
    expected_transitions = (
        {
            (lifecycle_name(source), lifecycle_name(target), lifecycle_name(action))
            for action, (source, target) in TRANSITIONS.items()
        }
        | {(lifecycle_name(source), "BLOCKED", "BLOCK") for source in BLOCK_SOURCES}
        | {
            (lifecycle_name(state), lifecycle_name(state), "CHECKPOINT")
            for state in CHECKPOINT_STATES
        }
    )
    actual_transitions = {
        (item.source, item.target, item.event) for item in model.transitions
    }
    if model.name != "governed-ticket" or set(model.states) != expected_states:
        raise ContractError("Lifecycle DSL state graph mismatch")
    if actual_transitions != expected_transitions:
        raise ContractError("Lifecycle DSL transition graph mismatch")
    if model.summary()["initial_state"] != "UNALLOCATED":
        raise ContractError("Lifecycle DSL initial state mismatch")
    if model.summary()["terminal_states"] != ["DONE"]:
        raise ContractError("Lifecycle DSL terminal state mismatch")


def reject_sensitive(
    value: object, *, allow_keys: frozenset[str] = frozenset()
) -> None:
    scan_no_sensitive(value, ContractError, allow_keys=allow_keys)


def validate_request(doc: dict[str, object]) -> None:
    if not isinstance(doc, dict) or set(doc) != REQUEST_KEYS:
        raise ContractError("request fields are not closed")
    if (
        doc["schema"] != "wellmanifest.ticket-lifecycle/v1"
        or doc["kind"] != "transition-request"
    ):
        raise ContractError("wrong document family")
    reject_sensitive(doc)
    for key in ("requestId", "repositoryRef", "workstreamRef", "idempotencyKey"):
        _match_str(doc[key], REFS[key], key)
    evidence = _validate_evidence_list(
        doc["evidenceRefs"], nonempty=True, label="evidenceRefs"
    )
    action = doc["action"]
    if not isinstance(action, str):
        raise ContractError("invalid action")
    if action == "allocate":
        if any(
            doc[key] is not None for key in ("ticket", "intentRef", "authorizationRef")
        ):
            raise ContractError("allocator owns the new ticket id")
    else:
        for key in ("ticket", "intentRef"):
            _match_str(doc[key], REFS[key], key)
        if action != "plan":
            _match_str(
                doc["authorizationRef"], REFS["authorizationRef"], "authorizationRef"
            )
    if action in {"allocate", "plan"} and doc["authorizationRef"] is not None:
        raise ContractError("authorization is not accepted in this state")
    if action == "block":
        if doc["expectedState"] not in BLOCK_SOURCES or doc["targetState"] != "blocked":
            raise ContractError("invalid block transition")
    elif action == "checkpoint":
        if (
            doc["expectedState"] not in CHECKPOINT_STATES
            or doc["targetState"] != doc["expectedState"]
        ):
            raise ContractError("checkpoint must preserve an active state")
        if sum(1 for item in evidence if CONTINUITY_REF.fullmatch(item)) != 1:
            raise ContractError("checkpoint requires exactly one continuity receipt")
    elif TRANSITIONS.get(action) != (doc["expectedState"], doc["targetState"]):
        raise ContractError("invalid transition")


def validate_editing_state(doc: dict[str, object]) -> None:
    if not isinstance(doc, dict):
        raise ContractError("editing state must be an object")
    reject_sensitive(doc)
    base_sha = doc.get("acceptedBaseSha")
    if (
        doc.get("state") != "editing"
        or not isinstance(base_sha, str)
        or SHA40.fullmatch(base_sha) is None
    ):
        raise ContractError("editing requires a real accepted base")
    if (
        doc.get("sessionExecutionAuthorized") is not True
        or doc.get("trustedMergeApproved") is not False
    ):
        raise ContractError("editing authority is invalid")


def validate_block_receipt(doc: dict[str, object]) -> None:
    if not isinstance(doc, dict):
        raise ContractError("block receipt must be an object")
    reject_sensitive(doc, allow_keys=RECEIPT_ALLOW_KEYS)
    if (
        doc.get("action") != "block"
        or doc.get("outcome") != "applied"
        or doc.get("afterState") != "blocked"
    ):
        raise ContractError("not an applied block receipt")
    if (
        doc.get("workstreamReleased") is not True
        or doc.get("secretsRedacted") is not True
    ):
        raise ContractError("blocked ticket must release scope and redact secrets")


def validate_close_receipt(doc: dict[str, object]) -> None:
    if not isinstance(doc, dict):
        raise ContractError("close receipt must be an object")
    reject_sensitive(doc, allow_keys=RECEIPT_ALLOW_KEYS)
    if doc.get("action") != "close" or doc.get("outcome") != "applied":
        raise ContractError("not an applied close receipt")
    if doc.get("beforeState") != "publication" or doc.get("afterState") != "done":
        raise ContractError("close receipt must bind publication to done")
    if (
        doc.get("workstreamReleased") is not True
        or doc.get("secretsRedacted") is not True
    ):
        raise ContractError("close receipt must release scope and redact secrets")
    _validate_evidence_list(
        doc.get("evidenceRefs"), nonempty=True, label="evidenceRefs"
    )


def validate_checkpoint_receipt(doc: dict[str, object]) -> None:
    if not isinstance(doc, dict):
        raise ContractError("checkpoint receipt must be an object")
    reject_sensitive(doc, allow_keys=RECEIPT_ALLOW_KEYS)
    if doc.get("action") != "checkpoint" or doc.get("outcome") != "applied":
        raise ContractError("not an applied checkpoint receipt")
    before = doc.get("beforeState")
    if before not in CHECKPOINT_STATES or doc.get("afterState") != before:
        raise ContractError("checkpoint receipt must preserve state")
    if (
        doc.get("workstreamReleased") is not False
        or doc.get("secretsRedacted") is not True
    ):
        raise ContractError("checkpoint cannot release scope and must redact secrets")
    evidence = _validate_evidence_list(
        doc.get("evidenceRefs"), nonempty=True, label="evidenceRefs"
    )
    if sum(1 for item in evidence if CONTINUITY_REF.fullmatch(item)) != 1:
        raise ContractError(
            "checkpoint receipt requires exactly one continuity receipt"
        )


def expect_rejected(
    name: str,
    validator: Callable[[dict[str, object]], None],
    base: dict[str, object],
    mutation: Callable[[dict[str, object]], None],
) -> str:
    doc = copy.deepcopy(base)
    mutation(doc)
    try:
        validator(doc)
    except ContractError:
        return name
    raise AssertionError(f"adversarial case accepted: {name}")


def run_all() -> dict[str, object]:
    schema = read_strict_json(SCHEMA_PATH, error_cls=ContractError)
    grammar = GRAMMAR_PATH.read_bytes()
    validate_lifecycle_profile(schema)
    if digest(canonical(schema)) != SCHEMA_DIGEST or digest(grammar) != GRAMMAR_DIGEST:
        raise ContractError("contract digest mismatch")
    lowered = grammar.lower()
    for forbidden in (
        b"shell",
        b"argv",
        b"password",
        b"credential",
        b"token",
        b"callbackurl",
        b"http://",
    ):
        if forbidden in lowered:
            raise ContractError(f"unsafe grammar surface: {forbidden.decode()}")
    request: dict[str, object] = {
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
    state: dict[str, object] = {
        "state": "editing",
        "acceptedBaseSha": "a" * 40,
        "sessionExecutionAuthorized": True,
        "trustedMergeApproved": False,
    }
    receipt: dict[str, object] = {
        "action": "block",
        "outcome": "applied",
        "afterState": "blocked",
        "workstreamReleased": True,
        "secretsRedacted": True,
    }
    close_receipt: dict[str, object] = {
        "action": "close",
        "outcome": "applied",
        "beforeState": "publication",
        "afterState": "done",
        "workstreamReleased": True,
        "secretsRedacted": True,
        "evidenceRefs": ["receipt:trusted-integration"],
    }
    cont_ref = "receipt:continuity.ticket-006.1.example"
    checkpoint_request: dict[str, object] = {
        **request,
        "requestId": "request:checkpoint",
        "action": "checkpoint",
        "ticket": "ticket-006",
        "expectedState": "editing",
        "targetState": "editing",
        "intentRef": "artifact:intent",
        "authorizationRef": "authorization:session",
        "evidenceRefs": [cont_ref],
        "idempotencyKey": "idempotency:checkpoint",
    }
    checkpoint_receipt: dict[str, object] = {
        "action": "checkpoint",
        "outcome": "applied",
        "beforeState": "editing",
        "afterState": "editing",
        "workstreamReleased": False,
        "secretsRedacted": True,
        "evidenceRefs": [cont_ref],
    }
    validate_request(request)
    validate_editing_state(state)
    validate_block_receipt(receipt)
    validate_close_receipt(close_receipt)
    validate_request(checkpoint_request)
    validate_checkpoint_receipt(checkpoint_receipt)
    cases: tuple[
        tuple[
            str,
            Callable[[dict[str, object]], None],
            dict[str, object],
            dict[str, object],
        ],
        ...,
    ] = (
        ("shell-command", validate_request, request, {"command": "rm -rf"}),
        (
            "external-url",
            validate_request,
            request,
            {"callbackUrl": "https://attacker.invalid"},
        ),
        ("preselected-ticket", validate_request, request, {"ticket": "ticket-999"}),
        ("wrong-transition", validate_request, request, {"targetState": "done"}),
        ("inline-password", validate_request, request, {"password": "secret"}),
        (
            "editing-without-base",
            validate_editing_state,
            state,
            {"acceptedBaseSha": None},
        ),
        (
            "editing-without-session-auth",
            validate_editing_state,
            state,
            {"sessionExecutionAuthorized": False},
        ),
        (
            "block-keeps-reservation",
            validate_block_receipt,
            receipt,
            {"workstreamReleased": False},
        ),
        (
            "close-keeps-reservation",
            validate_close_receipt,
            close_receipt,
            {"workstreamReleased": False},
        ),
        (
            "close-without-evidence",
            validate_close_receipt,
            close_receipt,
            {"evidenceRefs": []},
        ),
        (
            "checkpoint-state-movement",
            validate_request,
            checkpoint_request,
            {"targetState": "validating"},
        ),
        (
            "checkpoint-wrong-evidence",
            validate_request,
            checkpoint_request,
            {"evidenceRefs": ["receipt:other"]},
        ),
        (
            "checkpoint-duplicate-evidence",
            validate_request,
            checkpoint_request,
            {"evidenceRefs": [cont_ref, cont_ref]},
        ),
        (
            "checkpoint-releases-scope",
            validate_checkpoint_receipt,
            checkpoint_receipt,
            {"workstreamReleased": True},
        ),
    )
    rejected = [
        expect_rejected(name, fn, base_doc, lambda d, patch=patch: d.update(patch))
        for name, fn, base_doc, patch in cases
    ]
    return {
        "schema": "wellmanifest.ticket-lifecycle-conformance/v1",
        "ok": True,
        "positiveDocuments": 6,
        "adversarialRejected": rejected,
        "schemaDigest": "sha256:" + SCHEMA_DIGEST,
        "grammarDigest": "sha256:" + GRAMMAR_DIGEST,
        "splitPlanConformance": split_plan.self_test(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true")
    parser.parse_args(argv)
    _out(json.dumps(run_all(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
