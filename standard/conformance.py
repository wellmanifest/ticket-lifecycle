#!/usr/bin/env python3
"""Dependency-free semantic conformance for wellmanifest.ticket-lifecycle/v1."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from pathlib import Path

import lifecycle

ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "ticket-lifecycle.schema.json"
GRAMMAR_PATH = ROOT / "ticket-lifecycle.v1.gbnf"
LIFECYCLE_PATH = ROOT / "ticket-lifecycle.lifecycle"
LIFECYCLE_VALIDATOR_PATH = ROOT / "lifecycle.py"
SCHEMA_DIGEST = "0bcfe15aa82105e716e47e298a73ce9c67c9fb4b3629a8a0f0518d8c48b05dda"
GRAMMAR_DIGEST = "154b052441ef0695164ba0c513b4fe4dcadbd07184292add47f89fc7443864f5"
LIFECYCLE_SOURCE_REVISION = "4b5e131a670afb46ca87291479fed7c0fefcf370"
LIFECYCLE_VALIDATOR_DIGEST = "9c3f3076b5b45408d3eefc34cd567b58821aa565d3fe3bf6339641111079ede0"
LIFECYCLE_PROFILE_DIGEST = "af4e9eadcf336d1e295549da18ac0c24fca0e90d2946e7baee2e5541a30a32a4"

TRANSITIONS = {
    "allocate": ("unallocated", "allocated"), "plan": ("allocated", "planned"),
    "authorize": ("planned", "authorized"), "edit": ("authorized", "editing"),
    "validate": ("editing", "validating"), "publish": ("validating", "publication"),
    "close": ("publication", "done"), "resume": ("blocked", "planned"),
}
BLOCK_SOURCES = {"allocated", "planned", "authorized", "editing", "validating", "publication"}
CHECKPOINT_STATES = {"authorized", "editing", "validating", "publication", "blocked"}
REQUEST_KEYS = {"schema", "kind", "requestId", "repositoryRef", "workstreamRef", "action", "ticket", "expectedState", "targetState", "intentRef", "authorizationRef", "evidenceRefs", "idempotencyKey"}
REFS = {
    "requestId": r"^request:[a-z][a-z0-9._-]{0,95}$",
    "repositoryRef": r"^repository:[a-z][a-z0-9._-]{0,95}$",
    "workstreamRef": r"^workstream:[a-z][a-z0-9-]{0,63}$",
    "ticket": r"^ticket-[0-9]{3,}$", "intentRef": r"^artifact:[a-z][a-z0-9._:-]{0,159}$",
    "authorizationRef": r"^authorization:[a-z][a-z0-9._-]{0,127}$",
    "idempotencyKey": r"^idempotency:[a-z][a-z0-9._-]{0,127}$",
}
SENSITIVE = re.compile(r"(shell|command|argv|password|credential|token|secret|path|remote|url)", re.I)


class ContractError(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def lifecycle_name(value: str) -> str:
    return value.upper().replace("-", "_")


def validate_lifecycle_profile(schema: dict[str, object]) -> None:
    if digest(LIFECYCLE_VALIDATOR_PATH.read_bytes()) != LIFECYCLE_VALIDATOR_DIGEST:
        raise ContractError("pinned lifecycle validator digest mismatch")
    if digest(LIFECYCLE_PATH.read_bytes()) != LIFECYCLE_PROFILE_DIGEST:
        raise ContractError("pinned lifecycle profile digest mismatch")
    report = lifecycle.validate_path(LIFECYCLE_PATH, lifecycle.embedded_catalog())
    if not report.valid or len(report.lifecycles) != 1:
        raise ContractError("Lifecycle DSL profile is invalid")
    model = report.lifecycles[0]
    state_values = schema["$defs"]["state"]["enum"]  # type: ignore[index]
    expected_states = {lifecycle_name(str(value)) for value in state_values}
    expected_transitions = {
        (lifecycle_name(source), lifecycle_name(target), lifecycle_name(action))
        for action, (source, target) in TRANSITIONS.items()
    } | {
        (lifecycle_name(source), "BLOCKED", "BLOCK")
        for source in BLOCK_SOURCES
    } | {
        (lifecycle_name(state), lifecycle_name(state), "CHECKPOINT")
        for state in CHECKPOINT_STATES
    }
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


def reject_sensitive(value: object) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if SENSITIVE.search(key):
                raise ContractError(f"unsafe key: {key}")
            reject_sensitive(nested)
    elif isinstance(value, list):
        for nested in value:
            reject_sensitive(nested)


def validate_request(doc: dict[str, object]) -> None:
    if set(doc) != REQUEST_KEYS:
        raise ContractError("request fields are not closed")
    if doc["schema"] != "wellmanifest.ticket-lifecycle/v1" or doc["kind"] != "transition-request":
        raise ContractError("wrong document family")
    reject_sensitive(doc)
    for key in ("requestId", "repositoryRef", "workstreamRef", "idempotencyKey"):
        if not re.fullmatch(REFS[key], str(doc[key])):
            raise ContractError(f"invalid reference: {key}")
    evidence = doc["evidenceRefs"]
    if not isinstance(evidence, list) or not evidence or len(evidence) != len(set(evidence)):
        raise ContractError("evidence references must be nonempty and unique")
    action = str(doc["action"])
    if action == "allocate":
        if any(doc[key] is not None for key in ("ticket", "intentRef", "authorizationRef")):
            raise ContractError("allocator owns the new ticket id")
    else:
        for key in ("ticket", "intentRef"):
            if doc[key] is None or not re.fullmatch(REFS[key], str(doc[key])):
                raise ContractError(f"invalid reference: {key}")
        if action not in {"plan"} and (doc["authorizationRef"] is None or not re.fullmatch(REFS["authorizationRef"], str(doc["authorizationRef"]))):
            raise ContractError("authorization reference required")
    if action in {"allocate", "plan"} and doc["authorizationRef"] is not None:
        raise ContractError("authorization is not accepted in this state")
    if action == "block":
        if doc["expectedState"] not in BLOCK_SOURCES or doc["targetState"] != "blocked":
            raise ContractError("invalid block transition")
    elif action == "checkpoint":
        if doc["expectedState"] not in CHECKPOINT_STATES or doc["targetState"] != doc["expectedState"]:
            raise ContractError("checkpoint must preserve an active state")
        continuity = [
            item for item in evidence
            if re.fullmatch(r"receipt:continuity[.][a-z0-9._:-]+", str(item))
        ]
        if len(continuity) != 1:
            raise ContractError("checkpoint requires exactly one continuity receipt")
    elif TRANSITIONS.get(action) != (doc["expectedState"], doc["targetState"]):
        raise ContractError("invalid transition")


def validate_editing_state(doc: dict[str, object]) -> None:
    if doc.get("state") != "editing" or not re.fullmatch(r"[0-9a-f]{40}", str(doc.get("acceptedBaseSha"))):
        raise ContractError("editing requires a real accepted base")
    if doc.get("sessionExecutionAuthorized") is not True or doc.get("trustedMergeApproved") is not False:
        raise ContractError("editing authority is invalid")


def validate_block_receipt(doc: dict[str, object]) -> None:
    if doc.get("action") != "block" or doc.get("outcome") != "applied" or doc.get("afterState") != "blocked":
        raise ContractError("not an applied block receipt")
    if doc.get("workstreamReleased") is not True or doc.get("secretsRedacted") is not True:
        raise ContractError("blocked ticket must release scope and redact secrets")


def validate_close_receipt(doc: dict[str, object]) -> None:
    if doc.get("action") != "close" or doc.get("outcome") != "applied":
        raise ContractError("not an applied close receipt")
    if doc.get("beforeState") != "publication" or doc.get("afterState") != "done":
        raise ContractError("close receipt must bind publication to done")
    if doc.get("workstreamReleased") is not True or doc.get("secretsRedacted") is not True:
        raise ContractError("close receipt must release scope and redact secrets")
    evidence = doc.get("evidenceRefs")
    if not isinstance(evidence, list) or not evidence:
        raise ContractError("close receipt requires trusted integration evidence")


def validate_checkpoint_receipt(doc: dict[str, object]) -> None:
    if doc.get("action") != "checkpoint" or doc.get("outcome") != "applied":
        raise ContractError("not an applied checkpoint receipt")
    before = doc.get("beforeState")
    if before not in CHECKPOINT_STATES or doc.get("afterState") != before:
        raise ContractError("checkpoint receipt must preserve state")
    if doc.get("workstreamReleased") is not False or doc.get("secretsRedacted") is not True:
        raise ContractError("checkpoint cannot release scope and must redact secrets")
    evidence = doc.get("evidenceRefs")
    if not isinstance(evidence, list) or len(evidence) != len(set(evidence)):
        raise ContractError("checkpoint evidence must be unique")
    continuity = [
        item for item in evidence
        if re.fullmatch(r"receipt:continuity[.][a-z0-9._:-]+", str(item))
    ]
    if len(continuity) != 1:
        raise ContractError("checkpoint receipt requires exactly one continuity receipt")


def expect_rejected(name: str, validator, base: dict[str, object], mutation) -> str:
    doc = copy.deepcopy(base); mutation(doc)
    try:
        validator(doc)
    except ContractError:
        return name
    raise AssertionError(f"adversarial case accepted: {name}")


def run_all() -> dict[str, object]:
    schema = json.loads(SCHEMA_PATH.read_text()); grammar = GRAMMAR_PATH.read_bytes()
    validate_lifecycle_profile(schema)
    if digest(canonical(schema)) != SCHEMA_DIGEST or digest(grammar) != GRAMMAR_DIGEST:
        raise ContractError("contract digest mismatch")
    lowered = grammar.lower()
    for forbidden in (b"shell", b"argv", b"password", b"credential", b"token", b"callbackurl", b"http://"):
        if forbidden in lowered:
            raise ContractError(f"unsafe grammar surface: {forbidden.decode()}")
    request = {"schema": "wellmanifest.ticket-lifecycle/v1", "kind": "transition-request", "requestId": "request:allocate", "repositoryRef": "repository:demo", "workstreamRef": "workstream:integration", "action": "allocate", "ticket": None, "expectedState": "unallocated", "targetState": "allocated", "intentRef": None, "authorizationRef": None, "evidenceRefs": ["artifact:request"], "idempotencyKey": "idempotency:allocate"}
    state = {"state": "editing", "acceptedBaseSha": "a" * 40, "sessionExecutionAuthorized": True, "trustedMergeApproved": False}
    receipt = {"action": "block", "outcome": "applied", "afterState": "blocked", "workstreamReleased": True, "secretsRedacted": True}
    close_receipt = {
        "action": "close", "outcome": "applied", "beforeState": "publication",
        "afterState": "done", "workstreamReleased": True, "secretsRedacted": True,
        "evidenceRefs": ["receipt:trusted-integration"],
    }
    checkpoint_request = {
        **request,
        "requestId": "request:checkpoint",
        "action": "checkpoint",
        "ticket": "ticket-006",
        "expectedState": "editing",
        "targetState": "editing",
        "intentRef": "artifact:intent",
        "authorizationRef": "authorization:session",
        "evidenceRefs": ["receipt:continuity.ticket-006.1.example"],
        "idempotencyKey": "idempotency:checkpoint",
    }
    checkpoint_receipt = {
        "action": "checkpoint", "outcome": "applied",
        "beforeState": "editing", "afterState": "editing",
        "workstreamReleased": False, "secretsRedacted": True,
        "evidenceRefs": ["receipt:continuity.ticket-006.1.example"],
    }
    validate_request(request); validate_editing_state(state); validate_block_receipt(receipt); validate_close_receipt(close_receipt)
    validate_request(checkpoint_request); validate_checkpoint_receipt(checkpoint_receipt)
    rejected = [
        expect_rejected("shell-command", validate_request, request, lambda d: d.update(command="rm -rf")),
        expect_rejected("external-url", validate_request, request, lambda d: d.update(callbackUrl="https://attacker.invalid")),
        expect_rejected("preselected-ticket", validate_request, request, lambda d: d.update(ticket="ticket-999")),
        expect_rejected("wrong-transition", validate_request, request, lambda d: d.update(targetState="done")),
        expect_rejected("inline-password", validate_request, request, lambda d: d.update(password="secret")),
        expect_rejected("editing-without-base", validate_editing_state, state, lambda d: d.update(acceptedBaseSha=None)),
        expect_rejected("editing-without-session-auth", validate_editing_state, state, lambda d: d.update(sessionExecutionAuthorized=False)),
        expect_rejected("block-keeps-reservation", validate_block_receipt, receipt, lambda d: d.update(workstreamReleased=False)),
        expect_rejected("close-keeps-reservation", validate_close_receipt, close_receipt, lambda d: d.update(workstreamReleased=False)),
        expect_rejected("close-without-evidence", validate_close_receipt, close_receipt, lambda d: d.update(evidenceRefs=[])),
        expect_rejected("checkpoint-state-movement", validate_request, checkpoint_request, lambda d: d.update(targetState="validating")),
        expect_rejected("checkpoint-wrong-evidence", validate_request, checkpoint_request, lambda d: d.update(evidenceRefs=["receipt:other"])),
        expect_rejected("checkpoint-duplicate-evidence", validate_request, checkpoint_request, lambda d: d.update(evidenceRefs=["receipt:continuity.ticket-006.1.example"] * 2)),
        expect_rejected("checkpoint-releases-scope", validate_checkpoint_receipt, checkpoint_receipt, lambda d: d.update(workstreamReleased=True)),
    ]
    return {"schema": "wellmanifest.ticket-lifecycle-conformance/v1", "ok": True, "positiveDocuments": 6, "adversarialRejected": rejected, "schemaDigest": "sha256:" + SCHEMA_DIGEST, "grammarDigest": "sha256:" + GRAMMAR_DIGEST}


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--all", action="store_true"); parser.parse_args()
    print(json.dumps(run_all(), indent=2, sort_keys=True)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
