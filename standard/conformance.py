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
SCHEMA_DIGEST = "09f05e885634a65dd0e35c0ec74c23d9173b486e5dbb1b0abd690ccd0d7d6ba1"
GRAMMAR_DIGEST = "3578a5b963d6b8c8e4e68df50bd9bfd0bb709584053227036826619bb429e8ee"
LIFECYCLE_SOURCE_REVISION = "4b5e131a670afb46ca87291479fed7c0fefcf370"
LIFECYCLE_VALIDATOR_DIGEST = "9c3f3076b5b45408d3eefc34cd567b58821aa565d3fe3bf6339641111079ede0"
LIFECYCLE_PROFILE_DIGEST = "e107a2625d6819984749c9f0d03088cb3e903bec26245dec8ace85ddf76cc4fd"

TRANSITIONS = {
    "allocate": ("unallocated", "allocated"), "plan": ("allocated", "planned"),
    "authorize": ("planned", "authorized"), "edit": ("authorized", "editing"),
    "validate": ("editing", "validating"), "publish": ("validating", "publication"),
    "close": ("publication", "done"), "resume": ("blocked", "planned"),
}
BLOCK_SOURCES = {"allocated", "planned", "authorized", "editing", "validating", "publication"}
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
    validate_request(request); validate_editing_state(state); validate_block_receipt(receipt)
    rejected = [
        expect_rejected("shell-command", validate_request, request, lambda d: d.update(command="rm -rf")),
        expect_rejected("external-url", validate_request, request, lambda d: d.update(callbackUrl="https://attacker.invalid")),
        expect_rejected("preselected-ticket", validate_request, request, lambda d: d.update(ticket="ticket-999")),
        expect_rejected("wrong-transition", validate_request, request, lambda d: d.update(targetState="done")),
        expect_rejected("inline-password", validate_request, request, lambda d: d.update(password="secret")),
        expect_rejected("editing-without-base", validate_editing_state, state, lambda d: d.update(acceptedBaseSha=None)),
        expect_rejected("editing-without-session-auth", validate_editing_state, state, lambda d: d.update(sessionExecutionAuthorized=False)),
        expect_rejected("block-keeps-reservation", validate_block_receipt, receipt, lambda d: d.update(workstreamReleased=False)),
    ]
    return {"schema": "wellmanifest.ticket-lifecycle-conformance/v1", "ok": True, "positiveDocuments": 3, "adversarialRejected": rejected, "schemaDigest": "sha256:" + SCHEMA_DIGEST, "grammarDigest": "sha256:" + GRAMMAR_DIGEST}


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--all", action="store_true"); parser.parse_args()
    print(json.dumps(run_all(), indent=2, sort_keys=True)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
