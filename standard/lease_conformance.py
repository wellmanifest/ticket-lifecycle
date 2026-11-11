#!/usr/bin/env python3
"""Dependency-free conformance for expiring ticket execution leases."""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

try:
    from .ticket_io import _out, parse_rfc3339_utc, read_strict_json, scan_no_sensitive
except ImportError:
    if str(Path(__file__).resolve().parent) not in sys.path:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
    from ticket_io import (  # type: ignore[no-redef]
        _out,
        parse_rfc3339_utc,
        read_strict_json,
        scan_no_sensitive,
    )

ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "ticket-execution-lease.schema.json"
GRAMMAR_PATH = ROOT / "ticket-execution-lease.v1.gbnf"
LEASE_SCHEMA = "wellmanifest.ticket-execution-lease/v1"
REQUEST_SCHEMA = "wellmanifest.ticket-execution-lease-transition/v1"
RECEIPT_SCHEMA = "wellmanifest.ticket-execution-lease-receipt/v1"
SHA = re.compile(r"\A[0-9a-f]{64}\Z")
GIT_SHA = re.compile(r"\A[0-9a-f]{40}\Z")
ACTOR = re.compile(r"\Aactor:[a-z][a-z0-9._-]{0,127}\Z")
SESSION = re.compile(r"\Asession:[a-z][a-z0-9._-]{0,127}\Z")
LEASE = re.compile(r"\Alease:[a-z][a-z0-9._-]{0,127}\Z")
TICKET = re.compile(r"\Aticket-[0-9]{3,}\Z")
REPOSITORY = re.compile(r"\Arepository:[a-z][a-z0-9._-]{0,127}\Z")
WORKSTREAM = re.compile(r"\Aworkstream:[a-z][a-z0-9-]{0,63}\Z")
BRANCH = re.compile(r"\Abranch:(?!.*(?:^|/)\.{1,2}(?:/|\Z))[a-z][a-z0-9._/-]{0,127}\Z")
WORKTREE = re.compile(r"\Aworktree:[a-z][a-z0-9._-]{0,127}\Z")
REQUEST_ID = re.compile(r"\Arequest:[a-z][a-z0-9._-]{0,127}\Z")
IDEMPOTENCY = re.compile(r"\Aidempotency:[a-z][a-z0-9._-]{0,127}\Z")
AUTHORITY = re.compile(r"\Aauthority:[a-z][a-z0-9._-]{0,127}\Z")
LEASE_RECEIPT = re.compile(r"\Areceipt:lease\.[a-z][a-z0-9._:-]{0,159}\Z")
EVIDENCE = re.compile(
    r"\A(artifact|receipt|decision|knowledge):[a-z][a-z0-9._:-]{0,159}\Z"
)
LEASE_FIELDS = {
    "schema",
    "kind",
    "leaseId",
    "repositoryRef",
    "ticket",
    "workstreamRef",
    "branchRef",
    "worktreeId",
    "ownerActor",
    "ownerSession",
    "scopeHash",
    "headSha",
    "state",
    "generation",
    "fencing",
    "issuedAt",
    "leaseExpiresAt",
    "takeoverAt",
    "lastRenewedAt",
    "ttlSeconds",
    "graceSeconds",
    "eventSequence",
}
REQUEST_FIELDS = {
    "schema",
    "kind",
    "requestId",
    "leaseId",
    "action",
    "expectedGeneration",
    "expectedFencing",
    "requestedBy",
    "newOwnerActor",
    "newOwnerSession",
    "newWorktreeId",
    "requestedAt",
    "authorityRef",
    "evidenceRefs",
    "idempotencyKey",
}
RECEIPT_FIELDS = {
    "schema",
    "kind",
    "requestId",
    "leaseId",
    "action",
    "outcome",
    "code",
    "stateBefore",
    "stateAfter",
    "previousGeneration",
    "generation",
    "previousFencing",
    "fencing",
    "ownerActor",
    "ownerSession",
    "leaseExpiresAt",
    "takeoverAt",
    "receiptRef",
    "occurredAt",
}


class ContractError(ValueError):
    pass


def dt(value: object) -> datetime:
    return parse_rfc3339_utc(value, ContractError)


def closed(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ContractError(f"{label} fields are not closed")
    return value


def _match_str(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ContractError(f"invalid {label}")
    return value


def no_sensitive(value: object) -> None:
    scan_no_sensitive(value, ContractError)


def positive(value: object, label: str) -> None:
    if type(value) is not int or value < 1:
        raise ContractError(f"{label} must be a positive integer")


def validate_lease(value: dict[str, Any]) -> None:
    doc = closed(value, LEASE_FIELDS, "lease")
    if doc["schema"] != LEASE_SCHEMA or doc["kind"] != "execution-lease":
        raise ContractError("wrong lease family")
    no_sensitive(doc)
    for key, pat, lbl in (
        ("leaseId", LEASE, "lease identity"),
        ("repositoryRef", REPOSITORY, "lease identity"),
        ("ticket", TICKET, "ticket identity"),
        ("workstreamRef", WORKSTREAM, "ticket identity"),
        ("branchRef", BRANCH, "checkout identity"),
        ("worktreeId", WORKTREE, "checkout identity"),
        ("ownerActor", ACTOR, "owner identity"),
        ("ownerSession", SESSION, "owner identity"),
        ("scopeHash", SHA, "content binding"),
        ("headSha", GIT_SHA, "content binding"),
    ):
        _match_str(doc[key], pat, lbl)
    if doc["state"] not in {"active", "expired", "released"}:
        raise ContractError("invalid lease state")
    for key in ("generation", "fencing", "eventSequence"):
        positive(doc[key], key)
    if (doc["ttlSeconds"], doc["graceSeconds"]) != (3600, 600) or any(
        type(doc[k]) is not int for k in ("ttlSeconds", "graceSeconds")
    ):
        raise ContractError("lease timing must be 3600 seconds plus 600 seconds grace")
    issued, expires, takeover, renewed = (
        dt(doc[key])
        for key in ("issuedAt", "leaseExpiresAt", "takeoverAt", "lastRenewedAt")
    )
    if (
        issued > renewed
        or expires != renewed + timedelta(seconds=3600)
        or takeover != expires + timedelta(seconds=600)
    ):
        raise ContractError("lease timestamps do not match the timing contract")


def validate_request(value: dict[str, Any]) -> None:
    doc = closed(value, REQUEST_FIELDS, "request")
    if doc["schema"] != REQUEST_SCHEMA or doc["kind"] != "lease-transition-request":
        raise ContractError("wrong request family")
    no_sensitive(doc)
    for key, pattern in (
        ("requestId", REQUEST_ID),
        ("leaseId", LEASE),
        ("requestedBy", ACTOR),
        ("idempotencyKey", IDEMPOTENCY),
        ("authorityRef", AUTHORITY),
    ):
        _match_str(doc[key], pattern, key)
    if doc["action"] not in {"renew", "takeover", "release", "expire"}:
        raise ContractError("invalid action")
    positive(doc["expectedGeneration"], "expectedGeneration")
    positive(doc["expectedFencing"], "expectedFencing")
    dt(doc["requestedAt"])
    ev = doc["evidenceRefs"]
    if not isinstance(ev, list) or not ev:
        raise ContractError("evidence references are invalid")
    ev_items = [_match_str(item, EVIDENCE, "evidenceRefs") for item in ev]
    if len(ev_items) != len(set(ev_items)):
        raise ContractError("evidence references are invalid")
    supplied = (doc["newOwnerActor"], doc["newOwnerSession"], doc["newWorktreeId"])
    if doc["action"] == "takeover":
        _match_str(doc["newOwnerActor"], ACTOR, "takeover newOwnerActor")
        _match_str(doc["newOwnerSession"], SESSION, "takeover newOwnerSession")
        _match_str(doc["newWorktreeId"], WORKTREE, "takeover newWorktreeId")
    elif any(item is not None for item in supplied):
        raise ContractError("only takeover may name a new owner")


ACTIONS = {"renew", "takeover", "release", "expire"}
STATES = {"active", "expired", "released"}
OUTCOMES = {"accepted", "rejected", "idempotent"}


def validate_receipt(value: dict[str, Any]) -> None:
    doc = closed(value, RECEIPT_FIELDS, "receipt")
    if doc["schema"] != RECEIPT_SCHEMA or doc["kind"] != "lease-transition-receipt":
        raise ContractError("wrong receipt family")
    no_sensitive(doc)
    _match_str(doc["requestId"], REQUEST_ID, "receipt identity")
    _match_str(doc["leaseId"], LEASE, "receipt identity")
    if doc["action"] not in ACTIONS or doc["outcome"] not in OUTCOMES:
        raise ContractError("invalid receipt action or outcome")
    if doc["stateBefore"] not in STATES or doc["stateAfter"] not in STATES:
        raise ContractError("invalid receipt state")
    for key in ("previousGeneration", "generation", "previousFencing", "fencing"):
        positive(doc[key], key)
    if doc["outcome"] == "accepted" and (
        doc["generation"] != doc["previousGeneration"] + 1
        or doc["fencing"] != doc["previousFencing"] + 1
    ):
        raise ContractError("accepted receipt must advance both fences exactly once")
    _match_str(doc["ownerActor"], ACTOR, "receipt owner")
    _match_str(doc["ownerSession"], SESSION, "receipt owner")
    _match_str(doc["receiptRef"], LEASE_RECEIPT, "receipt reference")
    if dt(doc["takeoverAt"]) != dt(doc["leaseExpiresAt"]) + timedelta(seconds=600):
        raise ContractError("receipt takeover time is not bounded by grace")
    dt(doc["occurredAt"])


def evaluate(
    lease: dict[str, Any], request: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    validate_lease(lease)
    validate_request(request)
    before, act, req_by = lease["state"], request["action"], request["requestedBy"]
    now, take_at = dt(request["requestedAt"]), dt(lease["takeoverAt"])
    code = None
    if (
        request["leaseId"] != lease["leaseId"]
        or request["expectedGeneration"] != lease["generation"]
        or request["expectedFencing"] != lease["fencing"]
    ):
        code = "LEASE_STALE_FENCE"
    elif act in {"renew", "release"} and req_by != lease["ownerActor"]:
        code = "LEASE_NOT_OWNER"
    elif act == "renew" and now >= take_at:
        code = "LEASE_TAKEOVER_ELIGIBLE"
    elif act == "release" and before != "active":
        code = "LEASE_NOT_ACTIVE"
    elif act == "takeover" and req_by == lease["ownerActor"]:
        code = "LEASE_SAME_OWNER_TAKEOVER"
    elif act == "takeover" and (before != "active" or now < take_at):
        code = "LEASE_TAKEOVER_TOO_EARLY"
    elif act == "expire" and (before != "active" or now < take_at):
        code = "LEASE_EXPIRE_TOO_EARLY"
    next_lease = None
    if code is None:
        next_lease = copy.deepcopy(lease)
        for key in ("generation", "fencing", "eventSequence"):
            next_lease[key] += 1
        exp_iso = (now + timedelta(seconds=3600)).isoformat().replace("+00:00", "Z")
        tak_iso = (now + timedelta(seconds=4200)).isoformat().replace("+00:00", "Z")
        if act == "renew":
            next_lease.update(
                lastRenewedAt=request["requestedAt"],
                leaseExpiresAt=exp_iso,
                takeoverAt=tak_iso,
            )
        elif act == "takeover":
            next_lease.update(
                ownerActor=request["newOwnerActor"],
                ownerSession=request["newOwnerSession"],
                worktreeId=request["newWorktreeId"],
                issuedAt=request["requestedAt"],
                lastRenewedAt=request["requestedAt"],
                leaseExpiresAt=exp_iso,
                takeoverAt=tak_iso,
            )
        else:
            next_lease["state"] = "released" if act == "release" else "expired"
    target = next_lease or lease
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "kind": "lease-transition-receipt",
        "requestId": request["requestId"],
        "leaseId": lease["leaseId"],
        "action": act,
        "outcome": "accepted" if code is None else "rejected",
        "code": code,
        "stateBefore": before,
        "stateAfter": target["state"],
        "previousGeneration": lease["generation"],
        "generation": target["generation"],
        "previousFencing": lease["fencing"],
        "fencing": target["fencing"],
        "ownerActor": target["ownerActor"],
        "ownerSession": target["ownerSession"],
        "leaseExpiresAt": target["leaseExpiresAt"],
        "takeoverAt": target["takeoverAt"],
        "receiptRef": "receipt:lease." + request["requestId"].removeprefix("request:"),
        "occurredAt": request["requestedAt"],
    }
    return receipt, next_lease


def rejected(
    name: str,
    function: Callable[[dict[str, Any]], None],
    base: dict[str, Any],
    mutation: Callable[[dict[str, Any]], None],
) -> str:
    value = copy.deepcopy(base)
    mutation(value)
    try:
        function(value)
    except ContractError:
        return name
    raise AssertionError(f"adversarial case accepted: {name}")


def rejected_evaluation(
    name: str,
    lease: dict[str, Any],
    request: dict[str, Any],
    mutation: Callable[[dict[str, Any]], None],
    code: str,
) -> str:
    value = copy.deepcopy(request)
    mutation(value)
    receipt, next_lease = evaluate(lease, value)
    if next_lease is None and receipt["code"] == code:
        return name
    raise AssertionError(f"adversarial case accepted: {name}")


def run_all() -> dict[str, Any]:
    schema = read_strict_json(SCHEMA_PATH, error_cls=ContractError)
    if (
        schema["$id"] != "https://wellmanifest.dev/schemas/ticket-execution-lease/v1"
        or b"shell" in GRAMMAR_PATH.read_bytes().lower()
    ):
        raise ContractError("lease contract metadata or grammar is unsafe")
    base = {
        "schema": LEASE_SCHEMA,
        "kind": "execution-lease",
        "leaseId": "lease:ticket-011",
        "repositoryRef": "repository:demo",
        "ticket": "ticket-011",
        "workstreamRef": "workstream:integration",
        "branchRef": "branch:ticket-011-execution-lease-takeover",
        "worktreeId": "worktree:ticket-011",
        "ownerActor": "actor:agent-a",
        "ownerSession": "session:alpha",
        "scopeHash": "a" * 64,
        "headSha": "b" * 40,
        "state": "active",
        "generation": 1,
        "fencing": 1,
        "issuedAt": "2026-09-14T10:00:00Z",
        "leaseExpiresAt": "2026-09-14T11:00:00Z",
        "takeoverAt": "2026-09-14T11:10:00Z",
        "lastRenewedAt": "2026-09-14T10:00:00Z",
        "ttlSeconds": 3600,
        "graceSeconds": 600,
        "eventSequence": 1,
    }
    renew: dict[str, Any] = {
        "schema": REQUEST_SCHEMA,
        "kind": "lease-transition-request",
        "requestId": "request:renew",
        "leaseId": base["leaseId"],
        "action": "renew",
        "expectedGeneration": 1,
        "expectedFencing": 1,
        "requestedBy": "actor:agent-a",
        "newOwnerActor": None,
        "newOwnerSession": None,
        "newWorktreeId": None,
        "requestedAt": "2026-09-14T11:05:00Z",
        "authorityRef": "authority:controller",
        "evidenceRefs": ["receipt:lease.start"],
        "idempotencyKey": "idempotency:renew",
    }
    takeover: dict[str, Any] = {
        **renew,
        "requestId": "request:takeover",
        "action": "takeover",
        "requestedBy": "actor:agent-b",
        "newOwnerActor": "actor:agent-b",
        "newOwnerSession": "session:beta",
        "newWorktreeId": "worktree:ticket-011-reclaimed",
        "requestedAt": "2026-09-14T11:10:00Z",
        "idempotencyKey": "idempotency:takeover",
    }
    validate_lease(base)
    validate_request(renew)
    validate_request(takeover)
    renewed_receipt, renewed = evaluate(base, renew)
    assert renewed is not None and renewed["leaseExpiresAt"] == "2026-09-14T12:05:00Z"
    validate_receipt(renewed_receipt)

    def _mut(**patch: Any) -> Callable[[dict[str, Any]], None]:
        return lambda d: d.update(patch)

    rejected_cases = [
        rejected(
            "invalid-expiry",
            validate_lease,
            base,
            _mut(leaseExpiresAt="2026-09-14T11:01:00Z"),
        ),
        rejected_evaluation(
            "wrong-owner-renewal",
            base,
            renew,
            _mut(requestedBy="actor:agent-b"),
            "LEASE_NOT_OWNER",
        ),
        rejected_evaluation(
            "early-takeover",
            base,
            takeover,
            _mut(requestedAt="2026-09-14T11:09:59Z"),
            "LEASE_TAKEOVER_TOO_EARLY",
        ),
        rejected_evaluation(
            "stale-generation",
            base,
            renew,
            _mut(expectedGeneration=2),
            "LEASE_STALE_FENCE",
        ),
        rejected(
            "partial-new-owner", validate_request, takeover, _mut(newOwnerSession=None)
        ),
        rejected("unsafe-field", validate_request, renew, _mut(secret="x")),
    ]
    taken_receipt, taken = evaluate(base, takeover)
    assert (
        taken is not None
        and taken["ownerActor"] == "actor:agent-b"
        and taken["fencing"] == 2
    )
    validate_receipt(taken_receipt)
    old_agent = {
        **renew,
        "expectedGeneration": 1,
        "expectedFencing": 1,
        "requestedAt": "2026-09-14T11:11:00Z",
    }
    stale_receipt, stale = evaluate(taken, old_agent)
    assert stale is None and stale_receipt["code"] == "LEASE_STALE_FENCE"
    return {
        "schema": "wellmanifest.ticket-execution-lease-conformance/v1",
        "ok": True,
        "timing": {"ttlSeconds": 3600, "graceSeconds": 600},
        "positiveDocuments": 4,
        "adversarialRejected": rejected_cases + ["stale-fence-after-takeover"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true")
    parser.parse_args(argv)
    _out(json.dumps(run_all(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
