#!/usr/bin/env python3
"""Dependency-free conformance for expiring ticket execution leases."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "ticket-execution-lease.schema.json"
GRAMMAR_PATH = ROOT / "ticket-execution-lease.v1.gbnf"
LEASE_SCHEMA = "wellmanifest.ticket-execution-lease/v1"
REQUEST_SCHEMA = "wellmanifest.ticket-execution-lease-transition/v1"
RECEIPT_SCHEMA = "wellmanifest.ticket-execution-lease-receipt/v1"
SHA = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
ACTOR = re.compile(r"^actor:[a-z][a-z0-9._-]{0,127}$")
SESSION = re.compile(r"^session:[a-z][a-z0-9._-]{0,127}$")
LEASE = re.compile(r"^lease:[a-z][a-z0-9._-]{0,127}$")
TICKET = re.compile(r"^ticket-[0-9]{3,}$")
EVIDENCE = re.compile(r"^(artifact|receipt|decision|knowledge):[a-z][a-z0-9._:-]{0,159}$")
SENSITIVE = re.compile(r"(shell|command|argv|password|credential|secret|url|remote|token|path)", re.I)
LEASE_FIELDS = {"schema", "kind", "leaseId", "repositoryRef", "ticket", "workstreamRef", "branchRef", "worktreeId", "ownerActor", "ownerSession", "scopeHash", "headSha", "state", "generation", "fencing", "issuedAt", "leaseExpiresAt", "takeoverAt", "lastRenewedAt", "ttlSeconds", "graceSeconds", "eventSequence"}
REQUEST_FIELDS = {"schema", "kind", "requestId", "leaseId", "action", "expectedGeneration", "expectedFencing", "requestedBy", "newOwnerActor", "newOwnerSession", "newWorktreeId", "requestedAt", "authorityRef", "evidenceRefs", "idempotencyKey"}
RECEIPT_FIELDS = {"schema", "kind", "requestId", "leaseId", "action", "outcome", "code", "stateBefore", "stateAfter", "previousGeneration", "generation", "previousFencing", "fencing", "ownerActor", "ownerSession", "leaseExpiresAt", "takeoverAt", "receiptRef", "occurredAt"}


class ContractError(ValueError):
    pass


def dt(value: object) -> datetime:
    if not isinstance(value, str):
        raise ContractError("timestamp must be a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ContractError("timestamp is not RFC 3339") from error
    if parsed.tzinfo is None:
        raise ContractError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def closed(value: dict, fields: set[str], label: str) -> None:
    if set(value) != fields:
        raise ContractError(f"{label} fields are not closed")


def no_sensitive(value: object) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if SENSITIVE.search(key):
                raise ContractError(f"unsafe field: {key}")
            no_sensitive(nested)
    elif isinstance(value, list):
        for nested in value:
            no_sensitive(nested)


def positive(value: object, label: str) -> None:
    if type(value) is not int or value < 1:
        raise ContractError(f"{label} must be a positive integer")


def validate_lease(value: dict) -> None:
    closed(value, LEASE_FIELDS, "lease")
    if value["schema"] != LEASE_SCHEMA or value["kind"] != "execution-lease":
        raise ContractError("wrong lease family")
    no_sensitive(value)
    if not LEASE.fullmatch(value["leaseId"]) or not re.fullmatch(r"^repository:[a-z][a-z0-9._-]{0,127}$", value["repositoryRef"]):
        raise ContractError("invalid lease identity")
    if not TICKET.fullmatch(value["ticket"]) or not re.fullmatch(r"^workstream:[a-z][a-z0-9-]{0,63}$", value["workstreamRef"]):
        raise ContractError("invalid ticket identity")
    if not re.fullmatch(r"^branch:[a-z][a-z0-9._/-]{0,127}$", value["branchRef"]) or not re.fullmatch(r"^worktree:[a-z][a-z0-9._-]{0,127}$", value["worktreeId"]):
        raise ContractError("invalid checkout identity")
    if not ACTOR.fullmatch(value["ownerActor"]) or not SESSION.fullmatch(value["ownerSession"]):
        raise ContractError("invalid owner identity")
    if not SHA.fullmatch(value["scopeHash"]) or not GIT_SHA.fullmatch(value["headSha"]):
        raise ContractError("invalid content binding")
    if value["state"] not in {"active", "expired", "released"}:
        raise ContractError("invalid lease state")
    for key in ("generation", "fencing", "eventSequence"):
        positive(value[key], key)
    if value["ttlSeconds"] != 3600 or value["graceSeconds"] != 600:
        raise ContractError("lease timing must be 3600 seconds plus 600 seconds grace")
    issued, expires, takeover, renewed = (dt(value[key]) for key in ("issuedAt", "leaseExpiresAt", "takeoverAt", "lastRenewedAt"))
    if issued > renewed or expires != renewed + timedelta(seconds=3600) or takeover != expires + timedelta(seconds=600):
        raise ContractError("lease timestamps do not match the timing contract")


def validate_request(value: dict) -> None:
    closed(value, REQUEST_FIELDS, "request")
    if value["schema"] != REQUEST_SCHEMA or value["kind"] != "lease-transition-request":
        raise ContractError("wrong request family")
    no_sensitive(value)
    for key, pattern in (("requestId", r"^request:[a-z][a-z0-9._-]{0,127}$"), ("leaseId", LEASE.pattern), ("requestedBy", ACTOR.pattern), ("idempotencyKey", r"^idempotency:[a-z][a-z0-9._-]{0,127}$"), ("authorityRef", r"^authority:[a-z][a-z0-9._-]{0,127}$")):
        if not re.fullmatch(pattern, value[key]):
            raise ContractError(f"invalid {key}")
    if value["action"] not in {"renew", "takeover", "release", "expire"}:
        raise ContractError("invalid action")
    positive(value["expectedGeneration"], "expectedGeneration")
    positive(value["expectedFencing"], "expectedFencing")
    dt(value["requestedAt"])
    if not isinstance(value["evidenceRefs"], list) or not value["evidenceRefs"] or len(value["evidenceRefs"]) != len(set(value["evidenceRefs"])) or any(not EVIDENCE.fullmatch(item) for item in value["evidenceRefs"]):
        raise ContractError("evidence references are invalid")
    supplied = (value["newOwnerActor"], value["newOwnerSession"], value["newWorktreeId"])
    if value["action"] == "takeover":
        if not ACTOR.fullmatch(value["newOwnerActor"] or "") or not SESSION.fullmatch(value["newOwnerSession"] or "") or not value["newWorktreeId"].startswith("worktree:"):
            raise ContractError("takeover requires a complete new owner")
    elif any(item is not None for item in supplied):
        raise ContractError("only takeover may name a new owner")


def validate_receipt(value: dict) -> None:
    closed(value, RECEIPT_FIELDS, "receipt")
    if value["schema"] != RECEIPT_SCHEMA or value["kind"] != "lease-transition-receipt":
        raise ContractError("wrong receipt family")
    no_sensitive(value)
    if not re.fullmatch(r"^request:[a-z][a-z0-9._-]{0,127}$", value["requestId"]) or not LEASE.fullmatch(value["leaseId"]):
        raise ContractError("invalid receipt identity")
    if value["action"] not in {"renew", "takeover", "release", "expire"} or value["outcome"] not in {"accepted", "rejected", "idempotent"}:
        raise ContractError("invalid receipt action or outcome")
    if value["stateBefore"] not in {"active", "expired", "released"} or value["stateAfter"] not in {"active", "expired", "released"}:
        raise ContractError("invalid receipt state")
    for key in ("previousGeneration", "generation", "previousFencing", "fencing"):
        positive(value[key], key)
    if value["outcome"] == "accepted" and (value["generation"] != value["previousGeneration"] + 1 or value["fencing"] != value["previousFencing"] + 1):
        raise ContractError("accepted receipt must advance both fences exactly once")
    if not ACTOR.fullmatch(value["ownerActor"]) or not SESSION.fullmatch(value["ownerSession"]):
        raise ContractError("invalid receipt owner")
    if not re.fullmatch(r"^receipt:lease\.[a-z][a-z0-9._:-]{0,159}$", value["receiptRef"]):
        raise ContractError("invalid receipt reference")
    expires, takeover = dt(value["leaseExpiresAt"]), dt(value["takeoverAt"])
    if takeover != expires + timedelta(seconds=600):
        raise ContractError("receipt takeover time is not bounded by grace")
    dt(value["occurredAt"])


def evaluate(lease: dict, request: dict) -> tuple[dict, dict | None]:
    validate_lease(lease)
    validate_request(request)
    before = lease["state"]
    now = dt(request["requestedAt"])
    code = None
    if request["leaseId"] != lease["leaseId"] or request["expectedGeneration"] != lease["generation"] or request["expectedFencing"] != lease["fencing"]:
        code = "LEASE_STALE_FENCE"
    elif request["action"] in {"renew", "release"} and request["requestedBy"] != lease["ownerActor"]:
        code = "LEASE_NOT_OWNER"
    elif request["action"] == "renew" and now >= dt(lease["takeoverAt"]):
        code = "LEASE_TAKEOVER_ELIGIBLE"
    elif request["action"] == "release" and before != "active":
        code = "LEASE_NOT_ACTIVE"
    elif request["action"] == "takeover" and request["requestedBy"] == lease["ownerActor"]:
        code = "LEASE_SAME_OWNER_TAKEOVER"
    elif request["action"] == "takeover" and (before != "active" or now < dt(lease["takeoverAt"])):
        code = "LEASE_TAKEOVER_TOO_EARLY"
    elif request["action"] == "expire" and (before != "active" or now < dt(lease["takeoverAt"])):
        code = "LEASE_EXPIRE_TOO_EARLY"
    accepted = code is None
    next_lease = None
    if accepted:
        next_lease = copy.deepcopy(lease)
        next_lease["generation"] += 1
        next_lease["fencing"] += 1
        next_lease["eventSequence"] += 1
        if request["action"] == "renew":
            next_lease["lastRenewedAt"] = request["requestedAt"]
            next_lease["leaseExpiresAt"] = (now + timedelta(seconds=3600)).isoformat().replace("+00:00", "Z")
            next_lease["takeoverAt"] = (now + timedelta(seconds=4200)).isoformat().replace("+00:00", "Z")
        elif request["action"] == "takeover":
            next_lease.update(ownerActor=request["newOwnerActor"], ownerSession=request["newOwnerSession"], worktreeId=request["newWorktreeId"], issuedAt=request["requestedAt"], lastRenewedAt=request["requestedAt"], leaseExpiresAt=(now + timedelta(seconds=3600)).isoformat().replace("+00:00", "Z"), takeoverAt=(now + timedelta(seconds=4200)).isoformat().replace("+00:00", "Z"))
        elif request["action"] == "release":
            next_lease["state"] = "released"
        else:
            next_lease["state"] = "expired"
    receipt = {"schema": RECEIPT_SCHEMA, "kind": "lease-transition-receipt", "requestId": request["requestId"], "leaseId": lease["leaseId"], "action": request["action"], "outcome": "accepted" if accepted else "rejected", "code": code, "stateBefore": before, "stateAfter": next_lease["state"] if next_lease else before, "previousGeneration": lease["generation"], "generation": next_lease["generation"] if next_lease else lease["generation"], "previousFencing": lease["fencing"], "fencing": next_lease["fencing"] if next_lease else lease["fencing"], "ownerActor": next_lease["ownerActor"] if next_lease else lease["ownerActor"], "ownerSession": next_lease["ownerSession"] if next_lease else lease["ownerSession"], "leaseExpiresAt": next_lease["leaseExpiresAt"] if next_lease else lease["leaseExpiresAt"], "takeoverAt": next_lease["takeoverAt"] if next_lease else lease["takeoverAt"], "receiptRef": "receipt:lease." + request["requestId"].removeprefix("request:"), "occurredAt": request["requestedAt"]}
    return receipt, next_lease


def rejected(name: str, function, base: dict, mutation) -> str:
    value = copy.deepcopy(base)
    mutation(value)
    try:
        function(value)
    except ContractError:
        return name
    raise AssertionError(f"adversarial case accepted: {name}")


def rejected_evaluation(name: str, lease: dict, request: dict, mutation, code: str) -> str:
    value = copy.deepcopy(request)
    mutation(value)
    receipt, next_lease = evaluate(lease, value)
    if next_lease is None and receipt["code"] == code:
        return name
    raise AssertionError(f"adversarial case accepted: {name}")


def run_all() -> dict:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    if schema["$id"] != "https://wellmanifest.dev/schemas/ticket-execution-lease/v1" or b"shell" in GRAMMAR_PATH.read_bytes().lower():
        raise ContractError("lease contract metadata or grammar is unsafe")
    base = {"schema": LEASE_SCHEMA, "kind": "execution-lease", "leaseId": "lease:ticket-011", "repositoryRef": "repository:demo", "ticket": "ticket-011", "workstreamRef": "workstream:integration", "branchRef": "branch:ticket-011-execution-lease-takeover", "worktreeId": "worktree:ticket-011", "ownerActor": "actor:agent-a", "ownerSession": "session:alpha", "scopeHash": "a" * 64, "headSha": "b" * 40, "state": "active", "generation": 1, "fencing": 1, "issuedAt": "2026-09-14T10:00:00Z", "leaseExpiresAt": "2026-09-14T11:00:00Z", "takeoverAt": "2026-09-14T11:10:00Z", "lastRenewedAt": "2026-09-14T10:00:00Z", "ttlSeconds": 3600, "graceSeconds": 600, "eventSequence": 1}
    renew = {"schema": REQUEST_SCHEMA, "kind": "lease-transition-request", "requestId": "request:renew", "leaseId": base["leaseId"], "action": "renew", "expectedGeneration": 1, "expectedFencing": 1, "requestedBy": "actor:agent-a", "newOwnerActor": None, "newOwnerSession": None, "newWorktreeId": None, "requestedAt": "2026-09-14T11:05:00Z", "authorityRef": "authority:controller", "evidenceRefs": ["receipt:lease.start"], "idempotencyKey": "idempotency:renew"}
    takeover = {**renew, "requestId": "request:takeover", "action": "takeover", "expectedGeneration": 1, "expectedFencing": 1, "requestedBy": "actor:agent-b", "newOwnerActor": "actor:agent-b", "newOwnerSession": "session:beta", "newWorktreeId": "worktree:ticket-011-reclaimed", "requestedAt": "2026-09-14T11:10:00Z", "idempotencyKey": "idempotency:takeover"}
    validate_lease(base); validate_request(renew); validate_request(takeover)
    renewed_receipt, renewed = evaluate(base, renew)
    assert renewed is not None and renewed["leaseExpiresAt"] == "2026-09-14T12:05:00Z"
    validate_receipt(renewed_receipt)
    rejected_cases = [
        rejected("invalid-expiry", validate_lease, base, lambda d: d.update(leaseExpiresAt="2026-09-14T11:01:00Z")),
        rejected_evaluation("wrong-owner-renewal", base, renew, lambda d: d.update(requestedBy="actor:agent-b"), "LEASE_NOT_OWNER"),
        rejected_evaluation("early-takeover", base, takeover, lambda d: d.update(requestedAt="2026-09-14T11:09:59Z"), "LEASE_TAKEOVER_TOO_EARLY"),
        rejected_evaluation("stale-generation", base, renew, lambda d: d.update(expectedGeneration=2), "LEASE_STALE_FENCE"),
        rejected("partial-new-owner", validate_request, takeover, lambda d: d.update(newOwnerSession=None)),
        rejected("unsafe-field", validate_request, renew, lambda d: d.update(secret="x")),
    ]
    taken_receipt, taken = evaluate(base, takeover)
    assert taken is not None and taken["ownerActor"] == "actor:agent-b" and taken["fencing"] == 2
    validate_receipt(taken_receipt)
    old_agent = {**renew, "expectedGeneration": 1, "expectedFencing": 1, "requestedAt": "2026-09-14T11:11:00Z"}
    stale_receipt, stale = evaluate(taken, old_agent)
    assert stale is None and stale_receipt["code"] == "LEASE_STALE_FENCE"
    return {"schema": "wellmanifest.ticket-execution-lease-conformance/v1", "ok": True, "timing": {"ttlSeconds": 3600, "graceSeconds": 600}, "positiveDocuments": 4, "adversarialRejected": rejected_cases + ["stale-fence-after-takeover"]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true")
    parser.parse_args()
    print(json.dumps(run_all(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
