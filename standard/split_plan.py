#!/usr/bin/env python3
"""Deterministic, inert conformance for ``wellmanifest.split-plan/v1``."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "split-plan.schema.json"
GRAMMAR_PATH = ROOT / "split-plan.v1.gbnf"
SCHEMA_DIGEST = "b58f514650f97ee3a0acfa4ec49deb83bc829b1781fd1bacbd88ffcbd21b75e5"
GRAMMAR_DIGEST = "51fa704a4bec23ed22d4c20e502cf1a51d19847da0463cd18f0bb7c4ee70e4de"

ROOT_KEYS = {
    "schema",
    "kind",
    "planRef",
    "repositoryRef",
    "parentTicket",
    "sliceId",
    "idempotencyKey",
    "parent",
    "completedSlice",
    "successors",
    "integrationOwnerTicket",
}
PARENT_KEYS = {
    "acceptedBaseSha",
    "headSha",
    "checkpointSha",
    "checkpointReceiptRef",
    "snapshotReceiptRef",
    "secretScanReceiptRef",
}
COMPLETED_KEYS = {
    "allowedPaths",
    "materialPaths",
    "materialArtifactRefs",
    "validationReceiptRefs",
    "publicationState",
    "terminalReceiptRef",
}
SUCCESSOR_KEYS = {
    "nodeId",
    "ticket",
    "intentRef",
    "allocationReceiptRef",
    "allowedPaths",
    "dependsOn",
    "conflictsWith",
    "integrationOwner",
    "state",
    "terminalReceiptRef",
}
ACTIVE_STATES = {
    "allocated",
    "planned",
    "authorized",
    "editing",
    "validating",
    "publication",
    "blocked",
}
SHA = re.compile(r"^[0-9a-f]{40}$")
TICKET = re.compile(r"^ticket-[0-9]{3,}$")
ARTIFACT = re.compile(r"^artifact:[a-z][a-z0-9._:-]{0,159}$")
RECEIPT = re.compile(r"^receipt:[a-z][a-z0-9._:-]{0,159}$")
REPOSITORY = re.compile(r"^repository:[a-z][a-z0-9._-]{0,95}$")
SLICE = re.compile(r"^slice:[a-z][a-z0-9._-]{0,95}$")
NODE = re.compile(r"^node:[a-z][a-z0-9._-]{0,95}$")
IDEMPOTENCY = re.compile(r"^idempotency:[a-z][a-z0-9._-]{0,127}$")
SCOPE_PATH = re.compile(
    r"^(?!/)(?![A-Za-z]:[/\\])(?!.*(?:^|/)\.{1,2}(?:/|$))"
    r"(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+(?:/\*\*)?$"
)
MATERIAL_PATH = re.compile(
    r"^(?!/)(?![A-Za-z]:[/\\])(?!.*(?:^|/)\.{1,2}(?:/|$))"
    r"(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+$"
)


class SplitPlanError(ValueError):
    """Raised when a split plan is structurally or semantically unsafe."""


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def plan_digest(document: dict[str, Any]) -> str:
    return "sha256:" + digest_bytes(canonical_bytes(document))


def _object(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise SplitPlanError(f"{label} fields are not closed")
    return value


def _match(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise SplitPlanError(f"invalid {label}")
    return value


def _sorted_unique(
    value: object,
    label: str,
    pattern: re.Pattern[str],
    *,
    nonempty: bool,
) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value):
        raise SplitPlanError(f"{label} must be a canonical array")
    result = [_match(item, pattern, label) for item in value]
    if result != sorted(set(result)):
        raise SplitPlanError(f"{label} must be sorted and unique")
    return result


def _receipt(value: object, label: str, prefix: str | None = None) -> str:
    result = _match(value, RECEIPT, label)
    if prefix is not None and not result.startswith(prefix):
        raise SplitPlanError(f"{label} has the wrong receipt family")
    return result


def _scope_root(value: str) -> tuple[str, bool]:
    if value.endswith("/**"):
        return value[:-3], True
    return value, False


def _scope_covers(scope: str, path: str) -> bool:
    root, recursive = _scope_root(scope)
    return path == root or (recursive and path.startswith(root + "/"))


def _scopes_overlap(left: str, right: str) -> bool:
    left_root, left_recursive = _scope_root(left)
    right_root, right_recursive = _scope_root(right)
    if left_root == right_root:
        return True
    return (left_recursive and right_root.startswith(left_root + "/")) or (
        right_recursive and left_root.startswith(right_root + "/")
    )


def _carrier_path(path: str) -> bool:
    return (
        path in {"TODO.md", "project/TICKETS.md", "artifact-registry.json"}
        or path.startswith("project/ticket-")
        or path.startswith(".subactor/")
        or path.endswith("/artifact-registry.json")
    )


def _validate_parent(value: object) -> dict[str, Any]:
    parent = _object(value, PARENT_KEYS, "parent checkpoint")
    for key in ("acceptedBaseSha", "headSha", "checkpointSha"):
        _match(parent[key], SHA, key)
    _receipt(parent["checkpointReceiptRef"], "checkpointReceiptRef", "receipt:continuity.")
    _receipt(parent["snapshotReceiptRef"], "snapshotReceiptRef", "receipt:snapshot.")
    _receipt(parent["secretScanReceiptRef"], "secretScanReceiptRef", "receipt:secret-scan.")
    return parent


def _validate_completed(value: object) -> tuple[dict[str, Any], list[str]]:
    completed = _object(value, COMPLETED_KEYS, "completed slice")
    scopes = _sorted_unique(
        completed["allowedPaths"], "completed allowedPaths", SCOPE_PATH, nonempty=True
    )
    material = _sorted_unique(
        completed["materialPaths"], "materialPaths", MATERIAL_PATH, nonempty=True
    )
    _sorted_unique(
        completed["materialArtifactRefs"],
        "materialArtifactRefs",
        ARTIFACT,
        nonempty=True,
    )
    _sorted_unique(
        completed["validationReceiptRefs"],
        "validationReceiptRefs",
        RECEIPT,
        nonempty=True,
    )
    if all(_carrier_path(path) for path in material):
        raise SplitPlanError("completed slice is carrier-only")
    if any(not any(_scope_covers(scope, path) for scope in scopes) for path in material):
        raise SplitPlanError("material path escapes completed allowedPaths")
    state = completed["publicationState"]
    terminal = completed["terminalReceiptRef"]
    if state == "ready" and terminal is not None:
        raise SplitPlanError("ready slice cannot claim a terminal receipt")
    if state == "published":
        _receipt(terminal, "completed terminalReceiptRef")
    elif state != "ready":
        raise SplitPlanError("invalid completed publicationState")
    return completed, scopes


def _validate_successor(value: object) -> tuple[dict[str, Any], list[str]]:
    successor = _object(value, SUCCESSOR_KEYS, "successor")
    _match(successor["nodeId"], NODE, "nodeId")
    _match(successor["ticket"], TICKET, "successor ticket")
    _match(successor["intentRef"], ARTIFACT, "intentRef")
    _receipt(
        successor["allocationReceiptRef"],
        "allocationReceiptRef",
        "receipt:allocation.",
    )
    scopes = _sorted_unique(
        successor["allowedPaths"], "successor allowedPaths", SCOPE_PATH, nonempty=True
    )
    _sorted_unique(successor["dependsOn"], "dependsOn", TICKET, nonempty=False)
    _sorted_unique(
        successor["conflictsWith"], "conflictsWith", TICKET, nonempty=False
    )
    if not isinstance(successor["integrationOwner"], bool):
        raise SplitPlanError("integrationOwner must be boolean")
    state = successor["state"]
    terminal = successor["terminalReceiptRef"]
    if state == "done":
        _receipt(terminal, "successor terminalReceiptRef")
    elif state in ACTIVE_STATES:
        if terminal is not None:
            raise SplitPlanError("nonterminal successor cannot claim a terminal receipt")
    else:
        raise SplitPlanError("invalid successor state")
    return successor, scopes


def _assert_acyclic(successors: list[dict[str, Any]]) -> None:
    tickets = {item["ticket"] for item in successors}
    graph = {
        item["ticket"]: {dependency for dependency in item["dependsOn"] if dependency in tickets}
        for item in successors
    }
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(ticket: str) -> None:
        if ticket in visiting:
            raise SplitPlanError("successor dependency cycle")
        if ticket in visited:
            return
        visiting.add(ticket)
        for dependency in graph[ticket]:
            visit(dependency)
        visiting.remove(ticket)
        visited.add(ticket)

    for ticket in sorted(graph):
        visit(ticket)


def validate_document(value: object) -> dict[str, Any]:
    document = _object(value, ROOT_KEYS, "split plan")
    if document["schema"] != "wellmanifest.split-plan/v1" or document["kind"] != "split-plan":
        raise SplitPlanError("wrong split-plan document family")
    _match(document["planRef"], ARTIFACT, "planRef")
    _match(document["repositoryRef"], REPOSITORY, "repositoryRef")
    parent_ticket = _match(document["parentTicket"], TICKET, "parentTicket")
    _match(document["sliceId"], SLICE, "sliceId")
    _match(document["idempotencyKey"], IDEMPOTENCY, "idempotencyKey")
    _validate_parent(document["parent"])
    completed, completed_scopes = _validate_completed(document["completedSlice"])

    raw_successors = document["successors"]
    if not isinstance(raw_successors, list) or not 1 <= len(raw_successors) <= 64:
        raise SplitPlanError("successors must contain 1..64 nodes")
    validated = [_validate_successor(item) for item in raw_successors]
    successors = [item for item, _ in validated]
    successor_scopes = [scopes for _, scopes in validated]
    tickets = [item["ticket"] for item in successors]
    if tickets != sorted(set(tickets)):
        raise SplitPlanError("successors must be ticket-sorted and unique")
    if parent_ticket in tickets:
        raise SplitPlanError("parent ticket cannot be its own successor")
    node_ids = [item["nodeId"] for item in successors]
    allocations = [item["allocationReceiptRef"] for item in successors]
    if len(node_ids) != len(set(node_ids)) or len(allocations) != len(set(allocations)):
        raise SplitPlanError("node and allocation receipts must be unique")

    allowed_dependencies = set(tickets) | {parent_ticket}
    by_ticket = {item["ticket"]: item for item in successors}
    for item in successors:
        ticket = item["ticket"]
        dependencies = set(item["dependsOn"])
        conflicts = set(item["conflictsWith"])
        if ticket in dependencies or not dependencies <= allowed_dependencies:
            raise SplitPlanError("successor has a self or dangling dependency")
        if ticket in conflicts or not conflicts <= set(tickets):
            raise SplitPlanError("successor has a self or dangling conflict")
        if dependencies & conflicts:
            raise SplitPlanError("dependency cannot also be a conflict")
        for conflict in conflicts:
            if ticket not in set(by_ticket[conflict]["conflictsWith"]):
                raise SplitPlanError("conflictsWith must be symmetric")
    _assert_acyclic(successors)

    labelled_scopes = [("completed", path) for path in completed_scopes]
    for item, scopes in zip(successors, successor_scopes, strict=True):
        labelled_scopes.extend((item["ticket"], path) for path in scopes)
    for index, (left_owner, left_path) in enumerate(labelled_scopes):
        for right_owner, right_path in labelled_scopes[index + 1 :]:
            if left_owner != right_owner and _scopes_overlap(left_path, right_path):
                raise SplitPlanError(
                    f"allowedPaths overlap across {left_owner} and {right_owner}"
                )

    owner = document["integrationOwnerTicket"]
    marked = [item["ticket"] for item in successors if item["integrationOwner"]]
    if owner is None:
        if marked:
            raise SplitPlanError("integration owner marker exists without owner ticket")
    else:
        _match(owner, TICKET, "integrationOwnerTicket")
        if marked != [owner] or owner not in by_ticket:
            raise SplitPlanError("integration owner binding is inconsistent")

    terminal_receipts = [
        item["terminalReceiptRef"]
        for item in successors
        if item["terminalReceiptRef"] is not None
    ]
    if completed["terminalReceiptRef"] is not None:
        terminal_receipts.append(completed["terminalReceiptRef"])
    if len(terminal_receipts) != len(set(terminal_receipts)):
        raise SplitPlanError("terminal receipts must be unique")
    return document


def pending_projection(value: object) -> dict[str, Any]:
    document = validate_document(value)
    successors = document["successors"]
    terminal = sorted(
        item["ticket"] for item in successors if item["terminalReceiptRef"] is not None
    )
    pending = sorted(
        item["ticket"] for item in successors if item["terminalReceiptRef"] is None
    )
    pending_set = set(pending)
    edges = sorted(
        [dependency, item["ticket"]]
        for item in successors
        if item["ticket"] in pending_set
        for dependency in item["dependsOn"]
        if dependency in pending_set
    )
    return {
        "schema": "wellmanifest.split-plan-pending/v1",
        "planRef": document["planRef"],
        "parentTicket": document["parentTicket"],
        "planDigest": plan_digest(document),
        "pendingTickets": pending,
        "terminalTickets": terminal,
        "pendingEdges": edges,
    }


def example_document() -> dict[str, Any]:
    return {
        "schema": "wellmanifest.split-plan/v1",
        "kind": "split-plan",
        "planRef": "artifact:delivery-plan.workspace-refactor.v1",
        "repositoryRef": "repository:ticket-lifecycle",
        "parentTicket": "ticket-008",
        "sliceId": "slice:split-contract",
        "idempotencyKey": "idempotency:split.ticket-008.v1",
        "parent": {
            "acceptedBaseSha": "a" * 40,
            "headSha": "b" * 40,
            "checkpointSha": "c" * 40,
            "checkpointReceiptRef": "receipt:continuity.ticket-008.1.example",
            "snapshotReceiptRef": "receipt:snapshot.ticket-008.1.example",
            "secretScanReceiptRef": "receipt:secret-scan.ticket-008.1.example",
        },
        "completedSlice": {
            "allowedPaths": ["standard/split_plan.py"],
            "materialPaths": ["standard/split_plan.py"],
            "materialArtifactRefs": ["artifact:split-plan.validator.v1"],
            "validationReceiptRefs": ["receipt:validation.ticket-008.example"],
            "publicationState": "ready",
            "terminalReceiptRef": None,
        },
        "successors": [
            {
                "nodeId": "node:docs",
                "ticket": "ticket-009",
                "intentRef": "artifact:intent.ticket-009",
                "allocationReceiptRef": "receipt:allocation.ticket-009.example",
                "allowedPaths": ["docs/**"],
                "dependsOn": ["ticket-008"],
                "conflictsWith": [],
                "integrationOwner": False,
                "state": "planned",
                "terminalReceiptRef": None,
            },
            {
                "nodeId": "node:runtime",
                "ticket": "ticket-010",
                "intentRef": "artifact:intent.ticket-010",
                "allocationReceiptRef": "receipt:allocation.ticket-010.example",
                "allowedPaths": ["runtime/**"],
                "dependsOn": ["ticket-008"],
                "conflictsWith": [],
                "integrationOwner": False,
                "state": "done",
                "terminalReceiptRef": "receipt:github-pr.example.10",
            },
            {
                "nodeId": "node:integration",
                "ticket": "ticket-011",
                "intentRef": "artifact:intent.ticket-011",
                "allocationReceiptRef": "receipt:allocation.ticket-011.example",
                "allowedPaths": ["integration/**"],
                "dependsOn": ["ticket-009", "ticket-010"],
                "conflictsWith": [],
                "integrationOwner": True,
                "state": "planned",
                "terminalReceiptRef": None,
            },
        ],
        "integrationOwnerTicket": "ticket-011",
    }


def _rejected(
    name: str, base: dict[str, Any], mutation: Callable[[dict[str, Any]], None]
) -> str:
    candidate = copy.deepcopy(base)
    mutation(candidate)
    try:
        validate_document(candidate)
    except SplitPlanError:
        return name
    raise AssertionError(f"adversarial case accepted: {name}")


def self_test() -> dict[str, Any]:
    schema_bytes = SCHEMA_PATH.read_bytes()
    grammar_bytes = GRAMMAR_PATH.read_bytes()
    schema = json.loads(schema_bytes)
    if schema.get("$id") != "https://wellmanifest.dev/schemas/split-plan/v1":
        raise SplitPlanError("schema identity mismatch")
    if SCHEMA_DIGEST != "PENDING" and digest_bytes(schema_bytes) != SCHEMA_DIGEST:
        raise SplitPlanError("pinned split-plan schema digest mismatch")
    if GRAMMAR_DIGEST != "PENDING" and digest_bytes(grammar_bytes) != GRAMMAR_DIGEST:
        raise SplitPlanError("pinned split-plan grammar digest mismatch")

    base = example_document()
    validate_document(base)
    projection = pending_projection(base)
    if projection["pendingTickets"] != ["ticket-009", "ticket-011"]:
        raise AssertionError("terminal child receipt did not prune pending DAG")
    if projection != pending_projection(json.loads(canonical_bytes(base))):
        raise AssertionError("canonical replay changed pending projection")

    rejected = [
        _rejected("open-fields", base, lambda d: d.update(tool="git")),
        _rejected("absolute-path", base, lambda d: d["successors"][0].update(allowedPaths=["/tmp/work"])),
        _rejected("traversal-path", base, lambda d: d["successors"][0].update(allowedPaths=["docs/../src"])),
        _rejected("dot-segment", base, lambda d: d["successors"][0].update(allowedPaths=["docs/./src"])),
        _rejected("carrier-only", base, lambda d: d["completedSlice"].update(materialPaths=["TODO.md"], allowedPaths=["TODO.md"])),
        _rejected("material-escape", base, lambda d: d["completedSlice"].update(materialPaths=["src/app.py"])),
        _rejected("scope-overlap", base, lambda d: d["successors"][0].update(allowedPaths=["standard/**"])),
        _rejected("duplicate-ticket", base, lambda d: d["successors"][1].update(ticket="ticket-009")),
        _rejected("missing-allocation", base, lambda d: d["successors"][0].update(allocationReceiptRef=None)),
        _rejected("dangling-dependency", base, lambda d: d["successors"][0].update(dependsOn=["ticket-999"])),
        _rejected("dependency-cycle", base, lambda d: (d["successors"][0].update(dependsOn=["ticket-011"]), d["successors"][2].update(dependsOn=["ticket-009"]))),
        _rejected("asymmetric-conflict", base, lambda d: d["successors"][0].update(conflictsWith=["ticket-011"])),
        _rejected("owner-mismatch", base, lambda d: d.update(integrationOwnerTicket="ticket-009")),
        _rejected("done-without-terminal", base, lambda d: d["successors"][1].update(terminalReceiptRef=None)),
        _rejected("active-with-terminal", base, lambda d: d["successors"][0].update(terminalReceiptRef="receipt:github-pr.example.9")),
        _rejected("wrong-secret-scan-family", base, lambda d: d["parent"].update(secretScanReceiptRef="receipt:validation.example")),
        _rejected("unstable-order", base, lambda d: d.update(successors=list(reversed(d["successors"])))),
    ]
    return {
        "schema": "wellmanifest.split-plan-conformance/v1",
        "ok": True,
        "planDigest": plan_digest(base),
        "pendingProjection": projection,
        "adversarialRejected": rejected,
        "schemaDigest": "sha256:" + digest_bytes(schema_bytes),
        "grammarDigest": "sha256:" + digest_bytes(grammar_bytes),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("document", nargs="?", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--pending", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        result = self_test()
    elif args.document is not None:
        document = json.loads(args.document.read_text(encoding="utf-8"))
        result = pending_projection(document) if args.pending else {
            "schema": "wellmanifest.split-plan-validation/v1",
            "ok": True,
            "planDigest": plan_digest(validate_document(document)),
        }
    else:
        parser.error("provide --self-test or a split-plan document")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
