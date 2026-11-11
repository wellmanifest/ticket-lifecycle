#!/usr/bin/env python3
"""Deterministic, inert conformance for ``wellmanifest.split-plan/v1``."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    from .ticket_io import (
        _out,
        read_strict_json,
        run_split_plan_selftest,
        scan_no_sensitive_values,
        split_plan_example_document,
    )
    from .ticket_io import canonical_bytes as _io_canonical_bytes
except ImportError:
    if str(Path(__file__).resolve().parent) not in sys.path:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        from ticket_io import (  # type: ignore[no-redef]
            _out,
            read_strict_json,
            run_split_plan_selftest,
            scan_no_sensitive_values,
            split_plan_example_document,
        )
        from ticket_io import canonical_bytes as _io_canonical_bytes  # type: ignore[no-redef]
    except ImportError:
        run_split_plan_selftest = None  # type: ignore[assignment]
        split_plan_example_document = None  # type: ignore[assignment]

        def _out(msg: str, stream: Any = None) -> None:
            (sys.stdout if stream is None else stream).write(f"{msg}\n")

        def _io_canonical_bytes(
            value: object, error_cls: type[ValueError] = ValueError
        ) -> bytes:
            try:
                return json.dumps(
                    value, sort_keys=True, separators=(",", ":"), allow_nan=False
                ).encode()
            except (TypeError, ValueError) as exc:
                raise error_cls(str(exc)) from exc

        def read_strict_json(
            path: str | Path,
            *,
            max_bytes: int = 4194304,
            error_cls: type[ValueError] = ValueError,
        ) -> Any:
            p = Path(path)
            if p.is_symlink() or not p.is_file() or p.stat().st_size > max_bytes:
                raise error_cls("invalid split-plan input file")
            return json.loads(p.read_text(encoding="utf-8"))

        def scan_no_sensitive_values(root: object, error_cls: type[ValueError]) -> None:
            stack: list[tuple[object, int]] = [(root, 0)]
            while stack:
                cur, depth = stack.pop()
                if depth > 64:
                    raise error_cls("nesting depth exceeds 64")
                if isinstance(cur, dict):
                    stack.extend((v, depth + 1) for v in cur.values())
                elif isinstance(cur, list):
                    stack.extend((v, depth + 1) for v in cur)
                elif isinstance(cur, str) and any(
                    ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in cur
                ):
                    raise error_cls("control characters in string field are forbidden")


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
SHA = re.compile(r"\A[0-9a-f]{40}\Z")
TICKET = re.compile(r"\Aticket-[0-9]{3,}\Z")
ARTIFACT = re.compile(r"\Aartifact:[a-z][a-z0-9._:-]{0,159}\Z")
RECEIPT = re.compile(r"\Areceipt:[a-z][a-z0-9._:-]{0,159}\Z")
REPOSITORY = re.compile(r"\Arepository:[a-z][a-z0-9._-]{0,95}\Z")
SLICE = re.compile(r"\Aslice:[a-z][a-z0-9._-]{0,95}\Z")
NODE = re.compile(r"\Anode:[a-z][a-z0-9._-]{0,95}\Z")
IDEMPOTENCY = re.compile(r"\Aidempotency:[a-z][a-z0-9._-]{0,127}\Z")
SCOPE_PATH = re.compile(
    r"\A(?!/)(?![A-Za-z]:[/\\])(?!.*(?:^|/)\.{1,2}(?:/|\Z))"
    r"(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+(?:/\*\*)?\Z"
)
MATERIAL_PATH = re.compile(
    r"\A(?!/)(?![A-Za-z]:[/\\])(?!.*(?:^|/)\.{1,2}(?:/|\Z))"
    r"(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+\Z"
)


class SplitPlanError(ValueError):
    """Raised when a split plan is structurally or semantically unsafe."""


def canonical_bytes(value: object) -> bytes:
    return _io_canonical_bytes(value, error_cls=SplitPlanError)


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
    value: object, label: str, pattern: re.Pattern[str], *, nonempty: bool
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
    return (value[:-3], True) if value.endswith("/**") else (value, False)


def _scope_covers(scope: str, path: str) -> bool:
    root, recursive = _scope_root(scope)
    return path == root or (recursive and path.startswith(root + "/"))


def _scopes_overlap(left: str, right: str) -> bool:
    l_root, l_rec = _scope_root(left)
    r_root, r_rec = _scope_root(right)
    return (
        l_root == r_root
        or (l_rec and r_root.startswith(l_root + "/"))
        or (r_rec and l_root.startswith(r_root + "/"))
    )


def _carrier_path(path: str) -> bool:
    return (
        path in {"TODO.md", "project/TICKETS.md", "artifact-registry.json"}
        or path.startswith(("project/ticket-", ".subactor/"))
        or path.endswith("/artifact-registry.json")
    )


def _validate_parent(value: object) -> dict[str, Any]:
    parent = _object(value, PARENT_KEYS, "parent checkpoint")
    for key in ("acceptedBaseSha", "headSha", "checkpointSha"):
        _match(parent[key], SHA, key)
    _receipt(
        parent["checkpointReceiptRef"], "checkpointReceiptRef", "receipt:continuity."
    )
    _receipt(parent["snapshotReceiptRef"], "snapshotReceiptRef", "receipt:snapshot.")
    _receipt(
        parent["secretScanReceiptRef"], "secretScanReceiptRef", "receipt:secret-scan."
    )
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
    if any(
        not any(_scope_covers(scope, path) for scope in scopes) for path in material
    ):
        raise SplitPlanError("material path escapes completed allowedPaths")
    state, terminal = completed["publicationState"], completed["terminalReceiptRef"]
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
        successor["allocationReceiptRef"], "allocationReceiptRef", "receipt:allocation."
    )
    scopes = _sorted_unique(
        successor["allowedPaths"], "successor allowedPaths", SCOPE_PATH, nonempty=True
    )
    _sorted_unique(successor["dependsOn"], "dependsOn", TICKET, nonempty=False)
    _sorted_unique(successor["conflictsWith"], "conflictsWith", TICKET, nonempty=False)
    if not isinstance(successor["integrationOwner"], bool):
        raise SplitPlanError("integrationOwner must be boolean")
    state, terminal = successor["state"], successor["terminalReceiptRef"]
    if state == "done":
        _receipt(terminal, "successor terminalReceiptRef")
    elif state in ACTIVE_STATES:
        if terminal is not None:
            raise SplitPlanError(
                "nonterminal successor cannot claim a terminal receipt"
            )
    else:
        raise SplitPlanError("invalid successor state")
    return successor, scopes


def _assert_acyclic(successors: list[dict[str, Any]]) -> None:
    tickets = {item["ticket"] for item in successors}
    graph = {
        item["ticket"]: {dep for dep in item["dependsOn"] if dep in tickets}
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
    if (
        document["schema"] != "wellmanifest.split-plan/v1"
        or document["kind"] != "split-plan"
    ):
        raise SplitPlanError("wrong split-plan document family")
    scan_no_sensitive_values(document, SplitPlanError)
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
        deps, conflicts = set(item["dependsOn"]), set(item["conflictsWith"])
        if ticket in deps or not deps <= allowed_dependencies:
            raise SplitPlanError("successor has a self or dangling dependency")
        if ticket in conflicts or not conflicts <= set(tickets):
            raise SplitPlanError("successor has a self or dangling conflict")
        if deps & conflicts:
            raise SplitPlanError("dependency cannot also be a conflict")
        if any(ticket not in set(by_ticket[c]["conflictsWith"]) for c in conflicts):
            raise SplitPlanError("conflictsWith must be symmetric")
    _assert_acyclic(successors)

    labelled = [("completed", p) for p in completed_scopes] + [
        (item["ticket"], p)
        for item, scopes in zip(successors, successor_scopes, strict=True)
        for p in scopes
    ]
    for idx, (l_owner, l_path) in enumerate(labelled):
        for r_owner, r_path in labelled[idx + 1 :]:
            if l_owner != r_owner and _scopes_overlap(l_path, r_path):
                raise SplitPlanError(
                    f"allowedPaths overlap across {l_owner} and {r_owner}"
                )

    owner = document["integrationOwnerTicket"]
    marked = [item["ticket"] for item in successors if item["integrationOwner"]]
    if owner is None:
        if marked:
            raise SplitPlanError("integration owner marker exists without owner ticket")
    elif _match(owner, TICKET, "integrationOwnerTicket") and (
        marked != [owner] or owner not in by_ticket
    ):
        raise SplitPlanError("integration owner binding is inconsistent")

    terminals = [
        item["terminalReceiptRef"]
        for item in successors
        if item["terminalReceiptRef"] is not None
    ]
    if completed["terminalReceiptRef"] is not None:
        terminals.append(completed["terminalReceiptRef"])
    if len(terminals) != len(set(terminals)):
        raise SplitPlanError("terminal receipts must be unique")
    canonical_bytes(document)
    return document


def pending_projection(value: object) -> dict[str, Any]:
    document = validate_document(value)
    successors = document["successors"]
    terminal = sorted(
        i["ticket"] for i in successors if i["terminalReceiptRef"] is not None
    )
    pending = sorted(i["ticket"] for i in successors if i["terminalReceiptRef"] is None)
    pending_set = set(pending)
    edges = sorted(
        [dep, i["ticket"]]
        for i in successors
        if i["ticket"] in pending_set
        for dep in i["dependsOn"]
        if dep in pending_set
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
    if split_plan_example_document is None:
        raise SplitPlanError("split-plan self-test requires ticket_io")
    return split_plan_example_document()


def self_test() -> dict[str, Any]:
    if run_split_plan_selftest is None:
        raise SplitPlanError("split-plan self-test requires ticket_io")
    return run_split_plan_selftest(
        validate_document,
        pending_projection,
        plan_digest,
        SCHEMA_PATH,
        GRAMMAR_PATH,
        SCHEMA_DIGEST,
        GRAMMAR_DIGEST,
        SplitPlanError,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("document", nargs="?", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--pending", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            result = self_test()
        elif args.document is not None:
            doc = read_strict_json(args.document, error_cls=SplitPlanError)
            result = (
                pending_projection(doc)
                if args.pending
                else {
                    "schema": "wellmanifest.split-plan-validation/v1",
                    "ok": True,
                    "planDigest": plan_digest(validate_document(doc)),
                }
            )
        else:
            parser.error("provide --self-test or a split-plan document")
    except SplitPlanError as exc:
        _out(
            json.dumps({"ok": False, "error": str(exc)}, sort_keys=True),
            stream=sys.stderr,
        )
        return 1
    _out(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
