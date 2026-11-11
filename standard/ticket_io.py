"""Shared bounded regular-file/JSON I/O, secret scanning, and RFC3339 helpers for ticket-lifecycle."""

from __future__ import annotations

import copy
import errno
import hashlib
import json
import math
import os
import re
import stat
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 64

_SENSITIVE_KEY_RE = re.compile(
    r"(shell|command|argv|password|credential|secret|url|remote|token|path)",
    re.IGNORECASE,
)
_SECRET_VALUE_PATTERNS = (
    re.compile(r"\bAK" r"IA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh" r"[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-" r"(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRI" r"VATE KEY-----"),
)
_RFC3339_RE = re.compile(
    r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.(\d{1,9}))?(?:Z|[+-]\d{2}:\d{2})\Z"
)

__all__ = [
    "MAX_FILE_BYTES",
    "MAX_JSON_DEPTH",
    "_check_no_symlink_ancestors",
    "_check_utf8_str",
    "_out",
    "canonical_bytes",
    "digest_bytes",
    "parse_rfc3339_utc",
    "read_strict_json",
    "run_split_plan_selftest",
    "scan_no_sensitive",
    "scan_no_sensitive_values",
    "split_plan_example_document",
]


def _out(msg: str, stream: Any = None) -> None:
    target = sys.stdout if stream is None else stream
    target.write(f"{msg}\n")


def _check_utf8_str(value: str, error_cls: type[ValueError] = ValueError) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise error_cls("lone UTF-16 surrogate in string is forbidden") from exc


def _has_control_char(value: str) -> bool:
    return any(ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F for ch in value)


def _check_no_symlink_ancestors(
    path: str | Path,
    *,
    include_self: bool = False,
    error_cls: type[ValueError] = ValueError,
) -> Path:
    raw_path = os.fspath(path)
    path_obj = Path(raw_path)
    raw_parts = path_obj.parts if include_self else path_obj.parts[:-1]
    if path_obj.is_absolute():
        cur = Path(path_obj.anchor)
        walk_parts = raw_parts[1:]
    else:
        cwd = Path.cwd()
        if len(cwd.parts) > 2 and cwd.is_symlink():
            raise error_cls(f"symlink ancestor is forbidden: {cwd}")
        for anc in cwd.parents:
            if len(anc.parts) > 2 and anc.is_symlink():
                raise error_cls(f"symlink ancestor is forbidden: {anc}")
        cur = cwd
        walk_parts = raw_parts
    for part in walk_parts:
        if part in ("", "."):
            continue
        cur = cur / part
        if part != ".." and len(cur.parts) > 2 and cur.is_symlink():
            raise error_cls(f"symlink ancestor is forbidden: {cur}")
    abs_path = Path(os.path.abspath(raw_path))
    if include_self and abs_path.is_symlink():
        raise error_cls(f"symlink path is forbidden: {path_obj}")
    if any(anc.is_symlink() for anc in abs_path.parents if len(anc.parts) > 2):
        raise error_cls(f"symlink ancestor is forbidden: {path_obj}")
    return abs_path


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, val in pairs:
        if key in obj:
            raise ValueError(f"duplicate JSON key: {key!r}")
        obj[key] = val
    return obj


def _reject_constant(token: str) -> Any:
    raise ValueError(f"non-finite JSON constant {token!r} is forbidden")


def _parse_finite_float(token: str) -> float:
    parsed = float(token)
    if not math.isfinite(parsed):
        raise ValueError(f"non-finite JSON number {token!r} is forbidden")
    return parsed


def _parse_finite_int(token: str) -> int:
    digits = token.removeprefix("-")
    if len(digits) > 309:
        raise ValueError("JSON integer magnitude exceeds finite range")
    parsed = int(token)
    try:
        ok = math.isfinite(float(parsed))
    except OverflowError:
        ok = False
    if not ok:
        raise ValueError("JSON integer magnitude exceeds finite range")
    return parsed


def read_strict_json(
    path: str | Path,
    *,
    max_bytes: int = MAX_FILE_BYTES,
    error_cls: type[ValueError] = ValueError,
) -> Any:
    if type(max_bytes) is not int or max_bytes < 1:
        raise error_cls("max_bytes must be a positive integer")
    raw_path = os.fspath(path)
    _check_no_symlink_ancestors(raw_path, include_self=False, error_cls=error_cls)
    try:
        lst = os.lstat(raw_path)
    except OSError as exc:
        raise error_cls(f"cannot stat JSON input: {exc}") from exc
    if stat.S_ISLNK(lst.st_mode):
        raise error_cls(f"symlink JSON input is forbidden: {raw_path}")
    if not stat.S_ISREG(lst.st_mode):
        raise error_cls(f"JSON input must be a regular file: {raw_path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(raw_path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise error_cls(f"symlink JSON input is forbidden: {raw_path}") from exc
        raise error_cls(f"cannot open JSON input: {exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise error_cls(f"JSON input must be a regular file: {raw_path}")
        if (st.st_dev, st.st_ino) != (lst.st_dev, lst.st_ino):
            raise error_cls(f"JSON input inode changed during open: {raw_path}")
        if st.st_size > max_bytes:
            raise error_cls(f"JSON input exceeds {max_bytes} bytes: {raw_path}")
        chunks = bytearray()
        while True:
            chunk = os.read(fd, min(65536, max_bytes + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
            if len(chunks) > max_bytes:
                raise error_cls(f"JSON input exceeds {max_bytes} bytes: {raw_path}")
    finally:
        os.close(fd)
    try:
        text = bytes(chunks).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise error_cls(f"invalid UTF-8 in JSON input: {exc}") from exc
    _check_utf8_str(text, error_cls=error_cls)
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
            parse_float=_parse_finite_float,
            parse_int=_parse_finite_int,
        )
    except RecursionError as exc:
        raise error_cls(f"JSON nesting depth exceeds {MAX_JSON_DEPTH}") from exc
    except ValueError as exc:
        raise error_cls(str(exc)) from exc
    stack: list[tuple[Any, int]] = [(parsed, 0)]
    while stack:
        cur, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise error_cls(f"JSON nesting depth exceeds {MAX_JSON_DEPTH}")
        if isinstance(cur, dict):
            for key, val in cur.items():
                if not isinstance(key, str):
                    raise error_cls("JSON object keys must be strings")
                _check_utf8_str(key, error_cls=error_cls)
                stack.append((val, depth + 1))
        elif isinstance(cur, list):
            for val in cur:
                stack.append((val, depth + 1))
        elif isinstance(cur, str):
            _check_utf8_str(cur, error_cls=error_cls)
    return parsed


def canonical_bytes(value: object, error_cls: type[ValueError] = ValueError) -> bytes:
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        cur, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise error_cls(f"JSON nesting depth exceeds {MAX_JSON_DEPTH}")
        if isinstance(cur, dict):
            for key, val in cur.items():
                if not isinstance(key, str):
                    raise error_cls("JSON object keys must be strings")
                _check_utf8_str(key, error_cls=error_cls)
                stack.append((val, depth + 1))
        elif isinstance(cur, list):
            for val in cur:
                stack.append((val, depth + 1))
        elif isinstance(cur, str):
            _check_utf8_str(cur, error_cls=error_cls)
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise error_cls(f"value is not canonically JSON-serializable: {exc}") from exc


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def scan_no_sensitive(
    root: object,
    error_cls: type[ValueError],
    *,
    check_keys: bool = True,
    allow_keys: frozenset[str] = frozenset(),
) -> None:
    stack: list[tuple[object, int]] = [(root, 0)]
    while stack:
        cur, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise error_cls(f"nesting depth exceeds {MAX_JSON_DEPTH}")
        if isinstance(cur, dict):
            for key, nested in cur.items():
                if not isinstance(key, str):
                    raise error_cls("object keys must be strings")
                _check_utf8_str(key, error_cls=error_cls)
                if _has_control_char(key) or (
                    check_keys
                    and key not in allow_keys
                    and _SENSITIVE_KEY_RE.search(key)
                ):
                    raise error_cls(f"unsafe field: {key}")
                stack.append((nested, depth + 1))
        elif isinstance(cur, list):
            for nested in cur:
                stack.append((nested, depth + 1))
        elif isinstance(cur, str):
            _check_utf8_str(cur, error_cls=error_cls)
            if _has_control_char(cur):
                raise error_cls("control characters in string field are forbidden")
            for pattern in _SECRET_VALUE_PATTERNS:
                if pattern.search(cur):
                    raise error_cls("secret-bearing token value is forbidden")


def scan_no_sensitive_values(root: object, error_cls: type[ValueError]) -> None:
    scan_no_sensitive(root, error_cls, check_keys=False)


def parse_rfc3339_utc(value: object, error_cls: type[ValueError]) -> datetime:
    if not isinstance(value, str):
        raise error_cls("timestamp must be a string")
    match = _RFC3339_RE.fullmatch(value)
    if match is None:
        raise error_cls("timestamp is not RFC 3339")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    frac = match.group(1)
    if frac is not None and len(frac) > 6:
        dot_idx = normalized.index(".")
        tz_idx = dot_idx + 1 + len(frac)
        normalized = f"{normalized[:dot_idx]}.{frac[:6]}{normalized[tz_idx:]}"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise error_cls("timestamp is not RFC 3339") from exc
    if parsed.tzinfo is None:
        raise error_cls("timestamp must include a timezone")
    return parsed.astimezone(UTC)


def _sp_succ(
    node: str,
    ticket: str,
    scope: str,
    deps: list[str],
    *,
    owner: bool = False,
    state: str = "planned",
) -> dict[str, Any]:
    num = int(ticket.removeprefix("ticket-"))
    term = f"receipt:github-pr.example.{num}" if state == "done" else None
    return {
        "nodeId": f"node:{node}",
        "ticket": ticket,
        "intentRef": f"artifact:intent.{ticket}",
        "allocationReceiptRef": f"receipt:allocation.{ticket}.example",
        "allowedPaths": [scope],
        "dependsOn": deps,
        "conflictsWith": [],
        "integrationOwner": owner,
        "state": state,
        "terminalReceiptRef": term,
    }


def split_plan_example_document() -> dict[str, Any]:
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
            _sp_succ("docs", "ticket-009", "docs/**", ["ticket-008"]),
            _sp_succ(
                "runtime", "ticket-010", "runtime/**", ["ticket-008"], state="done"
            ),
            _sp_succ(
                "integration",
                "ticket-011",
                "integration/**",
                ["ticket-009", "ticket-010"],
                owner=True,
            ),
        ],
        "integrationOwnerTicket": "ticket-011",
    }


def run_split_plan_selftest(
    validate_fn: Callable[[object], dict[str, Any]],
    pending_fn: Callable[[object], dict[str, Any]],
    plan_digest_fn: Callable[[dict[str, Any]], str],
    schema_path: Path,
    grammar_path: Path,
    schema_digest: str,
    grammar_digest: str,
    error_cls: type[ValueError],
) -> dict[str, Any]:
    schema_bytes = schema_path.read_bytes()
    grammar_bytes = grammar_path.read_bytes()
    if (
        json.loads(schema_bytes).get("$id")
        != "https://wellmanifest.dev/schemas/split-plan/v1"
    ):
        raise error_cls("schema identity mismatch")
    if schema_digest != "PENDING" and digest_bytes(schema_bytes) != schema_digest:
        raise error_cls("pinned split-plan schema digest mismatch")
    if grammar_digest != "PENDING" and digest_bytes(grammar_bytes) != grammar_digest:
        raise error_cls("pinned split-plan grammar digest mismatch")
    base = split_plan_example_document()
    validate_fn(base)
    projection = pending_fn(base)
    if projection["pendingTickets"] != ["ticket-009", "ticket-011"]:
        raise AssertionError("terminal child receipt did not prune pending DAG")
    if projection != pending_fn(json.loads(canonical_bytes(base, error_cls=error_cls))):
        raise AssertionError("canonical replay changed pending projection")

    def _succ(idx: int, **patch: Any) -> Callable[[dict[str, Any]], None]:
        return lambda d: d["successors"][idx].update(patch)

    def _cycle(d: dict[str, Any]) -> None:
        d["successors"][0]["dependsOn"] = ["ticket-011"]
        d["successors"][2]["dependsOn"] = ["ticket-009"]

    cases: tuple[tuple[str, Callable[[dict[str, Any]], None]], ...] = (
        ("open-fields", lambda d: d.update(tool="git")),
        ("absolute-path", _succ(0, allowedPaths=["/work"])),
        ("traversal-path", _succ(0, allowedPaths=["docs/../src"])),
        ("dot-segment", _succ(0, allowedPaths=["docs/./src"])),
        (
            "carrier-only",
            lambda d: d["completedSlice"].update(
                materialPaths=["TODO.md"], allowedPaths=["TODO.md"]
            ),
        ),
        (
            "material-escape",
            lambda d: d["completedSlice"].update(materialPaths=["src/app.py"]),
        ),
        ("scope-overlap", _succ(0, allowedPaths=["standard/**"])),
        ("duplicate-ticket", _succ(1, ticket="ticket-009")),
        ("missing-allocation", _succ(0, allocationReceiptRef=None)),
        ("dangling-dependency", _succ(0, dependsOn=["ticket-999"])),
        ("dependency-cycle", _cycle),
        ("asymmetric-conflict", _succ(0, conflictsWith=["ticket-011"])),
        ("owner-mismatch", lambda d: d.update(integrationOwnerTicket="ticket-009")),
        ("done-without-terminal", _succ(1, terminalReceiptRef=None)),
        (
            "active-with-terminal",
            _succ(0, terminalReceiptRef="receipt:github-pr.example.9"),
        ),
        (
            "wrong-secret-scan-family",
            lambda d: d["parent"].update(
                secretScanReceiptRef="receipt:validation.example"
            ),
        ),
        (
            "unstable-order",
            lambda d: d.update(successors=list(reversed(d["successors"]))),
        ),
    )
    rejected: list[str] = []
    for name, mutation in cases:
        cand = copy.deepcopy(base)
        mutation(cand)
        try:
            validate_fn(cand)
        except error_cls:
            rejected.append(name)
            continue
        raise AssertionError(f"adversarial case accepted: {name}")
    return {
        "schema": "wellmanifest.split-plan-conformance/v1",
        "ok": True,
        "planDigest": plan_digest_fn(base),
        "pendingProjection": projection,
        "adversarialRejected": rejected,
        "schemaDigest": "sha256:" + digest_bytes(schema_bytes),
        "grammarDigest": "sha256:" + digest_bytes(grammar_bytes),
    }
