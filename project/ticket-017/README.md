# Ticket 017: Modularize split_plan under 500 lines and harden ticket and lease conformance inputs, types, and I/O

- **ID**: ticket-017
- **Owner**: tom
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-11-11

## Goal and scope

SESSION_EXECUTION_AUTHORIZATION: On 2026-11-11 user authorized auditing, fixing bugs, optimizing, and hardening `wellmanifest/*` standard repositories.

Extract shared regular-file/symlink-safe strict JSON loading, canonical JSON bytes, iterative secret-key/token scanning, and strict RFC3339 1–9 fractional-second UTC parsing into `standard/ticket_io.py` so `standard/split_plan.py` (`524L -> < 500L`, retaining standalone fallback compatibility and byte-identical `--self-test` output), `standard/conformance.py`, and `standard/lease_conformance.py` all stay strictly below 500 lines; anchor regexes with `\A...\Z`; fix `TypeError`/`AttributeError` crashes on non-string fields, `None` `newWorktreeId` in lease `takeover`, boolean `ttlSeconds`/`graceSeconds`, and unhashable `evidenceRefs` items; block `..` traversal in `branchRef` and invalid `worktreeId` in `takeover`; add `standard/test_ticket_lifecycle.py`; and mark merged `project/ticket-016/README.md` `DONE`.

## Acceptance criteria

- [x] AC-01: Modularize `standard/split_plan.py` strictly `< 500` lines via `standard/ticket_io.py` (with standalone fallback and byte-identical `self_test` output), harden `conformance.py` and `lease_conformance.py` against non-string/unhashable/traversal/secret/RFC3339 edge cases, and mark `project/ticket-016/README.md` `DONE`.
- [x] AC-02: All owned Python modules (`ticket_io.py`, `split_plan.py`, `conformance.py`, `lease_conformance.py`, `test_ticket_lifecycle.py`) remain `< 500` lines and pass `ruff check --no-cache`, `python3 standard/conformance.py --all`, `python3 standard/lease_conformance.py --all`, `python3 standard/split_plan.py --self-test`, `python3 -m unittest discover -s standard -p 'test_*.py' -v`, `./project/governance-check.sh --base origin/main`, and `wellman check` with 0 errors.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
